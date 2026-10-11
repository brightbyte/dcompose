"""The gate in front of commands that start a container from an image.

`docker run` becomes create, inspect, check, start: the daemon parses the
command line, and the policy looks at the container it produced, from an image
that cannot change between check and start. The one image-derived fact checked
is the identity the container would run as (see imageuser), unless the command
line sets a user: the person typing the command is trusted, the image is not.

An image that would run as root is not refused but run as nobody instead, with
a notice. An image that chose some other user itself, below the allowed range
or present on this host, is refused: overriding a deliberate choice silently
would only break it in a more confusing way.

`start` and `restart` apply the same check to existing containers, which cannot
be rewritten. `create` only gets the hardening defaults; its container is
checked when it is started. `audit` predicts the outcome for an image.
"""

import os
import sys
from typing import NamedTuple

from dcompose import imageuser, runargs
from dcompose.dockerclient import DockerError
from dcompose.text import printable

# Inserted before the user's own arguments, so the user can override both
# (for example `--cap-add NET_BIND_SERVICE`).
DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]
FALLBACK_USER = f"{imageuser.NOBODY}:{imageuser.NOBODY}"

VALUE_LONG = frozenset({"--detach-keys", "--checkpoint", "--checkpoint-dir", "--signal", "--time"})
VALUE_SHORT = frozenset("st")


class Context(NamedTuple):
    docker: object
    id_range: tuple
    local: object
    current_user: tuple | None = None  # (uid, gid) that `me` stands for; the real ones if None

    def current_ids(self):
        return self.current_user or (os.getuid(), os.getgid())


class Assessment(NamedTuple):
    kind: str            # explicit, ok, fallback or refused
    problems: list
    identity: imageuser.Identity | None = None


def assess(ctx, container, info, explicit=None):
    """What the image would be allowed to do. explicit: the user was set on the command line, if known."""
    image = ctx.docker.inspect_image(info["Image"])
    spec = info["Config"].get("User") or ""
    if explicit is None:
        explicit = spec != (image["Config"].get("User") or "")
    if explicit:
        return Assessment("explicit", [])  # trusted: the person typing the command chose it

    passwd = ctx.docker.read_file(container, "/etc/passwd") or ""
    groups = ctx.docker.read_file(container, "/etc/group") or ""
    try:
        identity = imageuser.resolve(spec, passwd, groups)
    except ValueError as e:
        return Assessment("refused", [str(e)])
    problems = imageuser.check(identity, ctx.id_range, ctx.local)
    if not problems:
        return Assessment("ok", [], identity)
    return Assessment("fallback" if imageuser.involves_root(identity) else "refused", problems, identity)


def run(ctx, args):
    """`docker run`; returns the exit code."""
    try:
        parsed = runargs.parse(args, ctx.current_ids())
    except runargs.ParseError as e:
        return refuse([f"cannot read the command line: {e}; use the real docker for this one"])

    created = create_checked(ctx, parsed, [])
    if isinstance(created, int):
        return created
    container, info, assessment = created

    if assessment.kind == "fallback":
        ctx.docker.remove(container)
        notice(f"image {parsed.image} would run as root; running it as nobody ({FALLBACK_USER}) instead. "
               "Use --user or --current-user to choose another user.")
        created = create_checked(ctx, parsed, [f"--user={FALLBACK_USER}"])
        if isinstance(created, int):
            return created
        container, info, assessment = created

    return ctx.docker.start(
        container,
        attach=not parsed.detach,
        interactive=bool(info["Config"].get("OpenStdin")),
        detach_keys=parsed.detach_keys,
    )


def create_checked(ctx, parsed, extra):
    """Create the container; (container, info, assessment), or an exit code if it must not start.

    A container that would be refused is removed. A fallback assessment is
    returned to the caller, which re-creates the container as nobody.
    """
    code, container = ctx.docker.create([*DEFAULTS, *extra, *parsed.create_args])
    if container is None:
        return code
    try:
        info = ctx.docker.inspect_container(container)
        problems = verify_split(info, parsed)
        assessment = Assessment("refused", problems) if problems else assess(
            ctx, container, info, explicit=parsed.user_given or bool(extra))
    except (DockerError, ValueError, KeyError) as e:
        assessment = Assessment("refused", [str(e)])
    if assessment.kind == "refused":
        ctx.docker.remove(container)
        return refuse(explain(assessment))
    return container, info, assessment


def audit(ctx, args):
    """`docker audit [--user USER | --current-user] IMAGE`: what `docker run IMAGE` would do.

    Exit status 1 means it would be refused.
    """
    try:
        parsed = runargs.parse(args, ctx.current_ids())
        # parse rewrites every way of giving a user to --user=...
        if parsed.command or any(not t.startswith("--user=") for t in parsed.create_args[:-1]):
            raise runargs.ParseError("only --user and --current-user can come before the image")
    except runargs.ParseError as e:
        print(f"dcompose: {printable(e)}\nusage: docker audit [--user USER | --current-user] IMAGE",
              file=sys.stderr)
        return 2

    image = parsed.image
    code, container = ctx.docker.create(["--pull=never", *parsed.create_args])
    if container is None:
        print(f"dcompose: image {printable(image)} is not available locally; run `docker pull` first "
              "(pulling does not run the image), then audit it", file=sys.stderr)
        return code or 1
    try:
        info = ctx.docker.inspect_container(container)
        assessment = assess(ctx, container, info, explicit=parsed.user_given)
    except (DockerError, ValueError, KeyError) as e:
        assessment = Assessment("refused", [str(e)])
    finally:
        ctx.docker.remove(container)

    return report_assessment(image, parsed, assessment)


def report_assessment(image, parsed, assessment):
    name = printable(image)
    who = imageuser.describe(assessment.identity) if assessment.identity else None
    if assessment.kind == "explicit":
        print(f"image {name}: the user is set on the command line; the image's own user is not checked")
    elif assessment.kind == "ok":
        print(f"image {name}: runs as {who}; accepted")
    elif assessment.kind == "fallback":
        print(f"image {name}: would run as {who}; "
              f"docker run would run it as nobody ({FALLBACK_USER}) instead")
        for problem in assessment.problems:
            print(f"  {printable(problem)}")
        print("  pass --user or --current-user to choose another user")
    else:
        print(f"image {name}: would be refused" + (f" (runs as {who})" if who else ""))
        for problem in assessment.problems:
            print(f"  {printable(problem)}")
        print("  pass --user or --current-user to choose a user yourself")
    if assessment.kind != "refused":
        print("docker run also adds " + " ".join(DEFAULTS) + "; later options override them")
    return 1 if assessment.kind == "refused" else 0


def check_existing(ctx, args):
    """Problems for the containers named in `docker start`/`restart` arguments."""
    problems = []
    for ref in container_refs(args):
        try:
            info = ctx.docker.inspect_container(ref)
            assessment = assess(ctx, info["Id"], info)
            problems += [f"{ref}: {p}" for p in explain(assessment)]
        except (DockerError, ValueError, KeyError) as e:
            problems.append(f"{ref}: {e}")
    return problems


def container_refs(args):
    refs = []
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            refs += args[i + 1:]
            break
        if token.startswith("--"):
            i += 1 if "=" in token or token not in VALUE_LONG else 2
        elif token.startswith("-") and token != "-":
            i += 2 if token[-1] in VALUE_SHORT else 1
        else:
            refs.append(token)
            i += 1
    return refs


def verify_split(info, parsed):
    """Our reading of the command line must match what the daemon created, or we refuse."""
    config = info["Config"]
    misread_image = config.get("Image") != parsed.image
    misread_command = parsed.command and (config.get("Cmd") or []) != parsed.command
    if misread_image or misread_command:
        return ["could not reliably tell the image from the command line; use the real docker for this one"]
    return []


def explain(assessment):
    """The problems, with how to get past them when they come from the image's own identity."""
    if assessment.identity is None:
        return assessment.problems
    return [f"{p}; pass --user to choose one" for p in assessment.problems]


def notice(text):
    print(f"dcompose: {printable(text)}", file=sys.stderr)


def refuse(problems):
    for problem in problems:
        print(f"dcompose: refusing: {printable(problem)}", file=sys.stderr)
    return 1
