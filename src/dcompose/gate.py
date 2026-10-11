"""The gate in front of commands that start a container from an image.

`docker run` becomes create, inspect, check, start: the daemon parses the
command line, and the policy looks at the container it produced, from an image
that cannot change between check and start. The one image-derived fact checked
is the identity the container would run as (see imageuser), unless the command
line sets a user: the person typing the command is trusted, the image is not.

An image user that is accepted is not left for the runtime to resolve a second time: the container
is re-created with `--user uid:gid` as the checked numbers, so a difference between our reading of the
image's passwd and group files and the runtime's can at worst refuse a good image, never run root.

With no user chosen on the command line: an image that would run as root is run as nobody
instead, with a notice; so is any image user at all if the container has bind mounts (or
devices), because a container that reaches host files must have its user chosen by the person
typing the command. The notice says which ids the image would have used, so that they can be
passed to --user. Without mounts the image's own non-root user is accepted, unless this host
has an account with that id (the container would share that account's kernel limits): that is
refused.

`start` and `restart` apply the same check to existing containers, which cannot
be rewritten. `create` only gets the hardening defaults; its container is
checked when it is started. `audit` predicts the outcome for an image.
"""

import os
import sys
from typing import NamedTuple

from dcompose import hostusers, imageuser, runargs
from dcompose.dockerclient import DockerError
from dcompose.text import printable

# Inserted before the user's own arguments, so the user can override both
# (for example `--cap-add NET_BIND_SERVICE`).
DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]
FALLBACK_USER = f"{imageuser.NOBODY}:{imageuser.NOBODY}"
MOUNTS_REASON = "there are bind mounts, so the user must be given explicitly"

VALUE_LONG = frozenset({"--detach-keys", "--checkpoint", "--checkpoint-dir", "--signal", "--time"})
VALUE_SHORT = frozenset("st")


class Context(NamedTuple):
    docker: object
    local: object
    current_user: tuple | None = None  # (uid, gid) that --as-me stands for; the real ones if None
    resolve_user: object = None        # turns the name given to --as into ids (hostusers.resolve_account)

    def current_ids(self):
        return self.current_user or (os.getuid(), os.getgid())

    def resolver(self):
        return self.resolve_user or hostusers.resolve_account


class Assessment(NamedTuple):
    kind: str            # explicit, ok, fallback or refused
    problems: list
    identity: imageuser.Identity | None = None
    reason: str | None = None  # why a fallback: "root" or "mounts"


def has_host_mounts(info):
    """Whether the container, as inspected, reaches host files or devices.

    Bind mounts, devices and volumes taken from another container all do. Named volumes live in
    docker's own directory and tmpfs in memory, so the user id means nothing to the host there.
    """
    host = info.get("HostConfig") or {}
    mounts = [*(info.get("Mounts") or []), *(host.get("Mounts") or [])]
    binds = [b for b in host.get("Binds") or [] if str(b).split(":")[0].startswith("/")]
    binds_or_devices = any(m.get("Type") == "bind" for m in mounts) or binds
    return bool(binds_or_devices or host.get("Devices") or host.get("VolumesFrom"))


def assess(ctx, container, info, explicit=None, mounts=None):
    """What the image would be allowed to do.

    explicit: the user was set on the command line, if known.
    mounts: the container reaches host files or devices; worked out from info if not given.

    With no user chosen, root is run as nobody; so is any image user if there are mounts, because
    a user that mounts something must be chosen explicitly. Without mounts the image's own
    non-root user is accepted unless this host has an account with that id.
    """
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
    if mounts is None:
        mounts = has_host_mounts(info)
    problems = imageuser.check(identity, ctx.local)
    if imageuser.involves_root(identity):
        return Assessment("fallback", problems, identity, "root")
    if mounts and not imageuser.is_nobody(identity):
        return Assessment("fallback", [MOUNTS_REASON], identity, "mounts")
    if problems:
        return Assessment("refused", problems, identity)
    return Assessment("ok", [], identity)


def run(ctx, args):
    """`docker run`; returns the exit code."""
    try:
        parsed = runargs.parse(args, ctx.current_ids(), ctx.resolver())
    except runargs.ParseError as e:
        return refuse([f"cannot read the command line: {e}; use the real docker for this one"])
    except hostusers.UserError as e:
        return refuse([str(e)])
    for message in parsed.notices:
        notice(message)

    created = create_checked(ctx, parsed, [])
    if isinstance(created, int):
        return created
    container, info, assessment = created

    if assessment.kind in ("fallback", "ok"):
        # Both are re-created with the user spelled as numbers: the runtime then has nothing of the
        # image's to resolve, whatever its passwd and group files say.
        ctx.docker.remove(container)
        if assessment.kind == "fallback":
            notice(fallback_notice(parsed.image, assessment, ctx.local))
        user = FALLBACK_USER if assessment.kind == "fallback" else image_user_spec(assessment)
        created = create_checked(ctx, parsed, [f"--user={user}"])
        if isinstance(created, int):
            return created
        container, info, assessment = created

    return ctx.docker.start(
        container,
        attach=not parsed.detach,
        interactive=bool(info["Config"].get("OpenStdin")),
        detach_keys=parsed.detach_keys,
    )


def fallback_summary(subject, assessment, local, what="container"):
    """Why something is run as nobody: it would run as root, or has mounts and no user chosen."""
    if assessment.reason == "root":
        return f"{subject} would run as root"
    who = imageuser.describe(assessment.identity, local)
    return f"{subject} would run as {who}, and the {what} has bind mounts"


def image_user_spec(assessment):
    """The `uid:gid` the image would have used: what to pass to run it as the image's user."""
    return f"{assessment.identity.uid}:{assessment.identity.gid}"


def fallback_notice(image, assessment, local):
    summary = fallback_summary(f"image {image}", assessment, local)
    if assessment.reason == "mounts":
        advice = f"To run it as the image's user, pass --user {image_user_spec(assessment)}."
    else:
        advice = "Use --user UID:GID, --as NAME or --as-me to choose another user."
    return f"{summary}; running it as nobody ({FALLBACK_USER}) instead. {advice}"


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
    """`docker audit [--user UID:GID | --as NAME | --as-me] IMAGE`: what `docker run IMAGE` would do.

    Exit status 1 means it would be refused.
    """
    try:
        parsed = runargs.parse(args, ctx.current_ids(), ctx.resolver())
        # parse rewrites every way of giving a user to --user=...
        if parsed.command or any(not t.startswith("--user=") for t in parsed.create_args[:-1]):
            raise runargs.ParseError("only --user, --as and --as-me can come before the image")
    except runargs.ParseError as e:
        print(f"dcompose: {printable(e)}\nusage: docker audit [--user UID:GID | --as NAME | --as-me] IMAGE",
              file=sys.stderr)
        return 2
    except hostusers.UserError as e:
        return refuse([str(e)])
    for message in parsed.notices:
        notice(message)

    image = parsed.image
    code, container = ctx.docker.create(["--pull=never", *parsed.create_args])
    if container is None:
        print(f"dcompose: image {printable(image)} is not available locally; run `docker pull` first "
              "(pulling does not run the image), then audit it", file=sys.stderr)
        return code or 1
    try:
        info = ctx.docker.inspect_container(container)
        # the container has no mounts yet: what happens with and without them differs, so say both
        outcomes = [assess(ctx, container, info, explicit=parsed.user_given, mounts=mounts)
                    for mounts in (False, True)]
    except (DockerError, ValueError, KeyError) as e:
        outcomes = [Assessment("refused", [str(e)])] * 2
    finally:
        ctx.docker.remove(container)

    return report_assessment(image, outcomes, ctx.local)


def report_assessment(image, outcomes, local):
    """Print what `docker run` would do without and with bind mounts. Exit status 1 if refused."""
    name = printable(image)
    without = outcomes[0]
    if without.kind == "explicit":
        print(f"image {name}: the user is set on the command line; the image's own user is not checked")
    else:
        texts = [describe_outcome(a, local) for a in outcomes]
        if texts[0] == texts[1]:
            print(f"image {name}: {texts[0]}")
        else:
            print(f"image {name}, without bind mounts: {texts[0]}")
            print(f"image {name}, with bind mounts or devices: {texts[1]}")
    if any(a.kind == "refused" for a in outcomes):
        print("  pass --user UID:GID, --as NAME or --as-me to choose a user yourself")
    else:
        print("docker run also adds " + " ".join(DEFAULTS) + "; later options override them")
    return 1 if any(a.kind == "refused" for a in outcomes) else 0


def describe_outcome(assessment, local):
    who = imageuser.describe(assessment.identity, local) if assessment.identity else None
    if assessment.kind == "ok":
        return f"runs as {who}; accepted"
    if assessment.kind == "fallback":
        text = f"would run as {who}; docker run would run it as nobody ({FALLBACK_USER}) instead"
        if assessment.reason == "mounts":
            text += f"; to run it as the image's user pass --user {image_user_spec(assessment)}"
        return text
    reasons = "; ".join(printable(p) for p in assessment.problems)
    return "would be refused" + (f" (runs as {who})" if who else "") + f": {reasons}"


def create_args(args, current_user=None, resolve=None):
    """The arguments of `docker create` with --as and --as-me replaced by ids, and --user checked.

    Returned as they are if they cannot be read: docker will report what is wrong with them.
    """
    try:
        parsed = runargs.parse(
            args, current_user or (os.getuid(), os.getgid()), resolve or hostusers.resolve_account)
    except runargs.ParseError:
        return args
    for message in parsed.notices:
        notice(message)
    return parsed.create_args


def check_existing(ctx, args):
    """Problems for the containers named in `docker start`/`restart` arguments."""
    problems = []
    for ref in container_refs(args):
        try:
            info = ctx.docker.inspect_container(ref)
            assessment = assess(ctx, info["Id"], info)
            if assessment.kind == "fallback":  # an existing container cannot be rewritten
                summary = fallback_summary("its image", assessment, ctx.local)
                problems.append(f"{ref}: {summary}; recreate it with --user UID:GID, --as NAME or --as-me")
            else:
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
    return [f"{p}; pass --user, --as or --as-me to choose one" for p in assessment.problems]


def notice(text):
    print(f"dcompose: {printable(text)}", file=sys.stderr)


def refuse(problems):
    for problem in problems:
        print(f"dcompose: refusing: {printable(problem)}", file=sys.stderr)
    return 1
