"""The gate in front of commands that start a container from an image.

`docker run` becomes create, inspect, check, start: the daemon parses the
command line, and the policy looks at the container it produced, from an image
that cannot change between check and start. The one image-derived fact checked
is the identity the container would run as (see imageuser), unless the command
line sets a user: the person typing the command is trusted, the image is not.

With no user chosen on the command line, in this order:
- the config file names a user for the image's repository, and the image was pulled from there:
  that user, whatever it is (images.configured_user);
- the image would run as root (uid, gid or a supplementary gid of 0): the configured default user
  instead, nobody unless configured otherwise, with a notice;
- otherwise the image's own user, if the id rules accept it (idrules); refused if not.

Whatever is accepted is not left for the runtime to resolve a second time: the container is re-created
with `--user uid:gid` as the checked numbers, so a difference between our reading of the image's passwd
and group files and the runtime's can at worst refuse a good image, never run root.

`start` and `restart` apply the same check to existing containers, which cannot
be rewritten. `create` only gets the hardening defaults; its container is
checked when it is started. `audit` predicts the outcome for an image.
"""

import os
import sys
from typing import NamedTuple

from dockscreen import config as configuration
from dockscreen import hostusers, images, imageuser, runargs
from dockscreen.dockerclient import DockerError
from dockscreen.text import printable

# Inserted before the user's own arguments, so the user can override both
# (for example `--cap-add NET_BIND_SERVICE`).
DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]
CHOOSE_HINT = "pass --user UID:GID, --as NAME or --as-me to choose a user"

VALUE_LONG = frozenset({"--detach-keys", "--checkpoint", "--checkpoint-dir", "--signal", "--time"})
VALUE_SHORT = frozenset("st")


class Context(NamedTuple):
    docker: object
    ids: object                        # idrules.Rules
    config: object = None              # config.Config; the process's own if None
    current_user: tuple | None = None  # (uid, gid) that --as-me stands for; the real ones if None
    resolve_user: object = None        # turns the name given to --as into ids (hostusers.resolve_account)

    @property
    def local(self):
        return self.ids.local

    def current_ids(self):
        return self.current_user or (os.getuid(), os.getgid())

    def resolver(self):
        return self.resolve_user or hostusers.resolve_account

    def settings(self):
        return self.config or configuration.current()


class Assessment(NamedTuple):
    kind: str            # explicit, configured, ok, fallback or refused
    problems: list
    identity: imageuser.Identity | None = None
    note: str | None = None  # an image_users entry for the repository that does not apply, and why


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


def assess(ctx, container, info, explicit=None, mounts=None, reference=None, built=False):
    """What the image would be allowed to do.

    explicit: the user was set on the command line, if known.
    mounts: the container reaches host files or devices; worked out from info if not given.
    reference: the image name as the command line or the service gave it (the container's if None).
    built: the image is built from a Dockerfile by the service; the config file never applies then.
    """
    image = ctx.docker.inspect_image(info["Image"])
    spec = info["Config"].get("User") or ""
    if explicit is None:
        explicit = spec != (image["Config"].get("User") or "")
    if explicit:
        return Assessment("explicit", [])  # trusted: the person typing the command chose it

    match = images.configured_user(ctx.settings(), reference or info["Config"].get("Image") or "",
                                   image.get("RepoDigests"), built)
    if match.user:
        return Assessment("configured", [], imageuser.Identity(*match.user, ()))

    passwd = ctx.docker.read_file(container, "/etc/passwd") or ""
    groups = ctx.docker.read_file(container, "/etc/group") or ""
    try:
        identity = imageuser.resolve(spec, passwd, groups)
    except ValueError as e:
        return Assessment("refused", [str(e)], note=match.problem)
    if imageuser.involves_root(identity):
        return Assessment("fallback", [], identity, match.problem)
    if mounts is None:
        mounts = has_host_mounts(info)
    problems = ctx.ids.problems(identity.uid, identity.gid, identity.supplementary, mounts=mounts)
    if problems:
        return Assessment("refused", [f"the image's {p}" for p in problems], identity, match.problem)
    return Assessment("ok", [], identity, match.problem)


def default_user_spec(ctx):
    """The `uid:gid` that replaces an image's root user."""
    uid, gid = ctx.settings().default_user
    return f"{uid}:{gid}"


def pinned_user(ctx, assessment):
    """The `uid:gid` a fallback, configured or accepted image user runs as, spelled as numbers."""
    if assessment.kind == "fallback":
        return default_user_spec(ctx)
    return f"{assessment.identity.uid}:{assessment.identity.gid}"


def root_default_notice(ctx):
    """A notice for every run when the configured default user is root, or None."""
    if 0 in ctx.settings().default_user:
        return (f"the configured default user is {default_user_spec(ctx)}: "
                "images that would run as root run as root")
    return None


def run(ctx, args):
    """`docker run`; returns the exit code."""
    try:
        parsed = runargs.parse(args, ctx.current_ids(), ctx.resolver())
    except runargs.ParseError as e:
        return refuse([f"cannot read the command line: {e}; use the real docker for this one"])
    except hostusers.UserError as e:
        return refuse([str(e)])
    for message in [*parsed.notices, root_default_notice(ctx)]:
        if message:
            notice(message)
    ctx = allowing_me(ctx, parsed.allow_me)

    created = create_checked(ctx, parsed, [])
    if isinstance(created, int):
        return created
    container, info, assessment = created

    if assessment.kind in ("fallback", "configured", "ok"):
        # All are re-created with the user spelled as numbers: the runtime then has nothing of the
        # image's to resolve, whatever its passwd and group files say.
        ctx.docker.remove(container)
        if assessment.kind == "fallback":
            notice(fallback_notice(ctx, parsed.image))
        created = create_checked(ctx, parsed, [f"--user={pinned_user(ctx, assessment)}"])
        if isinstance(created, int):
            return created
        container, info, assessment = created

    return ctx.docker.start(
        container,
        attach=not parsed.detach,
        interactive=bool(info["Config"].get("OpenStdin")),
        detach_keys=parsed.detach_keys,
    )


def allowing_me(ctx, allow_me):
    """ctx with the caller's own ids allowed, for --allow-me and --as-me."""
    return ctx._replace(ids=ctx.ids._replace(allow_me=True)) if allow_me else ctx


def fallback_notice(ctx, image):
    return (f"image {image} would run as root; running it as the default user ({default_user_spec(ctx)}) "
            f"instead; {CHOOSE_HINT} yourself")


def create_checked(ctx, parsed, extra):
    """Create the container; (container, info, assessment), or an exit code if it must not start.

    A container that would be refused is removed. Any other assessment is returned to the caller,
    which re-creates the container with the user as numbers.
    """
    code, container = ctx.docker.create([*DEFAULTS, *extra, *parsed.create_args])
    if container is None:
        return code
    try:
        info = ctx.docker.inspect_container(container)
        problems = verify_split(info, parsed)
        assessment = Assessment("refused", problems) if problems else assess(
            ctx, container, info, explicit=parsed.user_given or bool(extra), reference=parsed.image)
    except (DockerError, ValueError, KeyError) as e:
        assessment = Assessment("refused", [str(e)])
    if assessment.kind == "refused":
        ctx.docker.remove(container)
        return refuse(explain(assessment))
    return container, info, assessment


def audit(ctx, args):
    """`docker audit [--allow-me] [--user UID:GID | --as NAME | --as-me] IMAGE`: what `docker run IMAGE`
    would do.

    Exit status 1 means it would be refused.
    """
    usage = "usage: docker audit [--allow-me] [--user UID:GID | --as NAME | --as-me] IMAGE"
    try:
        parsed = runargs.parse(args, ctx.current_ids(), ctx.resolver())
        # parse rewrites every way of giving a user to --user=..., and drops --allow-me
        if parsed.command or any(not t.startswith("--user=") for t in parsed.create_args[:-1]):
            raise runargs.ParseError("only --allow-me, --user, --as and --as-me can come before the image")
    except runargs.ParseError as e:
        print(f"dockscreen: {printable(e)}\n{usage}", file=sys.stderr)
        return 2
    except hostusers.UserError as e:
        return refuse([str(e)])
    for message in parsed.notices:
        notice(message)
    ctx = allowing_me(ctx, parsed.allow_me)

    image = parsed.image
    code, container = ctx.docker.create(["--pull=never", *parsed.create_args])
    if container is None:
        print(f"dockscreen: image {printable(image)} is not available locally; run `docker pull` first "
              "(pulling does not run the image), then audit it", file=sys.stderr)
        return code or 1
    try:
        info = ctx.docker.inspect_container(container)
        # the container has no mounts yet: what happens with and without them differs, so say both
        outcomes = [assess(ctx, container, info, explicit=parsed.user_given, mounts=mounts, reference=image)
                    for mounts in (False, True)]
    except (DockerError, ValueError, KeyError) as e:
        outcomes = [Assessment("refused", [str(e)])] * 2
    finally:
        ctx.docker.remove(container)

    return report_assessment(ctx, image, outcomes)


def report_assessment(ctx, image, outcomes):
    """Print what `docker run` would do without and with bind mounts. Exit status 1 if refused."""
    name = printable(image)
    without = outcomes[0]
    if without.kind == "explicit":
        print(f"image {name}: the user is set on the command line; the image's own user is not checked")
    else:
        texts = [describe_outcome(ctx, a) for a in outcomes]
        if texts[0] == texts[1]:
            print(f"image {name}: {texts[0]}")
        else:
            print(f"image {name}, without bind mounts: {texts[0]}")
            print(f"image {name}, with bind mounts or devices: {texts[1]}")
        if without.note:
            print(f"  note: {printable(without.note)}")
    if any(a.kind == "refused" for a in outcomes):
        print(f"  {CHOOSE_HINT}")
    else:
        print("docker run also adds " + " ".join(DEFAULTS) + "; later options override them")
    return 1 if any(a.kind == "refused" for a in outcomes) else 0


def describe_outcome(ctx, assessment):
    who = imageuser.describe(assessment.identity, ctx.local) if assessment.identity else None
    if assessment.kind == "ok":
        return f"runs as {who}; accepted"
    if assessment.kind == "configured":
        return f"runs as {pinned_user(ctx, assessment)}, the user the config file sets for its repository"
    if assessment.kind == "fallback":
        return (f"would run as {who}; docker run would run it as the default user "
                f"({default_user_spec(ctx)}) instead")
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
    """Problems for the containers named in `docker start`/`restart` arguments.

    An existing container cannot be rewritten, so one whose user dockscreen would replace (by the
    default user or a configured one) is refused like one whose user is not accepted.
    """
    problems = []
    for ref in container_refs(args):
        try:
            info = ctx.docker.inspect_container(ref)
            assessment = assess(ctx, info["Id"], info)
            if assessment.kind in ("fallback", "configured"):
                user = pinned_user(ctx, assessment)
                problems.append(f"{ref}: its image's user would be replaced by {user}, which an existing "
                                f"container cannot be; recreate it with --user {user}")
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
    return [f"{p}; {CHOOSE_HINT}" for p in assessment.problems]


def notice(text):
    print(f"dockscreen: {printable(text)}", file=sys.stderr)


def refuse(problems):
    for problem in problems:
        print(f"dockscreen: refusing: {printable(problem)}", file=sys.stderr)
    return 1
