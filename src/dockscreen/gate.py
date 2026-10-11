"""The gate in front of commands that start a container from an image.

`docker run` becomes create, inspect, check, start: the daemon parses the
command line, and the policy looks at the container it produced, from an image
that cannot change between check and start. The one image-derived fact checked
is the identity the container would run as (see imageuser), unless the command
line sets a user: the person typing the command is trusted, the image is not.

With no user chosen on the command line, imagedecision decides it. Whatever it accepts is not left
for the runtime to resolve a second time: the container is re-created with `--user uid:gid` as the
checked numbers.

`start` and `restart` apply the same check to existing containers, which cannot
be rewritten. `create` only gets the hardening defaults; its container is
checked when it is started. `audit` predicts the outcome for an image.
"""

from typing import Protocol, runtime_checkable

from dockscreen import argscan, hostusers, imageuser, messages, runargs
from dockscreen.dockerclient import DockerError
from dockscreen.imagedecision import (
    Assessment,
    DockerAccess,
    Kind,
    assess,
    default_user_spec,
    pinned_user,
    root_default_notice,
)
from dockscreen.text import printable

@runtime_checkable
class RunnableDocker(DockerAccess, Protocol):
    """What `docker run` needs from docker on top of deciding: ctx.docker in this module is one."""

    def start(self, container, attach, interactive, detach_keys):
        """Start the container; its exit code when attached."""


# Inserted before the user's own arguments, so the user can override both
# (for example `--cap-add NET_BIND_SERVICE`).
DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]
CHOOSE_HINT = "pass --user UID:GID, --as NAME or --as-me to choose a user"

# Options of `docker start` and `restart` that take a value.
VALUE_LONG = frozenset({"--detach-keys", "--checkpoint", "--checkpoint-dir", "--signal", "--time"})
VALUE_SHORT = frozenset("st")


def run(ctx, args):
    """`docker run`; returns the exit code."""
    try:
        parsed = runargs.parse(args, ctx.runtime.me, ctx.runtime.resolve_account)
    except runargs.ParseError as e:
        return messages.refuse([f"cannot read the command line: {e}; use the real docker for this one"])
    except hostusers.UserError as e:
        return messages.refuse([str(e)])
    for message in [*parsed.notices, root_default_notice(ctx)]:
        if message:
            messages.notice(message)
    ctx = ctx.allowing_me(parsed.allow_me)

    created = create_checked(ctx, parsed, [])
    if isinstance(created, int):
        return created
    container, info, assessment = created

    if assessment.pins_user:
        # All are re-created with the user spelled as numbers: the runtime then has nothing of the
        # image's to resolve, whatever its passwd and group files say.
        ctx.docker.remove(container)
        if assessment.kind is Kind.FALLBACK:
            messages.notice(fallback_notice(ctx, parsed.image))
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
        assessment = Assessment(Kind.REFUSED, problems) if problems else assess(
            ctx, container, info, explicit=parsed.user_given or bool(extra), reference=parsed.image)
    except (DockerError, ValueError, KeyError) as e:
        assessment = Assessment(Kind.REFUSED, [str(e)])
    if assessment.refused:
        ctx.docker.remove(container)
        return messages.refuse(explain(assessment))
    return container, info, assessment


def audit(ctx, args):
    """`docker audit [--allow-me] [--user UID:GID | --as NAME | --as-me] IMAGE`: what `docker run IMAGE`
    would do.

    Exit status 1 means it would be refused.
    """
    usage = "usage: docker audit [--allow-me] [--user UID:GID | --as NAME | --as-me] IMAGE"
    try:
        parsed = runargs.parse(args, ctx.runtime.me, ctx.runtime.resolve_account)
        # parse rewrites every way of giving a user to --user=..., and drops --allow-me
        if parsed.command or any(not t.startswith("--user=") for t in parsed.create_args[:-1]):
            raise runargs.ParseError("only --allow-me, --user, --as and --as-me can come before the image")
    except runargs.ParseError as e:
        messages.notice(e)
        messages.notice(usage)
        return 2
    except hostusers.UserError as e:
        return messages.refuse([str(e)])
    for message in parsed.notices:
        messages.notice(message)
    ctx = ctx.allowing_me(parsed.allow_me)

    image = parsed.image
    code, container = ctx.docker.create(["--pull=never", *parsed.create_args])
    if container is None:
        messages.notice(f"image {image} is not available locally; run `docker pull` first "
                        "(pulling does not run the image), then audit it")
        return code or 1
    try:
        info = ctx.docker.inspect_container(container)
        # the container has no mounts yet: what happens with and without them differs, so say both
        outcomes = [assess(ctx, container, info, explicit=parsed.user_given, mounts=mounts, reference=image)
                    for mounts in (False, True)]
    except (DockerError, ValueError, KeyError) as e:
        outcomes = [Assessment(Kind.REFUSED, [str(e)])] * 2
    finally:
        ctx.docker.remove(container)

    return report_assessment(ctx, image, outcomes)


def report_assessment(ctx, image, outcomes):
    """Print what `docker run` would do without and with bind mounts. Exit status 1 if refused."""
    name = printable(image)
    without = outcomes[0]
    if without.kind is Kind.EXPLICIT:
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
    if any(a.refused for a in outcomes):
        print(f"  {CHOOSE_HINT}")
    else:
        print("docker run also adds " + " ".join(DEFAULTS) + "; later options override them")
    return 1 if any(a.refused for a in outcomes) else 0


def describe_outcome(ctx, assessment):
    who = imageuser.describe(assessment.identity, ctx.local) if assessment.identity else None
    if assessment.kind is Kind.OK:
        return f"runs as {who}; accepted"
    if assessment.kind is Kind.CONFIGURED:
        return f"runs as {pinned_user(ctx, assessment)}, the user the config file sets for its repository"
    if assessment.kind is Kind.FALLBACK:
        return (f"would run as {who}; docker run would run it as the default user "
                f"({default_user_spec(ctx)}) instead")
    reasons = "; ".join(printable(p) for p in assessment.problems)
    return "would be refused" + (f" (runs as {who})" if who else "") + f": {reasons}"


def create_args(args, runtime):
    """The arguments of `docker create` with --as and --as-me replaced by ids, and --user checked.

    Returned as they are if they cannot be read: docker will report what is wrong with them.
    """
    try:
        parsed = runargs.parse(args, runtime.me, runtime.resolve_account)
    except runargs.ParseError:
        return args
    for message in parsed.notices:
        messages.notice(message)
    return parsed.create_args


def check_existing(ctx, args):
    """Problems for the containers named in `docker start`/`restart` arguments.

    An existing container cannot be rewritten, so one whose user dockscreen would replace (by the
    default user or a configured one) is refused like one whose user is not accepted.
    """
    problems = []
    for ref in argscan.positionals(args, VALUE_LONG, VALUE_SHORT):
        try:
            info = ctx.docker.inspect_container(ref)
            assessment = assess(ctx, info["Id"], info)
            if assessment.replaces_image_user:
                user = pinned_user(ctx, assessment)
                problems.append(f"{ref}: its image's user would be replaced by {user}, which an existing "
                                f"container cannot be; recreate it with --user {user}")
            else:
                problems += [f"{ref}: {p}" for p in explain(assessment)]
        except (DockerError, ValueError, KeyError) as e:
            problems.append(f"{ref}: {e}")
    return problems


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
