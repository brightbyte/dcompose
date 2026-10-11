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
checked when it is started. `audit` takes a `docker run` command line, creates its container as
`run` would and reports what `run` would do, then removes it; it also points out what the command line
asks for that a project or an image may not (runpolicy).
"""

from typing import Protocol, runtime_checkable

from dockscreen import argscan, flags, hostusers, imageuser, messages, policy, runargs, runpolicy, verdict
from dockscreen.dockerclient import DockerError, DockerNotFound
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
from dockscreen.verdict import Verdict

@runtime_checkable
class RunnableDocker(DockerAccess, Protocol):
    """What `docker run` needs from docker on top of deciding: ctx.docker in this module is one."""

    def start(self, container, attach, interactive, detach_keys):
        """Start the container; its exit code when attached."""


# Inserted before the user's own arguments, so the user can override both
# (for example `--cap-add NET_BIND_SERVICE`).
DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]
CHOOSE_HINT = "pass --user UID:GID, --as NAME or --as-me to choose a user"
IMAGE_USERS_HINT = ("or, for an image pulled from a registry, give its repository a user in [image_users] "
                    "in {}")

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
    code, container, info, assessment = create_assessed(ctx, parsed, extra)
    if container is None:
        return code
    if assessment.refused:
        ctx.docker.remove(container)
        return messages.refuse(explain(ctx, assessment))
    return container, info, assessment


def create_assessed(ctx, parsed, extra):
    """Create the container as `docker run` would and assess it: (exit code, container, info, assessment).

    extra: arguments that go before the command line's own. Without a container (docker could not
    create one; it said why) the others are None. The container is left for the caller to remove.
    """
    code, container = ctx.docker.create([*DEFAULTS, *extra, *parsed.create_args])
    if container is None:
        return code, None, None, None
    info = None
    try:
        info = ctx.docker.inspect_container(container)
        problems = verify_split(info, parsed)
        assessment = Assessment(Kind.REFUSED, problems) if problems else assess(
            ctx, container, info, explicit=parsed.user_given or bool(extra), reference=parsed.image)
    except (DockerError, ValueError, KeyError) as e:
        assessment = Assessment(Kind.FAILED, [str(e)])
    return code, container, info, assessment


AUDIT_USAGE = ("usage: dockscreen [--allow-me] [--strict-screen] audit [--brief] [docker run options] "
               "IMAGE [COMMAND]")


def audit(ctx, args, strict=False):
    """`audit` with a `docker run` command line: what `docker run` would do with it, without starting it.

    The container is created as `run` would create it, pulling the image if `run` would, and removed.
    The exit status is the verdict: 1 if `run` would refuse, or with strict (--strict-screen) if the
    command line asks for something a project or an image may not; 3 if the audit failed to get that far.
    --brief, before the image, prints only the verdict, in one line.
    """
    brief, args = flags.strip(args, runargs.VALUE_OPTIONS, flags.BRIEF)
    try:
        parsed = runargs.parse(args, ctx.runtime.me, ctx.runtime.resolve_account)
    except runargs.ParseError as e:
        messages.notice(e)
        messages.notice(AUDIT_USAGE)
        return 2
    except hostusers.UserError as e:
        return verdict.report(Verdict.REFUSED, [str(e)], brief)
    if not brief:
        for message in parsed.notices:
            messages.notice(message)
    ctx = ctx.allowing_me(parsed.allow_me)

    try:
        _, container, info, assessment = create_assessed(ctx, parsed, [])
    except DockerNotFound as e:
        return verdict.report(Verdict.FAILED, [str(e)], brief)
    if container is None:
        reason = f"docker could not create a container for {parsed.image}"
        return verdict.report(Verdict.FAILED, [reason], brief)
    try:
        policy_ctx = policy.Context(ctx.runtime.cwd, ctx.ids, ctx.settings.mount_dirs,
                                    config_file=ctx.runtime.config_file)
        found = runpolicy.findings(info, parsed.user_given, policy_ctx) if info else []
    finally:
        ctx.docker.remove(container)

    outcome, reasons = audit_verdict(ctx, assessment, found, strict)
    if brief:
        print(verdict.brief(outcome, reasons))
    else:
        report_assessment(ctx, parsed.image, assessment)
        report_findings(found, strict)
        messages.notice(verdict.line(outcome))
    return int(outcome)


def audit_verdict(ctx, assessment, found, strict):
    """(verdict, reasons) of an audit: the assessment's, then the command line's findings if strict."""
    reasons = [*(explain(ctx, assessment) if assessment.refused else []), *(found if strict else [])]
    if assessment.failed:
        return Verdict.FAILED, reasons
    return (Verdict.REFUSED if reasons else Verdict.PASSED), reasons


def report_assessment(ctx, image, assessment):
    """Print what `docker run` would do about the user."""
    name, dot = printable(image), verdict.dot(assessment)
    if assessment.kind is Kind.EXPLICIT:
        print(f"{dot} image {name}: the user is set on the command line; the image's own user is not checked")
    else:
        print(f"{dot} image {name}: {describe_outcome(ctx, assessment)}")
        if assessment.note:
            print(f"{verdict.WARN} note: {printable(assessment.note)}")
    if assessment.refused:
        if not assessment.failed:
            print(f"  {CHOOSE_HINT}")
            print(f"  {IMAGE_USERS_HINT.format(ctx.runtime.config_file)}")
        return
    if assessment.pins_user:
        print(f"  docker run would create it again with --user={pinned_user(ctx, assessment)}, as numbers")
    print("  docker run also adds " + " ".join(DEFAULTS) + "; later options override them")


def report_findings(found, strict):
    """Print what the command line asks for that a project or an image may not."""
    dot = verdict.BAD if strict else verdict.WARN
    for finding in found:
        print(f"{dot} command line: {printable(finding)}")
    if found and not strict:
        print("  docker run allows these because you gave them; --strict-screen makes them fail the audit")


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
    if assessment.failed:
        return f"could not be assessed: {reasons}"
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
                problems += [f"{ref}: {p}" for p in explain(ctx, assessment)]
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


def explain(ctx, assessment):
    """The problems, with how to get past them when they come from the image's own identity."""
    if assessment.identity is None:
        return assessment.problems
    hint = f"{CHOOSE_HINT}, {IMAGE_USERS_HINT.format(ctx.runtime.config_file)}"
    return [f"{p}; {hint}" for p in assessment.problems]
