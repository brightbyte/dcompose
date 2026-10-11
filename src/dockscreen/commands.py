"""Custom subcommands.

A command is a callable(global_args, args, runtime, allow_me) -> exit code. `global_args` are the
compose-level options that preceded the subcommand (e.g. ["-f", "x.yml"]), so
a command can pass them on when it shells out to docker compose.

A name registered here shadows the docker compose subcommand of the same name.
"""

import subprocess
import sys

from dockscreen import (
    autofix,
    composeimages,
    composerun,
    hardening,
    messages,
    patch,
    policy,
    screen,
    shellenv,
)
from dockscreen.text import printable

COMMANDS = {}
ALIASES = {}  # alias -> command it stands for


def command(name, *aliases):
    def register(fn):
        COMMANDS[name] = fn
        for alias in aliases:
            COMMANDS[alias] = fn
            ALIASES[alias] = name
        return fn
    return register


HARDEN_HINT = "hint: the harden subcommand prints a compose override file with these fixes."


@command("doctor")
def doctor(global_args, args, runtime, allow_me=False):
    """Show the docker compose version that other commands are forwarded to."""
    return subprocess.call([runtime.docker.binary, "compose", *global_args, "version", *args])


@command("audit")
def audit(global_args, args, runtime, allow_me=False):
    """Run the checks that screen `up` without starting anything; pulls and builds images as up would."""
    if args:
        messages.notice("usage: dockscreen [compose options] audit")
        return 2

    try:
        project = composerun.load_project(global_args, runtime, allow_me)
        problems = project.problems()
    except (screen.ScreenError, ValueError) as e:
        project, problems = None, [str(e)]

    lines = screen.mount_dir_warnings(runtime)
    if project is not None:
        hardened, tools = project.hardened, project.tools
        lines += hardening.describe(project.additions)
        lines += shellenv.describe(hardened, runtime.env)
        if problems:
            lines.append("the images were not looked at because of the problems above: "
                         "nothing was pulled or built")
        else:
            messages.notice("pulling or building the images as `up` would, to look at the users they run as")
            with project.generated() as command:
                prepared = composeimages.prepare(command(hardened), hardened, [], tools)
            problems = prepared.problems
            lines += composeimages.describe(hardened, prepared, tools.gate_ctx)

    passed = messages.report(problems)
    if passed:
        messages.notice("audit passed")
    if project is not None:
        for line in lines:
            print(printable(line))
        if problems or project.additions:
            print(HARDEN_HINT)
    return 0 if passed else 1


@command("harden", "fix")
def harden(global_args, args, runtime, allow_me=False):
    """Print a compose override that fixes what can be fixed; exit 1 if problems remain.

    The patch is relative to the merged config as dockscreen will run it, defaults
    included: only what is needed on top of them to pass the audit is written out,
    and one comment says what is added automatically. Mount sources outside the
    project become placeholders to edit; problems without a safe automatic fix are
    listed as comments. Images are pulled and built first, as `up` would, to see
    which services need a user of their own.

    A user that has to be set becomes `${UID}:${GID}`, the caller's own, so the result is checked as
    if --allow-me were given, and the patch says that it needs it.
    """
    try:
        project = composerun.load_project(global_args, runtime, allow_me=True)
    except (screen.ScreenError, ValueError) as e:
        messages.notice(e)
        return 1
    if project.remote:
        messages.notice(screen.REMOTE_MESSAGE)
        return 1

    base, static = project.hardened, project.static_ctx()
    fixed = autofix.fix_config(base, static)
    remaining = policy.check_config(autofix.resolve_user_template(fixed, static), static)
    notes = [hardening.defaults_note()]
    if remaining:
        messages.notice("the images were not looked at because of the problems below: "
                        "nothing was pulled or built")
    else:
        remaining, notes = fix_image_users(project, fixed, notes)

    sys.stdout.write(patch.render(base, fixed, remaining, notes=notes))
    for problem in remaining:
        messages.notice(f"cannot fix automatically: {problem}")
    return 1 if remaining else 0


def fix_image_users(project, fixed, notes):
    """Set a user on the services whose image chose one that is not acceptable. (problems left, notes)."""
    with project.generated() as command:
        prepared = composeimages.prepare(command(fixed), fixed, [], project.tools)
    if not prepared.decisions:
        return prepared.problems, notes  # nothing could be looked at: pulling or building failed
    for name, decision in prepared.decisions.items():
        if decision.assessment.refused:
            fixed["services"][name]["user"] = autofix.USER_TEMPLATE
            notes.append(f"service {name}: image {decision.image} chose a user that is not acceptable, "
                         "so user is set explicitly")
    return [], notes
