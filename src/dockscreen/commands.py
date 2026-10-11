"""Custom subcommands.

A command is a callable(global_args, args) -> exit code. `global_args` are the
compose-level options that preceded the subcommand (e.g. ["-f", "x.yml"]), so
a command can pass them on when it shells out to docker compose.

A name registered here shadows the docker compose subcommand of the same name.
"""

import os
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
    realdocker,
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
def doctor(global_args, args, allow_me=False):
    """Show the docker compose version that other commands are forwarded to."""
    return subprocess.call([realdocker.docker_bin(), "compose", *global_args, "version", *args])


@command("audit")
def audit(global_args, args, allow_me=False):
    """Run the checks that screen `up` without starting anything; pulls and builds images as up would."""
    if args:
        messages.notice("usage: dockscreen [compose options] audit")
        return 2

    lines = []
    try:
        config, project_dir = screen.inspect(global_args)
        hardened, additions = hardening.apply(config)
        ctx = composerun.vetting_all(screen.context(project_dir, allow_me), hardened)
        problems = policy.check_config(hardened, ctx)
        tools = composerun.default_tools(allow_me)
        if screen.is_remote(global_args, os.environ, tools.docker):
            problems.append(screen.REMOTE_MESSAGE)
    except (screen.ScreenError, ValueError) as e:
        config, additions, problems = None, [], [str(e)]

    lines += screen.mount_dir_warnings(os.environ)
    lines += hardening.describe(additions)
    if config is not None:
        lines += shellenv.describe(hardened, os.environ)
    if config is not None and problems:
        lines.append("the images were not looked at because of the problems above: "
                     "nothing was pulled or built")
    elif config is not None:
        messages.notice("pulling or building the images as `up` would, to look at the users they run as")
        with composerun.generated(global_args, project_dir) as command:
            prepared = composeimages.prepare(command(hardened), hardened, [], tools)
        problems = prepared.problems
        lines += composeimages.describe(hardened, prepared, tools.gate_ctx)

    passed = messages.report(problems)
    if passed:
        messages.notice("audit passed")
    if config is not None:
        for line in lines:
            print(printable(line))
        if problems or additions:
            print(HARDEN_HINT)
    return 0 if passed else 1


@command("harden", "fix")
def harden(global_args, args, allow_me=False):
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
        config, project_dir = screen.inspect(global_args)
        base, _ = hardening.apply(config)
        static = composerun.vetting_all(screen.context(project_dir, allow_me=True), base)
        tools = composerun.default_tools(allow_me=True)
        if screen.is_remote(global_args, os.environ, tools.docker):
            raise screen.ScreenError(screen.REMOTE_MESSAGE)
    except (screen.ScreenError, ValueError) as e:
        messages.notice(e)
        return 1

    fixed = autofix.fix_config(base, static)
    remaining = policy.check_config(autofix.resolve_user_template(fixed, static), static)
    notes = [hardening.defaults_note()]
    if remaining:
        messages.notice("the images were not looked at because of the problems below: "
                        "nothing was pulled or built")
    else:
        remaining, notes = fix_image_users(global_args, project_dir, fixed, notes, tools)

    sys.stdout.write(patch.render(base, fixed, remaining, notes=notes))
    for problem in remaining:
        messages.notice(f"cannot fix automatically: {problem}")
    return 1 if remaining else 0


def fix_image_users(global_args, project_dir, fixed, notes, tools):
    """Set a user on the services whose image chose one that is not acceptable. (problems left, notes)."""
    with composerun.generated(global_args, project_dir) as command:
        prepared = composeimages.prepare(command(fixed), fixed, [], tools)
    if not prepared.decisions:
        return prepared.problems, notes  # nothing could be looked at: pulling or building failed
    for name, decision in prepared.decisions.items():
        if decision.assessment.refused:
            fixed["services"][name]["user"] = autofix.USER_TEMPLATE
            notes.append(f"service {name}: image {decision.image} chose a user that is not acceptable, "
                         "so user is set explicitly")
    return [], notes
