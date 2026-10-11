"""Custom subcommands.

A command is a callable(global_args, args) -> exit code. `global_args` are the
compose-level options that preceded the subcommand (e.g. ["-f", "x.yml"]), so
a command can pass them on when it shells out to docker compose.

A name registered here shadows the docker compose subcommand of the same name.
"""

import subprocess
import sys

from dcompose import autofix, composeimages, composerun, guard, hardening, patch, policy, realdocker
from dcompose.text import printable

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
def doctor(global_args, args):
    """Show the docker compose version that other commands are forwarded to."""
    return subprocess.call([realdocker.docker_bin(), "compose", *global_args, "version", *args])


@command("audit")
def audit(global_args, args):
    """Run the checks that guard `up` without starting anything; pulls and builds images as up would."""
    if args:
        print("usage: dcompose [compose options] audit", file=sys.stderr)
        return 2

    lines = []
    try:
        config, project_dir = guard.inspect(global_args)
        hardened, additions = hardening.apply(config)
        problems = policy.check_config(hardened, composerun.vetting_all(guard.context(project_dir), hardened))
        tools = composerun.default_tools()
    except (guard.GuardError, ValueError) as e:
        config, additions, problems = None, [], [str(e)]

    lines += hardening.describe(additions)
    if config is not None and problems:
        lines.append("the images were not looked at because of the problems above: "
                     "nothing was pulled or built")
    elif config is not None:
        with composerun.generated(global_args, project_dir) as command:
            prepared = composeimages.prepare(command(hardened), hardened, [], tools)
        problems = prepared.problems
        lines += composeimages.describe(hardened, prepared, tools.gate_ctx.local)

    passed = guard.report(problems)
    if passed:
        print("dcompose: audit passed", file=sys.stderr)
    if config is not None:
        for line in lines:
            print(printable(line))
        if problems or additions:
            print(HARDEN_HINT)
    return 0 if passed else 1


@command("harden", "fix")
def harden(global_args, args):
    """Print a compose override that fixes what can be fixed; exit 1 if problems remain.

    The patch is relative to the merged config as dcompose will run it, defaults
    included: only what is needed on top of them to pass the audit is written out,
    and one comment says what is added automatically. Mount sources outside the
    project become placeholders to edit; problems without a safe automatic fix are
    listed as comments. Images are pulled and built first, as `up` would, to see
    which services need a user of their own.
    """
    try:
        config, project_dir = guard.inspect(global_args)
        base, _ = hardening.apply(config)
        static = composerun.vetting_all(guard.context(project_dir), base)
        tools = composerun.default_tools()
    except (guard.GuardError, ValueError) as e:
        print(f"dcompose: {printable(e)}", file=sys.stderr)
        return 1

    fixed = autofix.fix_config(base, static)
    remaining = policy.check_config(autofix.resolve_user_template(fixed, static), static)
    notes = [hardening.defaults_note()]
    if remaining:
        print("dcompose: the images were not looked at because of the problems below: "
              "nothing was pulled or built", file=sys.stderr)
    else:
        remaining, notes = fix_image_users(global_args, project_dir, fixed, notes, tools)

    sys.stdout.write(patch.render(base, fixed, remaining, notes=notes))
    for problem in remaining:
        print(f"dcompose: cannot fix automatically: {printable(problem)}", file=sys.stderr)
    return 1 if remaining else 0


def fix_image_users(global_args, project_dir, fixed, notes, tools):
    """Set a user on the services whose image chose one that is not acceptable. (problems left, notes)."""
    with composerun.generated(global_args, project_dir) as command:
        prepared = composeimages.prepare(command(fixed), fixed, [], tools)
    if not prepared.decisions:
        return prepared.problems, notes  # nothing could be looked at: pulling or building failed
    for name, decision in prepared.decisions.items():
        if decision.assessment.kind == "refused":
            fixed["services"][name]["user"] = autofix.USER_TEMPLATE
            notes.append(f"service {name}: image {decision.image} chose a user that is not acceptable, "
                         "so user is set explicitly")
    return [], notes
