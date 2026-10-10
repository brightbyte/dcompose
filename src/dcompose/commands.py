"""Custom subcommands.

A command is a callable(global_args, args) -> exit code. `global_args` are the
compose-level options that preceded the subcommand (e.g. ["-f", "x.yml"]), so
a command can pass them on when it shells out to docker compose.

A name registered here shadows the docker compose subcommand of the same name.
"""

import subprocess
import sys

from dcompose import autofix, guard, imageinfo, patch, policy
from dcompose.text import printable

COMMANDS = {}


def command(name):
    def register(fn):
        COMMANDS[name] = fn
        return fn
    return register


@command("doctor")
def doctor(global_args, args):
    """Show the docker compose version that other commands are forwarded to."""
    return subprocess.call(["docker", "compose", *global_args, "version", *args])


@command("audit")
def audit(global_args, args):
    """Run the checks that guard `up` without starting anything; --remote asks registries for image users."""
    if set(args) - {"--remote"}:
        print("usage: dcompose [compose options] audit [--remote]", file=sys.stderr)
        return 2

    try:
        config, project_dir = guard.inspect(global_args)
        problems = policy.check_config(config, guard.context(project_dir))
    except guard.GuardError as e:
        config, problems = None, [str(e)]

    passed = guard.report(problems)
    if passed:
        print("dcompose: audit passed", file=sys.stderr)
    if config is not None:
        for line in imageinfo.describe(config, remote="--remote" in args):
            print(printable(line))
    return 0 if passed else 1


@command("fix")
def fix(global_args, args):
    """Print a compose override that fixes what can be fixed; exit 1 if problems remain.

    The patch is relative to the merged config the guard inspects. Mount sources
    outside the project become placeholders to edit; problems without a safe
    automatic fix are listed in the patch as comments.
    """
    try:
        config, project_dir = guard.inspect(global_args)
        ctx = guard.context(project_dir)
    except guard.GuardError as e:
        print(f"dcompose: {printable(e)}", file=sys.stderr)
        return 1

    fixed = autofix.fix_config(config, ctx)
    remaining = policy.check_config(autofix.resolve_user_template(fixed, ctx), ctx)
    sys.stdout.write(patch.render(config, fixed, remaining))
    for problem in remaining:
        print(f"dcompose: cannot fix automatically: {printable(problem)}", file=sys.stderr)
    return 1 if remaining else 0
