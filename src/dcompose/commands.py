"""Custom subcommands.

A command is a callable(global_args, args) -> exit code. `global_args` are the
compose-level options that preceded the subcommand (e.g. ["-f", "x.yml"]), so
a command can pass them on when it shells out to docker compose.

A name registered here shadows the docker compose subcommand of the same name.
"""

import os
import subprocess
import sys

from dcompose import guard, ids, imageinfo, patch, policy
from dcompose.text import printable

COMMANDS = {}


def command(name):
    def register(fn):
        COMMANDS[name] = fn
        return fn
    return register


@command("doctor")
def doctor(global_args, args):
    """Example command: show which docker compose we would be forwarding to."""
    return subprocess.call(["docker", "compose", *global_args, "version", *args])


@command("audit")
def audit(global_args, args):
    """Run the security checks that guard `up`, without starting anything. --remote: look up image users in registries."""
    if set(args) - {"--remote"}:
        print("usage: dcompose [compose options] audit [--remote]", file=sys.stderr)
        return 2

    try:
        config, project_dir = guard.inspect(global_args)
        problems = guard.evaluate(config, project_dir)
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
        extra_dirs = guard.extra_mount_dirs(os.environ)
    except guard.GuardError as e:
        print(f"dcompose: {printable(e)}", file=sys.stderr)
        return 1

    uid, gid = ids.allowed(os.environ)
    fixed = policy.fix_config(config, uid, gid, project_dir, extra_dirs)
    remaining = policy.check_config(
        policy.resolve_user_template(fixed, uid, gid), project_dir, uid, gid, extra_dirs)
    sys.stdout.write(patch.render(config, fixed, remaining))
    for problem in remaining:
        print(f"dcompose: cannot fix automatically: {printable(problem)}", file=sys.stderr)
    return 1 if remaining else 0
