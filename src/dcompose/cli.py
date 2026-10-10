"""Entry point: dispatch custom subcommands, forward everything else to docker compose.

We deliberately do not use argparse for the docker compose surface. Anything we
do not recognise must reach docker compose untouched, so the only thing we
parse is the position of the subcommand.
"""

import os
import sys

from dcompose import guard, ids
from dcompose.commands import COMMANDS

# Subcommands that create containers from the config. `alpha` is a group (older
# compose has `alpha watch`); guarding it is cheap and errs on the safe side.
RUNTIME_SUBCOMMANDS = frozenset({"up", "create", "run", "watch", "scale", "alpha"})
# Subcommands that only build: they get the build-related checks, not the runtime policy.
BUILD_SUBCOMMANDS = frozenset({"build", "bake"})
GUARDED_SUBCOMMANDS = RUNTIME_SUBCOMMANDS | BUILD_SUBCOMMANDS

# Global `docker compose` options that consume the following token as their value.
# Needed to tell `-f foo.yml up` (subcommand "up") from `-f up` (a value).
GLOBAL_OPTS_WITH_VALUE = frozenset({
    "--ansi",
    "--env-file",
    "-f", "--file",
    "--parallel",
    "--profile",
    "--progress",
    "--project-directory",
    "-p", "--project-name",
})


def find_subcommand(argv):
    """Return the index of the compose subcommand in argv, or None."""
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            return None
        if token in GLOBAL_OPTS_WITH_VALUE:
            i += 2
        elif token.startswith("-"):
            i += 1
        else:
            return i
    return None


def forward(argv):
    """Replace this process with `docker compose argv`, keeping tty, signals and exit code."""
    try:
        os.execvp("docker", ["docker", "compose", *argv])
    except FileNotFoundError:
        sys.exit("dcompose: 'docker' not found in PATH")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)

    try:
        ids.export(os.environ)
    except ValueError as e:
        print(f"dcompose: {e}", file=sys.stderr)
        return 1

    idx = find_subcommand(argv)
    if idx is not None and argv[idx] in COMMANDS:
        return COMMANDS[argv[idx]](global_args=argv[:idx], args=argv[idx + 1:])

    if is_guarded(argv, idx) and not guard.passes(argv[:idx], build_only=argv[idx] in BUILD_SUBCOMMANDS):
        return 1

    if wants_help(argv, idx):
        print_help()

    forward(argv)


def is_guarded(argv, idx):
    """Whether the guard must run: container-creating subcommands, unless compose only prints help.

    Only a leading --help counts. After `run <service>` the rest belongs to the
    command (`run app grep -h x`), and flag values can look like options, so
    anywhere else the guard runs. `up -h` is therefore guarded too, at worst a
    needless refusal.
    """
    if idx is None or argv[idx] not in GUARDED_SUBCOMMANDS:
        return False
    return argv[idx + 1:idx + 2] != ["--help"]


def wants_help(argv, idx):
    """True for no arguments, `help` or `--help`; `help <subcommand>` is compose's alone."""
    if idx is None:
        return not argv or "--help" in argv or "-h" in argv
    return argv[idx] == "help" and idx == len(argv) - 1


def print_help():
    lines = [
        "dcompose: docker compose with security checks and extra subcommands.",
        "Everything else is forwarded to docker compose unchanged.",
        "",
        f"{', '.join(sorted(GUARDED_SUBCOMMANDS))} refuse to run if the config mounts paths outside",
        "the project directory, runs as any user but the allowed one (you, or DCOMPOSE_UID/GID) or nobody,",
        "or asks for extra privileges. See `dcompose audit`.",
        "",
        "dcompose commands:",
    ]
    for name, fn in sorted(COMMANDS.items()):
        summary = (fn.__doc__ or "").strip().splitlines()[0] if fn.__doc__ else ""
        lines.append(f"  {name:<10}{summary}")
    lines += ["", "docker compose help follows.", ""]
    # flush: exec in forward() discards unflushed buffers
    print("\n".join(lines), flush=True)


if __name__ == "__main__":
    sys.exit(main())
