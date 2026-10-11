"""Entry point: dispatch custom subcommands, forward everything else to docker compose.

We deliberately do not use argparse for the docker compose surface. Anything we
do not recognise must reach docker compose untouched, so the only thing we
parse is the position of the subcommand.
"""

import os
import sys

from dockscreen import (
    composeargs,
    composerun,
    config,
    flags,
    hostusers,
    ids,
    messages,
    policy,
    realdocker,
    screen,
)
from dockscreen.commands import ALIASES, COMMANDS

# Subcommands that create containers from the config. `alpha` is a group (older
# compose has `alpha watch`); screening it is cheap and errs on the safe side.
RUNTIME_SUBCOMMANDS = frozenset({"up", "create", "run", "watch", "scale", "alpha"})
# Subcommands that only build: they get the build-related checks, not the runtime policy.
BUILD_SUBCOMMANDS = frozenset({"build", "bake"})
SCREENED_SUBCOMMANDS = RUNTIME_SUBCOMMANDS | BUILD_SUBCOMMANDS

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


def find_subcommand(argv, value_opts=GLOBAL_OPTS_WITH_VALUE):
    """Return the index of the subcommand in argv, or None. value_opts: options that take a value."""
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            return None
        if token in value_opts:
            i += 2
        elif token.startswith("-"):
            i += 1
        else:
            return i
    return None


def forward(argv):
    """Replace this process with `docker compose argv`, keeping tty, signals and exit code."""
    try:
        binary = realdocker.docker_bin()
        os.execvp(binary, [binary, "compose", *argv])
    except FileNotFoundError:
        messages.fatal(messages.DOCKER_NOT_FOUND)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
        return dispatch(argv)
    except config.ConfigError as e:
        return messages.refuse([f"config file {e}"])


def dispatch(argv):
    skipped, argv = flags.strip(argv, GLOBAL_OPTS_WITH_VALUE)
    if skipped:
        flags.banner()
        return forward(argv)

    allow_me, argv = flags.strip(argv, GLOBAL_OPTS_WITH_VALUE, flags.ALLOW_ME)
    as_me, argv = flags.strip(argv, GLOBAL_OPTS_WITH_VALUE, flags.AS_ME)
    if as_me:
        messages.notice(flags.AS_ME_MESSAGE)
        return 2
    config.current()  # a config file that cannot be trusted stops everything, before any docker runs
    ids.export(os.environ)

    idx = find_subcommand(argv)
    if idx is not None and argv[idx] in COMMANDS:
        return COMMANDS[argv[idx]](global_args=argv[:idx], args=argv[idx + 1:], allow_me=allow_me)

    if is_screened(argv, idx):
        if argv[idx] not in BUILD_SUBCOMMANDS:
            return composerun.run(argv, idx, allow_me=allow_me)
        if not screen.passes(argv[:idx], policy.check_build_config):
            return 1
    elif idx is not None and argv[idx] == "exec" and argv[idx + 1:idx + 2] != ["--help"]:
        args = rewrite_exec("exec", argv[idx + 1:])
        if args is None:
            return 1
        argv = [*argv[:idx + 1], *args]

    if wants_help(argv, idx):
        print_help()

    forward(argv)


def rewrite_exec(kind, args):
    """The arguments of `exec` (kind: "exec" or "docker exec") with --as and --as-me replaced by ids.

    None if the user they give cannot be used; that has been reported.
    """
    try:
        parsed = composeargs.parse(kind, args)
    except hostusers.UserError as e:
        messages.report([str(e)])
        return None
    for notice in parsed.notices:
        messages.notice(notice)
    return parsed.args


def is_screened(argv, idx):
    """Whether screening must run: SCREENED_SUBCOMMANDS, unless compose only prints help.

    Only a leading --help counts. After `run <service>` the rest belongs to the
    command (`run app grep -h x`), and flag values can look like options, so
    anywhere else screening runs. `up -h` is therefore screened too, at worst a
    needless refusal.
    """
    if idx is None or argv[idx] not in SCREENED_SUBCOMMANDS:
        return False
    return argv[idx + 1:idx + 2] != ["--help"]


def wants_help(argv, idx):
    """True for no arguments, `help` or `--help`; `help <subcommand>` is compose's alone."""
    if idx is None:
        return not argv or "--help" in argv or "-h" in argv
    return argv[idx] == "help" and idx == len(argv) - 1


def print_help():
    lines = [
        "dockscreen: docker compose with security checks and extra subcommands.",
        "Everything else is forwarded to docker compose unchanged.",
        "",
        f"{', '.join(sorted(RUNTIME_SUBCOMMANDS))} refuse to run if the config mounts paths outside",
        "the project directory, runs as root, as an account of this host or (with mounts) outside the",
        "nobody range, or asks for extra privileges. They run the project from the checked config, with",
        "cap_drop ALL and no-new-privileges added to every service that lacks them.",
        f"{flags.ALLOW_ME}, before the subcommand, allows services to run as you.",
        f"{', '.join(sorted(BUILD_SUBCOMMANDS))} refuse builds that read outside the project, use the",
        "host network, run privileged or forward your SSH agent. See `dockscreen audit`.",
        f"{flags.SKIP_SCREENING}, before the subcommand, turns all of this off.",
        "",
        "dockscreen commands:",
    ]
    for name, fn in sorted(COMMANDS.items()):
        if name in ALIASES:
            continue
        summary = (fn.__doc__ or "").strip().splitlines()[0] if fn.__doc__ else ""
        also = [alias for alias, primary in ALIASES.items() if primary == name]
        lines.append(f"  {name:<10}{summary}" + (f" (also: {', '.join(also)})" if also else ""))
    lines += ["", "docker compose help follows.", ""]
    # flush: exec in forward() discards unflushed buffers
    print("\n".join(lines), flush=True)


if __name__ == "__main__":
    sys.exit(main())
