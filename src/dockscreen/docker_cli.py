"""Entry point: `dockscreen`, a wrapper for `docker`, which can also be installed as `docker`.

`compose` goes to compose_cli, commands that start containers from images
go through the gate, everything else is exec'd to the real docker unchanged.
"""

import os
import sys

from dockscreen import (
    argscan,
    compose_cli,
    config,
    flags,
    gate,
    helptext,
    hostusers,
    imagedecision,
    messages,
    screen,
    verdict,
)
from dockscreen.dockerclient import DockerNotFound
from dockscreen.runtime import load_runtime
from dockscreen.verdict import Verdict

# Global `docker` options that consume the following token as their value.
DOCKER_OPTS_WITH_VALUE = frozenset({
    "--config", "-c", "--context", "-H", "--host", "-l", "--log-level",
    "--tlscacert", "--tlscert", "--tlskey",
})
GATED = frozenset({"run", "create", "start", "restart", "exec", "audit"})


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
        return dispatch(argv)
    except config.ConfigError as e:
        return messages.refuse([f"config file {e}"])
    except DockerNotFound as e:
        messages.notice(e)
        return 1


def dispatch(argv):
    skipped, argv = flags.strip(argv, DOCKER_OPTS_WITH_VALUE)
    runtime = load_runtime()  # a config file that cannot be trusted stops everything, before any docker runs
    if skipped:
        flags.banner()
        return passthrough(argv, runtime)

    allow_me, argv = flags.strip(argv, DOCKER_OPTS_WITH_VALUE, flags.ALLOW_ME)
    strict, argv = flags.strip(argv, DOCKER_OPTS_WITH_VALUE, flags.STRICT_SCREEN)

    idx = argscan.find_subcommand(argv, DOCKER_OPTS_WITH_VALUE)
    if strict and (idx is None or argv[idx] != "audit"):
        # refused, not ignored: a caller who asks for strict screening must not get the lenient kind
        return messages.refuse([f"{flags.STRICT_SCREEN} is only supported for audit so far"])
    if idx is None:
        if not argv or "--help" in argv or "-h" in argv:
            helptext.show(helptext.docker_overview)
        return passthrough(argv, runtime)
    if argv[idx] == "help":
        return show_help(argv[idx + 1:], argv, runtime)

    if argv[idx] == "compose":
        if idx != 0:
            messages.notice("docker options before `compose` are not supported")
            return 1
        return compose_cli.main([*([flags.ALLOW_ME] if allow_me else []), *argv[1:]], runtime)

    sub, end = argv[idx], idx
    if sub == "container" and idx + 1 < len(argv) and argv[idx + 1] in GATED - {"audit"}:
        sub, end = argv[idx + 1], idx + 1
    if wants_command_help(sub, argv[end + 1:]):
        return show_command_help(sub, argv, runtime)
    if sub not in GATED:
        return passthrough(argv, runtime)
    return gated(argv, sub, idx, end, runtime, allow_me, strict)


def gated(argv, sub, idx, end, runtime, allow_me=False, strict=False):
    lead, args = argv[:end + 1], argv[end + 1:]
    if sub == "audit" and not args:
        messages.notice(gate.AUDIT_USAGE)
        messages.notice("Run 'dockscreen audit --help' for more.")
        return 2
    if sub in ("run", "create") and not args:
        return passthrough(argv, runtime)  # docker says what is missing
    if sub == "create":
        try:
            resolved = gate.create_args(args, runtime)
        except hostusers.UserError as e:
            return messages.refuse([str(e)])
        return passthrough([*lead, *gate.DEFAULTS, *resolved], runtime)
    if sub == "exec":
        resolved = compose_cli.rewrite_exec("docker exec", args, runtime)
        return 1 if resolved is None else passthrough([*lead, *resolved], runtime)

    docker = runtime.docker
    if screen.is_remote(argv[:idx], runtime.env, docker):
        return verdict.report(Verdict.REFUSED, [screen.REMOTE_MESSAGE])

    ctx = imagedecision.Context(docker, runtime.rules(allow_me), runtime)
    if sub == "run":
        return gate.run(ctx, args)
    if sub == "audit":
        return gate.audit(ctx, args, strict)
    if not verdict.screened(gate.check_existing(ctx, args)):
        return 1
    return passthrough(argv, runtime)


def show_help(rest, argv, runtime):
    """`help` and `help COMMAND`: dockscreen's help, then docker's own."""
    if not rest:
        helptext.show(helptext.docker_overview)
        return passthrough(argv, runtime)
    if rest[0] == "compose":
        return compose_cli.main(["help", *rest[1:]], runtime)
    return show_command_help(rest[0], [rest[0], "--help"], runtime)


def wants_command_help(sub, args):
    """--help, or -h, as the first argument after the command. For run and create, -h is --hostname."""
    return args[:1] == ["--help"] or (args[:1] == ["-h"] and sub not in ("run", "create"))


def show_command_help(name, argv, runtime):
    """dockscreen's help for the command, if it audits or adds it, then docker's own (argv asks for it)."""
    topic = helptext.DOCKER.get(name)
    if topic is not None:
        helptext.show(lambda width: helptext.topic(topic, "Docker's own", width))
        if not topic.docker_help:
            return 0
    return passthrough(argv, runtime)


def passthrough(argv, runtime):
    """Replace this process with the real docker."""
    binary = runtime.docker.binary
    try:
        os.execvp(binary, [binary, *argv])
    except FileNotFoundError:
        messages.fatal(messages.DOCKER_NOT_FOUND)


if __name__ == "__main__":
    sys.exit(main())
