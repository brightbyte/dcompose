"""Entry point for a wrapper installed as `docker`.

`docker compose` goes to dockscreen, commands that start containers from images
go through the gate, everything else is exec'd to the real docker unchanged.
"""

import os
import sys

from dockscreen import (
    cli,
    config,
    flags,
    gate,
    hostusers,
    idrules,
    imageuser,
    messages,
    realdocker,
    screen,
)
from dockscreen.dockerclient import Docker

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


def dispatch(argv):
    skipped, argv = flags.strip(argv, DOCKER_OPTS_WITH_VALUE)
    if skipped:
        flags.banner()
        return passthrough(argv)

    allow_me, argv = flags.strip(argv, DOCKER_OPTS_WITH_VALUE, flags.ALLOW_ME)
    config.current()  # a config file that cannot be trusted stops everything, before any docker runs

    idx = cli.find_subcommand(argv, DOCKER_OPTS_WITH_VALUE)
    if idx is None:
        return passthrough(argv)

    if argv[idx] == "compose":
        if idx != 0:
            messages.notice("docker options before `compose` are not supported")
            return 1
        return cli.main([*([flags.ALLOW_ME] if allow_me else []), *argv[1:]])

    sub, end = argv[idx], idx
    if sub == "container" and idx + 1 < len(argv) and argv[idx + 1] in GATED - {"audit"}:
        sub, end = argv[idx + 1], idx + 1
    if sub not in GATED:
        return passthrough(argv)
    return gated(argv, sub, idx, end, allow_me)


def gated(argv, sub, idx, end, allow_me=False):
    lead, args = argv[:end + 1], argv[end + 1:]
    if sub == "audit":
        if not args or args[:1] == ["--help"]:
            messages.notice("usage: docker audit [--user UID:GID | --as NAME | --as-me] IMAGE")
            messages.notice("Predict what `docker run IMAGE` would do: run, run as nobody, or be refused.")
            return 2
    elif args[:1] == ["--help"] or (sub in ("run", "create") and not args):
        return passthrough(argv)
    if sub == "create":
        try:
            resolved = gate.create_args(args)
        except hostusers.UserError as e:
            return messages.refuse([str(e)])
        return passthrough([*lead, *gate.DEFAULTS, *resolved])
    if sub == "exec":
        resolved = cli.rewrite_exec("docker exec", args)
        return 1 if resolved is None else passthrough([*lead, *resolved])

    docker = Docker()
    if screen.is_remote(argv[:idx], os.environ, docker):
        return messages.refuse([screen.REMOTE_MESSAGE])

    ctx = gate.Context(docker, idrules.rules(imageuser.LocalIds(), allow_me))
    if sub == "run":
        return gate.run(ctx, args)
    if sub == "audit":
        return gate.audit(ctx, args)
    problems = gate.check_existing(ctx, args)
    return messages.refuse(problems) if problems else passthrough(argv)


def passthrough(argv):
    """Replace this process with the real docker."""
    binary = realdocker.docker_bin()
    try:
        os.execvp(binary, [binary, *argv])
    except FileNotFoundError:
        messages.fatal(messages.DOCKER_NOT_FOUND)


if __name__ == "__main__":
    sys.exit(main())
