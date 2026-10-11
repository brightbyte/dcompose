"""Entry point for a wrapper installed as `docker`.

`docker compose` goes to dockscreen, commands that start containers from images
go through the gate, everything else is exec'd to the real docker unchanged.
"""

import os
import sys

from dockscreen import cli, gate, guard, hostusers, imageuser, realdocker, skipflag
from dockscreen.dockerclient import Docker

# Global `docker` options that consume the following token as their value.
DOCKER_OPTS_WITH_VALUE = frozenset({
    "--config", "-c", "--context", "-H", "--host", "-l", "--log-level",
    "--tlscacert", "--tlscert", "--tlskey",
})
GATED = frozenset({"run", "create", "start", "restart", "audit"})


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)

    skipped, argv = skipflag.strip(argv, DOCKER_OPTS_WITH_VALUE)
    if skipped:
        skipflag.banner()
        return passthrough(argv)

    idx = cli.find_subcommand(argv, DOCKER_OPTS_WITH_VALUE)
    if idx is None:
        return passthrough(argv)

    if argv[idx] == "compose":
        if idx != 0:
            print("dockscreen: docker options before `compose` are not supported", file=sys.stderr)
            return 1
        return cli.main(argv[1:])

    sub, end = argv[idx], idx
    if sub == "container" and idx + 1 < len(argv) and argv[idx + 1] in GATED - {"audit"}:
        sub, end = argv[idx + 1], idx + 1
    if sub not in GATED:
        return passthrough(argv)
    return gated(argv, sub, idx, end)


def gated(argv, sub, idx, end):
    lead, args = argv[:end + 1], argv[end + 1:]
    if sub == "audit":
        if not args or args[:1] == ["--help"]:
            print("usage: docker audit [--user UID:GID | --as NAME | --as-me] IMAGE\n"
                  "Predict what `docker run IMAGE` would do: run, run as nobody, or be refused.",
                  file=sys.stderr)
            return 2
    elif args[:1] == ["--help"] or (sub in ("run", "create") and not args):
        return passthrough(argv)
    if sub == "create":
        try:
            resolved = gate.create_args(args)
        except hostusers.UserError as e:
            return gate.refuse([str(e)])
        return passthrough([*lead, *gate.DEFAULTS, *resolved])

    docker = Docker()
    if guard.is_remote(argv[:idx], os.environ, docker):
        return gate.refuse([guard.REMOTE_MESSAGE])

    ctx = gate.Context(docker, imageuser.LocalIds())
    if sub == "run":
        return gate.run(ctx, args)
    if sub == "audit":
        return gate.audit(ctx, args)
    problems = gate.check_existing(ctx, args)
    return gate.refuse(problems) if problems else passthrough(argv)


def passthrough(argv):
    """Replace this process with the real docker."""
    binary = realdocker.docker_bin()
    try:
        os.execvp(binary, [binary, *argv])
    except FileNotFoundError:
        sys.exit("dockscreen: 'docker' not found in PATH")


if __name__ == "__main__":
    sys.exit(main())
