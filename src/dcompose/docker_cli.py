"""Entry point for a wrapper installed as `docker`.

`docker compose` goes to dcompose, commands that start containers from images
go through the gate, everything else is exec'd to the real docker unchanged.
"""

import os
import sys

from dcompose import cli, gate, guard, ids, imageuser, realdocker, skipflag
from dcompose.dockerclient import Docker

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
            print("dcompose: docker options before `compose` are not supported", file=sys.stderr)
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
            print("usage: docker audit [--user USER | --current-user] IMAGE\n"
                  "Predict what `docker run IMAGE` would do: run, run as nobody, or be refused.",
                  file=sys.stderr)
            return 2
    elif args[:1] == ["--help"] or (sub in ("run", "create") and not args):
        return passthrough(argv)
    if sub == "create":
        return passthrough([*lead, *gate.DEFAULTS, *args])

    docker = Docker()
    try:
        id_range = ids.id_range(os.environ)
    except ValueError as e:
        return gate.refuse([str(e)])
    if is_remote(argv[:idx], os.environ, docker):
        return gate.refuse(["the daemon is not the default local one; ids and paths cannot be checked"])

    ctx = gate.Context(docker, id_range, imageuser.LocalIds())
    if sub == "run":
        return gate.run(ctx, args)
    if sub == "audit":
        return gate.audit(ctx, args)
    problems = gate.check_existing(ctx, args)
    return gate.refuse(problems) if problems else passthrough(argv)


def is_remote(global_args, env, docker):
    """Whether the daemon might not be this host's own, where host ids and paths mean nothing."""
    if guard.option_values(global_args, "--host", "-H"):
        return True
    if guard.option_values(global_args, "--context", "-c"):
        return True
    host = env.get("DOCKER_HOST", "")
    if host and not host.startswith("unix://"):
        return True
    if env.get("DOCKER_CONTEXT") not in (None, "", "default"):
        return True
    return docker.context() != "default"


def passthrough(argv):
    """Replace this process with the real docker."""
    binary = realdocker.docker_bin()
    try:
        os.execvp(binary, [binary, *argv])
    except FileNotFoundError:
        sys.exit("dcompose: 'docker' not found in PATH")


if __name__ == "__main__":
    sys.exit(main())
