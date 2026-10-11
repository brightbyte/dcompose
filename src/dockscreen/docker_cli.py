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
    hostusers,
    imagedecision,
    messages,
    screen,
)
from dockscreen.dockerclient import DockerNotFound
from dockscreen.runtime import load_runtime

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
            print_help()
        return passthrough(argv, runtime)

    if argv[idx] == "compose":
        if idx != 0:
            messages.notice("docker options before `compose` are not supported")
            return 1
        return compose_cli.main([*([flags.ALLOW_ME] if allow_me else []), *argv[1:]], runtime)

    sub, end = argv[idx], idx
    if sub == "container" and idx + 1 < len(argv) and argv[idx + 1] in GATED - {"audit"}:
        sub, end = argv[idx + 1], idx + 1
    if sub not in GATED:
        return passthrough(argv, runtime)
    return gated(argv, sub, idx, end, runtime, allow_me, strict)


def gated(argv, sub, idx, end, runtime, allow_me=False, strict=False):
    lead, args = argv[:end + 1], argv[end + 1:]
    if sub == "audit":
        if not args or args[:1] == ["--help"]:
            messages.notice(gate.AUDIT_USAGE)
            messages.notice("Say what `docker run` with these arguments would do, without starting anything.")
            return 2
    elif args[:1] == ["--help"] or (sub in ("run", "create") and not args):
        return passthrough(argv, runtime)
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
        return messages.refuse([screen.REMOTE_MESSAGE])

    ctx = imagedecision.Context(docker, runtime.rules(allow_me), runtime)
    if sub == "run":
        return gate.run(ctx, args)
    if sub == "audit":
        return gate.audit(ctx, args, strict)
    problems = gate.check_existing(ctx, args)
    return messages.refuse(problems) if problems else passthrough(argv, runtime)


def print_help():
    lines = [
        "dockscreen: docker with security checks. Everything else is forwarded to docker unchanged.",
        "",
        "compose runs docker compose on projects that pass the checks; see `dockscreen compose --help`.",
        "run checks the user an image runs as: root becomes the default user (nobody unless configured),",
        "and an account of this host, or with mounts an id outside the nobody range, is refused. start and",
        "restart refuse containers that would fail that check. create and run add --cap-drop=ALL and",
        "no-new-privileges. audit takes the arguments of run and says what run would do, without",
        "starting anything; audit --brief says only passed, refused or failed.",
        f"{flags.ALLOW_ME}, before the subcommand, allows containers to run as you.",
        f"{flags.STRICT_SCREEN}, before audit, also fails it for what the command line asks for that a",
        "project or an image may not have.",
        f"{flags.SKIP_SCREENING}, before the subcommand, turns all of this off.",
        "",
        "docker help follows.",
        "",
    ]
    # flush: exec in passthrough() discards unflushed buffers
    print("\n".join(lines), flush=True)


def passthrough(argv, runtime):
    """Replace this process with the real docker."""
    binary = runtime.docker.binary
    try:
        os.execvp(binary, [binary, *argv])
    except FileNotFoundError:
        messages.fatal(messages.DOCKER_NOT_FOUND)


if __name__ == "__main__":
    sys.exit(main())
