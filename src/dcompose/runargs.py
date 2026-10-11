"""Splitting `docker run` arguments, just far enough to run them as `docker create` + `docker start`.

We need the image position and the few flags that `run` has and `create` lacks
(`-d`, `--sig-proxy`, `--detach-keys`, `-a`). Nothing security-relevant hangs
on this: the policy looks at the container the daemon created from the result,
and gate.verify_split checks that our reading of the command line matched the
daemon's.
"""

from typing import NamedTuple

# Long options of `docker run`/`create` that take a value in the next argument.
LONG_VALUE_FLAGS = frozenset({
    "--add-host", "--annotation", "--attach", "--blkio-weight", "--blkio-weight-device", "--cap-add",
    "--cap-drop", "--cgroup-parent", "--cgroupns", "--cidfile", "--cpu-period", "--cpu-quota",
    "--cpu-rt-period", "--cpu-rt-runtime", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems",
    "--detach-keys", "--device", "--device-cgroup-rule", "--device-read-bps", "--device-read-iops",
    "--device-write-bps", "--device-write-iops", "--dns", "--dns-option", "--dns-search", "--domainname",
    "--entrypoint", "--env", "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd",
    "--health-interval", "--health-retries", "--health-start-interval", "--health-start-period",
    "--health-timeout", "--hostname", "--ip", "--ip6", "--ipc", "--isolation", "--kernel-memory",
    "--label", "--label-file", "--link", "--link-local-ip", "--log-driver", "--log-opt", "--mac-address",
    "--memory", "--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount", "--name",
    "--network", "--network-alias", "--oom-score-adj", "--pid", "--pids-limit", "--platform", "--publish",
    "--pull", "--restart", "--runtime", "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout",
    "--storage-opt", "--sysctl", "--tmpfs", "--ulimit", "--user", "--userns", "--uts", "--volume",
    "--volume-driver", "--volumes-from", "--workdir",
})
SHORT_VALUE_FLAGS = frozenset("acehlmpuvw")


CURRENT_USER_FLAG = "--current-user"
CURRENT_USER_NAME = "me"  # `--user me`: not a docker feature, replaced by the caller's uid:gid


class ParseError(Exception):
    pass


class ParsedRun(NamedTuple):
    create_args: list
    image: str
    command: list
    detach: bool
    detach_keys: str
    user_given: bool  # --user, -u or --current-user before the image


class _State:
    def __init__(self, current_user):
        self.current_user = f"{current_user[0]}:{current_user[1]}"
        self.kept = []
        self.detach = False
        self.detach_keys = None
        self.user_given = False

    def user_value(self, value):
        self.user_given = True
        return self.current_user if value == CURRENT_USER_NAME else value


def parse(args, current_user):
    """Split run arguments; current_user is the (uid, gid) that `me` and --current-user stand for."""
    state = _State(current_user)
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            state.kept.append(token)
            i += 1
            break
        if token.startswith("--"):
            i = parse_long(args, i, state)
        elif token.startswith("-") and token != "-":
            i = parse_short(args, i, state)
        else:
            break
    if i >= len(args):
        raise ParseError("no image found in the command line")
    return ParsedRun([*state.kept, *args[i:]], args[i], args[i + 1:], state.detach, state.detach_keys,
                     state.user_given)


def parse_long(args, i, state):
    """Handle one --option; returns the index after it and its value."""
    token = args[i]
    name, has_value, value = token.partition("=")
    if name == CURRENT_USER_FLAG:
        state.kept.append(f"--user={state.user_value(CURRENT_USER_NAME)}")
    elif name == "--detach":
        state.detach = value.lower() != "false" if has_value else True
    elif name == "--sig-proxy":
        pass
    elif name in ("--detach-keys", "--attach"):
        if not has_value:
            i += 1
            value = value_at(args, i, name)
        if name == "--detach-keys":
            state.detach_keys = value
    elif name == "--user":
        if not has_value:
            i += 1
            value = value_at(args, i, name)
        state.kept.append(f"--user={state.user_value(value)}")
    else:
        state.kept.append(token)
        if name in LONG_VALUE_FLAGS and not has_value:
            i += 1
            state.kept.append(value_at(args, i, name))
    return i + 1


def parse_short(args, i, state):
    """Handle one cluster such as -itv or -p80:80; returns the index after it."""
    token = args[i]
    keep = ""
    next_is_value = False
    consumed = 1
    for j in range(1, len(token)):
        char = token[j]
        if char == "d":
            state.detach = True
        elif char in SHORT_VALUE_FLAGS:
            rest = token[j + 1:]
            if char == "a":  # --attach has no `create` equivalent; dropped with its value
                if not rest:
                    value_at(args, i + 1, token)
                    consumed = 2
                break
            if char == "u":  # a user is a value we may rewrite: move it out of the cluster
                value = rest or value_at(args, i + 1, token)
                consumed = 1 if rest else 2
                if keep:
                    state.kept.append("-" + keep)
                state.kept.append(f"--user={state.user_value(value)}")
                return i + consumed
            keep += char + rest
            next_is_value = not rest
            break
        else:
            keep += char
    if keep:
        state.kept.append("-" + keep)
    if next_is_value:
        state.kept.append(value_at(args, i + 1, token))
        consumed = 2
    return i + consumed


def value_at(args, index, flag):
    if index >= len(args):
        raise ParseError(f"{flag} needs a value")
    return args[index]
