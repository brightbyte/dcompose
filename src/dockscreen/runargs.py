"""Splitting `docker run` arguments, just far enough to run them as `docker create` + `docker start`.

We need the image position and the few flags that `run` has and `create` lacks
(`-d`, `--sig-proxy`, `--detach-keys`, `-a`). Nothing security-relevant hangs
on this: the policy looks at the container the daemon created from the result,
and gate.verify_split checks that our reading of the command line matched the
daemon's.
"""

from typing import NamedTuple

from dockscreen import flags, hostusers, ids

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


class ParseError(Exception):
    pass


class ParsedRun(NamedTuple):
    create_args: list
    image: str
    command: list
    detach: bool
    detach_keys: str
    user_given: bool  # --user, -u, --as or --as-me before the image
    notices: list     # what resolving user names on this host did, for the caller to print
    allow_me: bool = False  # --allow-me or --as-me before the image


class _State:
    def __init__(self, current_user, resolve):
        self.current_user = ids.format_user(current_user)
        self.resolve = resolve
        self.notices = []
        self.kept = []
        self.detach = False
        self.detach_keys = None
        self.user_given = False
        self.allow_me = False

    def user_value(self, value):
        """The value of --user or -u: numeric ids only."""
        self.user_given = True
        return hostusers.require_numeric(value)

    def account_value(self, name):
        """The value of --as: a local account, as ids."""
        self.user_given = True
        resolved, messages = self.resolve(name)
        self.notices += messages
        return resolved


def parse(args, current_user, resolve=hostusers.resolve_account):
    """Split run arguments.

    current_user: the (uid, gid) that --as-me stands for.
    resolve: turns the name given to --as into "uid:gid" (hostusers.resolve_account), with messages.
    Raises hostusers.UserError if --user is not numeric or --as does not name a local user.
    """
    state = _State(current_user, resolve)
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
                     state.user_given, state.notices, state.allow_me)


def parse_long(args, i, state):
    """Handle one --option; returns the index after it and its value."""
    token = args[i]
    name, has_value, value = token.partition("=")
    if name == flags.AS_ME:
        state.user_given = state.allow_me = True
        state.kept.append(f"--user={state.current_user}")
    elif name == flags.ALLOW_ME:  # not a docker option: dropped
        state.allow_me = True
    elif name == flags.AS:
        if not has_value:
            i += 1
            value = value_at(args, i, name)
        state.kept.append(f"--user={state.account_value(value)}")
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
