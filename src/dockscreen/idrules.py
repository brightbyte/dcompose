"""Which uids and gids a project or an image may choose for a container.

Applies to every id that comes from an untrusted source: `user:`, hook users and `group_add` in a compose
file, and the user an image runs as. Ids from the command line and the config file are trusted and are
not checked here.

Never accepted, unless they are allowed ids (below):
- 0, root;
- an id that exists on this host: the container would share that account's kernel limits
  (processes, inotify watches), and own its files in anything it mounts;
- an id in a subordinate range (/etc/subuid, /etc/subgid, any owner): files with these ids belong to
  rootless containers on this host;
- 65535 and 4294967295, which tools read as "no id".

With host mounts (bind mounts, devices, volumes_from, secrets, configs) the id must be an allowed id,
because what the container can write on the host depends on it.

Allowed ids: the nobody range and the default user from the config file, ids the caller adds for one
check (a configured image user), and the caller's own ids when --allow-me was given.
"""

from typing import NamedTuple

from dockscreen import config as configuration

SUBUID_FILE = "/etc/subuid"
SUBGID_FILE = "/etc/subgid"


class Rules(NamedTuple):
    me: tuple                # (uid, gid) of the caller
    allow_me: bool           # --allow-me (or --as-me on docker run)
    nobody_range: tuple      # inclusive (low, high)
    default_user: tuple      # (uid, gid) that replaces root
    local: object            # hostusers.HostAccounts: the accounts on this host
    subordinate: object      # Subordinate: ranges in /etc/subuid and /etc/subgid

    def allowed(self, kind, value, extra=()):
        """Whether value is an allowed id. kind: "uid" or "gid"; extra: further allowed (uid, gid) pairs."""
        index = 0 if kind == "uid" else 1
        low, high = self.nobody_range
        pairs = [self.default_user, *extra, *([self.me] if self.allow_me else [])]
        return low <= value <= high or any(pair[index] == value for pair in pairs)

    def problem(self, kind, value, mounts, extra=()):
        """Why value may not be used, or None. kind: "uid", "gid" or "supplementary gid"."""
        base = "uid" if kind == "uid" else "gid"
        if self.allowed(base, value, extra):
            return None
        if value == 0:
            return f"{kind} 0 is root"
        if value in configuration.NO_ID:
            return f"{kind} {value} means \"no id\" to many tools"
        if value == self.me[0 if base == "uid" else 1]:
            return f"{kind} {value} is yours; pass --allow-me to allow it"
        name = self.local.user_name(value) if base == "uid" else self.local.group_name(value)
        if name is not None:
            account = "user" if base == "uid" else "group"
            return f"{kind} {value} exists on this host (local {account} {name})"
        if self.subordinate.contains(base, value):
            return f"{kind} {value} is in a subordinate id range of this host (rootless containers)"
        if mounts:
            low, high = self.nobody_range
            return f"{kind} {value} is not in the nobody range {low}-{high}, and there are host mounts"
        return None

    def problems(self, uid, gid, supplementary=(), mounts=False, extra=()):
        """Problems with running as these ids; empty if acceptable."""
        checks = [("uid", uid), ("gid", gid), *(("supplementary gid", g) for g in supplementary)]
        found = [self.problem(kind, value, mounts, extra) for kind, value in checks if value is not None]
        return [p for p in found if p]


class Subordinate:
    """The subordinate id ranges of this host, read once: `name:start:count` lines, malformed ones skipped."""

    def __init__(self, uid_file=None, gid_file=None):
        self.ranges = {
            "uid": read_ranges(uid_file or SUBUID_FILE),
            "gid": read_ranges(gid_file or SUBGID_FILE),
        }

    def contains(self, kind, value):
        return any(start <= value < start + count for start, count in self.ranges[kind])


def read_ranges(path):
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return []
    ranges = []
    for line in text.splitlines():
        fields = line.strip().split(":")
        if len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit():
            ranges.append((int(fields[1]), int(fields[2])))
    return ranges
