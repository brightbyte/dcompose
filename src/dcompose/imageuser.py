"""Which uid and gids a container would run as, and whether an image may choose them.

The image is hostile, so its own /etc/passwd and /etc/group decide the
identity docker will use, and the rule is applied to that: not root, and not an
id that exists on this host. `nobody` is exempt.
"""

import grp
import pwd
from typing import NamedTuple

NOBODY = 65534


class Identity(NamedTuple):
    uid: int
    gid: int
    supplementary: tuple


class LocalIds:
    """The ids that exist on this host, through NSS (so LDAP and sssd accounts count)."""

    def user_name(self, uid):
        """The local account with this uid, or None."""
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return None

    def group_name(self, gid):
        """The local group with this gid, or None."""
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return None


def parse_passwd(text):
    """[(name, uid, gid)], skipping malformed lines."""
    entries = []
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) >= 4 and fields[2].isascii() and fields[2].isdigit() \
                and fields[3].isascii() and fields[3].isdigit():
            entries.append((fields[0], int(fields[2]), int(fields[3])))
    return entries


def parse_group(text):
    """[(name, gid, members)], skipping malformed lines."""
    entries = []
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) >= 3 and fields[2].isascii() and fields[2].isdigit():
            members = fields[3].split(",") if len(fields) > 3 and fields[3] else []
            entries.append((fields[0], int(fields[2]), members))
    return entries


def resolve(spec, passwd_text, group_text):
    """Mirror how docker turns a `user[:group]` spec into ids, using the image's files.

    A numeric uid without a passwd entry gets gid 0. Raises ValueError for a
    name the image does not define, which docker would refuse to start too.
    """
    passwd = parse_passwd(passwd_text)
    groups = parse_group(group_text)
    user_part, _, group_part = (spec or "0").partition(":")

    entry = next((p for p in passwd if p[0] == user_part or (_is_id(user_part) and p[1] == int(user_part))),
                 None)
    if entry:
        username, uid, default_gid = entry
    elif _is_id(user_part):
        username, uid, default_gid = None, int(user_part), 0
    else:
        raise ValueError(f"user {user_part!r} is not defined in the image")

    gid = default_gid
    if group_part:
        group = next(
            (g for g in groups if g[0] == group_part or (_is_id(group_part) and g[1] == int(group_part))),
            None,
        )
        if group:
            gid = group[1]
        elif _is_id(group_part):
            gid = int(group_part)
        else:
            raise ValueError(f"group {group_part!r} is not defined in the image")

    supplementary = tuple(sorted({g[1] for g in groups if username and username in g[2]}))
    return Identity(uid, gid, supplementary)


def _is_id(text):
    return text.isascii() and text.isdigit()


def involves_root(identity):
    return 0 in (identity.uid, identity.gid, *identity.supplementary)


def describe(identity, local=None):
    """The identity in words; with local (LocalIds), also which local accounts the ids are."""
    def who(kind, value):
        if local is None:
            return str(value)
        name = local.user_name(value) if kind == "user" else local.group_name(value)
        return f"{value} (local {kind} {name})" if name else f"{value} (no local {kind})"

    text = f"uid {who('user', identity.uid)}, gid {who('group', identity.gid)}"
    if identity.supplementary:
        text += ", supplementary gids " + ", ".join(who("group", g) for g in identity.supplementary)
    return text


def is_nobody(identity):
    return {identity.uid, identity.gid, *identity.supplementary} == {NOBODY}


def check(identity, local):
    """Problems with letting the image run as this identity; empty if acceptable.

    Root, and ids that exist on this host: a container shares the kernel's per-user limits (processes,
    inotify watches) with the host account of the same id, and owns that account's files in anything it
    mounts. Whether it mounts anything is decided by the caller (gate.assess).
    """
    problems = []
    for kind, value, lookup in (
        [("uid", identity.uid, local.user_name)]
        + [("gid", identity.gid, local.group_name)]
        + [("supplementary gid", g, local.group_name) for g in identity.supplementary]
    ):
        if value == NOBODY:
            continue
        if value == 0:
            problems.append(f"the image would run with {kind} 0 (root)")
        elif (name := lookup(value)) is not None:
            account = "user" if kind == "uid" else "group"
            problems.append(f"the image would run with {kind} {value}, which exists on this host "
                            f"(local {account} {name})")
    return problems
