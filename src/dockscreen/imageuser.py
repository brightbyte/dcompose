"""Which uid and gids a container would run as, read from the image as docker reads it.

The image is hostile, so its own /etc/passwd and /etc/group decide the identity docker would use;
idrules decides whether the image may have it. Whatever is accepted runs pinned as numbers, so a
difference between this reading and docker's can at worst refuse a good image.
"""

import grp
import pwd
from typing import NamedTuple

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


# What Go's unicode.IsSpace trims; Python's str.strip() differs (it also strips \x1c to \x1f).
GO_SPACE = "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009" \
           "\u200a\u2028\u2029\u202f\u205f\u3000"
INT64_MAX = 2**63 - 1
INT64_MIN = -(2**63)


def lines(text):
    """The non-empty lines of a passwd or group file as moby reads them: split on newlines only,
    each stripped of surrounding whitespace."""
    stripped = (line.strip(GO_SPACE) for line in text.split("\n"))
    return [line for line in stripped if line]


def atoi(text):
    """Go's strconv.Atoi with the error ignored, as moby does: a sign and ASCII digits, else 0;
    a number out of range is the nearest limit."""
    digits = text[1:] if text[:1] in "+-" else text
    if not (digits and all(c in "0123456789" for c in digits)):
        return 0
    return max(INT64_MIN, min(INT64_MAX, int(text)))


def fields(line, count):
    """The first count colon-separated fields; fields missing from a short line are empty."""
    parts = line.split(":")[:count]
    return parts + [""] * (count - len(parts))


def parse_passwd(text):
    """[(name, uid, gid)] like moby: a line with missing or malformed numbers has uid 0 and gid 0."""
    entries = []
    for line in lines(text):
        name, _, uid, gid, *_ = fields(line, 7)
        entries.append((name, atoi(uid), atoi(gid)))
    return entries


def parse_group(text):
    """[(name, gid, members)] like moby."""
    entries = []
    for line in lines(text):
        name, _, gid, members = fields(line, 4)
        entries.append((name, atoi(gid), members.split(",") if members else []))
    return entries


def resolve(spec, passwd_text, group_text):
    """Mirror how docker turns a `user[:group]` spec into ids, using the image's files.

    A numeric user or group is an id, never a name (moby looks it up by number only). A numeric
    uid without a passwd entry gets gid 0. Raises ValueError for a name the image does not define,
    which docker would refuse to start too, and for a negative id.
    """
    passwd = parse_passwd(passwd_text)
    groups = parse_group(group_text)
    user_part, _, group_part = (spec or "0").partition(":")
    user_part = user_part or "0"  # moby: no user means the default, uid 0

    entry = find(passwd, user_part)
    if entry:
        username, uid, default_gid = entry
    elif _is_id(user_part):
        username, uid, default_gid = None, int(user_part), 0
    else:
        raise ValueError(f"user {user_part!r} is not defined in the image")

    gid = default_gid
    if group_part:
        group = find(groups, group_part)
        if group:
            gid = group[1]
        elif _is_id(group_part):
            gid = int(group_part)
        else:
            raise ValueError(f"group {group_part!r} is not defined in the image")

    if min(uid, gid) < 0:
        raise ValueError("the image's user has a negative id")
    supplementary = tuple(sorted({g[1] for g in groups if username and username in g[2]}))
    return Identity(uid, gid, supplementary)


def find(entries, arg):
    """The first entry (name, id, ...) that arg names: by id if arg is a number, else by name."""
    if _is_id(arg):
        return next((e for e in entries if e[1] == int(arg)), None)
    return next((e for e in entries if e[0] == arg), None)


def _is_id(text):
    """Whether Go's Atoi reads text as a number: an optional sign and ASCII digits."""
    digits = text[1:] if text[:1] in "+-" else text
    return bool(digits) and all(c in "0123456789" for c in digits)


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
