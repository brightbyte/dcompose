"""Numeric uids and gids, and the uid and gid compose files see.

dockscreen exports UID and GID, the real ids of the caller, for compose files to interpolate
(`user: "${UID}:${GID}"`); values already in the environment are overwritten. Running as these ids is
not allowed unless --allow-me is given (see idrules): exporting them only makes the project's intent
readable.

Ids given by the command line, the config file or the project are ASCII digits only. How docker reads
ids out of an image's passwd and group files is different, and lives in imageuser.
"""

import os

EXPORTED = ("UID", "GID")


def export(env):
    """Set UID and GID in env to the real ids. Idempotent."""
    env["UID"] = str(os.getuid())
    env["GID"] = str(os.getgid())


def is_id(text):
    return text.isascii() and text.isdigit()


def parse_id(value):
    """The numeric id, or None."""
    text = str(value)
    return int(text) if is_id(text) else None


def parse_user(spec):
    """(uid, gid) from "uid:gid" with numeric ids, or None for anything else."""
    user, colon, group = spec.partition(":")
    if not (colon and is_id(user) and is_id(group)):
        return None
    return int(user), int(group)


def format_user(ids):
    """"uid:gid" from (uid, gid)."""
    uid, gid = ids
    return f"{uid}:{gid}"
