"""The uid/gid compose files see, and the ids the policy accepts.

dockscreen exports two pairs of variables for compose files to interpolate:
  UID, GID                  the real current user, always
  DOCKSCREEN_UID/GID          the ids containers are allowed to run as: the
                            values already set in the environment, else the
                            real ones

Setting DOCKSCREEN_UID/GID turns the rule from "run as me" into "run as exactly
this id": the real user is then refused unless it is the same id. `nobody` is
accepted in either case (see policy.check_user).
"""

import os


def allowed(env):
    """(uid, gid) that containers may run as."""
    return (
        pick(env, "DOCKSCREEN_UID", os.getuid()),
        pick(env, "DOCKSCREEN_GID", os.getgid()),
    )


def pick(env, name, default):
    value = env.get(name)
    if not value:
        return default
    if not value.isdigit():
        raise ValueError(f"{name}={value!r} is not a numeric id")
    return int(value)


EXPORTED = ("UID", "GID", "DOCKSCREEN_UID", "DOCKSCREEN_GID")


def export(env):
    """Set the four variables in env. Idempotent. Any UID/GID already in env is overwritten."""
    allowed_uid, allowed_gid = allowed(env)
    env["UID"] = str(os.getuid())
    env["GID"] = str(os.getgid())
    env["DOCKSCREEN_UID"] = str(allowed_uid)
    env["DOCKSCREEN_GID"] = str(allowed_gid)

