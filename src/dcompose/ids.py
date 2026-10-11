"""The uid/gid compose files see, and the ids the policy accepts.

dcompose exports two pairs of variables for compose files to interpolate:
  UID, GID                  the real current user, always
  DCOMPOSE_UID/GID          the ids containers are allowed to run as: the
                            values already set in the environment, else the
                            real ones

Setting DCOMPOSE_UID/GID turns the rule from "run as me" into "run as exactly
this id": the real user is then refused unless it is the same id. `nobody` is
accepted in either case (see policy.check_user).
"""

import os


def allowed(env):
    """(uid, gid) that containers may run as."""
    return (
        pick(env, "DCOMPOSE_UID", os.getuid()),
        pick(env, "DCOMPOSE_GID", os.getgid()),
    )


def pick(env, name, default):
    value = env.get(name)
    if not value:
        return default
    if not value.isdigit():
        raise ValueError(f"{name}={value!r} is not a numeric id")
    return int(value)


def export(env):
    """Set the four variables in env. Idempotent. Any UID/GID already in env is overwritten."""
    allowed_uid, allowed_gid = allowed(env)
    env["UID"] = str(os.getuid())
    env["GID"] = str(os.getgid())
    env["DCOMPOSE_UID"] = str(allowed_uid)
    env["DCOMPOSE_GID"] = str(allowed_gid)

