"""Mechanical fixes for policy problems, for `dcompose fix`.

fix_config removes or replaces only what has a safe automatic fix; checking
the result with policy.check_config reports what is left.
"""

import copy
import os

from dcompose import policy

# What fix puts into `user`: the allowed ids come from the environment (see ids.py), never from a literal.
USER_TEMPLATE = "${DCOMPOSE_UID}:${DCOMPOSE_GID}"

# Keys whose removal is a safe fix.
REMOVABLE_SERVICE_KEYS = (
    "privileged", "cap_add", "devices", "device_cgroup_rules", "gpus", "cgroup_parent", "external_links",
    "runtime", *policy.NAMESPACE_KEYS,
)


def fix_config(config, ctx):
    """Return a copy of config with the mechanically fixable problems removed.

    Fixable: user/group, privileges, host namespaces, and bind mount sources
    outside the project, which become placeholder paths for the user to edit.
    Unknown keys, volumes, networks, secrets, build contexts and env files have
    no safe automatic fix; they stay and are reported by check_config on the result.
    """
    fixed = copy.deepcopy(config)
    allowed_gids = policy.allowed_ids(ctx.gid)
    for service in fixed.get("services", {}).values():
        if policy.check_user(service.get("user"), ctx):
            service["user"] = USER_TEMPLATE
        service["group_add"] = [g for g in service.get("group_add", []) if policy.parse_id(g) in allowed_gids]
        if not service["group_add"]:
            del service["group_add"]
        if policy.check_security_opt(service.get("security_opt"), ctx):
            service["security_opt"] = ["no-new-privileges:true"]
        if policy.check_cap_drop(service.get("cap_drop"), ctx):
            service["cap_drop"] = ["ALL"]
        for key in REMOVABLE_SERVICE_KEYS:
            service.pop(key, None)
        if "volumes_from" in service:
            service["volumes_from"] = [
                v for v in service["volumes_from"] if not str(v).startswith("container:")]
            if not service["volumes_from"]:
                del service["volumes_from"]
        if "volumes" in service:
            service["volumes"] = [fix_mount(m, ctx) for m in service["volumes"]]
    return fixed


def resolve_user_template(config, ctx):
    """Copy of config with USER_TEMPLATE replaced by the ids it should resolve to, for re-checking."""
    resolved = copy.deepcopy(config)
    for service in resolved.get("services", {}).values():
        if service.get("user") == USER_TEMPLATE:
            service["user"] = f"{ctx.uid}:{ctx.gid}"
    return resolved


def fix_mount(mount, ctx):
    if mount.get("type") != "bind" or policy.is_inside_any(mount["source"], ctx.mount_roots):
        return mount
    return {**mount, "source": placeholder_source(mount["source"], ctx.project_dir)}


def placeholder_source(source, project_dir):
    """Relative, upper-case stand-in for a bad source: /etc becomes ./ETC.

    The upper case keeps it from naming the same directory as a real
    lower-case one, and marks it as something to edit.
    """
    relative = os.path.relpath(source, project_dir)
    if relative.startswith(os.pardir):
        relative = source.lstrip(os.sep)
    return "./" + relative.replace(os.sep, "_").upper()
