"""Mechanical fixes for policy problems, for `dockscreen fix`.

fix_config removes or replaces only what has a safe automatic fix; checking
the result with policy.check_config reports what is left.
"""

import copy
import os

from dockscreen import ids, policy

# What fix puts into `user`: the caller's own ids, which dockscreen exports (ids.py) and allows only with
# --allow-me. A literal would only fit the person who ran harden.
USER_TEMPLATE = "${UID}:${GID}"

# Keys whose removal is a safe fix.
REMOVABLE_SERVICE_KEYS = (*policy.FORBIDDEN_KEYS, "runtime", *policy.NAMESPACE_KEYS)


def fix_config(config, ctx):
    """Return a copy of config with the mechanically fixable problems removed.

    Fixable: user/group, privileges, host namespaces, and bind mount sources
    outside the project, which become placeholder paths for the user to edit.
    Unknown keys, volumes, networks, secrets, build contexts and env files have
    no safe automatic fix; they stay and are reported by check_config on the result.
    """
    fixed = copy.deepcopy(config)
    for name, service in fixed.get("services", {}).items():
        service_ctx = ctx.for_service(name, service)._replace(mounts=policy.has_host_mounts(service))
        vetted = name in ctx.vetted and not service.get("user")
        if not vetted and policy.check_user(service.get("user"), service_ctx):
            service["user"] = USER_TEMPLATE
        service["group_add"] = [
            g for g in service.get("group_add", []) if not policy.check_group_add([g], service_ctx)]
        if not service["group_add"]:
            del service["group_add"]
        if policy.check_security_opt(service.get("security_opt"), service_ctx):
            service["security_opt"] = [policy.SECURITY_OPT]
        if policy.check_cap_drop(service.get("cap_drop"), ctx):
            service["cap_drop"] = [policy.CAP_DROP]
        for key in REMOVABLE_SERVICE_KEYS:
            service.pop(key, None)
        if "volumes_from" in service:
            service["volumes_from"] = [
                v for v in service["volumes_from"] if not str(v).startswith("container:")]
            if not service["volumes_from"]:
                del service["volumes_from"]
        if "volumes" in service:
            service["volumes"] = [fix_mount(m, service_ctx) for m in service["volumes"]]
    return fixed


def resolve_user_template(config, ctx):
    """Copy of config with USER_TEMPLATE replaced by the ids it should resolve to, for re-checking."""
    resolved = copy.deepcopy(config)
    for service in resolved.get("services", {}).values():
        if service.get("user") == USER_TEMPLATE:
            service["user"] = ids.format_user(ctx.ids.me)
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
