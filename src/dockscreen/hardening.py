"""Defaults dockscreen adds to every service before running it.

A project does not have to set these itself: a service without `cap_drop: [ALL]`
or `no-new-privileges` gets them, and the names root and nobody in `user:` are resolved
to ids. A project cannot weaken them, because adding
`cap_add` or `no-new-privileges:false` is still refused by the policy. The
additions are reported by `audit` and written out by `harden`.
"""

import copy
import json
from typing import NamedTuple

from dockscreen import policy

CAP_DROP = "ALL"
SECURITY_OPT = "no-new-privileges:true"


# The only names a compose file may use: resolved to ids here, so the generated file never asks the
# image to resolve a name. Every other name is left for the policy to refuse.
USER_NAMES = {"root": 0, "nobody": 65534}
GROUP_NAMES = {"root": 0, "nobody": 65534, "nogroup": 65534}


class Addition(NamedTuple):
    service: str
    key: str
    message: str  # what was missing or a name, and what dockscreen does about it


def apply(config):
    """(config with the defaults added and user names resolved, the list of additions)."""
    hardened = copy.deepcopy(config)
    additions = []
    for name, service in (hardened.get("services") or {}).items():
        additions += resolve_user_names(name, service)
        if policy.check_cap_drop(service.get("cap_drop"), None):
            reason = "is not set" if not service.get("cap_drop") else f"does not include {CAP_DROP}"
            service["cap_drop"] = [*(service.get("cap_drop") or []), CAP_DROP]
            additions.append(Addition(
                name, "cap_drop", f"cap_drop {reason}; dockscreen adds cap_drop: {json.dumps([CAP_DROP])}"))
        if not any(str(o) in policy.NO_NEW_PRIVILEGES for o in service.get("security_opt") or []):
            reason = "is not set" if not service.get("security_opt") else "does not include no-new-privileges"
            service["security_opt"] = [*(service.get("security_opt") or []), SECURITY_OPT]
            additions.append(Addition(
                name, "security_opt",
                f"security_opt {reason}; dockscreen adds security_opt: {json.dumps([SECURITY_OPT])}"))
    return hardened, additions


def resolve_user_names(name, service):
    """Replace the names root and nobody (and nogroup) in the service's user by ids."""
    spec = service.get("user")
    if not spec:
        return []
    user, has_group, group = str(spec).partition(":")
    if user not in USER_NAMES and group not in GROUP_NAMES:
        return []
    uid = str(USER_NAMES.get(user, user))
    # a bare name has the group of the same id, as the account does in every image that has one
    gid = str(GROUP_NAMES.get(group, group)) if has_group else uid
    resolved = f"{uid}:{gid}"
    service["user"] = resolved
    message = f"user {spec!r} is a name; dockscreen resolves it to {json.dumps(resolved)}"
    return [Addition(name, "user", message)]


def describe(additions):
    """One line per addition: what was missing and what dockscreen fills in."""
    return [f"service {a.service}: {a.message}" for a in additions]


def defaults_note():
    """One general sentence for generated files, instead of a line per service."""
    return (f'dockscreen also adds cap_drop: ["{CAP_DROP}"] and security_opt: ["{SECURITY_OPT}"] to every '
            "service that lacks them, resolves the user names nobody and root to ids, and runs a service "
            "that sets no user as nobody when its image would run as root or it has bind mounts, "
            "so these are not repeated here")


def summary(additions):
    """One line for a run: which services got which defaults."""
    services = {}
    for a in additions:
        services.setdefault(a.service, []).append(a.key)
    return "hardening defaults added: " + ", ".join(f"{s} ({', '.join(k)})" for s, k in services.items())
