"""Defaults dockscreen adds to every service before running it.

A project does not have to set these itself: a service without `cap_drop: [ALL]`
or `no-new-privileges` gets them. Names in `user:`, hook users and `group_add` are resolved
to ids on this host, so the generated file never asks the image to resolve a name; the policy
then checks the ids, and refuses a name that does not exist here. A project cannot weaken them, because adding
`cap_add` or `no-new-privileges:false` is still refused by the policy. The
additions are reported by `audit` and written out by `harden`.
"""

import copy
import json
from typing import NamedTuple

from dockscreen import ids, policy
from dockscreen.policy import CAP_DROP, SECURITY_OPT

class Addition(NamedTuple):
    service: str
    key: str
    message: str  # what was missing or a name, and what dockscreen does about it


def apply(config, accounts):
    """(config with the defaults added and user names resolved, the list of additions).

    accounts: the users and groups to resolve names with (hostusers.HostAccounts).
    """
    hardened = copy.deepcopy(config)
    additions = []
    for name, service in (hardened.get("services") or {}).items():
        additions += resolve_user_names(name, service, accounts)
        if policy.check_cap_drop(service.get("cap_drop"), None):
            reason = "is not set" if not service.get("cap_drop") else f"does not include {CAP_DROP}"
            service["cap_drop"] = [*(service.get("cap_drop") or []), CAP_DROP]
            additions.append(Addition(
                name, "cap_drop", f"cap_drop {reason}; dockscreen adds cap_drop: {json.dumps([CAP_DROP])}"))
        if not policy.has_no_new_privileges(service.get("security_opt")):
            reason = "is not set" if not service.get("security_opt") else "does not include no-new-privileges"
            service["security_opt"] = [*(service.get("security_opt") or []), SECURITY_OPT]
            additions.append(Addition(
                name, "security_opt",
                f"security_opt {reason}; dockscreen adds security_opt: {json.dumps([SECURITY_OPT])}"))
    return hardened, additions


def resolve_user_names(name, service, accounts):
    """Replace names in the service's user, hook users and group_add by their ids on this host."""
    additions = []
    if service.get("user"):
        resolved = resolve_spec(service["user"], accounts)
        if resolved != service["user"]:
            additions.append(Addition(name, "user", resolved_message("user", service["user"], resolved)))
            service["user"] = resolved
    for key in ("post_start", "pre_stop"):
        for hook in service.get(key) or []:
            if isinstance(hook, dict) and hook.get("user"):
                resolved = resolve_spec(hook["user"], accounts)
                if resolved != hook["user"]:
                    message = resolved_message(f"{key} user", hook["user"], resolved)
                    additions.append(Addition(name, key, message))
                    hook["user"] = resolved
    if service.get("group_add"):
        resolved = [resolve_group(g, accounts) for g in service["group_add"]]
        if resolved != service["group_add"]:
            additions.append(Addition(name, "group_add", resolved_message(
                "group_add", service["group_add"], resolved)))
            service["group_add"] = resolved
    return additions


def resolve_spec(spec, accounts):
    """`name` becomes that account's `uid:gid`, a group name its gid; numbers and unknown names stay.

    A uid alone stays alone: the policy refuses it rather than guess a group.
    """
    user, has_group, group = str(spec).partition(":")
    account = accounts.user(user) if user and ids.parse_id(user) is None else None
    uid = str(account[0]) if account else user
    if has_group:
        gid = resolve_group(group, accounts)
    elif account:
        gid = str(account[1])  # a name brings its primary group, as with --as
    else:
        return str(spec) if uid == user else uid
    return f"{uid}:{gid}"


def resolve_group(group, accounts):
    if ids.parse_id(group) is not None:
        return group
    gid = accounts.group(str(group))
    return group if gid is None else str(gid)


def resolved_message(what, before, after):
    return (f"{what} {json.dumps(before)} names an account on this host; "
            f"dockscreen resolves it to {json.dumps(after)}")


def describe(additions):
    """One line per addition: what was missing and what dockscreen fills in."""
    return [f"service {a.service}: {a.message}" for a in additions]


def defaults_note():
    """One general sentence for generated files, instead of a line per service."""
    return (f'dockscreen also adds cap_drop: ["{CAP_DROP}"] and security_opt: ["{SECURITY_OPT}"] to every '
            "service that lacks them, resolves user and group names to ids on this host, and runs a "
            "service that sets no user as the configured default user when its image would run as root, "
            "so these are not repeated here")


def summary(additions):
    """One line for a run: which services got which defaults."""
    services = {}
    for a in additions:
        services.setdefault(a.service, []).append(a.key)
    return "hardening defaults added: " + ", ".join(f"{s} ({', '.join(k)})" for s, k in services.items())
