"""Defaults dcompose adds to every service before running it.

A project does not have to set these itself: a service without `cap_drop: [ALL]`
or `no-new-privileges` gets them. A project cannot weaken them, because adding
`cap_add` or `no-new-privileges:false` is still refused by the policy. The
additions are reported by `audit` and written out by `harden`.
"""

import copy
import json
from typing import NamedTuple

from dcompose import policy

CAP_DROP = "ALL"
SECURITY_OPT = "no-new-privileges:true"


class Addition(NamedTuple):
    service: str
    key: str
    value: str   # the entry that is appended to the key's list
    reason: str  # why it is needed


def apply(config):
    """(config with the defaults added, the list of additions); the input is left alone."""
    hardened = copy.deepcopy(config)
    additions = []
    for name, service in (hardened.get("services") or {}).items():
        if policy.check_cap_drop(service.get("cap_drop"), None):
            reason = "is not set" if not service.get("cap_drop") else f"does not include {CAP_DROP}"
            service["cap_drop"] = [*(service.get("cap_drop") or []), CAP_DROP]
            additions.append(Addition(name, "cap_drop", CAP_DROP, reason))
        if not any(str(o) in policy.NO_NEW_PRIVILEGES for o in service.get("security_opt") or []):
            reason = "is not set" if not service.get("security_opt") else "does not include no-new-privileges"
            service["security_opt"] = [*(service.get("security_opt") or []), SECURITY_OPT]
            additions.append(Addition(name, "security_opt", SECURITY_OPT, reason))
    return hardened, additions


def describe(additions):
    """One line per addition: what was missing and what dcompose fills in."""
    return [
        f"service {a.service}: {a.key} {a.reason}; dcompose adds {a.key}: {json.dumps([a.value])}"
        for a in additions
    ]


def defaults_note():
    """One general sentence for generated files, instead of a line per service."""
    return (f'dcompose also adds cap_drop: ["{CAP_DROP}"] and security_opt: ["{SECURITY_OPT}"] to every '
            "service that lacks them, and runs a service that sets no user as nobody when its image would "
            "run as root, so these are not repeated here")


def summary(additions):
    """One line for a run: which services got which defaults."""
    services = {}
    for a in additions:
        services.setdefault(a.service, []).append(a.key)
    return "hardening defaults added: " + ", ".join(f"{s} ({', '.join(k)})" for s, k in services.items())
