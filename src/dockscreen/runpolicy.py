"""The compose policy applied to a container that a `docker run` command line created.

The command line is trusted, so `docker run` does not refuse what it asks for. `audit` points it out
anyway: the inspected container is read back into the compose service keys it corresponds to, and
policy.check_service judges them as it would judge a project's, with the same wording. Bind mounts
are judged against the current directory, where a project would have its own.

A user the command line chooses is judged by the id rules too, as if a project had chosen it.
"""

from dockscreen import policy

# Inspected HostConfig fields that hold what the compose key of the same meaning holds.
FIELDS = {
    "Privileged": "privileged",
    "CapAdd": "cap_add",
    "CapDrop": "cap_drop",
    "SecurityOpt": "security_opt",
    "Devices": "devices",
    "DeviceCgroupRules": "device_cgroup_rules",
    "DeviceRequests": "gpus",
    "CgroupParent": "cgroup_parent",
    "Runtime": "runtime",
    "GroupAdd": "group_add",
    "PidMode": "pid",
    "IpcMode": "ipc",
    "UTSMode": "uts",
    "UsernsMode": "userns_mode",
    "CgroupnsMode": "cgroup",
    "NetworkMode": "network_mode",
}


def findings(info, explicit_user, ctx):
    """What the policy would refuse in a project that asked for what this container has.

    info: the container as inspected; explicit_user: the command line chose the user;
    ctx: the policy.Context, with the current directory as the project directory.
    """
    return policy.check_service(service_of(info, explicit_user), ctx, vetted=not explicit_user)


def service_of(info, explicit_user):
    """The compose service keys that the inspected container corresponds to."""
    host = info.get("HostConfig") or {}
    service = {key: host[field] for field, key in FIELDS.items() if host.get(field)}
    service.setdefault("cap_drop", [])
    service.setdefault("security_opt", [])
    if host.get("VolumesFrom"):
        service["volumes_from"] = [f"container:{source}" for source in host["VolumesFrom"]]
    if volumes := mounts(info):
        service["volumes"] = volumes
    if explicit_user:
        service["user"] = info["Config"].get("User") or ""
    return service


def mounts(info):
    """The container's mounts as compose writes them (type, source, target), each source once.

    -v puts a bind mount in HostConfig.Binds, --mount in HostConfig.Mounts; inspect also lists them all
    in Mounts.
    """
    host = info.get("HostConfig") or {}
    found = []
    for bind in host.get("Binds") or []:
        source, _, rest = str(bind).partition(":")
        if source.startswith("/"):
            found.append({"type": "bind", "source": source, "target": rest.partition(":")[0]})
    for mount in [*(host.get("Mounts") or []), *(info.get("Mounts") or [])]:
        kind = str(mount.get("Type") or "").lower()
        target = mount.get("Target") or mount.get("Destination") or ""
        found.append({"type": kind, "source": mount.get("Source") or "", "target": target})
    unique = {}
    for mount in found:
        unique.setdefault((mount["type"], mount["source"]), mount)
    return list(unique.values())
