"""Security policy over a resolved compose config (`docker compose config --format json`).

The policy is an allowlist and fails closed: a key that is not listed below is
refused, so a Compose feature added tomorrow is denied until someone has
reviewed it. Every structure that can carry unlisted keys (service, mount,
build, volume, network, secret, deploy, develop, hooks) has its own list. Keys
beginning with `x-` are extension fields that Compose itself ignores; they pass
everywhere except in `build` (see check_build).

A key is listed either as harmless (any value is fine) or as checked (it has an
entry in SERVICE_CHECKS that validates the value). Checks take the value and a
Context, whose uid/gid are the ids containers may run as (ids.allowed), which
need not be the real user's.

Every check returns a list of human-readable problems; an empty list means the
config is acceptable. Nothing here touches docker, only the filesystem for
realpath resolution.
"""

import os
from typing import NamedTuple

NOBODY = 65534

NO_NEW_PRIVILEGES = frozenset({"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"})
# A tuple: the order of the checks is the order of the problems reported.
NAMESPACE_KEYS = ("pid", "ipc", "uts", "userns_mode", "cgroup", "network_mode")

# Volume driver_opts types that stay on this host's filesystem or memory.
LOCAL_VOLUME_TYPES = frozenset({"", "none", "tmpfs"})
NETWORK_DRIVERS = frozenset({None, "", "bridge", "none"})
NETWORK_DRIVER_OPTS = frozenset({"com.docker.network.driver.mtu"})

# Service keys whose value cannot widen access beyond the container. Network
# exposure (ports, extra_hosts, dns, logging) is deliberately not restricted.
HARMLESS_SERVICE_KEYS = frozenset({
    "annotations", "attach", "blkio_config", "command", "configs", "container_name", "cpu_count",
    "cpu_percent", "cpu_period", "cpu_quota", "cpu_rt_period", "cpu_rt_runtime", "cpu_shares", "cpus",
    "cpuset", "depends_on", "dns", "dns_opt", "dns_search", "domainname", "entrypoint", "environment",
    "expose", "extra_hosts", "healthcheck", "hostname", "image", "init", "isolation", "labels", "links",
    "logging", "mac_address", "mem_limit", "mem_reservation", "mem_swappiness", "memswap_limit",
    "networks", "oom_kill_disable", "oom_score_adj", "pids_limit", "platform", "ports", "profiles",
    "pull_policy", "read_only", "restart", "scale", "secrets", "shm_size", "stdin_open",
    "stop_grace_period", "stop_signal", "storage_opt", "sysctls", "tmpfs", "tty", "ulimits",
    "working_dir",
})
# Keys that must be present: a missing value is a problem in itself.
REQUIRED_SERVICE_KEYS = frozenset({"user", "security_opt", "cap_drop"})

TOP_LEVEL_KEYS = frozenset({"name", "services", "volumes", "networks", "secrets", "configs", "version"})
VOLUME_KEYS = frozenset({"name", "driver", "driver_opts", "external", "labels"})
NETWORK_KEYS = frozenset({
    "name", "driver", "driver_opts", "external", "internal", "attachable", "enable_ipv4", "enable_ipv6",
    "ipam", "labels",
})
IPAM_KEYS = frozenset({"driver", "config", "options"})
SECRET_KEYS = frozenset({"name", "file", "environment", "content", "external", "labels"})
MOUNT_KEYS = frozenset({
    "type", "source", "target", "read_only", "consistency", "bind", "volume", "tmpfs", "image",
})
MOUNT_SUBKEYS = {
    "bind": frozenset({"propagation", "create_host_path", "selinux", "recursive"}),
    "volume": frozenset({"nocopy", "subpath"}),
    "tmpfs": frozenset({"size", "mode"}),
    "image": frozenset({"subpath"}),
}
BUILD_HARMLESS_KEYS = frozenset({
    "args", "dockerfile_inline", "extra_hosts", "isolation", "labels", "no_cache", "platforms",
    "provenance", "pull", "sbom", "secrets", "shm_size", "tags", "target", "ulimits",
})
BUILD_KEYS = BUILD_HARMLESS_KEYS | {
    "context", "dockerfile", "additional_contexts", "network", "privileged", "ssh",
}
DEPLOY_KEYS = frozenset({
    "mode", "replicas", "labels", "update_config", "rollback_config", "restart_policy", "resources",
    "placement", "endpoint_mode",
})
DEVELOP_KEYS = frozenset({"watch"})
WATCH_KEYS = frozenset({"path", "action", "target", "ignore", "include", "initial_sync"})
# Not sync+exec: it runs a command in the container.
WATCH_ACTIONS = frozenset({"sync", "rebuild", "sync+restart"})
HOOK_KEYS = frozenset({"command", "user", "privileged", "working_dir", "environment"})


class Context(NamedTuple):
    """What the policy allows: the project, the ids containers may run as, extra mount sources."""
    project_dir: str
    uid: int
    gid: int
    extra_dirs: tuple = ()  # DOCKSCREEN_DIRS
    # Services whose unset `user` is acceptable because their image was looked at and would
    # run as an acceptable user (see composeimages). Only dockscreen sets this, never the project.
    vetted: frozenset = frozenset()

    @property
    def mount_roots(self):
        return (self.project_dir, *self.extra_dirs)


def check_config(config, ctx):
    project = config.get("name")
    problems = unknown_keys(config, TOP_LEVEL_KEYS, "top-level key")
    for name, service in (config.get("services") or {}).items():
        problems += [f"service {name}: {p}" for p in check_service(service or {}, ctx, name in ctx.vetted)]
    for key, volume in (config.get("volumes") or {}).items():
        problems += [f"volume {key}: {p}" for p in check_volume(key, volume, project, ctx)]
    for key, network in (config.get("networks") or {}).items():
        problems += [f"network {key}: {p}" for p in check_network(key, network, project, ctx)]
    return problems + check_file_sources(config, ctx)


def check_build_config(config, ctx):
    """The subset of the policy that applies to `build`: what building can reach on the host.

    Runtime hardening (user, capabilities, mounts) is irrelevant until containers run.
    """
    problems = []
    for name, service in (config.get("services") or {}).items():
        if service and "build" in service:
            problems += [f"service {name}: {p}" for p in check_build(service["build"], ctx)]
    return problems + check_file_sources(config, ctx)  # build secrets refer to these


def unknown_keys(mapping, allowed, what, extensions=True):
    """Keys not on the list. `x-` extension fields pass unless extensions is False."""
    return [
        f"{what} {key!r} is not on the allow list"
        for key in mapping
        if key not in allowed and not (extensions and str(key).startswith("x-"))
    ]


def check_service(service, ctx, vetted=False):
    problems = unknown_keys(service, HARMLESS_SERVICE_KEYS | SERVICE_CHECKS.keys(), "key")
    for key, check in SERVICE_CHECKS.items():
        if key == "user" and vetted:
            continue
        if key in REQUIRED_SERVICE_KEYS or key in service:
            problems += check(service.get(key), ctx)
    return problems


# --- users and privileges -------------------------------------------------

def allowed_ids(own):
    return {own, NOBODY}


def parse_id(value):
    """The numeric id, or None. Names are not accepted: the image's /etc/passwd resolves them,
    and a crafted image can map any name to uid 0."""
    text = str(value)
    return int(text) if text.isascii() and text.isdigit() else None


def check_id(kind, value, allowed):
    number = parse_id(value)
    if number is None:
        return [(f"{kind} {value!r} is not numeric; use an id (names are resolved by the image, which can "
                 "map them to root; only nobody and root are resolved by dockscreen, in `user:`)")]
    if number not in allowed:
        return [f"{kind} {value!r} is neither the allowed id nor {NOBODY} (nobody)"]
    return []


def check_user(value, ctx):
    if not value:
        return ["user is not set, the image default may be root"]

    # A bare uid gets gid 0 when the image has no passwd entry for it.
    uid_part, has_gid, gid_part = str(value).partition(":")
    problems = check_id("user", uid_part, allowed_ids(ctx.uid))
    if has_gid:
        problems += check_id("group", gid_part, allowed_ids(ctx.gid))
    else:
        problems.append(f"user {value!r} has no group, use uid:gid")
    return problems


def check_group_add(value, ctx):
    problems = []
    for extra in value or []:
        problems += check_id("group_add", extra, allowed_ids(ctx.gid))
    return problems


def check_security_opt(value, ctx):
    options = [str(o) for o in value or []]
    problems = [f"security_opt {o!r} is not allowed" for o in options if o not in NO_NEW_PRIVILEGES]
    if not any(o in NO_NEW_PRIVILEGES for o in options):
        problems.append("security_opt must include no-new-privileges:true")
    return problems


def check_cap_drop(value, ctx):
    if "ALL" not in {str(c).upper() for c in value or []}:
        return ["cap_drop must include ALL"]
    return []


def forbidden(key):
    """Checker for keys that are refused whenever they carry a value."""
    return lambda value, ctx: [f"{key} is not allowed"] if value else []


def check_namespace(key):
    def check(value, ctx):
        text = str(value)
        if text == "host" or text.startswith("container:"):
            return [f"{key}: {text} shares a namespace outside the project"]
        return []
    return check


def check_runtime(value, ctx):
    return [] if value in (None, "", "runc") else [f"runtime {value!r} is not allowed"]


# --- mounts and files -----------------------------------------------------

def check_volumes_from(value, ctx):
    return [
        f"volumes_from {source!r} reaches a container outside the project"
        for source in value or []
        if str(source).startswith("container:")
    ]


def check_mounts(value, ctx):
    problems = []
    for mount in value or []:
        problems += unknown_keys(mount, MOUNT_KEYS, "mount key")
        for sub, allowed in MOUNT_SUBKEYS.items():
            problems += unknown_keys(mount.get(sub) or {}, allowed, f"mount {sub} key")
        kind = mount.get("type")
        if kind == "bind":
            if not is_inside_any(mount.get("source", ""), ctx.mount_roots):
                problems.append(
                    f"bind mount {mount.get('source')!r} is outside {roots_text(ctx.mount_roots)}")
        elif kind not in ("volume", "tmpfs", "image"):
            problems.append(f"mount type {kind!r} is not allowed")
    return problems


def check_build(value, ctx):
    build = {"context": value} if isinstance(value, str) else value or {}
    # No extension fields here: `docker buildx bake` reads `x-bake` from compose files, and it can
    # set outputs and cache destinations on the host. Compose's own build does not pass it on.
    problems = unknown_keys(build, BUILD_KEYS, "build key", extensions=False)
    context = build.get("context")
    if context and is_host_path(context):
        dockerfile = build.get("dockerfile")
        if not is_inside(context, ctx.project_dir):
            problems.append(f"build context {context!r} is outside {ctx.project_dir}")
        elif dockerfile and not is_inside(os.path.join(context, dockerfile), ctx.project_dir):
            problems.append(f"build dockerfile {dockerfile!r} is outside {ctx.project_dir}")
    for name, source in (build.get("additional_contexts") or {}).items():
        if is_host_path(source) and not is_inside(str(source), ctx.project_dir):
            problems.append(
                f"build additional_contexts {name!r}: {source!r} is outside {ctx.project_dir}")
    if build.get("network") not in (None, "", "none"):
        problems.append(f"build network {build['network']!r} is not allowed")
    if build.get("privileged"):
        problems.append("build privileged is not allowed")
    if build.get("ssh"):
        problems.append("build ssh forwards your SSH agent and is not allowed")
    return problems


def is_host_path(source):
    """Whether a build source is a path on this host, not a URL (`git://`, `docker-image://`) or a service."""
    text = str(source)
    return "://" not in text and not text.startswith("service:")


def check_host_files(key):
    """env_file and label_file only show up in the config when it is loaded without env resolution."""
    def check(value, ctx):
        problems = []
        for entry in [value] if isinstance(value, (str, dict)) else value or []:
            path = entry.get("path") if isinstance(entry, dict) else entry
            if path and not is_inside(path, ctx.project_dir):
                problems.append(f"{key} {path!r} is outside {ctx.project_dir}")
        return problems
    return check


# --- other structured keys ------------------------------------------------

def check_develop(value, ctx):
    value = value or {}
    problems = unknown_keys(value, DEVELOP_KEYS, "develop key")
    for rule in value.get("watch") or []:
        problems += unknown_keys(rule, WATCH_KEYS, "develop.watch key")
        if rule.get("action") not in WATCH_ACTIONS:
            problems.append(f"develop.watch action {rule.get('action')!r} is not allowed")
        if not is_inside(rule.get("path", ""), ctx.project_dir):
            problems.append(f"develop.watch path {rule.get('path')!r} is outside {ctx.project_dir}")
    return problems


def check_deploy(value, ctx):
    value = value or {}
    problems = unknown_keys(value, DEPLOY_KEYS, "deploy key")
    reservations = (value.get("resources") or {}).get("reservations") or {}
    for key in ("devices", "generic_resources"):
        if reservations.get(key):
            problems.append(
                f"deploy.resources.reservations.{key} grants host devices and is not allowed")
    return problems


def check_hooks(key):
    """post_start and pre_stop run commands in the container; they must not escalate."""
    def check(value, ctx):
        problems = []
        for hook in value or []:
            problems += unknown_keys(hook, HOOK_KEYS, f"{key} key")
            if hook.get("privileged"):
                problems.append(f"{key} privileged is not allowed")
            if hook.get("user") is not None:
                problems += check_user(hook["user"], ctx)
        return problems
    return check


SERVICE_CHECKS = {
    "user": check_user,
    "group_add": check_group_add,
    "privileged": forbidden("privileged"),
    "cap_add": forbidden("cap_add"),
    "cap_drop": check_cap_drop,
    "security_opt": check_security_opt,
    "devices": forbidden("devices"),
    "device_cgroup_rules": forbidden("device_cgroup_rules"),
    "gpus": forbidden("gpus"),
    "cgroup_parent": forbidden("cgroup_parent"),
    "external_links": forbidden("external_links"),
    "runtime": check_runtime,
    **{key: check_namespace(key) for key in NAMESPACE_KEYS},
    "volumes": check_mounts,
    "volumes_from": check_volumes_from,
    "build": check_build,
    "env_file": check_host_files("env_file"),
    "label_file": check_host_files("label_file"),
    "develop": check_develop,
    "deploy": check_deploy,
    "post_start": check_hooks("post_start"),
    "pre_stop": check_hooks("pre_stop"),
}


# --- top-level volumes, networks, secrets ---------------------------------

def check_scope(key, item, project):
    """Named volumes and networks must belong to this project, not to another one."""
    if item.get("external"):
        return ["external resources are not allowed, they may belong to another project"]
    if not project:
        return ["config has no project name"]
    expected = f"{project}_{key}"
    if item.get("name") != expected:
        return [f"name {item.get('name')!r} is not the project-scoped {expected!r}"]
    return []


def check_volume(key, volume, project, ctx):
    volume = volume or {}
    problems = [*unknown_keys(volume, VOLUME_KEYS, "key"), *check_scope(key, volume, project)]
    driver = volume.get("driver")
    if driver not in (None, "", "local"):
        return [*problems, f"driver {driver!r} is not allowed"]
    return [*problems, *check_driver_opts(volume.get("driver_opts") or {}, ctx)]


def check_driver_opts(opts, ctx):
    # The local driver can turn a named volume into a bind mount or a network mount.
    kind = opts.get("type", "")
    if kind not in LOCAL_VOLUME_TYPES:
        return [f"driver_opts type {kind!r} is not allowed"]
    device = opts.get("device", "")
    if not device or kind == "tmpfs":
        return []
    if not os.path.isabs(device):
        return [f"device {device!r} must be an absolute path"]
    if not is_inside_any(device, ctx.mount_roots):
        return [f"device {device!r} is outside {roots_text(ctx.mount_roots)}"]
    return []


def check_network(key, network, project, ctx):
    network = network or {}
    problems = [*unknown_keys(network, NETWORK_KEYS, "key"), *check_scope(key, network, project)]
    if network.get("driver") not in NETWORK_DRIVERS:
        problems.append(f"driver {network.get('driver')!r} is not allowed")
    problems += unknown_keys(network.get("driver_opts") or {}, NETWORK_DRIVER_OPTS, "driver_opts key")
    ipam = network.get("ipam") or {}
    problems += unknown_keys(ipam, IPAM_KEYS, "ipam key")
    if ipam.get("driver") not in (None, "", "default"):
        problems.append(f"ipam driver {ipam['driver']!r} is not allowed")
    return problems


def check_file_sources(config, ctx):
    """Secrets and configs: both building and running read their files from the host."""
    problems = []
    for kind in ("secrets", "configs"):
        for key, item in (config.get(kind) or {}).items():
            problems += [f"{kind} {key}: {p}" for p in check_file_source(item, ctx)]
    return problems


def check_file_source(item, ctx):
    item = item or {}
    problems = unknown_keys(item, SECRET_KEYS, "key")
    if item.get("external"):
        problems.append("external resources are not allowed, they may belong to another project")
    if item.get("environment"):
        problems.append(
            f"environment {item['environment']!r} copies a variable from dockscreen's environment")
    source = item.get("file")
    if source and not is_inside(source, ctx.project_dir):
        problems.append(f"file {source!r} is outside {ctx.project_dir}")
    return problems


# --- paths ----------------------------------------------------------------

def roots_text(mount_roots):
    project_dir, *extra = mount_roots
    return f"{project_dir}" + (" and DOCKSCREEN_DIRS" if extra else "")


def is_inside_any(path, roots):
    return any(is_inside(path, root) for root in roots)


def is_inside(path, root):
    """Whether path, resolved relative to root and through symlinks, is root or below it."""
    real_root = os.path.realpath(root)
    real = os.path.realpath(os.path.join(real_root, path))
    return os.path.commonpath([real_root, real]) == real_root
