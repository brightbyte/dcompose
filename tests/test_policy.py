import os

import pytest

from dcompose import policy

UID = os.getuid()
GID = os.getgid()
OWN = f"{UID}:{GID}"

# The disallowed-user cases assume the current user is neither root nor nobody.
pytestmark = pytest.mark.skipif(
    UID in (0, policy.NOBODY) or GID in (0, policy.NOBODY),
    reason="current user must be neither root nor nobody",
)


@pytest.fixture
def project(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "outside").mkdir()
    root = tmp_path / "project"
    root.mkdir()
    (root / "data").mkdir()
    os.symlink(tmp_path / "outside", root / "escape")
    return root


def service(**overrides):
    """A service that satisfies every requirement; tests override one thing at a time."""
    return {"user": OWN, "security_opt": ["no-new-privileges:true"], "cap_drop": ["ALL"], **overrides}


def check(project, config, extra_dirs=()):
    return policy.check_config({"name": "proj", **config}, str(project), UID, GID, extra_dirs)


def problems_for(project, **overrides):
    return check(project, {"services": {"web": service(**overrides)}})


def test_compliant_config_has_no_problems(project):
    config = {
        "services": {"web": service(
            image="x:1", ports=["80:80"], x_ignored=1, **{"x-extension": {"anything": 1}},
            volumes=[{"type": "bind", "source": str(project / "data"), "target": "/d",
                      "bind": {"create_host_path": True}},
                     {"type": "volume", "source": "data", "target": "/c"}],
            build={"context": str(project), "dockerfile": "Dockerfile", "args": {"A": "1"}},
            env_file=[{"path": str(project / ".env")}],
            networks={"default": None},
            deploy={"resources": {"limits": {"memory": "1g"}}},
            develop={"watch": [{"path": str(project / "src"), "action": "sync", "target": "/src"}]},
        )},
        "volumes": {"data": {"name": "proj_data", "driver": "local"}},
        "networks": {"default": {"name": "proj_default", "driver": "bridge"}},
        "secrets": {"s": {"file": str(project / "secret.txt")}},
        "x-top": 1,
    }
    config["services"]["web"].pop("x_ignored")
    assert check(project, config) == []


# --- allowlist ------------------------------------------------------------

def test_unknown_service_key_is_refused_and_extension_keys_are_not(project):
    assert problems_for(project, provider={"type": "x"}) == [
        "service web: key 'provider' is not on the allow list"]
    assert problems_for(project, use_api_socket=True) == [
        "service web: key 'use_api_socket' is not on the allow list"]
    assert problems_for(project, **{"x-anything": 1}) == []


def test_unknown_keys_are_refused_in_nested_structures(project):
    assert problems_for(project, volumes=[{"type": "volume", "source": "d", "target": "/d", "new": 1}])
    assert problems_for(project, volumes=[{"type": "bind", "source": str(project), "target": "/d",
                                           "bind": {"new": 1}}])
    assert problems_for(project, build={"context": str(project), "new": 1})
    assert problems_for(project, deploy={"new": 1})
    assert check(project, {"new_top_level": {}})
    assert check(project, {"volumes": {"v": {"name": "proj_v", "new": 1}}})
    assert check(project, {"networks": {"n": {"name": "proj_n", "new": 1}}})
    assert check(project, {"secrets": {"s": {"new": 1}}})


def test_every_checked_key_is_outside_the_harmless_list():
    assert not policy.HARMLESS_SERVICE_KEYS & policy.SERVICE_CHECKS.keys()
    assert set(policy.REQUIRED_SERVICE_KEYS) <= policy.SERVICE_CHECKS.keys()


# --- users ----------------------------------------------------------------

@pytest.mark.parametrize("user", [OWN, "65534:65534", f"{UID}:65534", f"{UID:08d}:{GID}"])
def test_allowed_users(project, user):
    assert problems_for(project, user=user) == []


@pytest.mark.parametrize("user", [
    None, "", "root", "0:0", str(UID), f"{UID}:0", f"0:{GID}", f"{UID + 1}:{GID}",
    "nobody", "nobody:nogroup", f"{UID}:nogroup", f"{UID}:{GID}x",  # names resolve through the image
])
def test_disallowed_users(project, user):
    assert problems_for(project, user=user)


def test_group_add_takes_numeric_allowed_ids_only(project):
    assert problems_for(project, group_add=[str(GID), 65534]) == []
    assert problems_for(project, group_add=["0"])
    assert problems_for(project, group_add=["nogroup"])


# --- privileges -----------------------------------------------------------

@pytest.mark.parametrize("override", [
    {"privileged": True},
    {"cap_add": ["SYS_ADMIN"]},
    {"devices": ["/dev/sda:/dev/sda"]},
    {"device_cgroup_rules": ["c *:* rwm"]},
    {"gpus": "all"},
    {"cgroup_parent": "/"},
    {"external_links": ["other:db"]},
    {"runtime": "nvidia"},
    {"pid": "host"},
    {"network_mode": "host"},
    {"ipc": "container:other"},
    {"volumes_from": ["container:other"]},
])
def test_privilege_escalation_is_refused(project, override):
    assert problems_for(project, **override)


def test_services_in_the_same_project_may_be_referenced(project):
    assert problems_for(project, volumes_from=["other:ro"], network_mode="service:other", runtime="runc") == []


@pytest.mark.parametrize("security_opt, ok", [
    (["no-new-privileges:true"], True),
    (["no-new-privileges=true"], True),
    (["no-new-privileges"], True),
    (["no-new-privileges:false"], False),
    ([], False),
    (None, False),
    (["no-new-privileges:true", "seccomp=unconfined"], False),
    (["apparmor=unconfined"], False),
])
def test_no_new_privileges_is_required(project, security_opt, ok):
    config = service()
    config.pop("security_opt")
    if security_opt is not None:
        config["security_opt"] = security_opt
    assert (check(project, {"services": {"web": config}}) == []) == ok


@pytest.mark.parametrize("cap_drop, ok", [(["ALL"], True), (["all"], True), (["ALL", "NET_RAW"], True),
                                          (["NET_RAW"], False), ([], False), (None, False)])
def test_cap_drop_all_is_required(project, cap_drop, ok):
    config = service()
    config.pop("cap_drop")
    if cap_drop is not None:
        config["cap_drop"] = cap_drop
    assert (check(project, {"services": {"web": config}}) == []) == ok


# --- mounts ---------------------------------------------------------------

def bind(source):
    return {"type": "bind", "source": str(source), "target": "/x"}


def test_bind_mount_outside_project_is_refused(project):
    assert problems_for(project, volumes=[bind("/var/run/docker.sock")])


def test_bind_mount_through_symlink_out_of_project_is_refused(project):
    # The path looks inside the project but its realpath is not.
    assert problems_for(project, volumes=[bind(project / "escape")])


def test_bind_mount_of_sibling_with_common_prefix_is_refused(project):
    assert problems_for(project, volumes=[bind(str(project) + "-other")])


def test_mounts_from_extra_dirs_are_allowed(project):
    outside = project.parent / "outside"
    config = {"services": {"web": service(volumes=[
        bind(outside), bind(outside / "deeper"), bind(project / "escape"),  # last: symlink into outside
    ])}}

    assert check(project, config, [str(outside)]) == []
    assert len(check(project, config)) == 3


def test_extra_dirs_do_not_allow_their_siblings_or_other_mounts(project):
    outside = project.parent / "outside"
    config = {"services": {"web": service(volumes=[bind(project.parent / "outside-other"), bind("/etc")])}}
    assert len(check(project, config, [str(outside)])) == 2


# --- build ----------------------------------------------------------------

def test_build_context_outside_project_is_refused(project):
    assert problems_for(project, build={"context": "/"}) == [
        f"service web: build context '/' is outside {project}"]


@pytest.mark.parametrize("build", [
    {"context": "{p}", "dockerfile": "../../etc/Dockerfile"},
    {"context": "{p}", "additional_contexts": {"lib": "/usr/lib"}},
    {"context": "{p}", "network": "host"},
    {"context": "{p}", "privileged": True},
    {"context": "{p}", "ssh": ["default"]},
    {"context": "{p}", "cache_to": ["type=local,dest=/tmp/x"]},
])
def test_unsafe_build_options_are_refused(project, build):
    build = {k: str(project) if v == "{p}" else v for k, v in build.items()}
    assert problems_for(project, build=build)


def test_remote_build_contexts_and_images_are_not_paths(project):
    assert problems_for(project, build={
        "context": "https://example.org/repo.git",
        "additional_contexts": {"base": "docker-image://alpine", "other": "service:db"},
    }) == []


# --- named volumes, networks, secrets -------------------------------------

def test_external_and_foreign_named_volumes_and_networks_are_refused(project):
    assert check(project, {"volumes": {"v": {"name": "v", "external": True}}})
    assert check(project, {"volumes": {"v": {"name": "other_v"}}})
    assert check(project, {"networks": {"n": {"name": "n", "external": True}}})
    assert check(project, {"networks": {"n": {"name": "other_n"}}})
    assert check(project, {"volumes": {"v": {"name": "proj_v"}}} | {"name": ""})  # no project name


def test_volume_drivers_and_options(project):
    def volume(**fields):
        return check(project, {"volumes": {"v": {"name": "proj_v", **fields}}})

    assert volume(driver="local", driver_opts={"type": "tmpfs", "device": "tmpfs"}) == []
    assert volume(driver="local", driver_opts={"type": "none", "o": "bind", "device": str(project / "data")}) == []
    assert volume(driver="rclone")
    assert volume(driver_opts={"type": "nfs", "device": ":/export"})
    assert volume(driver_opts={"type": "none", "o": "bind", "device": "relative/dir"})
    assert volume(driver_opts={"type": "none", "o": "bind", "device": "/etc"})


def test_extra_dirs_apply_to_volume_devices_but_not_to_build_contexts(project):
    outside = str(project.parent / "outside")
    config = {
        "volumes": {"v": {"name": "proj_v", "driver_opts": {"o": "bind", "device": outside}}},
        "services": {"web": service(build={"context": outside})},
    }
    assert check(project, config, [outside]) == [f"service web: build context {outside!r} is outside {project}"]


def test_network_drivers_and_options(project):
    def network(**fields):
        return check(project, {"networks": {"n": {"name": "proj_n", **fields}}})

    assert network(driver="bridge", ipam={"config": [{"subnet": "10.0.0.0/24"}]},
                   driver_opts={"com.docker.network.driver.mtu": "1400"}) == []
    assert network(driver="host")
    assert network(driver="macvlan")
    assert network(ipam={"driver": "custom"})
    assert network(driver_opts={"com.docker.network.bridge.name": "docker0"})


def test_secrets_and_configs(project):
    assert check(project, {"secrets": {"s": {"file": "/etc/shadow"}}})
    assert check(project, {"secrets": {"s": {"environment": "AWS_SECRET_ACCESS_KEY"}}})
    assert check(project, {"configs": {"c": {"external": True}}})
    assert check(project, {"configs": {"c": {"content": "inline"}}}) == []


# --- host files and structured keys ---------------------------------------

@pytest.mark.parametrize("value", ["{p}/../x.env", ["/etc/environment"], [{"path": "/home/me/.aws/env"}]])
def test_env_and_label_files_outside_project_are_refused(project, value):
    value = [v.replace("{p}", str(project)) if isinstance(v, str) else v for v in value] \
        if isinstance(value, list) else value.replace("{p}", str(project))
    assert problems_for(project, env_file=value)
    assert problems_for(project, label_file=value)


def test_develop_watch(project):
    def watch(**rule):
        return problems_for(project, develop={"watch": [{"path": str(project), "action": "sync", **rule}]})

    assert watch() == []
    assert watch(action="sync+exec")
    assert watch(exec={"command": "x"})
    assert watch(path="/etc")


def test_deploy_cannot_reserve_devices(project):
    assert problems_for(project, deploy={"resources": {"reservations": {"devices": [{"driver": "nvidia"}]}}})
    assert problems_for(project, deploy={"resources": {"reservations": {"memory": "1g"}}}) == []


def test_lifecycle_hooks_cannot_escalate(project):
    assert problems_for(project, post_start=[{"command": "x", "privileged": True}])
    assert problems_for(project, pre_stop=[{"command": "x", "user": "0"}])
    assert problems_for(project, post_start=[{"command": "x", "user": str(UID) + ":" + str(GID)}]) == []


# --- fix ------------------------------------------------------------------

def test_fix_config_leaves_nothing_fixable(project):
    config = {"services": {"web": {
        "user": "0:0", "group_add": ["0", "nogroup"], "privileged": True, "cap_add": ["ALL"],
        "devices": ["/dev/sda"], "security_opt": ["seccomp=unconfined"], "network_mode": "host",
        "volumes_from": ["container:x", "db"], "runtime": "nvidia",
    }}}
    fixed = policy.fix_config(config, UID, GID, str(project))
    assert fixed["services"]["web"] == {
        "user": policy.USER_TEMPLATE, "security_opt": ["no-new-privileges:true"], "cap_drop": ["ALL"],
        "volumes_from": ["db"],
    }
    resolved = policy.resolve_user_template(fixed, UID, GID)
    assert check(project, resolved) == []


def test_fix_config_does_not_touch_input_and_keeps_unfixable_problems(project):
    config = {"services": {"web": service(privileged=True, build={"context": "/"}, provider={"type": "x"})}}
    fixed = policy.fix_config(config, UID, GID, str(project))
    assert config["services"]["web"]["privileged"] is True
    assert check(project, fixed) == [
        "service web: key 'provider' is not on the allow list",
        f"service web: build context '/' is outside {project}",
    ]


def test_fix_config_replaces_bad_mount_sources_with_relative_upper_case_placeholders(project):
    mounts = [
        {"type": "bind", "source": "/etc", "target": "/e", "read_only": True},
        {"type": "bind", "source": "/var/run/docker.sock", "target": "/s"},
        {"type": "bind", "source": str(project / "escape"), "target": "/x"},  # symlink out
        {"type": "bind", "source": str(project / "data"), "target": "/d"},  # fine, kept as is
        {"type": "volume", "source": "cache", "target": "/c"},
    ]
    config = {"services": {"web": service(volumes=mounts)}}

    fixed = policy.fix_config(config, UID, GID, str(project))

    web = fixed["services"]["web"]["volumes"]
    assert [m["source"] for m in web] == [
        "./ETC", "./VAR_RUN_DOCKER.SOCK", "./ESCAPE", str(project / "data"), "cache"]
    assert web[0]["read_only"] is True  # other mount attributes survive
    assert check(project, fixed) == []
    assert config["services"]["web"]["volumes"] == mounts


def test_fix_config_keeps_a_compliant_service(project):
    config = {"services": {"web": service()}}
    assert policy.fix_config(config, UID, GID, str(project)) == config


def test_fix_config_keeps_mounts_from_extra_dirs(project):
    outside = str(project.parent / "outside")
    config = {"services": {"web": service(volumes=[bind(outside), bind("/etc")])}}

    fixed = policy.fix_config(config, UID, GID, str(project), [outside])

    assert [m["source"] for m in fixed["services"]["web"]["volumes"]] == [outside, "./ETC"]
