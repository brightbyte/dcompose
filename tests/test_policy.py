import os

import pytest

from dockscreen import autofix, policy

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


def context(project, extra_dirs=()):
    return policy.Context(str(project), UID, GID, tuple(str(d) for d in extra_dirs))


def check(project, config, extra_dirs=()):
    return policy.check_config({"name": "proj", **config}, context(project, extra_dirs))


def problems_for(project, **overrides):
    return check(project, {"services": {"web": service(**overrides)}})


def assert_refused(problems, *reasons):
    """Every reason shows up in some problem, and every problem matches a reason.

    A refusal for an unrelated reason, such as a typo that makes a key unknown, does not pass.
    """
    assert problems, "expected a refusal"
    for problem in problems:
        assert any(reason in problem for reason in reasons), f"unexpected problem: {problem}"
    for reason in reasons:
        assert any(reason in problem for problem in problems), f"missing reason: {reason}"


def test_compliant_config_has_no_problems(project):
    config = {
        "services": {"web": service(
            image="x:1", ports=["80:80"], **{"x-extension": {"anything": 1}},
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
    assert check(project, config) == []


# --- allowlist ------------------------------------------------------------

def test_unknown_service_key_is_refused_and_extension_keys_are_not(project):
    assert problems_for(project, provider={"type": "x"}) == [
        "service web: key 'provider' is not on the allow list"]
    assert problems_for(project, use_api_socket=True) == [
        "service web: key 'use_api_socket' is not on the allow list"]
    assert problems_for(project, **{"x-anything": 1}) == []


def test_unknown_keys_are_refused_in_nested_structures(project):
    unknown = "'new' is not on the allow list"
    volume_mount = {"type": "volume", "source": "d", "target": "/d", "new": 1}
    assert_refused(problems_for(project, volumes=[volume_mount]), f"mount key {unknown}")
    assert_refused(problems_for(project, volumes=[{"type": "bind", "source": str(project), "target": "/d",
                                                   "bind": {"new": 1}}]),
                   f"mount bind key {unknown}")
    assert_refused(problems_for(project, build={"context": str(project), "new": 1}), f"build key {unknown}")
    assert_refused(problems_for(project, deploy={"new": 1}), f"deploy key {unknown}")
    assert_refused(check(project, {"new_top_level": {}}),
                   "top-level key 'new_top_level' is not on the allow list")
    assert_refused(check(project, {"volumes": {"v": {"name": "proj_v", "new": 1}}}),
                   f"volume v: key {unknown}")
    assert_refused(check(project, {"networks": {"n": {"name": "proj_n", "new": 1}}}),
                   f"network n: key {unknown}")
    assert_refused(check(project, {"secrets": {"s": {"new": 1}}}), f"secrets s: key {unknown}")


def test_every_checked_key_is_outside_the_harmless_list():
    assert not policy.HARMLESS_SERVICE_KEYS & policy.SERVICE_CHECKS.keys()
    assert policy.REQUIRED_SERVICE_KEYS <= policy.SERVICE_CHECKS.keys()


# --- users ----------------------------------------------------------------

@pytest.mark.parametrize("user", [OWN, "65534:65534", f"{UID}:65534", f"{UID:08d}:{GID}"])
def test_allowed_users(project, user):
    assert problems_for(project, user=user) == []


@pytest.mark.parametrize("user, reasons", [
    (None, ["user is not set"]),
    ("", ["user is not set"]),
    ("root", ["user 'root' is not numeric", "user 'root' has no group"]),
    ("0:0", ["user '0' is neither", "group '0' is neither"]),
    (str(UID), [f"user '{UID}' has no group"]),
    (f"{UID}:0", ["group '0' is neither"]),
    (f"0:{GID}", ["user '0' is neither"]),
    (f"{UID + 1}:{GID}", [f"user '{UID + 1}' is neither"]),
    # names resolve through the image, which can map them to root
    ("nobody", ["user 'nobody' is not numeric", "user 'nobody' has no group"]),
    ("nobody:nogroup", ["user 'nobody' is not numeric", "group 'nogroup' is not numeric"]),
    (f"{UID}:nogroup", ["group 'nogroup' is not numeric"]),
    (f"{UID}:{GID}x", [f"group '{GID}x' is not numeric"]),
])
def test_disallowed_users(project, user, reasons):
    assert_refused(problems_for(project, user=user), *reasons)


def test_group_add_takes_numeric_allowed_ids_only(project):
    assert problems_for(project, group_add=[str(GID), 65534]) == []
    assert_refused(problems_for(project, group_add=["0"]), "group_add '0' is neither")
    assert_refused(problems_for(project, group_add=["nogroup"]), "group_add 'nogroup' is not numeric")


# --- privileges -----------------------------------------------------------

@pytest.mark.parametrize("override, reason", [
    ({"privileged": True}, "privileged is not allowed"),
    ({"cap_add": ["SYS_ADMIN"]}, "cap_add is not allowed"),
    ({"devices": ["/dev/sda:/dev/sda"]}, "devices is not allowed"),
    ({"device_cgroup_rules": ["c *:* rwm"]}, "device_cgroup_rules is not allowed"),
    ({"gpus": "all"}, "gpus is not allowed"),
    ({"cgroup_parent": "/"}, "cgroup_parent is not allowed"),
    ({"external_links": ["other:db"]}, "external_links is not allowed"),
    ({"runtime": "nvidia"}, "runtime 'nvidia' is not allowed"),
    ({"pid": "host"}, "pid: host shares a namespace"),
    ({"network_mode": "host"}, "network_mode: host shares a namespace"),
    ({"ipc": "container:other"}, "ipc: container:other shares a namespace"),
    ({"volumes_from": ["container:other"]}, "volumes_from 'container:other' reaches a container"),
])
def test_privilege_escalation_is_refused(project, override, reason):
    assert_refused(problems_for(project, **override), reason)


def test_services_in_the_same_project_may_be_referenced(project):
    assert problems_for(
        project, volumes_from=["other:ro"], network_mode="service:other", runtime="runc") == []


@pytest.mark.parametrize("security_opt, reasons", [
    (["no-new-privileges:true"], []),
    (["no-new-privileges=true"], []),
    (["no-new-privileges"], []),
    (["no-new-privileges:false"],
     ["'no-new-privileges:false' is not allowed", "must include no-new-privileges"]),
    ([], ["must include no-new-privileges"]),
    (None, ["must include no-new-privileges"]),
    (["no-new-privileges:true", "seccomp=unconfined"], ["'seccomp=unconfined' is not allowed"]),
    (["apparmor=unconfined"], ["'apparmor=unconfined' is not allowed", "must include no-new-privileges"]),
])
def test_no_new_privileges_is_required(project, security_opt, reasons):
    config = service()
    config.pop("security_opt")
    if security_opt is not None:
        config["security_opt"] = security_opt
    problems = check(project, {"services": {"web": config}})
    if reasons:
        assert_refused(problems, *reasons)
    else:
        assert problems == []


@pytest.mark.parametrize("cap_drop, ok", [(["ALL"], True), (["all"], True), (["ALL", "NET_RAW"], True),
                                          (["NET_RAW"], False), ([], False), (None, False)])
def test_cap_drop_all_is_required(project, cap_drop, ok):
    config = service()
    config.pop("cap_drop")
    if cap_drop is not None:
        config["cap_drop"] = cap_drop
    problems = check(project, {"services": {"web": config}})
    if ok:
        assert problems == []
    else:
        assert_refused(problems, "cap_drop must include ALL")


# --- mounts ---------------------------------------------------------------

def bind(source):
    return {"type": "bind", "source": str(source), "target": "/x"}


def test_bind_mount_outside_project_is_refused(project):
    assert_refused(problems_for(project, volumes=[bind("/var/run/docker.sock")]),
                   "bind mount '/var/run/docker.sock' is outside")


def test_bind_mount_through_symlink_out_of_project_is_refused(project):
    # The path looks inside the project but its realpath is not.
    assert_refused(problems_for(project, volumes=[bind(project / "escape")]), "/escape' is outside")


def test_bind_mount_of_sibling_with_common_prefix_is_refused(project):
    assert_refused(problems_for(project, volumes=[bind(str(project) + "-other")]), "-other' is outside")


def test_mounts_from_extra_dirs_are_allowed(project):
    outside = project.parent / "outside"
    config = {"services": {"web": service(volumes=[
        bind(outside), bind(outside / "deeper"), bind(project / "escape"),  # last: symlink into outside
    ])}}

    assert check(project, config, [outside]) == []
    assert len(check(project, config)) == 3


def test_extra_dirs_do_not_allow_their_siblings_or_other_mounts(project):
    outside = project.parent / "outside"
    config = {"services": {"web": service(volumes=[bind(project.parent / "outside-other"), bind("/etc")])}}
    assert len(check(project, config, [outside])) == 2


# --- build ----------------------------------------------------------------

def test_build_context_outside_project_is_refused(project):
    assert problems_for(project, build={"context": "/"}) == [
        f"service web: build context '/' is outside {project}"]


@pytest.mark.parametrize("build, reason", [
    ({"dockerfile": "../../etc/Dockerfile"}, "build dockerfile '../../etc/Dockerfile' is outside"),
    ({"additional_contexts": {"lib": "/usr/lib"}}, "build additional_contexts 'lib': '/usr/lib' is outside"),
    ({"network": "host"}, "build network 'host' is not allowed"),
    ({"privileged": True}, "build privileged is not allowed"),
    ({"ssh": ["default"]}, "build ssh forwards your SSH agent"),
    ({"cache_to": ["type=local,dest=/tmp/x"]}, "build key 'cache_to' is not on the allow list"),
    ({"entitlements": ["network.host"]}, "build key 'entitlements' is not on the allow list"),
    ({"x-bake": {"output": ["type=local,dest=/home/me"]}}, "build key 'x-bake' is not on the allow list"),
])
def test_unsafe_build_options_are_refused_when_building_and_running(project, build, reason):
    build = {"context": str(project), **build}
    build_only = policy.check_build_config(
        {"name": "proj", "services": {"web": {"build": build}}}, context(project))

    assert_refused(problems_for(project, build=build), reason)
    assert_refused(build_only, reason)


def test_remote_build_contexts_and_images_are_not_paths(project):
    assert problems_for(project, build={
        "context": "https://example.org/repo.git",
        "additional_contexts": {"base": "docker-image://alpine", "other": "service:db"},
    }) == []


def test_build_config_check_ignores_runtime_policy(project):
    config = {"name": "proj", "services": {"web": {"build": {"context": str(project)}, "privileged": True,
                                                   "user": "0"}}}
    assert policy.check_build_config(config, context(project)) == []


def test_build_config_check_covers_secret_files(project):
    config = {"name": "proj", "secrets": {"s": {"file": "/etc/shadow"}}}
    assert_refused(policy.check_build_config(config, context(project)), "file '/etc/shadow' is outside")


# --- named volumes, networks, secrets -------------------------------------

def test_external_and_foreign_named_volumes_and_networks_are_refused(project):
    external = "external resources are not allowed"
    assert_refused(check(project, {"volumes": {"v": {"name": "v", "external": True}}}), external)
    assert_refused(check(project, {"volumes": {"v": {"name": "other_v"}}}),
                   "name 'other_v' is not the project-scoped 'proj_v'")
    assert_refused(check(project, {"networks": {"n": {"name": "n", "external": True}}}), external)
    assert_refused(check(project, {"networks": {"n": {"name": "other_n"}}}),
                   "name 'other_n' is not the project-scoped 'proj_n'")
    assert_refused(check(project, {"volumes": {"v": {"name": "proj_v"}}} | {"name": ""}),
                   "config has no project name")


def test_volume_drivers_and_options(project):
    def volume(**fields):
        return check(project, {"volumes": {"v": {"name": "proj_v", **fields}}})

    assert volume(driver="local", driver_opts={"type": "tmpfs", "device": "tmpfs"}) == []
    assert volume(driver_opts={"type": "none", "o": "bind", "device": str(project / "data")}) == []
    assert_refused(volume(driver="rclone"), "driver 'rclone' is not allowed")
    assert_refused(volume(driver_opts={"type": "nfs", "device": ":/export"}),
                   "driver_opts type 'nfs' is not allowed")
    assert_refused(volume(driver_opts={"type": "none", "o": "bind", "device": "relative/dir"}),
                   "device 'relative/dir' must be an absolute path")
    assert_refused(volume(driver_opts={"type": "none", "o": "bind", "device": "/etc"}),
                   "device '/etc' is outside")


def test_extra_dirs_apply_to_volume_devices_but_not_to_build_contexts(project):
    outside = str(project.parent / "outside")
    config = {
        "volumes": {"v": {"name": "proj_v", "driver_opts": {"o": "bind", "device": outside}}},
        "services": {"web": service(build={"context": outside})},
    }
    assert check(project, config, [outside]) == [
        f"service web: build context {outside!r} is outside {project}"]


def test_network_drivers_and_options(project):
    def network(**fields):
        return check(project, {"networks": {"n": {"name": "proj_n", **fields}}})

    assert network(driver="bridge", ipam={"config": [{"subnet": "10.0.0.0/24"}]},
                   driver_opts={"com.docker.network.driver.mtu": "1400"}) == []
    assert_refused(network(driver="host"), "driver 'host' is not allowed")
    assert_refused(network(driver="macvlan"), "driver 'macvlan' is not allowed")
    assert_refused(network(ipam={"driver": "custom"}), "ipam driver 'custom' is not allowed")
    assert_refused(network(driver_opts={"com.docker.network.bridge.name": "docker0"}),
                   "driver_opts key 'com.docker.network.bridge.name' is not on the allow list")


def test_secrets_and_configs(project):
    assert_refused(check(project, {"secrets": {"s": {"file": "/etc/shadow"}}}),
                   "file '/etc/shadow' is outside")
    assert_refused(check(project, {"secrets": {"s": {"environment": "AWS_SECRET_ACCESS_KEY"}}}),
                   "environment 'AWS_SECRET_ACCESS_KEY' copies a variable")
    assert_refused(check(project, {"configs": {"c": {"external": True}}}),
                   "external resources are not allowed")
    assert check(project, {"configs": {"c": {"content": "inline"}}}) == []


# --- host files and structured keys ---------------------------------------

@pytest.mark.parametrize("key", ["env_file", "label_file"])
@pytest.mark.parametrize("value, path", [
    ("../x.env", "../x.env"),  # relative paths resolve against the project
    (["/etc/environment"], "/etc/environment"),
    ([{"path": "/home/me/.aws/env"}], "/home/me/.aws/env"),
])
def test_env_and_label_files_outside_project_are_refused(project, key, value, path):
    assert_refused(problems_for(project, **{key: value}), f"{key} {path!r} is outside")


def test_develop_watch(project):
    def watch(**rule):
        return problems_for(project, develop={"watch": [{"path": str(project), "action": "sync", **rule}]})

    assert watch() == []
    assert_refused(watch(action="sync+exec"), "develop.watch action 'sync+exec' is not allowed")
    assert_refused(watch(exec={"command": "x"}), "develop.watch key 'exec' is not on the allow list")
    assert_refused(watch(path="/etc"), "develop.watch path '/etc' is outside")


def test_deploy_cannot_reserve_devices(project):
    devices = {"resources": {"reservations": {"devices": [{"driver": "nvidia"}]}}}
    assert_refused(problems_for(project, deploy=devices),
                   "deploy.resources.reservations.devices grants host devices")
    assert problems_for(project, deploy={"resources": {"reservations": {"memory": "1g"}}}) == []


def test_lifecycle_hooks_cannot_escalate(project):
    assert_refused(problems_for(project, post_start=[{"command": "x", "privileged": True}]),
                   "post_start privileged is not allowed")
    assert_refused(problems_for(project, pre_stop=[{"command": "x", "user": "0"}]),
                   "user '0' is neither", "user '0' has no group")
    assert problems_for(project, post_start=[{"command": "x", "user": OWN}]) == []


# --- fix ------------------------------------------------------------------

def test_fix_config_leaves_nothing_fixable(project):
    config = {"services": {"web": {
        "user": "0:0", "group_add": ["0", "nogroup"], "privileged": True, "cap_add": ["ALL"],
        "devices": ["/dev/sda"], "security_opt": ["seccomp=unconfined"], "network_mode": "host",
        "volumes_from": ["container:x", "db"], "runtime": "nvidia",
    }}}
    fixed = autofix.fix_config(config, context(project))
    assert fixed["services"]["web"] == {
        "user": autofix.USER_TEMPLATE, "security_opt": ["no-new-privileges:true"], "cap_drop": ["ALL"],
        "volumes_from": ["db"],
    }
    resolved = autofix.resolve_user_template(fixed, context(project))
    assert check(project, resolved) == []


def test_fix_config_does_not_touch_input_and_keeps_unfixable_problems(project):
    config = {"services": {"web": service(privileged=True, build={"context": "/"}, provider={"type": "x"})}}
    fixed = autofix.fix_config(config, context(project))
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

    fixed = autofix.fix_config(config, context(project))

    web = fixed["services"]["web"]["volumes"]
    assert [m["source"] for m in web] == [
        "./ETC", "./VAR_RUN_DOCKER.SOCK", "./ESCAPE", str(project / "data"), "cache"]
    assert web[0]["read_only"] is True  # other mount attributes survive
    assert check(project, fixed) == []
    assert config["services"]["web"]["volumes"] == mounts


def test_fix_config_keeps_a_compliant_service(project):
    config = {"services": {"web": service()}}
    assert autofix.fix_config(config, context(project)) == config


def test_fix_config_keeps_mounts_from_extra_dirs(project):
    outside = project.parent / "outside"
    config = {"services": {"web": service(volumes=[bind(outside), bind("/etc")])}}

    fixed = autofix.fix_config(config, context(project, [outside]))

    assert [m["source"] for m in fixed["services"]["web"]["volumes"]] == [str(outside), "./ETC"]
