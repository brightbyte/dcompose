import os

import pytest
from fakes import FakeDocker, host_account, rules, runtime

from dockscreen import argscan, config, docker_cli, gate, hostusers, imagedecision
from dockscreen.dockerclient import DockerError, first_file_of_tar

DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]


# The caller is 4242:4343 here, so that uid 1000 is someone else: daniel, a local account.
ME = (4242, 4343)


def ctx(docker, settings=None, allow_me=False):
    settings = settings or config.Config()
    return imagedecision.Context(docker, rules(me=ME, allow_me=allow_me, settings=settings),
                                 runtime(settings=settings, me=ME))


def test_acceptable_image_user_runs_attached_with_hardening_defaults():
    docker = FakeDocker(image_user="app", command=["echo"], open_stdin=True)

    assert gate.run(ctx(docker), ["-i", "img", "echo"]) == 42  # the container's exit code

    assert docker.calls[0] == ("create", [*DEFAULTS, "-i", "img", "echo"])
    assert docker.calls[-1] == ("start", "cid1", True, True, None)


def test_detached_run_starts_without_attaching():
    docker = FakeDocker(image_user="app")
    gate.run(ctx(docker), ["-d", "--detach-keys=ctrl-x", "img"])
    assert docker.calls[0][1][-1] == "img" and "-d" not in docker.calls[0][1]
    assert docker.calls[-1] == ("start", "cid1", False, False, "ctrl-x")


def test_an_image_choosing_a_user_the_host_has_is_refused_and_the_container_removed(capsys):
    docker = FakeDocker(image_user="web")  # uid 1000: the host has an account with that id

    assert gate.run(ctx(docker), ["img"]) == 1

    err = capsys.readouterr().err
    assert "the image's uid 1000 exists on this host (local user daniel)" in err and "pass --user" in err
    assert docker.names() == ["create", "inspect", "remove"]  # never started


@pytest.mark.parametrize("image_user, ids", [
    ("pg", "998:998"), ("998", "998:998"), ("app", "100000:100001"), ("424242:7", "424242:7")])
def test_without_mounts_the_images_own_non_root_user_is_kept_whatever_its_id(image_user, ids, capsys):
    docker = FakeDocker(image_user=image_user)
    assert gate.run(ctx(docker), ["img"]) == 42
    assert f"--user={ids}" in docker.calls[3][1]  # the second create: pinned
    assert "nobody" not in capsys.readouterr().err


def test_an_accepted_image_user_is_pinned_as_numbers_so_the_runtime_resolves_nothing():
    docker = FakeDocker(image_user="app")

    assert gate.run(ctx(docker), ["img"]) == 42

    # created as the image has it, checked, removed, and created again with the checked ids
    assert docker.names() == ["create", "inspect", "remove", "create", "inspect", "start"]
    assert "--user=100000:100001" not in docker.calls[0][1]
    assert docker.calls[3][1] == [*DEFAULTS, "--user=100000:100001", "img"]
    assert docker.calls[-1][:2] == ("start", "cid1")


# --- mounts: the user must be chosen explicitly --------------------------------------

BIND = {"Mounts": [{"Type": "bind", "Source": "/p", "Destination": "/p"}]}


@pytest.mark.parametrize("extra", [
    BIND,
    {"HostConfig": {"Binds": ["/p:/p:ro"]}},
    {"HostConfig": {"Mounts": [{"Type": "bind"}]}},
    {"HostConfig": {"Devices": [{"PathOnHost": "/dev/dri"}]}},
    {"HostConfig": {"VolumesFrom": ["other"]}},
])
def test_has_host_mounts(extra):
    assert imagedecision.has_host_mounts({"Config": {}, **extra})


@pytest.mark.parametrize("extra", [
    {},
    {"Mounts": [{"Type": "volume", "Name": "data"}, {"Type": "tmpfs"}]},
    {"HostConfig": {"Binds": ["data:/var/lib/data"], "Devices": [], "VolumesFrom": None}},
])
def test_named_volumes_and_tmpfs_are_not_host_mounts(extra):
    assert not imagedecision.has_host_mounts({"Config": {}, **extra})


def test_with_a_bind_mount_an_image_user_outside_the_nobody_range_is_refused(capsys):
    docker = FakeDocker(image_user="pg", info_extra=BIND)

    assert gate.run(ctx(docker), ["-v", "/p:/p", "img"]) == 1

    assert docker.names() == ["create", "inspect", "remove"]
    err = capsys.readouterr().err
    assert ("the image's uid 998 is not in the nobody range 65530-65534, and there are host mounts; "
            "pass --user UID:GID, --as NAME or --as-me to choose a user") in err


@pytest.mark.parametrize("extra", [
    {"HostConfig": {"Devices": [{"PathOnHost": "/dev/dri"}]}},
    {"HostConfig": {"VolumesFrom": ["other"]}},
])
def test_devices_and_volumes_from_count_as_mounts(extra, capsys):
    docker = FakeDocker(image_user="app", info_extra=extra)
    assert gate.run(ctx(docker), ["img"]) == 1
    assert "not in the nobody range" in capsys.readouterr().err


def test_named_volumes_are_not_host_mounts(capsys):
    docker = FakeDocker(image_user="app", info_extra={"Mounts": [{"Type": "volume", "Name": "data"}]})
    assert gate.run(ctx(docker), ["img"]) == 42
    assert "--user=100000:100001" in docker.calls[3][1]


def test_an_image_that_is_already_nobody_is_accepted_with_mounts():
    docker = FakeDocker(image_user="nobody", info_extra=BIND)
    assert gate.run(ctx(docker), ["img"]) == 42
    assert "--user=65534:65534" in docker.calls[3][1]


def test_a_user_on_the_command_line_is_all_a_mounting_container_needs(capsys):
    docker = FakeDocker(image_user="pg", container_user="998:998", info_extra=BIND)
    assert gate.run(ctx(docker), ["--user", "998:998", "-v", "/p:/p", "img"]) == 42
    assert docker.names().count("create") == 1 and capsys.readouterr().err == ""


def test_root_with_mounts_runs_as_the_default_user(capsys):
    docker = FakeDocker(image_user="", info_extra=BIND)
    assert gate.run(ctx(docker), ["img"]) == 42
    assert "image img would run as root; running it as the default user (65534:65534)" in (
        capsys.readouterr().err)


def test_the_default_user_comes_from_the_config_file(capsys):
    docker = FakeDocker(image_user="")
    assert gate.run(ctx(docker, config.Config(default_user=(4000, 4001))), ["img"]) == 42
    assert docker.calls[3][1][:3] == [*DEFAULTS, "--user=4000:4001"]
    assert "running it as the default user (4000:4001)" in capsys.readouterr().err


def test_a_root_default_user_is_announced_on_every_run(capsys):
    docker = FakeDocker(image_user="app")
    gate.run(ctx(docker, config.Config(default_user=(0, 0))), ["img"])
    assert "the configured default user is 0:0" in capsys.readouterr().err


# --- users the config file sets for an image repository -----------------------------

IMG_USERS = config.Config(image_users={"docker.io/library/img": (999, 999)})


def test_a_configured_image_user_replaces_the_images_own(capsys):
    docker = FakeDocker(image_user="", info_extra=BIND, repo_digests=["img@sha256:abc"])

    assert gate.run(ctx(docker, IMG_USERS), ["img"]) == 42

    assert docker.calls[3][1][:3] == [*DEFAULTS, "--user=999:999"]  # root included, mounts or not
    assert capsys.readouterr().err == ""  # configured: no notice


def test_a_configured_user_needs_the_image_to_have_been_pulled_from_that_repository(capsys):
    docker = FakeDocker(image_user="", repo_digests=["evil.example/img@sha256:abc"])
    assert gate.run(ctx(docker, IMG_USERS), ["img"]) == 42
    assert "--user=65534:65534" in docker.calls[3][1]  # an image tagged img locally: the normal rules


def test_audit_says_why_a_configured_user_does_not_apply(capsys):
    assert audit_with(FakeDocker(image_user="nobody"), IMG_USERS, "img") == 0
    assert ("note: the config sets a user for docker.io/library/img, but this image was not pulled from "
            "there") in capsys.readouterr().out


# --- --allow-me ------------------------------------------------------------------

def test_an_image_whose_user_is_the_caller_needs_allow_me(capsys):
    docker = FakeDocker(image_user="4242:4343")
    assert gate.run(ctx(docker), ["img"]) == 1
    assert "the image's uid 4242 is yours; pass --allow-me to allow it" in capsys.readouterr().err

    docker = FakeDocker(image_user="4242:4343")
    assert gate.run(ctx(docker), ["--allow-me", "img"]) == 42
    assert docker.calls[0][1] == [*DEFAULTS, "img"]  # --allow-me is dockscreen's, not docker's
    assert docker.calls[3][1][:3] == [*DEFAULTS, "--user=4242:4343"]


def test_allow_me_applies_with_mounts_too():
    docker = FakeDocker(image_user="4242:4343", info_extra=BIND)
    assert gate.run(ctx(docker, allow_me=True), ["img"]) == 42


@pytest.mark.parametrize("image_user", ["", "root", "0:0", "424242"])  # the last gets gid 0: no passwd entry
def test_an_image_that_would_run_as_root_is_run_as_nobody_instead(image_user, capsys):
    docker = FakeDocker(image_user=image_user, open_stdin=True)

    assert gate.run(ctx(docker), ["-i", "img"]) == 42

    creates = [call[1] for call in docker.calls if call[0] == "create"]
    assert creates == [[*DEFAULTS, "-i", "img"], [*DEFAULTS, "--user=65534:65534", "-i", "img"]]
    assert docker.names().count("remove") == 1
    assert docker.calls[docker.names().index("remove")] == ("remove", "cid1")
    assert docker.calls[-1] == ("start", "cid1", True, True, None)
    err = capsys.readouterr().err
    assert "would run as root; running it as the default user (65534:65534) instead" in err


@pytest.mark.parametrize("flags", [
    ["--user", "1000:1000"], ["-u", "0:0"], ["--user=0:0"], ["--as-me"], ["--as", "alice"],
])
def test_a_user_on_the_command_line_prevents_the_fallback(flags, capsys):
    docker = FakeDocker(image_user="")  # root, which would fall back without the flag
    context = imagedecision.Context(docker, rules(me=ME), runtime(me=ME))

    assert gate.run(context, [*flags, "img"]) == 42

    assert docker.names().count("create") == 1
    assert "default user" not in capsys.readouterr().err


def test_as_me_means_the_callers_ids():
    docker = FakeDocker(image_user="")
    context = imagedecision.Context(docker, rules(me=ME), runtime(me=ME))
    gate.run(context, ["--as-me", "img"])
    assert docker.calls[0][1] == [*DEFAULTS, "--user=4242:4343", "img"]


def test_failure_to_create_the_fallback_container_is_passed_on():
    docker = FakeDocker(image_user="")
    creates = iter([(0, "cid1"), (125, None)])
    docker.create = lambda args: next(creates)
    assert gate.run(ctx(docker), ["img"]) == 125


def test_a_user_on_the_command_line_is_trusted():
    docker = FakeDocker(image_user="", container_user="1000:1000")
    assert gate.run(ctx(docker), ["--user", "1000:1000", "img"]) == 42
    assert "remove" not in docker.names()


def test_existing_containers_cannot_be_rewritten_so_a_root_image_is_refused():
    docker = FakeDocker(image_user="")
    problems = gate.check_existing(ctx(docker), ["c1"])
    assert problems == [
        ("c1: its image's user would be replaced by 65534:65534, which an existing container cannot "
         "be; recreate it with --user 65534:65534")]


def test_an_existing_container_with_mounts_follows_the_mount_rule_too():
    docker = FakeDocker(image_user="app", info_extra=BIND)
    problems = gate.check_existing(ctx(docker), ["c1"])
    assert problems and all("not in the nobody range" in p for p in problems)
    assert gate.check_existing(ctx(FakeDocker(image_user="app")), ["c1"]) == []  # no mounts: fine


def test_user_unknown_to_the_image_is_refused(capsys):
    docker = FakeDocker(image_user="ghost")
    assert gate.run(ctx(docker), ["img"]) == 1
    assert "not defined in the image" in capsys.readouterr().err


def test_misread_command_line_is_refused_and_cleaned_up(capsys):
    docker = FakeDocker(image_user="app", image="something-else")
    assert gate.run(ctx(docker), ["img"]) == 1
    assert "could not reliably tell the image" in capsys.readouterr().err
    assert docker.names()[-1] == "remove"

    docker = FakeDocker(image_user="app", command=["different"])
    assert gate.run(ctx(docker), ["img", "ls", "-d"]) == 1


def test_create_failure_is_passed_on():
    docker = FakeDocker(create_code=125)
    assert gate.run(ctx(docker), ["img"]) == 125
    assert docker.names() == ["create"]


def test_unreadable_command_line_is_refused(capsys):
    assert gate.run(ctx(FakeDocker()), ["--name"]) == 1
    assert "cannot read the command line" in capsys.readouterr().err


@pytest.mark.parametrize("args, refs", [
    (["a", "b"], ["a", "b"]),
    (["-a", "-i", "a"], ["a"]),
    (["--detach-keys", "x", "a", "--attach"], ["a"]),
    (["--detach-keys=x", "a"], ["a"]),
    (["-t", "5", "a"], ["a"]),
    (["--time=5", "a", "--", "-weird"], ["a", "-weird"]),
])
def test_container_refs(args, refs):
    assert argscan.positionals(args, gate.VALUE_LONG, gate.VALUE_SHORT) == refs


def test_existing_containers_are_checked_by_the_same_rule():
    ok = FakeDocker(image_user="app")
    assert gate.check_existing(ctx(ok), ["web1"]) == []
    bad = FakeDocker(image_user="web")
    assert "web1: the image's uid 1000 exists on this host" in gate.check_existing(ctx(bad), ["web1"])[0]
    assert "no such" in gate.check_existing(ctx(bad), ["gone"])[0].lower()


# --- docker_cli routing ---------------------------------------------------

@pytest.fixture
def routed(monkeypatch):
    calls = []
    monkeypatch.setattr(docker_cli, "passthrough", lambda argv, _: calls.append(("exec", argv)) or 0)
    monkeypatch.setattr(docker_cli.compose_cli, "main", lambda argv, _: calls.append(("compose", argv)) or 0)
    monkeypatch.setattr("dockscreen.runtime.Docker", lambda binary: FakeDocker(image_user="app"))
    return calls


def test_compose_is_routed_to_dockscreen(routed):
    docker_cli.main(["compose", "-f", "a.yml", "up"])
    assert routed == [("compose", ["-f", "a.yml", "up"])]


@pytest.mark.parametrize("argv, expect_help", [
    ([], True),
    (["--help"], True),
    (["-h"], True),
    (["ps"], False),
    (["run", "--help"], False),  # docker's own help for the subcommand
])
def test_dockscreen_help_precedes_dockers(routed, capsys, argv, expect_help):
    docker_cli.main(argv)
    assert routed == [("exec", argv)]
    out = capsys.readouterr().out
    assert ("dockscreen: docker with security checks" in out) == expect_help
    if expect_help:
        assert "dockscreen compose --help" in out


def test_docker_options_before_compose_are_refused(routed, capsys):
    assert docker_cli.main(["--context", "x", "compose", "up"]) == 1
    assert routed == []


@pytest.mark.parametrize("argv", [["ps"], ["images", "-a"], ["--version"], [],
                                  ["exec", "-u", "0:0", "c", "sh"],
                                  ["run", "--help"], ["run"], ["start", "--help"], ["container", "ls"]])
def test_other_commands_pass_through_unchanged(routed, argv):
    docker_cli.main(argv)
    assert routed == [("exec", argv)]


@pytest.mark.parametrize("argv", [["exec", "-u", "root", "c", "sh"], ["exec", "-itu0", "c", "sh"],
                                  ["container", "exec", "--user=www-data", "c", "sh"]])
def test_exec_takes_numeric_users_only(routed, argv, capsys):
    assert docker_cli.main(argv) == 1
    assert routed == [] and "--user takes numeric ids as uid:gid" in capsys.readouterr().err


def test_exec_as_a_local_user_reaches_docker_as_numeric_ids(routed, monkeypatch):
    monkeypatch.setattr(hostusers, "resolve_account", lambda name, accounts: ("1001:1002", []))
    docker_cli.main(["-l", "debug", "container", "exec", "--as=alice", "c", "sh"])
    assert routed == [("exec", ["-l", "debug", "container", "exec", "--user=1001:1002", "c", "sh"])]


def test_exec_as_me_reaches_docker_as_the_callers_ids(routed):
    docker_cli.main(["exec", "--as-me", "c", "sh"])
    assert routed == [("exec", ["exec", f"--user={os.getuid()}:{os.getgid()}", "c", "sh"])]


def test_allow_me_before_the_subcommand_reaches_the_gate_and_not_docker(routed, monkeypatch):
    own = FakeDocker(image_user=f"{os.getuid()}:{os.getgid()}")
    monkeypatch.setattr("dockscreen.runtime.Docker", lambda binary: own)
    assert docker_cli.main(["--allow-me", "run", "img"]) == 42
    docker_cli.main(["--allow-me", "compose", "up"])
    assert routed == [("compose", ["--allow-me", "up"])]


@pytest.mark.parametrize("argv, expected", [
    (["create", "-it", "img"], ["create", *DEFAULTS, "-it", "img"]),
    (["container", "create", "img"], ["container", "create", *DEFAULTS, "img"]),
    (["-l", "debug", "create", "img"], ["-l", "debug", "create", *DEFAULTS, "img"]),
])
def test_create_gets_the_hardening_defaults_and_nothing_else(routed, argv, expected):
    docker_cli.main(argv)
    assert routed == [("exec", expected)]


def test_start_is_checked_then_passed_through(routed, monkeypatch):
    docker_cli.main(["start", "-a", "c1"])
    assert routed == [("exec", ["start", "-a", "c1"])]

    monkeypatch.setattr("dockscreen.runtime.Docker", lambda binary: FakeDocker(image_user=""))
    routed.clear()
    assert docker_cli.main(["container", "restart", "c1"]) == 1
    assert routed == []


def test_run_goes_through_the_gate(routed):
    assert docker_cli.main(["container", "run", "--rm", "img"]) == 42
    assert routed == []


@pytest.mark.parametrize("env, argv", [
    ({"DOCKER_HOST": "tcp://10.0.0.1:2375"}, ["run", "img"]),
    ({"DOCKER_CONTEXT": "prod"}, ["run", "img"]),
    ({}, ["-H", "ssh://x", "run", "img"]),
    ({}, ["--context=prod", "start", "c"]),
])
def test_remote_daemons_are_refused(routed, monkeypatch, env, argv, capsys):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert docker_cli.main(argv) == 1
    assert "not the default local one" in capsys.readouterr().err


def test_a_non_default_current_context_is_refused(routed, monkeypatch):
    rootless = FakeDocker(image_user="app", context="rootless")
    monkeypatch.setattr("dockscreen.runtime.Docker", lambda binary: rootless)
    assert docker_cli.main(["run", "img"]) == 1


def test_local_unix_socket_is_fine(routed, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    assert docker_cli.main(["run", "img"]) == 42


def test_first_file_of_tar():
    import io
    import tarfile
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        data = b"root:x:0:0\n"
        info = tarfile.TarInfo("passwd")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/shadow"
        archive.addfile(link)
    assert first_file_of_tar(buffer.getvalue()) == "root:x:0:0\n"
    assert first_file_of_tar(b"not a tar") is None


# --- docker audit ---------------------------------------------------------

def audit(docker, *args):
    return gate.audit(ctx(docker), list(args))


def audit_with(docker, settings, *args):
    return gate.audit(ctx(docker, settings), list(args))


def test_audit_says_what_happens_without_and_with_mounts(capsys):
    docker = FakeDocker(image_user="app")
    assert audit(docker, "img") == 1
    out = capsys.readouterr().out
    assert out.splitlines() == [
        ("image img, without bind mounts: runs as uid 100000 (no local user), "
         "gid 100001 (no local group); accepted"),
        ("image img, with bind mounts or devices: would be refused (runs as uid 100000 (no local user), "
         "gid 100001 (no local group)): the image's uid 100000 is not in the nobody range 65530-65534, "
         "and there are host mounts; the image's gid 100001 is not in the nobody range 65530-65534, "
         "and there are host mounts"),
        "  pass --user UID:GID, --as NAME or --as-me to choose a user",
    ]
    assert docker.names() == ["create", "inspect", "remove"]  # nothing is started
    assert docker.calls[0][1] == ["--pull=never", "img"]      # and nothing is pulled


def test_audit_of_a_root_image_is_the_same_with_and_without_mounts(capsys):
    assert audit(FakeDocker(image_user=""), "img") == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == ("image img: would run as uid 0 (local user root), gid 0 (local group root); "
                      "docker run would run it as the default user (65534:65534) instead")
    assert len(out) == 2  # one outcome, then the line about the defaults


def test_audit_predicts_a_refusal_and_exits_one(capsys):
    assert audit(FakeDocker(image_user="web"), "img") == 1
    out = capsys.readouterr().out
    assert ("image img: would be refused (runs as uid 1000 (local user daniel), "
            "gid 1000 (local group daniel)): the image's uid 1000 exists on this host "
            "(local user daniel)") in out
    assert "pass --user UID:GID, --as NAME or --as-me to choose a user" in out


def test_audit_takes_allow_me(capsys):
    assert audit(FakeDocker(image_user="4242:4343"), "img") == 1
    assert audit(FakeDocker(image_user="4242:4343"), "--allow-me", "img") == 0


def test_audit_with_a_user_does_not_check_the_image(capsys):
    docker = FakeDocker(image_user="")
    assert audit(docker, "--user", "1000:1000", "img") == 0
    assert "the user is set on the command line" in capsys.readouterr().out
    assert docker.calls[0][1] == ["--pull=never", "--user=1000:1000", "img"]


def test_audit_of_an_image_that_is_not_local_says_how_to_proceed(capsys):
    docker = FakeDocker(image_missing=True)
    assert audit(docker, "img") == 1
    assert "not available locally; run `docker pull` first" in capsys.readouterr().err


@pytest.mark.parametrize("args", [[], ["--rm", "img"], ["img", "ls"], ["--name", "x", "img"]])
def test_audit_takes_only_a_user_and_an_image(args, capsys):
    assert audit(FakeDocker(), *args) == 2
    assert "usage: docker audit" in capsys.readouterr().err


def test_audit_removes_the_container_even_when_inspection_fails():
    docker = FakeDocker()
    docker.inspect_container = lambda ref: (_ for _ in ()).throw(DockerError("boom"))
    assert audit(docker, "img") == 1
    assert ("remove", "cid1") in docker.calls


# --- docker audit routing ---------------------------------------------------

def test_docker_audit_is_routed_to_the_audit(routed, capsys):
    assert docker_cli.main(["audit", "img"]) == 1  # app would be refused with mounts
    assert "runs as uid 100000" in capsys.readouterr().out
    assert routed == []


def test_docker_audit_without_an_image_prints_usage(routed, capsys):
    assert docker_cli.main(["audit"]) == 2
    assert "usage: docker audit" in capsys.readouterr().err


def test_docker_audit_needs_a_local_daemon(routed, monkeypatch, capsys):
    monkeypatch.setenv("DOCKER_HOST", "tcp://10.0.0.1:2375")
    assert docker_cli.main(["audit", "img"]) == 1
    assert "not the default local one" in capsys.readouterr().err


def test_container_audit_is_not_a_thing(routed):
    docker_cli.main(["container", "audit"])
    assert routed == [("exec", ["container", "audit"])]


# --- users on the command line ---------------------------------------------------

def test_as_resolves_a_local_account_on_the_host_and_docker_gets_ids(capsys):
    docker = FakeDocker(image_user="")  # root: would fall back if no user were given

    assert gate.run(ctx(docker), ["--as", "alice", "img"]) == 42

    assert docker.calls[0][1] == [*DEFAULTS, "--user=4242:4343", "img"]
    assert docker.names().count("create") == 1  # a user was given: no fallback
    assert "[dockscreen] Resolving user alice to uid 4242, gid 4343" in capsys.readouterr().err


def test_as_with_an_account_the_host_does_not_have_is_refused_before_anything_is_created(capsys):
    docker = FakeDocker()
    assert gate.run(ctx(docker), ["--as", "www-data", "img"]) == 1
    err = capsys.readouterr().err
    assert "user 'www-data' does not exist on this host; use --user with a numeric id" in err
    assert docker.calls == []


@pytest.mark.parametrize("flags", [["--user", "alice"], ["-u", "root"], ["--user=1000:staff"]])
def test_user_with_a_name_is_refused_before_anything_is_created(flags, capsys):
    docker = FakeDocker()
    assert gate.run(ctx(docker), [*flags, "img"]) == 1
    err = capsys.readouterr().err
    assert "--user takes numeric ids as uid:gid" in err and "--as NAME runs as a local user" in err
    assert docker.calls == []


def test_audit_takes_as_and_refuses_names_for_user(capsys):
    docker = FakeDocker(image_user="")
    assert audit(docker, "--as", "alice", "img") == 0
    captured = capsys.readouterr()
    assert docker.calls[0][1] == ["--pull=never", "--user=4242:4343", "img"]
    assert "Resolving user alice to uid 4242, gid 4343" in captured.err

    assert audit(FakeDocker(), "--user", "alice", "img") == 1
    assert "--user takes numeric ids as uid:gid" in capsys.readouterr().err


def test_create_resolves_as_and_keeps_everything_else(routed, monkeypatch, capsys):
    monkeypatch.setattr(docker_cli.gate.hostusers, "resolve_account", host_account)

    docker_cli.main(["create", "-it", "--as", "alice", "--name", "x", "img", "sh", "-c", "id"])

    assert routed == [("exec", ["create", *DEFAULTS, "-it", "--user=4242:4343", "--name", "x", "img",
                                "sh", "-c", "id"])]
    assert "Resolving user alice to uid 4242, gid 4343" in capsys.readouterr().err


@pytest.mark.parametrize("flags", [["--as", "ghost"], ["--user", "alice"]])
def test_create_with_a_user_that_cannot_be_used_is_refused(routed, monkeypatch, flags):
    monkeypatch.setattr(docker_cli.gate.hostusers, "resolve_account", host_account)
    assert docker_cli.main(["create", *flags, "img"]) == 1
    assert routed == []


def test_create_with_an_unreadable_command_line_is_left_to_docker(routed):
    docker_cli.main(["create", "--name"])
    assert routed == [("exec", ["create", *DEFAULTS, "--name"])]


def test_a_config_file_that_cannot_be_trusted_stops_the_docker_wrapper_too(routed, monkeypatch, capsys):
    def broken(env, home, uid):
        raise config.ConfigError("/etc/dockscreen/config.toml: unknown key 'typo'")
    monkeypatch.setattr(config, "load_current", broken)
    assert docker_cli.main(["ps"]) == 1
    assert routed == [] and "unknown key 'typo'" in capsys.readouterr().err


@pytest.mark.parametrize("kind, refused, pins_user, replaces_image_user", [
    (imagedecision.Kind.EXPLICIT, False, False, False),   # the command line's user runs as given
    (imagedecision.Kind.CONFIGURED, False, True, True),
    (imagedecision.Kind.OK, False, True, False),           # the image's own user, pinned as numbers
    (imagedecision.Kind.FALLBACK, False, True, True),
    (imagedecision.Kind.REFUSED, True, False, False),
])
def test_assessment_predicates(kind, refused, pins_user, replaces_image_user):
    assessment = imagedecision.Assessment(kind, [])
    assert (assessment.refused, assessment.pins_user, assessment.replaces_image_user) == (
        refused, pins_user, replaces_image_user)
