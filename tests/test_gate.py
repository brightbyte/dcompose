import pytest
from fakes import GROUP, PASSWD, Local, host_account

from dcompose import docker_cli, gate
from dcompose.dockerclient import DockerError, first_file_of_tar

DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]


class FakeDocker:
    """Records calls. `image_user` is the image's USER; `container_user` is what the container reports."""

    def __init__(self, image_user="", container_user=None, image="img", command=None, passwd=PASSWD,
                 group=GROUP, open_stdin=False, create_code=0, context="default", image_missing=False,
                 info_extra=None):
        self.image_user = image_user
        self.container_user = image_user if container_user is None else container_user
        self.image, self.command = image, command or []
        self.passwd, self.group = passwd, group
        self.open_stdin, self.create_code, self.current_context = open_stdin, create_code, context
        self.image_missing = image_missing
        self.info_extra = info_extra or {}  # for example {"Mounts": [{"Type": "bind"}]}
        self.calls = []

    def create(self, args):
        self.calls.append(("create", args))
        if "--pull=never" in args and self.image_missing:
            return 1, None
        for arg in args:
            if arg.startswith("--user="):
                self.container_user = arg[len("--user="):]
        return (self.create_code, "cid1" if self.create_code == 0 else None)

    def inspect_container(self, ref):
        self.calls.append(("inspect", ref))
        if ref == "gone":
            raise DockerError("No such container: gone")
        return {"Id": "id-" + ref, "Image": "sha256:abc", "Config": {
            "Image": self.image, "Cmd": self.command, "User": self.container_user,
            "OpenStdin": self.open_stdin}, **self.info_extra}

    def inspect_image(self, ref):
        return {"Config": {"User": self.image_user}}

    def read_file(self, container, path):
        return {"/etc/passwd": self.passwd, "/etc/group": self.group}[path]

    def start(self, container, attach, interactive, detach_keys):
        self.calls.append(("start", container, attach, interactive, detach_keys))
        return 42

    def remove(self, container):
        self.calls.append(("remove", container))

    def context(self):
        return self.current_context

    def names(self):
        return [call[0] for call in self.calls]


def ctx(docker):
    return gate.Context(docker, Local(), resolve_user=host_account)


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
    assert "uid 1000, which exists on this host (local user daniel)" in err and "pass --user" in err
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
    assert gate.has_host_mounts({"Config": {}, **extra})


@pytest.mark.parametrize("extra", [
    {},
    {"Mounts": [{"Type": "volume", "Name": "data"}, {"Type": "tmpfs"}]},
    {"HostConfig": {"Binds": ["data:/var/lib/data"], "Devices": [], "VolumesFrom": None}},
])
def test_named_volumes_and_tmpfs_are_not_host_mounts(extra):
    assert not gate.has_host_mounts({"Config": {}, **extra})


def test_with_a_bind_mount_the_images_user_is_replaced_by_nobody_and_its_ids_are_echoed(capsys):
    docker = FakeDocker(image_user="pg", info_extra=BIND)

    assert gate.run(ctx(docker), ["-v", "/p:/p", "img"]) == 42

    creates = [call[1] for call in docker.calls if call[0] == "create"]
    assert creates[1][:3] == [*DEFAULTS, "--user=65534:65534"]
    err = capsys.readouterr().err
    assert ("image img would run as uid 998 (no local user), gid 998 (no local group), and the container "
            "has bind mounts; running it as nobody (65534:65534) instead. "
            "To run it as the image's user, pass --user 998:998.") in err


@pytest.mark.parametrize("extra", [
    {"HostConfig": {"Devices": [{"PathOnHost": "/dev/dri"}]}},
    {"HostConfig": {"VolumesFrom": ["other"]}},
])
def test_devices_and_volumes_from_count_as_mounts(extra, capsys):
    docker = FakeDocker(image_user="app", info_extra=extra)
    gate.run(ctx(docker), ["img"])
    assert docker.names().count("create") == 2 and "--user 100000:100001" in capsys.readouterr().err


def test_named_volumes_do_not_make_the_user_explicit(capsys):
    docker = FakeDocker(image_user="app", info_extra={"Mounts": [{"Type": "volume", "Name": "data"}]})
    assert gate.run(ctx(docker), ["img"]) == 42
    assert "--user=100000:100001" in docker.calls[3][1] and "nobody" not in capsys.readouterr().err


def test_an_image_that_is_already_nobody_needs_no_fallback_with_mounts():
    docker = FakeDocker(image_user="nobody", info_extra=BIND)
    assert gate.run(ctx(docker), ["img"]) == 42
    assert "--user=65534:65534" in docker.calls[3][1]


def test_a_host_account_id_with_mounts_is_replaced_not_refused(capsys):
    docker = FakeDocker(image_user="web", info_extra=BIND)  # uid 1000 is daniel here
    assert gate.run(ctx(docker), ["img"]) == 42
    assert "image img would run as uid 1000 (local user daniel), gid 1000 (local group daniel)" in (
        capsys.readouterr().err)


def test_a_user_on_the_command_line_is_all_a_mounting_container_needs(capsys):
    docker = FakeDocker(image_user="pg", container_user="998:998", info_extra=BIND)
    assert gate.run(ctx(docker), ["--user", "998:998", "-v", "/p:/p", "img"]) == 42
    assert docker.names().count("create") == 1 and "nobody" not in capsys.readouterr().err


def test_root_with_mounts_says_root_not_the_mounts_reason(capsys):
    docker = FakeDocker(image_user="", info_extra=BIND)
    gate.run(ctx(docker), ["img"])
    err = capsys.readouterr().err
    assert "image img would run as root; running it as nobody (65534:65534) instead." in err
    assert "bind mounts" not in err


@pytest.mark.parametrize("image_user", ["", "root", "0:0", "424242"])  # the last gets gid 0: no passwd entry
def test_an_image_that_would_run_as_root_is_run_as_nobody_instead(image_user, capsys):
    docker = FakeDocker(image_user=image_user, open_stdin=True)

    assert gate.run(ctx(docker), ["-i", "img"]) == 42

    creates = [call[1] for call in docker.calls if call[0] == "create"]
    assert creates == [[*DEFAULTS, "-i", "img"], [*DEFAULTS, "--user=65534:65534", "-i", "img"]]
    assert docker.names().count("remove") == 1
    assert docker.calls[docker.names().index("remove")] == ("remove", "cid1")
    assert docker.calls[-1] == ("start", "cid1", True, True, None)
    assert "would run as root; running it as nobody (65534:65534) instead" in capsys.readouterr().err


@pytest.mark.parametrize("flags", [
    ["--user", "1000:1000"], ["-u", "0:0"], ["--user=0:0"], ["--as-me"], ["--as", "alice"],
])
def test_a_user_on_the_command_line_prevents_the_fallback(flags, capsys):
    docker = FakeDocker(image_user="")  # root, which would fall back without the flag
    context = gate.Context(docker, Local(), current_user=(4242, 4343),
                           resolve_user=host_account)

    assert gate.run(context, [*flags, "img"]) == 42

    assert docker.names().count("create") == 1
    assert "nobody" not in capsys.readouterr().err


def test_as_me_means_the_callers_ids():
    docker = FakeDocker(image_user="")
    context = gate.Context(docker, Local(), current_user=(4242, 4343))
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
        "c1: its image would run as root; recreate it with --user UID:GID, --as NAME or --as-me"]


def test_an_existing_container_with_mounts_needs_its_user_chosen_too():
    docker = FakeDocker(image_user="app", info_extra=BIND)
    problems = gate.check_existing(ctx(docker), ["c1"])
    assert len(problems) == 1 and "and the container has bind mounts; recreate it with --user" in problems[0]
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
    assert gate.container_refs(args) == refs


def test_existing_containers_are_checked_by_the_same_rule():
    ok = FakeDocker(image_user="app")
    assert gate.check_existing(ctx(ok), ["web1"]) == []
    bad = FakeDocker(image_user="web")
    assert "web1: the image would run with uid 1000" in gate.check_existing(ctx(bad), ["web1"])[0]
    assert "no such" in gate.check_existing(ctx(bad), ["gone"])[0].lower()


# --- docker_cli routing ---------------------------------------------------

@pytest.fixture
def routed(monkeypatch):
    calls = []
    monkeypatch.setattr(docker_cli, "passthrough", lambda argv: calls.append(("exec", argv)) or 0)
    monkeypatch.setattr(docker_cli.cli, "main", lambda argv: calls.append(("compose", argv)) or 0)
    monkeypatch.setattr(docker_cli, "Docker", lambda: FakeDocker(image_user="app"))
    monkeypatch.setattr(docker_cli.imageuser, "LocalIds", Local)
    return calls


def test_compose_is_routed_to_dcompose(routed):
    docker_cli.main(["compose", "-f", "a.yml", "up"])
    assert routed == [("compose", ["-f", "a.yml", "up"])]


def test_docker_options_before_compose_are_refused(routed, capsys):
    assert docker_cli.main(["--context", "x", "compose", "up"]) == 1
    assert routed == []


@pytest.mark.parametrize("argv", [["ps"], ["images", "-a"], ["--version"], [], ["exec", "-u", "0", "c", "sh"],
                                  ["run", "--help"], ["run"], ["start", "--help"], ["container", "ls"]])
def test_other_commands_pass_through_unchanged(routed, argv):
    docker_cli.main(argv)
    assert routed == [("exec", argv)]


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

    monkeypatch.setattr(docker_cli, "Docker", lambda: FakeDocker(image_user=""))
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
    monkeypatch.setattr(docker_cli, "Docker", lambda: FakeDocker(image_user="app", context="rootless"))
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


def test_audit_says_what_happens_without_and_with_mounts(capsys):
    docker = FakeDocker(image_user="app")
    assert audit(docker, "img") == 0
    out = capsys.readouterr().out
    assert out.splitlines() == [
        ("image img, without bind mounts: runs as uid 100000 (no local user), "
         "gid 100001 (no local group); accepted"),
        ("image img, with bind mounts or devices: would run as uid 100000 (no local user), "
         "gid 100001 (no local group); docker run would run it as nobody (65534:65534) instead; "
         "to run it as the image's user pass --user 100000:100001"),
        ("docker run also adds --cap-drop=ALL --security-opt=no-new-privileges:true; "
         "later options override them"),
    ]
    assert docker.names() == ["create", "inspect", "remove"]  # nothing is started
    assert docker.calls[0][1] == ["--pull=never", "img"]      # and nothing is pulled


def test_audit_of_a_root_image_is_the_same_with_and_without_mounts(capsys):
    assert audit(FakeDocker(image_user=""), "img") == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == ("image img: would run as uid 0 (local user root), gid 0 (local group root); "
                      "docker run would run it as nobody (65534:65534) instead")
    assert len(out) == 2  # one outcome, then the line about the defaults


def test_audit_predicts_a_refusal_without_mounts_and_exits_one(capsys):
    assert audit(FakeDocker(image_user="web"), "img") == 1
    out = capsys.readouterr().out
    assert ("image img, without bind mounts: would be refused (runs as uid 1000 (local user daniel), "
            "gid 1000 (local group daniel)): the image would run with uid 1000, which exists on this host "
            "(local user daniel)") in out
    assert "image img, with bind mounts or devices: would run as uid 1000 (local user daniel)" in out
    assert "pass --user UID:GID, --as NAME or --as-me to choose a user yourself" in out


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
    assert docker_cli.main(["audit", "img"]) == 0
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
    assert "dcompose: Resolving user alice to uid 4242, gid 4343" in capsys.readouterr().err


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
