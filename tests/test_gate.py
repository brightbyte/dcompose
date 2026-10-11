import pytest
from fakes import GROUP, PASSWD, Local

from dcompose import docker_cli, gate, ids
from dcompose.dockerclient import DockerError, first_file_of_tar

DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]


class FakeDocker:
    """Records calls. `image_user` is the image's USER; `container_user` is what the container reports."""

    def __init__(self, image_user="", container_user=None, image="img", command=None, passwd=PASSWD,
                 group=GROUP, open_stdin=False, create_code=0, context="default", image_missing=False):
        self.image_user = image_user
        self.container_user = image_user if container_user is None else container_user
        self.image, self.command = image, command or []
        self.passwd, self.group = passwd, group
        self.open_stdin, self.create_code, self.current_context = open_stdin, create_code, context
        self.image_missing = image_missing
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
            "OpenStdin": self.open_stdin}}

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
    return gate.Context(docker, ids.DEFAULT_ID_RANGE, Local())


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


def test_an_image_choosing_a_low_user_itself_is_refused_and_the_container_removed(capsys):
    docker = FakeDocker(image_user="web")  # uid 1000: below the range, and it exists on this host

    assert gate.run(ctx(docker), ["img"]) == 1

    err = capsys.readouterr().err
    assert "uid 1000, outside the allowed range" in err and "pass --user" in err
    assert docker.names() == ["create", "inspect", "remove"]  # never started


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
    ["--user", "1000:1000"], ["-u", "root"], ["--user=0"], ["--current-user"], ["--user", "me"],
])
def test_a_user_on_the_command_line_prevents_the_fallback(flags, capsys):
    docker = FakeDocker(image_user="")  # root, which would fall back without the flag
    context = gate.Context(docker, ids.DEFAULT_ID_RANGE, Local(), current_user=(4242, 4343))

    assert gate.run(context, [*flags, "img"]) == 42

    assert docker.names().count("create") == 1
    assert "nobody" not in capsys.readouterr().err


def test_current_user_means_the_callers_ids():
    docker = FakeDocker(image_user="")
    context = gate.Context(docker, ids.DEFAULT_ID_RANGE, Local(), current_user=(4242, 4343))
    gate.run(context, ["--current-user", "img"])
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
    assert "uid 0" in gate.check_existing(ctx(docker), ["c1"])[0]


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
    bad = FakeDocker(image_user="")
    assert "web1: the image would run with uid 0" in gate.check_existing(ctx(bad), ["web1"])[0]
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


def test_bad_id_range_is_refused(routed, monkeypatch, capsys):
    monkeypatch.setenv("DCOMPOSE_ID_RANGE", "nonsense")
    assert docker_cli.main(["run", "img"]) == 1
    assert "DCOMPOSE_ID_RANGE" in capsys.readouterr().err


def test_id_range_setting(monkeypatch):
    assert ids.id_range({}) == ids.DEFAULT_ID_RANGE
    assert ids.id_range({"DCOMPOSE_ID_RANGE": "200000-265535"}) == (200000, 265535)
    for bad in ("1", "5-1", "a-b", "-5"):
        with pytest.raises(ValueError):
            ids.id_range({"DCOMPOSE_ID_RANGE": bad})


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


def test_audit_accepts_an_image_with_a_suitable_user(capsys):
    docker = FakeDocker(image_user="app")
    assert audit(docker, "img") == 0
    out = capsys.readouterr().out
    assert "image img: runs as uid 100000, gid 100001; accepted" in out
    assert "docker run also adds --cap-drop=ALL --security-opt=no-new-privileges:true" in out
    assert docker.names() == ["create", "inspect", "remove"]  # nothing is started
    assert docker.calls[0][1] == ["--pull=never", "img"]      # and nothing is pulled


def test_audit_predicts_the_fallback_and_exits_zero(capsys):
    assert audit(FakeDocker(image_user=""), "img") == 0
    out = capsys.readouterr().out
    assert "would run as uid 0, gid 0; docker run would run it as nobody (65534:65534) instead" in out
    assert "pass --user or --current-user" in out


def test_audit_predicts_a_refusal_and_exits_one(capsys):
    assert audit(FakeDocker(image_user="web"), "img") == 1
    out = capsys.readouterr().out
    assert "image img: would be refused (runs as uid 1000, gid 1000)" in out
    assert "outside the allowed range" in out


def test_audit_with_a_user_does_not_check_the_image(capsys):
    docker = FakeDocker(image_user="")
    assert audit(docker, "--user", "1000", "img") == 0
    assert "the user is set on the command line" in capsys.readouterr().out
    assert docker.calls[0][1] == ["--pull=never", "--user=1000", "img"]


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


def test_default_id_range_admits_the_distroless_convention():
    assert ids.DEFAULT_ID_RANGE[0] == 65532
