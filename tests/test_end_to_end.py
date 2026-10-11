"""dockscreen against a fake `docker` script: real subprocesses, real files, no real docker."""
import io
import json
import os
import stat
import tarfile

import fakes
import pytest
from fakes import PASSWD

from dockscreen import compose_cli, composerun, realdocker
from dockscreen.dockerclient import Docker

UID, GID = os.getuid(), os.getgid()

# Canned answers come from files next to the script; every call is appended to `calls`.
FAKE_DOCKER = """#!/bin/sh
DIR=$(dirname "$0")
printf '%s\\n' "@@call" "$@" >> "$DIR/calls"
FILE=""; PREV=""
for ARG in "$@"; do [ "$PREV" = "-f" ] && FILE="$ARG"; PREV="$ARG"; done
case " $* " in
  *" config --services "*) echo web; exit 0 ;;
  *" config "*)
    # compose reads the generated file back; the project's own config otherwise
    if [ -n "$FILE" ]; then cat "$FILE"; else cat "$DIR/config.json"; fi; exit 0 ;;
  *" pull "*) touch "$DIR/pulled"; exit 0 ;;
  *" build "*) exit 0 ;;
esac
case "$1 $2" in
  "context show") echo default; exit 0 ;;
  "image inspect") [ -e "$DIR/pulled" ] || exit 1; cat "$DIR/image.json"; exit 0 ;;
  "container inspect") cat "$DIR/container.json"; exit 0 ;;
esac
case "$1" in
  create) echo cid; exit 0 ;;
  rm) exit 0 ;;
  cp) case "$3" in cid:/etc/passwd) cat "$DIR/passwd.tar" ;; *) exit 1 ;; esac; exit 0 ;;
esac
while [ $# -gt 0 ]; do
  if [ "$1" = "-f" ]; then cp "$2" "$DIR/file-read"; echo "$2" > "$DIR/file-path"; fi
  shift
done
exit 5
"""


def set_image_user(fake_dir, user):
    (fake_dir / "image.json").write_text(json.dumps([{"Config": {"User": user}}]))
    (fake_dir / "container.json").write_text(json.dumps([
        {"Id": "cid", "Image": "x:1", "Config": {"Image": "x:1", "User": user}}]))


def tar_of(name, text):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        data = text.encode()
        info = tarfile.TarInfo(name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@pytest.fixture
def project(tmp_path, monkeypatch):
    fake_dir = tmp_path / "fake"
    fake_dir.mkdir()
    docker = fake_dir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    (fake_dir / "passwd.tar").write_bytes(tar_of("passwd", PASSWD))
    set_image_user(fake_dir, "")
    monkeypatch.setattr(realdocker, "locate", lambda settings, env: str(docker))
    # the real tools: real subprocesses against the fake script
    tools = composerun.composeimages.Tools(
        composerun.imagedecision.Context(Docker(str(docker)), fakes.rules(), fakes.runtime(me=(1000, 1000))),
        lambda cmd: __import__("subprocess").run(cmd, capture_output=True, text=True, check=False),
        composerun.run_child)
    fakes.install_tools(monkeypatch, tools)

    work = tmp_path / "work"
    work.mkdir()
    (work / "compose.yaml").write_text("services: {}\n")
    monkeypatch.chdir(work)

    def configure(**service):
        config = {"name": "proj", "services": {"web": {"image": "x:1", **service}}}
        (fake_dir / "config.json").write_text(json.dumps(config))

    configure(user="65534:65534")
    return fake_dir, work, configure


def calls(fake_dir):
    groups = []
    for line in (fake_dir / "calls").read_text().splitlines():
        if line == "@@call":
            groups.append([])
        else:
            groups[-1].append(line)
    return groups


def compose_calls(fake_dir):
    return [c for c in calls(fake_dir) if c[0] == "compose"]


def test_up_pulls_then_runs_compose_from_the_hardened_file_and_returns_its_exit_code(project, capsys):
    fake_dir, work, _ = project

    assert compose_cli.main(["--profile", "dev", "up", "-d"]) == 5

    config_call, verify_call, services_call, pull_call, up_call = compose_calls(fake_dir)
    assert config_call[:3] == ["compose", "--profile", "dev"] and "--no-env-resolution" in config_call
    assert config_call[config_call.index("--profile", 3) + 1] == "*"  # every profile is inspected
    assert verify_call[-4:] == ["config", "--format", "json", "--no-env-resolution"]
    assert services_call[-2:] == ["config", "--services"] and pull_call[-2:] == ["pull", "web"]
    path = (fake_dir / "file-path").read_text().strip()
    assert up_call == ["compose", "--profile", "dev", "-f", path, "--project-directory", str(work.resolve()),
                       "--project-name", "proj", "up", "-d"]
    hardened = json.loads((fake_dir / "file-read").read_text())
    assert hardened["services"]["web"]["cap_drop"] == ["ALL"]
    assert not os.path.exists(path)  # removed once compose has exited
    assert "hardening defaults added: web (cap_drop, security_opt)" in capsys.readouterr().err


def test_a_root_image_is_run_as_the_default_user_from_a_pinned_generated_file(project, capsys):
    fake_dir, _, configure = project
    configure(pull_policy="always")  # no user: the image decides

    assert compose_cli.main(["up"]) == 5

    assert [c[-2:] for c in compose_calls(fake_dir)][2:4] == [["config", "--services"], ["pull", "web"]]
    create = next(c for c in calls(fake_dir) if c[0] == "create")
    assert create == ["create", "--pull=never", "--", "x:1"]  # looked at, never started
    assert any(c[0] == "rm" for c in calls(fake_dir))
    web = json.loads((fake_dir / "file-read").read_text())["services"]["web"]
    assert web["user"] == "65534:65534" and web["pull_policy"] == "never"
    err = capsys.readouterr().err
    assert "image x:1 would run as root; dockscreen runs it as the default user (65534:65534)" in err


def test_an_image_that_chose_a_low_user_is_refused_and_nothing_starts(project, capsys):
    fake_dir, _, configure = project
    configure()
    set_image_user(fake_dir, "web")  # uid 1000 in the passwd above, and the fake host has it

    assert compose_cli.main(["up"]) == 1

    assert not (fake_dir / "file-read").exists()  # compose never ran on the project
    err = capsys.readouterr().err
    assert "service web: image x:1: the image's uid 1000 exists on this host" in err


def test_a_refused_project_never_starts_compose(project, capsys):
    fake_dir, _, _ = project
    (fake_dir / "config.json").write_text(json.dumps(
        {"name": "proj", "services": {"web": {"image": "x", "user": "0:0", "privileged": True}}}))

    assert compose_cli.main(["up"]) == 1

    # only the config call and the look at the daemon's context: nothing was pulled either
    assert [c[0] for c in calls(fake_dir)] == ["compose", "context"]
    err = capsys.readouterr().err
    assert "privileged is not allowed" in err and "user '0:0': uid 0 is root" in err
