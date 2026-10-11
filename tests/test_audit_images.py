"""`audit` and `harden` pull and build as `up` would, then say what happens to services without a user."""
import os

from fakes import FakeImages, make_tools

from dcompose import commands, composerun, guard

UID, GID = os.getuid(), os.getgid()


def project(**services):
    """Services set up to pass everything except what the test is about; none sets a user by default."""
    hardened = {"cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
    return {"name": "proj", "services": {
        name: {"image": f"{name}:1", **hardened, **fields} for name, fields in services.items()}}


def setup(monkeypatch, tmp_path, config, images, **kwargs):
    monkeypatch.setattr(guard, "inspect", lambda global_args: (config, str(tmp_path)))
    tools, recorder = make_tools(images, **kwargs)
    monkeypatch.setattr(composerun, "default_tools", lambda: tools)
    return recorder


def pulls(recorder):
    return [cmd[-2:] for cmd in recorder.children if "pull" in cmd]


# --- audit ----------------------------------------------------------------------

def test_audit_pulls_and_says_what_happens_to_each_service_without_a_user(monkeypatch, capsys, tmp_path):
    config = project(web={}, db={}, cache={"user": f"{UID}:{GID}"})
    images = FakeImages(users={"web:1": "", "db:1": "app", "cache:1": ""}, local={"db:1"})
    recorder = setup(monkeypatch, tmp_path, config, images, active=("web", "db", "cache"))

    assert commands.audit([], []) == 0

    captured = capsys.readouterr()
    assert "audit passed" in captured.err
    assert captured.out.splitlines() == [
        "service db: no user set; image db:1 runs as uid 100000, gid 100001; accepted",
        "service web: no user set; image web:1 would run as root; dcompose runs it as nobody (65534:65534)",
    ]
    assert [cmd[-3:] for cmd in recorder.children] == [["pull", "cache", "web"]]  # db is already local


def test_audit_refuses_an_image_that_chose_a_low_user(monkeypatch, capsys, tmp_path):
    config = project(web={})
    setup(monkeypatch, tmp_path, config, FakeImages(users={"web:1": "web"}))

    assert commands.audit([], []) == 1

    assert "service web: image web:1: the image would run with uid 1000" in capsys.readouterr().err


def test_audit_does_not_pull_or_build_a_project_that_fails_the_static_checks(monkeypatch, capsys, tmp_path):
    config = project(web={"privileged": True})
    recorder = setup(monkeypatch, tmp_path, config, FakeImages(users={"web:1": ""}))

    assert commands.audit([], []) == 1

    captured = capsys.readouterr()
    assert "privileged is not allowed" in captured.err
    assert "nothing was pulled or built" in captured.out
    assert recorder.children == [] and recorder.captured == []


def test_audit_reports_a_failed_pull(monkeypatch, capsys, tmp_path):
    config = project(web={})
    setup(monkeypatch, tmp_path, config, FakeImages(users={}, local=set()), codes={"pull": 1})
    assert commands.audit([], []) == 1
    assert "docker compose pull web failed" in capsys.readouterr().err


def test_audit_takes_no_arguments(capsys):
    assert commands.audit([], ["--remote"]) == 2
    assert "usage: dcompose [compose options] audit" in capsys.readouterr().err


# --- harden ---------------------------------------------------------------------

def test_harden_writes_nothing_for_a_root_image_and_never_the_pull_pin(monkeypatch, capsys, tmp_path):
    config = project(web={"pull_policy": "always"}, db={})
    images = FakeImages(users={"web:1": "", "db:1": "app"})
    recorder = setup(monkeypatch, tmp_path, config, images, active=("web", "db"))

    assert commands.harden([], []) == 0

    out = capsys.readouterr().out
    assert out.splitlines()[-1] == "services: {}"       # nothing is needed: dcompose does it all
    assert "pull_policy" not in out and "never" not in out  # the pin lives in the generated file only
    assert "user:" not in out.replace("sets no user", "")
    assert pulls(recorder) == [["pull", "web"]]  # the project's always policy: the images were looked at
    assert "runs a service that sets no user as nobody when its image would run as root" in out


def test_harden_sets_a_user_where_the_image_chose_one_that_is_not_acceptable(monkeypatch, capsys, tmp_path):
    config = project(web={}, db={})
    images = FakeImages(users={"web:1": "web", "db:1": "app"})
    setup(monkeypatch, tmp_path, config, images, active=("web", "db"))

    assert commands.harden([], []) == 0

    out = capsys.readouterr().out
    assert ("# note: service web: image web:1 chose a user that is not acceptable, "
            "so user is set explicitly") in out
    body = out.split("services:", 1)[1]
    assert '"web":' in body and '    user: "${DCOMPOSE_UID}:${DCOMPOSE_GID}"' in body
    assert '"db"' not in body  # its image's own user was fine


def test_harden_does_not_pull_or_build_while_other_problems_remain(monkeypatch, capsys, tmp_path):
    config = project(web={"build": {"context": "/"}})  # a build context outside the project: no safe fix
    recorder = setup(monkeypatch, tmp_path, config, FakeImages(users={"web:1": ""}))

    assert commands.harden([], []) == 1

    captured = capsys.readouterr()
    assert "nothing was pulled or built" in captured.err
    assert "cannot fix automatically" in captured.err
    assert recorder.children == []


def test_harden_reports_a_failed_pull_as_a_problem_it_cannot_fix(monkeypatch, capsys, tmp_path):
    setup(monkeypatch, tmp_path, project(web={}), FakeImages(users={}, local=set()), codes={"pull": 1})
    assert commands.harden([], []) == 1
    assert "cannot fix automatically: docker compose pull web failed" in capsys.readouterr().err
