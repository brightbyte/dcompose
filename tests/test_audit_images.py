"""`audit` and `harden` pull and build as `up` would, then say what happens to services without a user."""
import os

from fakes import FakeImages, install_tools, make_tools, runtime

from dockscreen import commands, screen
from dockscreen.verdict import BAD, GOOD, WARN

UID, GID = os.getuid(), os.getgid()


def project(**services):
    """Services set up to pass everything except what the test is about; none sets a user by default."""
    hardened = {"cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
    return {"name": "proj", "services": {
        name: {"image": f"{name}:1", **hardened, **fields} for name, fields in services.items()}}


def setup(monkeypatch, tmp_path, config, images, **kwargs):
    monkeypatch.setattr(screen, "inspect", lambda global_args, runtime: (config, str(tmp_path)))
    tools, recorder = make_tools(images, **kwargs)
    install_tools(monkeypatch, tools)
    return recorder


def pulls(recorder):
    return [cmd[-2:] for cmd in recorder.children if "pull" in cmd]


# --- audit ----------------------------------------------------------------------

def test_audit_pulls_and_says_what_happens_to_each_service_without_a_user(monkeypatch, capsys, tmp_path):
    config = project(web={}, db={}, cache={"user": "65534:65534"})
    images = FakeImages(users={"web:1": "", "db:1": "app", "cache:1": ""}, local={"db:1"})
    recorder = setup(monkeypatch, tmp_path, config, images, active=("web", "db", "cache"))

    assert commands.audit([], [], runtime()) == 0

    captured = capsys.readouterr()
    assert "audit passed" in captured.err
    # said before the pulling starts, on stderr so that the report on stdout stays clean
    assert captured.err.index("pulling or building the images") < captured.err.index("audit passed")
    assert "pulling or building" not in captured.out
    assert captured.out.splitlines() == [
        (f"{GOOD} service db: no user set; image db:1 runs as uid 100000 (no local user), "
         "gid 100001 (no local group); accepted"),
        (f"{WARN} service web: no user set; image web:1 would run as root; dockscreen runs it as the "
         "default user (65534:65534)"),
    ]
    assert [cmd[-3:] for cmd in recorder.children] == [["pull", "cache", "web"]]  # db is already local


def test_audit_refuses_an_image_that_chose_a_low_user(monkeypatch, capsys, tmp_path):
    config = project(web={})
    setup(monkeypatch, tmp_path, config, FakeImages(users={"web:1": "web"}))

    assert commands.audit([], [], runtime()) == 1

    assert "service web: image web:1: the image's uid 1000 exists on this host" in capsys.readouterr().err


def test_audit_does_not_pull_or_build_a_project_that_fails_the_static_checks(monkeypatch, capsys, tmp_path):
    config = project(web={"privileged": True})
    recorder = setup(monkeypatch, tmp_path, config, FakeImages(users={"web:1": ""}))

    assert commands.audit([], [], runtime()) == 1

    captured = capsys.readouterr()
    assert "privileged is not allowed" in captured.err
    assert "nothing was pulled or built" in captured.out
    assert recorder.children == [] and recorder.captured == []


def test_a_failed_pull_fails_the_audit_rather_than_refusing(monkeypatch, capsys, tmp_path):
    config = project(web={})
    setup(monkeypatch, tmp_path, config, FakeImages(users={}, local=set()), codes={"pull": 1})
    assert commands.audit([], [], runtime()) == 3
    assert capsys.readouterr().err.splitlines()[-2:] == [
        f"[dockscreen] {BAD} docker compose pull web failed", "[dockscreen] \u2757 audit failed"]


def test_a_config_compose_cannot_read_fails_the_audit(monkeypatch, capsys):
    def unreadable(global_args, runtime):
        raise screen.InspectError("docker compose config failed:\nbad yaml")
    monkeypatch.setattr(screen, "inspect", unreadable)
    assert commands.audit([], ["--brief"], runtime()) == 3
    assert capsys.readouterr().out == "\u2757 failed: docker compose config failed:\\x0abad yaml\n"


def test_a_project_refused_before_inspection_is_refused_not_failed(monkeypatch, capsys):
    def sensitive(global_args, runtime):
        raise screen.ScreenError("the project directory /home/me contains /home/me")
    monkeypatch.setattr(screen, "inspect", sensitive)
    assert commands.audit([], [], runtime()) == 1
    assert f"[dockscreen] {BAD} refusing: the project directory /home/me" in capsys.readouterr().err


def test_brief_prints_only_the_verdict(monkeypatch, capsys, tmp_path):
    config = project(web={}, db={})
    setup(monkeypatch, tmp_path, config, FakeImages(users={"web:1": "app", "db:1": "web"}),
          active=("web", "db"))
    assert commands.audit([], ["--brief"], runtime()) == 1
    captured = capsys.readouterr()
    assert captured.out == ("\u274c refused: service db: image db:1: the image's uid 1000 exists on this "
                            "host (local user daniel); the image's gid 1000 exists on this host "
                            "(local group daniel); set user: to choose one, or give its repository a "
                            f"user in [image_users] in {runtime().config_file}\n")
    assert captured.err == ""


def test_brief_says_passed(monkeypatch, capsys, tmp_path):
    setup(monkeypatch, tmp_path, project(web={}), FakeImages(users={"web:1": "app"}))
    assert commands.audit([], ["--brief"], runtime()) == 0
    assert capsys.readouterr().out == "\u2705 passed\n"


def test_audit_takes_only_brief(capsys):
    assert commands.audit([], ["--remote"], runtime()) == 2
    assert "usage: dockscreen compose [compose options] audit [--brief]" in capsys.readouterr().err


# --- harden ---------------------------------------------------------------------

def test_harden_writes_nothing_for_a_root_image_and_never_the_pull_pin(monkeypatch, capsys, tmp_path):
    config = project(web={"pull_policy": "always"}, db={})
    images = FakeImages(users={"web:1": "", "db:1": "app"})
    recorder = setup(monkeypatch, tmp_path, config, images, active=("web", "db"))

    assert commands.harden([], [], runtime()) == 0

    out = capsys.readouterr().out
    assert out.splitlines()[-1] == "services: {}"       # nothing is needed: dockscreen does it all
    assert "pull_policy" not in out and "never" not in out  # the pin lives in the generated file only
    assert "user:" not in out.replace("sets no user", "")
    assert pulls(recorder) == [["pull", "web"]]  # the project's always policy: the images were looked at
    assert ("runs a service that sets no user as the configured default user when its image would run "
            "as root") in out


def test_harden_sets_a_user_where_the_image_chose_one_that_is_not_acceptable(monkeypatch, capsys, tmp_path):
    config = project(web={}, db={})
    images = FakeImages(users={"web:1": "web", "db:1": "app"})
    setup(monkeypatch, tmp_path, config, images, active=("web", "db"))

    assert commands.harden([], [], runtime()) == 0

    out = capsys.readouterr().out
    assert ("# note: service web: image web:1 chose a user that is not acceptable, "
            "so user is set explicitly") in out
    body = out.split("services:", 1)[1]
    assert '"web":' in body and '    user: "${UID}:${GID}"' in body
    assert "dockscreen allows that only with --allow-me" in out
    assert '"db"' not in body  # its image's own user was fine


def test_harden_does_not_pull_or_build_while_other_problems_remain(monkeypatch, capsys, tmp_path):
    config = project(web={"build": {"context": "/"}})  # a build context outside the project: no safe fix
    recorder = setup(monkeypatch, tmp_path, config, FakeImages(users={"web:1": ""}))

    assert commands.harden([], [], runtime()) == 1

    captured = capsys.readouterr()
    assert "nothing was pulled or built" in captured.err
    assert "cannot fix automatically" in captured.err
    assert recorder.children == []


def test_harden_reports_a_failed_pull_as_a_problem_it_cannot_fix(monkeypatch, capsys, tmp_path):
    setup(monkeypatch, tmp_path, project(web={}), FakeImages(users={}, local=set()), codes={"pull": 1})
    assert commands.harden([], [], runtime()) == 1
    assert "cannot fix automatically: docker compose pull web failed" in capsys.readouterr().err


def test_audit_does_not_announce_pulling_when_the_static_checks_fail(monkeypatch, capsys, tmp_path):
    setup(monkeypatch, tmp_path, project(web={"privileged": True}), FakeImages())
    commands.audit([], [], runtime())
    assert "pulling or building" not in capsys.readouterr().err


def test_audit_lists_the_variables_taken_from_the_shell(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("FROMSHELL", "secret")
    config = project(web={"user": f"{UID}:{GID}", "environment": {"FROMSHELL": "secret"}})
    setup(monkeypatch, tmp_path, config, FakeImages(users={"web:1": ""}))

    commands.audit([], [], runtime())

    out = capsys.readouterr().out
    assert "service web: environment variables taken from your shell: FROMSHELL" in out
    assert "secret" not in out


def test_a_remote_daemon_is_refused_before_anything_is_pulled(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("DOCKER_HOST", "tcp://build-box:2375")
    recorder = setup(monkeypatch, tmp_path, project(web={}), FakeImages(users={"web:1": ""}))

    assert commands.audit([], [], runtime()) == 1
    assert commands.harden([], [], runtime()) == 1

    assert "the daemon is not the default local one" in capsys.readouterr().err
    assert recorder.children == []
