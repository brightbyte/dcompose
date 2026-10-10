import json
import subprocess

from dcompose import commands, guard, imageinfo


class FakeRun:
    """Stands in for subprocess.run; `responses` maps (first words of the command) to (rc, out, err)."""

    def __init__(self, local=None, remote=None):
        self.local = local or {}    # image -> User
        self.remote = remote or {}  # image -> stdout or ("error", stderr)
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        image = cmd[-1]
        if cmd[:3] == ["docker", "image", "inspect"]:
            if image in self.local:
                return subprocess.CompletedProcess(cmd, 0, self.local[image] + "\n", "")
            return subprocess.CompletedProcess(cmd, 1, "", "No such image")
        outcome = self.remote[image]
        if isinstance(outcome, tuple):
            return subprocess.CompletedProcess(cmd, 1, "", outcome[1])
        return subprocess.CompletedProcess(cmd, 0, outcome, "")


def config(**services):
    return {"name": "proj", "services": services}


def test_local_images_report_their_user_and_root_when_unset():
    run = FakeRun(local={"app:1": "node", "base:1": ""})
    lines = imageinfo.describe(config(a={"image": "app:1"}, b={"image": "base:1"}), False, run)
    assert lines == [
        "service a: image app:1: default user node (local)",
        "service b: image base:1: default user root (the image sets no user) (local)",
    ]


def test_missing_images_are_not_looked_up_remotely_by_default_but_hinted():
    run = FakeRun()
    lines = imageinfo.describe(config(a={"image": "nginx:1"}), False, run)
    assert lines[0] == "service a: image nginx:1: not available locally"
    assert "--remote" in lines[-1]
    assert all(cmd[1] == "image" for cmd in run.calls)  # no registry access


def test_no_hint_when_everything_is_local():
    run = FakeRun(local={"app:1": "1000"})
    assert not any("hint" in l for l in imageinfo.describe(config(a={"image": "app:1"}), False, run))


def test_remote_lookup_reads_the_config_user():
    out = json.dumps({"config": {"User": "nginx"}})
    run = FakeRun(remote={"nginx:1": out})
    lines = imageinfo.describe(config(a={"image": "nginx:1"}), True, run)
    assert lines == ["service a: image nginx:1: default user nginx (registry)"]


def test_remote_lookup_of_multi_platform_index():
    same = json.dumps({"linux/amd64": {"config": {"User": "x"}}, "linux/arm64": {"config": {"User": "x"}}})
    differ = json.dumps({"linux/amd64": {"config": {"User": "x"}}, "linux/arm64": {"config": {}}})
    assert imageinfo.user_from_image_json(json.loads(same)) == "x"
    assert imageinfo.user_from_image_json(json.loads(differ)) == "(none), x (varies by platform)"


def test_remote_failure_is_reported_not_raised():
    run = FakeRun(remote={"priv:1": ("error", "pull access denied\nunauthorized")})
    lines = imageinfo.describe(config(a={"image": "priv:1"}), True, run)
    assert lines == ["service a: image priv:1: not available locally, registry lookup failed: unauthorized"]


def test_built_service_uses_the_compose_image_name_and_never_goes_remote():
    built = FakeRun(local={"proj-web": "app"})
    assert imageinfo.describe(config(web={"build": {"context": "."}}), True, built) == [
        "service web: image proj-web: default user app (local)"]

    unbuilt = FakeRun()
    lines = imageinfo.describe(config(web={"build": {"context": "."}, "image": "x:1"}), True, unbuilt)
    assert lines == ["service web: image x:1: not built yet (a Dockerfile's USER is not looked up)"]
    assert all(cmd[1] == "image" for cmd in unbuilt.calls)


def test_audit_prints_problems_and_image_info_and_passes_remote_through(monkeypatch, capsys, tmp_path):
    cfg = config(web={"image": "x:1", "user": "0:0"})
    monkeypatch.setattr(guard, "inspect", lambda global_args: (cfg, str(tmp_path)))
    seen = {}
    monkeypatch.setattr(imageinfo, "describe", lambda config, remote: seen.update(remote=remote) or ["INFO"])

    assert commands.audit([], ["--remote"]) == 1

    captured = capsys.readouterr()
    assert "refusing" in captured.err and "INFO" in captured.out
    assert seen == {"remote": True}


def test_audit_rejects_unknown_arguments(capsys):
    assert commands.audit([], ["--bogus"]) == 2


def test_services_that_set_a_user_are_not_described():
    run = FakeRun(local={"app:1": "node"})
    lines = imageinfo.describe(
        config(a={"image": "app:1", "user": "1:1"}, b={"image": "app:1"}), False, run)
    assert lines == ["service b: image app:1: default user node (local)"]
    assert run.calls == [["docker", "image", "inspect", "--format", "{{.Config.User}}", "--", "app:1"]]


def test_image_names_that_look_like_options_are_never_passed_to_docker():
    run = FakeRun()
    lines = imageinfo.describe(config(a={"image": "--builder=evil"}), True, run)
    assert lines == ["service a: image --builder=evil: not a valid image name"]
    assert run.calls == []


def test_image_names_follow_a_double_dash_separator():
    run = FakeRun(remote={"nginx:1": json.dumps({"config": {}})})
    imageinfo.describe(config(a={"image": "nginx:1"}), True, run)
    assert all(cmd[-2:] == ["--", "nginx:1"] for cmd in run.calls)
