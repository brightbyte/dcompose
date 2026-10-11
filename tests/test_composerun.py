import os

import pytest
from fakes import FakeImages, make_tools, read_raw, runtime

from dockscreen import argscan, composerun, hostusers, screen

UID, GID = os.getuid(), os.getgid()


def project_config(**service):
    return {"name": "proj", "services": {"web": {"image": "x:1", "user": "65534:65534", **service}}}


def inspect_as(monkeypatch, tmp_path, config):
    monkeypatch.setattr(screen, "inspect", lambda global_args, runtime: (config, str(tmp_path)))


def up(argv, idx, tools, allow_me=False):
    return composerun.run(argv, idx, runtime(), tools, allow_me=allow_me)


def last(recorder):
    """The command that was run on the project, and the config behind it."""
    return recorder.children[-1], recorder.configs[-1]


def test_compose_runs_from_the_hardened_config_with_the_project_pinned(monkeypatch, tmp_path, capsys):
    inspect_as(monkeypatch, tmp_path, project_config())
    tools, recorder = make_tools(FakeImages(users={"x:1": "app"}), codes={"up": 7})

    code = up(["-f", "a.yml", "--profile", "x", "up", "-d", "web"], 4, tools)

    assert code == 7  # compose's exit code
    cmd, config = last(recorder)
    path = cmd[cmd.index("-f") + 1]
    # our file, directory and name replace the user's; other global options and the subcommand are kept
    assert cmd[1:] == ["compose", "--profile", "x", "-f", path, "--project-directory", str(tmp_path),
                       "--project-name", "proj", "up", "-d", "web"]
    web = config["services"]["web"]
    assert web["cap_drop"] == ["ALL"] and web["security_opt"] == ["no-new-privileges:true"]
    assert "hardening defaults added: web (cap_drop, security_opt)" in capsys.readouterr().err


def test_every_generated_file_is_private_and_removed_afterwards(monkeypatch, tmp_path):
    inspect_as(monkeypatch, tmp_path, project_config())
    modes = []
    tools, recorder = make_tools(FakeImages(users={"x:1": "app"}), on_child=lambda cmd: modes.append(
        os.stat(cmd[cmd.index("-f") + 1]).st_mode & 0o777))

    up(["up"], 0, tools)

    assert modes and set(modes) == {0o600}
    for cmd in recorder.children:
        path = cmd[cmd.index("-f") + 1]
        assert not os.path.exists(path) and not os.path.exists(os.path.dirname(path))


def test_a_config_with_problems_never_reaches_compose_and_nothing_is_pulled(monkeypatch, tmp_path, capsys):
    inspect_as(monkeypatch, tmp_path, project_config(privileged=True))
    tools, recorder = make_tools(FakeImages())

    assert up(["up"], 0, tools) == 1

    assert "privileged is not allowed" in capsys.readouterr().err
    assert recorder.children == [] and recorder.captured == []  # not even `config --services`


def test_what_is_checked_is_what_runs(monkeypatch, tmp_path):
    inspect_as(monkeypatch, tmp_path, project_config(ports=["80:80"], labels={"a": "b"}))
    tools, recorder = make_tools(FakeImages(users={"x:1": "app"}))
    up(["up"], 0, tools)
    web = last(recorder)[1]["services"]["web"]
    assert web["ports"] == ["80:80"] and web["labels"] == {"a": "b"} and last(recorder)[1]["name"] == "proj"


def test_inspection_failure_and_missing_project_name_are_refusals(monkeypatch, tmp_path, capsys):
    def boom(global_args, runtime):
        raise screen.ScreenError("no compose file found")
    monkeypatch.setattr(screen, "inspect", boom)
    tools, recorder = make_tools()
    assert up(["up"], 0, tools) == 1
    assert "no compose file found" in capsys.readouterr().err

    nameless = project_config()
    del nameless["name"]
    inspect_as(monkeypatch, tmp_path, nameless)
    assert up(["up"], 0, tools) == 1
    assert "config has no project name" in capsys.readouterr().err
    assert recorder.children == []


def test_the_callers_own_ids_need_allow_me(monkeypatch, tmp_path, capsys):
    inspect_as(monkeypatch, tmp_path, project_config(user=f"{UID}:{GID}"))
    tools, recorder = make_tools(FakeImages(users={"x:1": "app"}))

    assert up(["up"], 0, tools) == 1
    assert f"uid {UID} is yours; pass --allow-me to allow it" in capsys.readouterr().err
    assert recorder.children == []

    assert up(["up"], 0, tools, allow_me=True) == 0
    assert last(recorder)[1]["services"]["web"]["user"] == f"{UID}:{GID}"


def test_run_with_a_user_on_the_command_line_skips_deciding_that_services_image(
        monkeypatch, tmp_path, capsys):
    config = no_user()
    inspect_as(monkeypatch, tmp_path, config)
    tools, recorder = make_tools(FakeImages(users={"x:1": "web"}))  # uid 1000: would be refused

    assert up(["run", "--rm", "-u", "1000:1000", "web", "sh"], 0, tools) == 0
    assert last(recorder)[0][-6:] == ["run", "--rm", "-u", "1000:1000", "web", "sh"]


def test_run_as_a_local_user_reaches_compose_as_numeric_ids(monkeypatch, tmp_path, capsys):
    inspect_as(monkeypatch, tmp_path, no_user())
    monkeypatch.setattr(hostusers, "resolve_account",
                        lambda name, _: ("1000:1000", [f"Resolving user {name} to uid 1000, gid 1000"]))
    tools, recorder = make_tools(FakeImages(users={"x:1": "web"}))  # uid 1000: would be refused

    assert up(["run", "--as", "alice", "web", "sh"], 0, tools) == 0
    assert last(recorder)[0][-4:] == ["run", "--user=1000:1000", "web", "sh"]
    assert "Resolving user alice" in capsys.readouterr().err


def test_run_as_me_reaches_compose_as_the_callers_ids(monkeypatch, tmp_path):
    inspect_as(monkeypatch, tmp_path, no_user())
    tools, recorder = make_tools(FakeImages(users={"x:1": "web"}))

    assert up(["run", "--as-me", "web", "sh"], 0, tools) == 0
    assert last(recorder)[0][-4:] == ["run", f"--user={os.getuid()}:{os.getgid()}", "web", "sh"]


@pytest.mark.parametrize("args, message", [
    (["run", "-u", "postgres", "web"], "--user takes numeric ids as uid:gid, not 'postgres'"),
    (["run", "--user=1000", "web"], "give the group too"),
])
def test_run_takes_numeric_users_only(monkeypatch, tmp_path, capsys, args, message):
    inspect_as(monkeypatch, tmp_path, no_user())
    tools, recorder = make_tools(FakeImages(users={"x:1": "app"}))
    assert up(args, 0, tools) == 1
    assert message in capsys.readouterr().err and recorder.children == []


def test_no_defaults_notice_when_nothing_was_added(monkeypatch, tmp_path, capsys):
    hardened = project_config(cap_drop=["ALL"], security_opt=["no-new-privileges:true"])
    inspect_as(monkeypatch, tmp_path, hardened)
    tools, _ = make_tools(FakeImages(users={"x:1": "app"}))
    up(["up"], 0, tools)
    assert capsys.readouterr().err == ""


# --- services that set no user ---------------------------------------------------

def no_user(**fields):
    config = project_config(cap_drop=["ALL"], security_opt=["no-new-privileges:true"], **fields)
    del config["services"]["web"]["user"]
    return config


def test_a_root_image_runs_as_the_default_user_with_the_image_pinned_in_the_generated_file(
        monkeypatch, tmp_path, capsys):
    inspect_as(monkeypatch, tmp_path, no_user(pull_policy="always"))
    tools, recorder = make_tools(FakeImages(users={"x:1": ""}), codes={"up": 3})

    assert up(["up", "-d"], 0, tools) == 3

    web = last(recorder)[1]["services"]["web"]
    assert web["user"] == "65534:65534"
    # in the generated file only: the image that was checked is the one that runs
    assert web["pull_policy"] == "never"
    pulled = [cmd[-2:] for cmd in recorder.children if "pull" in cmd]
    assert pulled == [["pull", "web"]]    # the project's policy (always) was applied first
    assert ("service web: image x:1 would run as root; dockscreen runs it as the default user "
            "(65534:65534)") in capsys.readouterr().err


def test_images_are_acquired_from_a_config_that_still_has_the_projects_pull_policy(monkeypatch, tmp_path):
    config = no_user(pull_policy="always")
    inspect_as(monkeypatch, tmp_path, config)
    tools, recorder = make_tools(FakeImages(users={"x:1": ""}))
    up(["up"], 0, tools)
    # the config the images were acquired from still has the project's own policy
    assert recorder.configs[0]["services"]["web"]["pull_policy"] == "always"
    assert "user" not in recorder.configs[0]["services"]["web"]
    assert config["services"]["web"]["pull_policy"] == "always"


def test_an_acceptable_image_user_is_kept_but_pinned_as_numbers(monkeypatch, tmp_path, capsys):
    inspect_as(monkeypatch, tmp_path, no_user())
    tools, recorder = make_tools(FakeImages(users={"x:1": "app"}))

    assert up(["up"], 0, tools) == 0

    web = last(recorder)[1]["services"]["web"]
    assert web["user"] == "100000:100001" and web["pull_policy"] == "never"
    assert "default user" not in capsys.readouterr().err


def test_an_image_that_chose_a_low_user_is_refused_before_anything_runs(monkeypatch, tmp_path, capsys):
    inspect_as(monkeypatch, tmp_path, no_user())
    tools, recorder = make_tools(FakeImages(users={"x:1": "web"}))

    assert up(["up"], 0, tools) == 1

    assert "service web: image x:1: the image's uid 1000 exists on this host" in capsys.readouterr().err
    assert all("up" not in cmd for cmd in recorder.children)


def test_failing_to_pull_stops_the_run(monkeypatch, tmp_path, capsys):
    inspect_as(monkeypatch, tmp_path, no_user())
    tools, recorder = make_tools(FakeImages(users={"x:1": "app"}, local=set()), codes={"pull": 1})
    assert up(["up"], 0, tools) == 1
    assert "docker compose pull web failed" in capsys.readouterr().err
    assert [cmd[-2:] for cmd in recorder.children] == [["pull", "web"]]


def test_a_service_that_is_not_started_gets_the_default_user_as_a_fail_safe(monkeypatch, tmp_path):
    config = no_user()
    config["services"]["debug"] = {
        "image": "d:1", "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
    inspect_as(monkeypatch, tmp_path, config)
    tools, recorder = make_tools(FakeImages(users={"x:1": "app", "d:1": ""}), active=("web",))

    up(["up", "web"], 0, tools)

    services = last(recorder)[1]["services"]
    assert services["debug"]["user"] == "65534:65534" and "pull_policy" not in services["debug"]
    assert services["web"]["user"] == "100000:100001"


@pytest.mark.parametrize("args, kept", [
    (["-f", "a.yml", "-p", "n", "--project-directory", "d", "--profile", "x"], ["--profile", "x"]),
    (["--file=a.yml", "--project-name=n", "--project-directory=d"], []),
    (["-fa.yml", "-pn"], []),
    (["--env-file", "e", "--ansi", "never"], ["--env-file", "e", "--ansi", "never"]),
    ([], []),
])
def test_strip_options(args, kept):
    assert argscan.strip_options(args, composerun.REPLACED_OPTIONS) == kept


def test_run_child_exit_codes_and_signals():
    assert composerun.run_child(["true"]) == 0
    assert composerun.run_child(["sh", "-c", "exit 3"]) == 3
    assert composerun.run_child(["sh", "-c", "kill -TERM $$"]) == 128 + 15
    assert composerun.run_child(["/nonexistent/docker"]) == 127


def test_run_child_passes_termination_to_the_child_and_restores_handlers():
    import signal
    import threading
    before = signal.getsignal(signal.SIGTERM)
    timer = threading.Timer(0.3, lambda: os.kill(os.getpid(), signal.SIGTERM))
    timer.start()
    code = composerun.run_child(["sh", "-c", "trap 'exit 9' TERM; while true; do sleep 0.1; done"])
    timer.cancel()
    assert code == 9
    assert signal.getsignal(signal.SIGTERM) == before


def test_dollars_are_written_as_compose_printed_them(monkeypatch, tmp_path):
    # `config` prints a literal $ as $$, and compose reads $$ back as a literal $: escaping again
    # would make `$$` into `$$$$` and the config would no longer be the one that was checked
    inspect_as(monkeypatch, tmp_path, project_config(pid="$${P:-host}", labels={"a": "$$x"}))
    raw = []
    tools, _ = make_tools(FakeImages(users={"x:1": "app"}),
                                 on_child=lambda cmd: raw.append(read_raw(cmd)))

    assert up(["up"], 0, tools) == 0

    assert all('"$${P:-host}"' in text and '"$$x"' in text for text in raw)


def test_a_config_compose_would_read_differently_is_refused_and_not_run(monkeypatch, tmp_path, capsys):
    inspect_as(monkeypatch, tmp_path, project_config(pid="${P:-host}"))
    tools, recorder = make_tools(FakeImages(users={"x:1": "app"}), reads=lambda c: {**c, "name": "other"})

    assert up(["up"], 0, tools) == 1

    assert "reads the checked config differently at config.name" in capsys.readouterr().err
    assert recorder.children == []


def test_variables_taken_from_the_shell_are_announced_by_name_and_service_but_not_run_differently(
        monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("FROMSHELL", "secret")
    inspect_as(monkeypatch, tmp_path, project_config(environment={"FROMSHELL": "secret", "OWN": "x"}))
    tools, recorder = make_tools(FakeImages(users={"x:1": "app"}))

    assert up(["up"], 0, tools) == 0

    err = capsys.readouterr().err
    assert "service web: environment variables taken from your shell: FROMSHELL" in err
    assert "secret" not in err
    assert last(recorder)[1]["services"]["web"]["environment"] == {"FROMSHELL": "secret", "OWN": "x"}


@pytest.mark.parametrize("env", [
    {"DOCKER_HOST": "tcp://build-box:2375"}, {"DOCKER_HOST": "ssh://me@box"}, {"DOCKER_CONTEXT": "prod"}])
def test_a_remote_daemon_is_refused_because_paths_and_ids_mean_nothing_there(
        monkeypatch, tmp_path, capsys, env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    inspect_as(monkeypatch, tmp_path, project_config())
    tools, recorder = make_tools(FakeImages(users={"x:1": "app"}))

    assert up(["up"], 0, tools) == 1

    assert "the daemon is not the default local one" in capsys.readouterr().err
    assert recorder.children == [] and recorder.captured == []


def test_a_context_option_is_refused_too(monkeypatch, tmp_path, capsys):
    inspect_as(monkeypatch, tmp_path, project_config())
    tools, recorder = make_tools(FakeImages(users={"x:1": "app"}))
    assert up(["--context", "prod", "up"], 2, tools) == 1
    assert recorder.children == []
