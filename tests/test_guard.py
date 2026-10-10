import pytest

from dcompose import cli, guard
from dcompose.commands import COMMANDS


def test_project_directory_is_dir_of_first_file(tmp_path):
    result = guard.project_directory(["-f", "a/x.yml", "-f", "b/y.yml"], {}, str(tmp_path))
    assert result == str(tmp_path / "a")


def test_project_directory_option_wins_over_file(tmp_path):
    result = guard.project_directory(
        ["-f", "a/x.yml", "--project-directory=b"], {}, str(tmp_path))
    assert result == str(tmp_path / "b")


def test_project_directory_from_compose_file_env(tmp_path):
    env = {"COMPOSE_FILE": "a/x.yml:b/y.yml"}
    assert guard.project_directory([], env, str(tmp_path)) == str(tmp_path / "a")


def test_project_directory_searches_parents(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / "sub").mkdir()
    assert guard.project_directory([], {}, str(tmp_path / "sub")) == str(tmp_path)


def test_stdin_compose_file_is_refused(tmp_path):
    with pytest.raises(guard.GuardError):
        guard.project_directory(["-f", "-"], {}, str(tmp_path))


def test_missing_compose_file_is_refused(tmp_path):
    with pytest.raises(guard.GuardError):
        guard.project_directory([], {}, str(tmp_path))


@pytest.fixture
def forwarded(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "forward", calls.append)
    return calls


@pytest.mark.parametrize("subcommand", sorted(cli.GUARDED_SUBCOMMANDS))
def test_guarded_subcommand_with_problems_is_not_forwarded(forwarded, monkeypatch, subcommand):
    monkeypatch.setattr(guard, "check", lambda global_args, build_only=False: ["privileged is not allowed"])
    assert cli.main(["-f", "a.yml", subcommand]) == 1
    assert forwarded == []


def test_guarded_subcommand_without_problems_is_forwarded(forwarded, monkeypatch):
    seen = []
    monkeypatch.setattr(guard, "check", lambda global_args, build_only=False: seen.append((global_args, build_only)) or [])
    cli.main(["-f", "a.yml", "up", "-d"])
    assert seen == [(["-f", "a.yml"], False)]
    assert forwarded == [["-f", "a.yml", "up", "-d"]]


def test_unguarded_subcommand_is_not_inspected(forwarded, monkeypatch):
    monkeypatch.setattr(guard, "check", lambda global_args, build_only=False: 1 / 0)
    cli.main(["ps"])
    assert forwarded == [["ps"]]


def test_extra_mount_dirs_are_split_on_pathsep():
    assert guard.extra_mount_dirs({"DCOMPOSE_DIRS": "/a:/b/c::"}) == ["/a", "/b/c"]
    assert guard.extra_mount_dirs({}) == []


def test_relative_extra_mount_dir_is_refused():
    with pytest.raises(guard.GuardError):
        guard.extra_mount_dirs({"DCOMPOSE_DIRS": "/a:relative"})


@pytest.mark.parametrize("argv, guarded", [
    (["up"], True),
    (["run", "app", "ls", "-h"], True),
    (["run", "app", "grep", "-h", "foo"], True),
    (["run", "app", "--help"], True),
    (["run", "-e", "--help", "app"], True),  # a flag value, not a help request
    (["up", "-d", "--help"], True),
    (["up", "-h"], True),
    (["up", "--help"], False),
    (["run", "--help"], False),
    (["watch", "--help"], False),
    (["ps"], False),
    (["logs", "-f"], False),
    ([], False),
])
def test_is_guarded(argv, guarded):
    assert cli.is_guarded(argv, cli.find_subcommand(argv)) == guarded


@pytest.mark.parametrize("line", ["COMPOSE_FILE=other.yml", "export COMPOSE_FILE=a:b", "  COMPOSE_PATH_SEPARATOR=;"])
def test_compose_vars_in_dotenv_make_the_project_directory_unverifiable(tmp_path, line):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / ".env").write_text(f"OTHER=1\n{line}\n")
    with pytest.raises(guard.GuardError):
        guard.project_directory([], {}, str(tmp_path))


def test_dotenv_in_a_directory_on_the_way_up_is_scanned_too(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / ".env").write_text("COMPOSE_FILE=elsewhere.yml\n")
    with pytest.raises(guard.GuardError):
        guard.project_directory([], {}, str(tmp_path / "sub"))


def test_unrelated_dotenv_variables_are_fine_and_explicit_files_skip_the_scan(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / ".env").write_text("MY_COMPOSE_FILE=x\nPASSWORD=y\n")
    assert guard.project_directory([], {}, str(tmp_path)) == str(tmp_path)

    (tmp_path / ".env").write_text("COMPOSE_FILE=elsewhere.yml\n")
    assert guard.project_directory(["-f", "compose.yaml"], {}, str(tmp_path)) == str(tmp_path)


def test_config_is_loaded_without_env_resolution(monkeypatch):
    seen = []

    def fake_run(cmd, **kwargs):
        seen.append(cmd)
        return __import__("subprocess").CompletedProcess(cmd, 0, "{}", "")

    monkeypatch.setattr(guard.subprocess, "run", fake_run)
    guard.load_config(["-f", "a.yml"])
    assert "--no-env-resolution" in seen[0] and seen[0][:4] == ["docker", "compose", "-f", "a.yml"]


@pytest.mark.parametrize("subcommand, build_only", [("up", False), ("run", False), ("build", True), ("bake", True)])
def test_build_subcommands_get_the_build_only_check(forwarded, monkeypatch, subcommand, build_only):
    seen = []
    monkeypatch.setattr(guard, "check", lambda global_args, build_only=False: seen.append(build_only) or [])
    cli.main([subcommand])
    assert seen == [build_only]
    assert forwarded == [[subcommand]]


def test_build_only_check_ignores_runtime_policy_but_catches_what_building_reaches(tmp_path):
    def evaluate(**service):
        config = {"name": "p", "services": {"web": {"build": {"context": str(tmp_path)}, **service}}}
        return guard.evaluate(config, str(tmp_path), build_only=True)

    assert evaluate(privileged=True, user="0") == []  # runtime problems are not a build concern
    for build in ({"ssh": ["default"]}, {"network": "host"}, {"privileged": True},
                  {"additional_contexts": {"h": "/home"}}, {"cache_to": ["type=local,dest=/tmp/x"]},
                  {"x-bake": {"output": ["type=local,dest=/home/me"]}}, {"entitlements": ["network.host"]}):
        assert evaluate(build={"context": str(tmp_path), **build}), build


def test_build_only_check_covers_secret_files(tmp_path):
    config = {"name": "p", "secrets": {"s": {"file": "/etc/shadow"}}}
    assert guard.evaluate(config, str(tmp_path), build_only=True)
