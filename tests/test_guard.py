import subprocess

import pytest

from dockscreen import guard


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


def test_extra_mount_dirs_are_split_on_pathsep():
    assert guard.extra_mount_dirs({"DOCKSCREEN_DIRS": "/a:/b/c::"}) == ["/a", "/b/c"]
    assert guard.extra_mount_dirs({}) == []


def test_relative_extra_mount_dir_is_refused():
    with pytest.raises(guard.GuardError):
        guard.extra_mount_dirs({"DOCKSCREEN_DIRS": "/a:relative"})


@pytest.mark.parametrize("line", [
    "COMPOSE_FILE=other.yml", "export COMPOSE_FILE=a:b", "  COMPOSE_PATH_SEPARATOR=;",
])
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
        return subprocess.CompletedProcess(cmd, 0, "{}", "")

    monkeypatch.setattr(guard.subprocess, "run", fake_run)
    guard.load_config(["-f", "a.yml"])
    assert "--no-env-resolution" in seen[0] and seen[0][:4] == ["docker", "compose", "-f", "a.yml"]
