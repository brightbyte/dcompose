import os
import subprocess

import pytest

from dockscreen import config, screen


def test_project_directory_is_dir_of_first_file(tmp_path):
    result = screen.project_directory(["-f", "a/x.yml", "-f", "b/y.yml"], {}, str(tmp_path))
    assert result == str(tmp_path / "a")


def test_project_directory_option_wins_over_file(tmp_path):
    result = screen.project_directory(
        ["-f", "a/x.yml", "--project-directory=b"], {}, str(tmp_path))
    assert result == str(tmp_path / "b")


def test_project_directory_from_compose_file_env(tmp_path):
    env = {"COMPOSE_FILE": "a/x.yml:b/y.yml"}
    assert screen.project_directory([], env, str(tmp_path)) == str(tmp_path / "a")


def test_project_directory_searches_parents(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / "sub").mkdir()
    assert screen.project_directory([], {}, str(tmp_path / "sub")) == str(tmp_path)


def test_stdin_compose_file_is_refused(tmp_path):
    with pytest.raises(screen.ScreenError):
        screen.project_directory(["-f", "-"], {}, str(tmp_path))


def test_missing_compose_file_is_refused(tmp_path):
    with pytest.raises(screen.ScreenError):
        screen.project_directory([], {}, str(tmp_path))


def test_sensitive_paths_are_found_inside_a_directory_after_resolving_symlinks(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "code").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    os.symlink(home, tmp_path / "link-to-home")

    assert screen.sensitive_inside(str(home / "code"), {}) == []
    assert str(home) in screen.sensitive_inside(str(tmp_path / "link-to-home"), {})
    assert "/etc" in screen.sensitive_inside("/", {})


def test_mount_dirs_that_contain_sensitive_paths_get_a_warning(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "code").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    settings = config.Config(mount_dirs=(str(home / "code"), str(tmp_path)))
    monkeypatch.setattr(config, "current", lambda: settings)

    assert screen.mount_dir_warnings({}) == [
        f"warning: the configured mount dir {tmp_path} contains {home}, so containers can mount it"]


def test_a_project_directory_containing_the_home_directory_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "compose.yaml").write_text("")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(screen.ScreenError, match="contains"):
        screen.inspect([])


def test_the_walk_up_stops_at_the_home_directory(tmp_path):
    (tmp_path / "compose.yaml").write_text("")  # a stray file in "home"
    (tmp_path / "work").mkdir()
    with pytest.raises(screen.ScreenError, match="your home directory or not yours"):
        screen.find_compose_dir(str(tmp_path / "work"), home=str(tmp_path))
    assert screen.find_compose_dir(str(tmp_path / "work"), home="/elsewhere") == str(tmp_path)


def test_the_walk_up_stops_at_a_directory_owned_by_someone_else(tmp_path):
    (tmp_path / "work").mkdir()
    with pytest.raises(screen.ScreenError, match="no compose file found"):
        # uid 12345 owns nothing here: the first parent already belongs to someone else
        screen.find_compose_dir(str(tmp_path / "work"), home="/elsewhere", uid=12345)


def test_the_starting_directory_is_used_whoever_owns_it(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    assert screen.find_compose_dir(str(tmp_path), home="/elsewhere", uid=12345) == str(tmp_path)


@pytest.mark.parametrize("line", [
    "COMPOSE_FILE=other.yml", "export COMPOSE_FILE=a:b", "  COMPOSE_PATH_SEPARATOR=;",
])
def test_compose_vars_in_dotenv_make_the_project_directory_unverifiable(tmp_path, line):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / ".env").write_text(f"OTHER=1\n{line}\n")
    with pytest.raises(screen.ScreenError):
        screen.project_directory([], {}, str(tmp_path))


def test_dotenv_in_a_directory_on_the_way_up_is_scanned_too(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / ".env").write_text("COMPOSE_FILE=elsewhere.yml\n")
    with pytest.raises(screen.ScreenError):
        screen.project_directory([], {}, str(tmp_path / "sub"))


def test_unrelated_dotenv_variables_are_fine_and_explicit_files_skip_the_scan(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / ".env").write_text("MY_COMPOSE_FILE=x\nPASSWORD=y\n")
    assert screen.project_directory([], {}, str(tmp_path)) == str(tmp_path)

    (tmp_path / ".env").write_text("COMPOSE_FILE=elsewhere.yml\n")
    assert screen.project_directory(["-f", "compose.yaml"], {}, str(tmp_path)) == str(tmp_path)


def test_config_is_loaded_without_env_resolution(monkeypatch):
    seen = []

    def fake_run(cmd, **kwargs):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "{}", "")

    monkeypatch.setattr(screen.subprocess, "run", fake_run)
    screen.load_config(["-f", "a.yml"])
    assert "--no-env-resolution" in seen[0] and seen[0][:4] == ["docker", "compose", "-f", "a.yml"]
