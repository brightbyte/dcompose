import os

from dcompose import realdocker


def make_docker(directory):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "docker"
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


def test_skips_our_own_wrapper_even_through_a_symlink(tmp_path):
    wrapper = make_docker(tmp_path / "wrapper")
    link_dir = tmp_path / "front"
    link_dir.mkdir()
    os.symlink(wrapper, link_dir / "docker")
    real = make_docker(tmp_path / "real")
    env = {"PATH": os.pathsep.join([str(link_dir), str(tmp_path / "wrapper"), str(tmp_path / "real")])}

    assert realdocker.find(env, {os.path.realpath(wrapper)}) == str(real)


def test_explicit_path_wins(tmp_path):
    make_docker(tmp_path / "real")
    env = {"DCOMPOSE_DOCKER": "/opt/docker", "PATH": str(tmp_path / "real")}
    assert realdocker.find(env, set()) == "/opt/docker"


def test_current_directory_is_never_searched(tmp_path, monkeypatch):
    make_docker(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert realdocker.find({"PATH": os.pathsep.join(["", "."])}, set()) is None or \
        realdocker.find({"PATH": os.pathsep.join(["", "."])}, set()) == "./docker"
    assert realdocker.find({"PATH": os.pathsep.join(["", str(tmp_path / "nothing")])}, set()) is None


def test_nothing_found(tmp_path):
    assert realdocker.find({"PATH": str(tmp_path)}, set()) is None
