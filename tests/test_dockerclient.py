import pytest

from dockscreen import docker_cli, realdocker
from dockscreen.dockerclient import Docker, DockerNotFound


def test_a_missing_binary_is_docker_not_found(tmp_path):
    docker = Docker(str(tmp_path / "no-docker"))

    with pytest.raises(DockerNotFound, match="'docker' not found in PATH"):
        docker.context()
    with pytest.raises(DockerNotFound):
        docker.read_file("c1", "/etc/passwd")
    with pytest.raises(DockerNotFound):
        docker.start("c1", attach=True, interactive=False, detach_keys=None)


def test_the_docker_wrapper_reports_a_missing_binary_without_a_traceback(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(realdocker, "locate", lambda settings, env: str(tmp_path / "no-docker"))

    assert docker_cli.main(["run", "img"]) == 1
    assert capsys.readouterr().err == "[dockscreen] 'docker' not found in PATH\n"
