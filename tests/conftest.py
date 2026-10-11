import os

import pytest

from dcompose import cli


@pytest.fixture(autouse=True)
def isolated_environ(monkeypatch):
    """cli.main exports UID/GID into os.environ; keep that from leaking between tests."""
    monkeypatch.setattr(os, "environ", dict(os.environ))


@pytest.fixture(autouse=True)
def local_daemon(monkeypatch):
    """Whatever daemon the developer's shell points at, tests talk to the default local one."""
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)


@pytest.fixture
def forwarded(monkeypatch):
    """The argv lists cli.main would have handed to docker compose."""
    calls = []
    monkeypatch.setattr(cli, "forward", calls.append)
    return calls


@pytest.fixture(autouse=True)
def fixed_docker_binary(monkeypatch):
    """Commands are asserted against plain "docker", wherever the real binary lives."""
    from dcompose import realdocker
    monkeypatch.setattr(realdocker, "docker_bin", lambda: "docker")


@pytest.fixture(autouse=True)
def fake_image_tools(monkeypatch):
    """`audit` and `harden` pull and build; tests get a docker with no images unless they say otherwise."""
    from fakes import FakeImages, make_tools

    from dcompose import composerun
    tools, recorder = make_tools(FakeImages())
    monkeypatch.setattr(composerun, "default_tools", lambda: tools)
    return recorder
