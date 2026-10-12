import os

import pytest

from dockscreen import compose_cli


@pytest.fixture(autouse=True)
def isolated_environ(monkeypatch):
    """compose_cli.main exports UID/GID into os.environ; keep that from leaking between tests."""
    monkeypatch.setattr(os, "environ", dict(os.environ))


@pytest.fixture(autouse=True)
def local_daemon(monkeypatch):
    """Whatever daemon the developer's shell points at, tests talk to the default local one."""
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)


@pytest.fixture
def forwarded(monkeypatch):
    """The argv lists compose_cli.main would have handed to docker compose."""
    calls = []
    monkeypatch.setattr(compose_cli, "forward", lambda argv, runtime: calls.append(argv))
    return calls


@pytest.fixture(autouse=True)
def fixed_docker_binary(monkeypatch):
    """Commands are asserted against plain "docker", wherever the real binary lives."""
    from dockscreen import realdocker
    monkeypatch.setattr(realdocker, "locate", lambda settings, env: "docker")


@pytest.fixture(autouse=True)
def fake_image_tools(monkeypatch):
    """`audit` and `harden` pull and build; tests get a docker with no images unless they say otherwise."""
    from fakes import FakeImages, install_tools, make_tools

    tools, recorder = make_tools(FakeImages())
    install_tools(monkeypatch, tools)
    return recorder


@pytest.fixture(autouse=True)
def fake_accounts(monkeypatch):
    """Accounts are looked up in fakes.Accounts, not this host's."""
    from fakes import Accounts

    from dockscreen import hostusers
    monkeypatch.setattr(hostusers, "HostAccounts", Accounts)


@pytest.fixture(autouse=True)
def default_config(monkeypatch):
    """No config file and no subordinate ids: tests see the defaults, whatever this host has."""
    from dockscreen import config, idrules
    monkeypatch.setattr(config, "load_current", lambda env, home, uid: config.Config())
    monkeypatch.setattr(idrules, "SUBUID_FILE", "/nonexistent/subuid")
    monkeypatch.setattr(idrules, "SUBGID_FILE", "/nonexistent/subgid")


@pytest.fixture(autouse=True)
def unwrapped_reports(monkeypatch):
    """Report lines stay whole, whatever terminal runs the tests: COLUMNS below the minimum turns
    wrapping off. Tests of the wrapping set the width themselves."""
    monkeypatch.setenv("COLUMNS", "10")
