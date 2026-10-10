import os

import pytest

from dcompose import cli


@pytest.fixture(autouse=True)
def isolated_environ(monkeypatch):
    """cli.main exports UID/GID into os.environ; keep that from leaking between tests."""
    monkeypatch.setattr(os, "environ", dict(os.environ))


@pytest.fixture
def forwarded(monkeypatch):
    """The argv lists cli.main would have handed to docker compose."""
    calls = []
    monkeypatch.setattr(cli, "forward", calls.append)
    return calls
