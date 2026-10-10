import os

import pytest


@pytest.fixture(autouse=True)
def isolated_environ(monkeypatch):
    """cli.main exports UID/GID into os.environ; keep that from leaking between tests."""
    monkeypatch.setattr(os, "environ", dict(os.environ))
