"""The real collaborators and the tests' fakes provide the methods their protocols name.

isinstance on a runtime_checkable protocol checks that the methods exist, not their signatures.
"""

import pytest
from fakes import Accounts, FakeDocker, FakeImages, NoSubordinate

from dockscreen import gate, hostusers, idrules, imagedecision
from dockscreen.dockerclient import Docker


@pytest.mark.parametrize("implementation, protocol", [
    (Docker("docker"), gate.RunnableDocker),
    (FakeDocker(), gate.RunnableDocker),
    (FakeImages(), imagedecision.DockerAccess),
    (hostusers.HostAccounts(), hostusers.Accounts),
    (Accounts(), hostusers.Accounts),
    (idrules.Subordinate(), idrules.SubordinateRanges),
    (NoSubordinate(), idrules.SubordinateRanges),
])
def test_implementations_provide_their_protocol(implementation, protocol):
    assert isinstance(implementation, protocol)
