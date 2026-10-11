import pytest

from dcompose import shellenv


def config(**services):
    return {"name": "p", "services": {name: {"environment": env} for name, env in services.items()}}


def test_variables_that_are_the_shells_own_are_listed_per_service_without_their_values():
    shell = {"TOKEN": "s3cret", "HOME": "/home/me", "UID": "1000"}
    cfg = config(web={"TOKEN": "s3cret", "OWN": "x", "UID": "1000"}, db={"HOME": "/home/me"}, job={"A": "b"})

    assert shellenv.copied(cfg, shell) == {"web": ["TOKEN"], "db": ["HOME"]}
    lines = shellenv.describe(cfg, shell)
    assert lines == ["service db: environment variables taken from your shell: HOME",
                     "service web: environment variables taken from your shell: TOKEN"]
    assert all("s3cret" not in line for line in lines)


@pytest.mark.parametrize("environment, shell", [
    ({"A": "explicit"}, {"A": "other"}),
    ({"A": "x"}, {}),
    ({"A": None}, {"A": "shell"}),
    ({"A": ""}, {"A": ""}),
    ({"B": "secret"}, {"A": "secret"}),   # interpolated under another name: not recognised
    ({"DCOMPOSE_UID": "1000"}, {"DCOMPOSE_UID": "1000"}),
])
def test_nothing_is_reported_for_these(environment, shell):
    assert shellenv.copied(config(web=environment), shell) == {}


def test_services_without_an_environment_are_fine():
    assert shellenv.copied({"services": {"web": {}, "db": None}}, {"A": "b"}) == {}
