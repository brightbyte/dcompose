import os

import pytest

from dockscreen import cli, ids


def test_export_sets_the_real_ids_and_is_idempotent():
    env = {"UID": "7", "GID": "8"}

    ids.export(env)
    ids.export(env)

    # a pre-set UID/GID is overwritten: a project's .env cannot make ${UID} mean someone else
    assert env == {"UID": str(os.getuid()), "GID": str(os.getgid())}


def test_main_exports_ids_for_compose_interpolation(monkeypatch):
    monkeypatch.setattr(cli, "forward", lambda argv: None)
    monkeypatch.setenv("UID", "7")

    cli.main(["ps"])

    assert os.environ["UID"] == str(os.getuid())


@pytest.mark.parametrize("spec, expected", [
    ("1000:1000", (1000, 1000)),
    ("0:0", (0, 0)),
    ("1000", None),     # a uid alone leaves the group to the image
    ("alice:1", None),  # names are not ids
    ("1:", None),
    ("١:1", None),      # Unicode digits are not ids
    ("-1:1", None),
])
def test_parse_user(spec, expected):
    assert ids.parse_user(spec) == expected


def test_parse_id():
    assert ids.parse_id(42) == 42
    assert ids.parse_id("42") == 42
    assert ids.parse_id("x") is None


def test_format_user():
    assert ids.format_user((1, 2)) == "1:2"
