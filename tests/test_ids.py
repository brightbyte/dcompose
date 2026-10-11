import os

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
