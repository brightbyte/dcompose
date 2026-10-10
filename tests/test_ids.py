import os

import pytest

from dcompose import cli, guard, ids, policy

UID = os.getuid()
GID = os.getgid()


def test_allowed_defaults_to_the_real_user():
    assert ids.allowed({}) == (UID, GID)


def test_dcompose_variables_define_the_allowed_ids_independently():
    assert ids.allowed({"DCOMPOSE_UID": "21"}) == (21, GID)
    assert ids.allowed({"DCOMPOSE_GID": "22"}) == (UID, 22)


def test_empty_counts_as_unset_and_uid_gid_are_ignored():
    assert ids.allowed({"DCOMPOSE_UID": "", "UID": "7", "GID": "8"}) == (UID, GID)


def test_non_numeric_id_is_an_error():
    with pytest.raises(ValueError):
        ids.allowed({"DCOMPOSE_UID": "root"})


def test_export_sets_real_ids_and_allowed_ids_and_is_idempotent():
    env = {"UID": "7", "GID": "8", "DCOMPOSE_UID": "21"}

    ids.export(env)
    ids.export(env)

    assert env["UID"] == str(UID) and env["GID"] == str(GID)  # a pre-set UID/GID is overwritten
    assert env["DCOMPOSE_UID"] == "21" and env["DCOMPOSE_GID"] == str(GID)


def test_main_exports_ids_for_compose_interpolation(monkeypatch):
    monkeypatch.setattr(cli, "forward", lambda argv: None)
    monkeypatch.setenv("UID", "7")
    monkeypatch.delenv("DCOMPOSE_UID", raising=False)

    cli.main(["ps"])

    assert os.environ["UID"] == str(UID)
    assert os.environ["DCOMPOSE_UID"] == str(UID)


def test_main_refuses_a_malformed_id(monkeypatch, capsys):
    monkeypatch.setenv("DCOMPOSE_UID", "root")
    assert cli.main(["ps"]) == 1
    assert "not a numeric id" in capsys.readouterr().err


# The policy tests below need a real user that is neither root nor nobody,
# so that "someone else" can be built as UID + 1.
needs_ordinary_user = pytest.mark.skipif(
    UID in (0, policy.NOBODY - 1, policy.NOBODY) or GID in (0, policy.NOBODY - 1, policy.NOBODY),
    reason="current user must be neither root nor adjacent to nobody",
)


def audit_with_user(monkeypatch, tmp_path, user):
    config = {"name": "proj", "services": {"web": {
        "user": user, "security_opt": ["no-new-privileges:true"], "cap_drop": ["ALL"]}}}
    monkeypatch.setattr(guard, "inspect", lambda global_args: (config, str(tmp_path)))
    ids.export(os.environ)
    return guard.check([])


@needs_ordinary_user
def test_real_user_is_refused_once_dcompose_ids_name_someone_else(monkeypatch, tmp_path):
    monkeypatch.setenv("DCOMPOSE_UID", str(UID + 1))
    monkeypatch.setenv("DCOMPOSE_GID", str(GID + 1))

    assert audit_with_user(monkeypatch, tmp_path, f"{UID}:{GID}")  # "do not run as me"
    assert audit_with_user(monkeypatch, tmp_path, f"{UID + 1}:{GID + 1}") == []
    assert audit_with_user(monkeypatch, tmp_path, "65534:65534") == []  # nobody stays acceptable


@needs_ordinary_user
def test_real_user_is_accepted_without_dcompose_ids(monkeypatch, tmp_path):
    monkeypatch.delenv("DCOMPOSE_UID", raising=False)
    monkeypatch.delenv("DCOMPOSE_GID", raising=False)

    assert audit_with_user(monkeypatch, tmp_path, f"{UID}:{GID}") == []
    assert audit_with_user(monkeypatch, tmp_path, f"{UID + 1}:{GID}")
