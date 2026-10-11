import pytest
from fakes import Local, rules

from dockscreen import config, idrules


class Accounts:
    def __init__(self, uids=(), gids=()):
        self.uids, self.gids = dict(uids), dict(gids)

    def user_name(self, uid):
        return self.uids.get(uid)

    def group_name(self, gid):
        return self.gids.get(gid)


@pytest.mark.parametrize("uid, gid, supplementary", [
    (100000, 100001, (100002,)),
    (65532, 65532, ()),     # distroless nonroot
    (999, 998, (997,)),     # postgres, mariadb: low, but this host has no such account
    (1, 1, ()),
])
def test_ids_that_are_not_root_and_unknown_to_the_host_are_accepted_without_mounts(uid, gid, supplementary):
    assert rules(local=Accounts()).problems(uid, gid, supplementary) == []


@pytest.mark.parametrize("uid, gid, supplementary, reason", [
    (0, 100001, (), "uid 0 is root"),
    (100000, 0, (), "gid 0 is root"),
    (100000, 100001, (0,), "supplementary gid 0 is root"),
    (65535, 100001, (), 'uid 65535 means "no id" to many tools'),
    (4294967295, 100001, (), 'uid 4294967295 means "no id" to many tools'),
])
def test_root_and_no_id_are_refused_in_every_position(uid, gid, supplementary, reason):
    assert rules(local=Accounts()).problems(uid, gid, supplementary) == [reason]


def test_ids_that_exist_on_this_host_are_refused_with_the_local_account_named():
    local = Accounts(uids={1000: "daniel"}, gids={100001: "staff", 999: "docker"})
    assert rules(local=local).problems(1000, 100001, (999,)) == [
        "uid 1000 exists on this host (local user daniel)",
        "gid 100001 exists on this host (local group staff)",
        "supplementary gid 999 exists on this host (local group docker)",
    ]


def test_the_nobody_range_and_the_default_user_are_allowed_even_where_they_exist_locally():
    local = Accounts(uids={65534: "nobody", 4000: "svc"}, gids={65534: "nogroup", 4001: "svc"})
    settings = config.Config(default_user=(4000, 4001))
    assert rules(local=local, settings=settings).problems(65534, 65534, (65534,), mounts=True) == []
    assert rules(local=local, settings=settings).problems(4000, 4001, mounts=True) == []


def test_the_callers_ids_are_refused_with_a_pointer_to_allow_me_and_allowed_with_it():
    assert rules(me=(1000, 1000), local=Local()).problems(1000, 1000) == [
        "uid 1000 is yours; pass --allow-me to allow it", "gid 1000 is yours; pass --allow-me to allow it"]
    assert rules(me=(1000, 1000), allow_me=True, local=Local()).problems(1000, 1000, mounts=True) == []


def test_with_mounts_only_allowed_ids_pass():
    settings = config.Config(nobody_range=(70000, 70010))
    assert rules(local=Accounts(), settings=settings).problems(70005, 70010, mounts=True) == []
    assert rules(local=Accounts(), settings=settings).problems(5000, 70010, mounts=True) == [
        "uid 5000 is not in the nobody range 70000-70010, and there are host mounts"]


def test_extra_ids_are_allowed_for_one_check():
    assert rules(local=Accounts()).problems(5000, 5001, mounts=True, extra=[(5000, 5001)]) == []


def test_subordinate_ranges_are_read_from_subuid_and_subgid(tmp_path):
    (tmp_path / "subuid").write_text("alice:100000:65536\nbob:200000:10\nbroken\n1001:300000:x\n")
    (tmp_path / "subgid").write_text("alice:100000:65536\n")
    subordinate = idrules.Subordinate(str(tmp_path / "subuid"), str(tmp_path / "subgid"))

    assert subordinate.contains("uid", 100000) and subordinate.contains("uid", 165535)
    assert not subordinate.contains("uid", 165536)
    assert subordinate.contains("uid", 200009) and not subordinate.contains("uid", 200010)
    assert subordinate.contains("gid", 100000) and not subordinate.contains("gid", 200000)
    assert rules(local=Accounts(), subordinate=subordinate).problems(100000, 5000) == [
        "uid 100000 is in a subordinate id range of this host (rootless containers)"]


def test_missing_subordinate_files_mean_no_ranges(tmp_path):
    subordinate = idrules.Subordinate(str(tmp_path / "none"), str(tmp_path / "none"))
    assert not subordinate.contains("uid", 100000)
