import pytest
from fakes import host_account

from dcompose import hostusers


@pytest.mark.parametrize("spec", ["1000:1000", "0:0", "65534:65534", "1000:0"])
def test_user_takes_numeric_ids_and_leaves_them_as_typed(spec):
    assert hostusers.require_numeric(spec) == spec


@pytest.mark.parametrize("spec", [
    "alice", "nobody", "root", "1000:staff", "alice:1000", "", "1000:", ":1000", "-1", "1000", "0",
])
def test_user_refuses_everything_else_and_points_at_the_alternatives(spec):
    with pytest.raises(hostusers.UserError) as error:
        hostusers.require_numeric(spec)
    assert "--user takes numeric ids as uid:gid" in str(error.value)
    assert "--as NAME runs as a local user, --as-me as yourself" in str(error.value)


def test_as_resolves_a_local_account_with_its_primary_group():
    assert host_account("alice") == ("4242:4343", ["Resolving user alice to uid 4242, gid 4343"])
    assert host_account("nobody") == ("65534:65534", ["Resolving user nobody to uid 65534, gid 65534"])


def test_as_with_a_name_the_host_does_not_have():
    with pytest.raises(hostusers.UnknownUser, match="user 'ghost' does not exist on this host; use --user"):
        host_account("ghost")


@pytest.mark.parametrize("name", ["1000", "alice:staff", ""])
def test_as_takes_a_name_not_an_id_or_a_group(name):
    with pytest.raises(hostusers.UserError, match="--as takes the name of a local user"):
        host_account(name)


def test_the_hosts_own_accounts_are_used_by_default():
    assert hostusers.resolve_account("root") == ("0:0", ["Resolving user root to uid 0, gid 0"])


def test_a_uid_without_a_gid_says_to_give_the_group():
    with pytest.raises(hostusers.UserError, match="not '1000'; give the group too, as uid:gid"):
        hostusers.require_numeric("1000")
