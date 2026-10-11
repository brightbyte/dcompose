import pytest

from dockscreen import composeargs, hostusers


@pytest.mark.parametrize("args, service, user_given", [
    (["web"], "web", False),
    (["--rm", "-e", "A=1", "web", "sh", "-u", "x"], "web", False),  # after the service: the command's
    (["-u", "1000:1000", "web"], "web", True),
    (["--user=1000:1000", "web"], "web", True),
    (["--user", "1000:1000", "web"], "web", True),
    (["-iu1000:1000", "web"], "web", True),
    (["-Tu", "1000:1000", "web"], "web", True),
    (["--name", "x", "-v", "a:/b", "-w", "/w", "web"], "web", False),
    (["--", "web"], "web", False),
    ([], None, False),
])
def test_run_arguments(args, service, user_given):
    parsed = composeargs.parse("run", args)
    assert (parsed.service, parsed.user_given, parsed.args) == (service, user_given, args)


@pytest.mark.parametrize("args", [
    ["-u", "postgres", "web"], ["--user=1000", "web"], ["-iu", "root", "web"],
    ["--user", "1000:staff", "web"],
])
def test_users_must_be_numeric_uid_gid(args):
    with pytest.raises(hostusers.UserError, match="--user takes numeric ids as uid:gid"):
        composeargs.parse("run", args)




def test_exec_and_docker_exec_have_their_own_options():
    assert composeargs.parse("exec", ["--index", "2", "-u", "0:0", "web", "sh"])[:2] == ("web", True)
    assert composeargs.parse("docker exec", ["--detach-keys", "x", "-it", "c", "sh"])[:2] == ("c", False)
    with pytest.raises(hostusers.UserError):
        composeargs.parse("docker exec", ["--env-file", "e", "-u", "www-data", "c", "sh"])


def resolve(name):
    if name != "alice":
        raise hostusers.UnknownUser(f"user {name!r} does not exist on this host")
    return "1001:1002", ["Resolving user alice to uid 1001, gid 1002"]


@pytest.mark.parametrize("subcommand, args, rewritten", [
    ("run", ["--rm", "--as", "alice", "web", "id"], ["--rm", "--user=1001:1002", "web", "id"]),
    ("run", ["--as=alice", "--", "web"], ["--user=1001:1002", "--", "web"]),
    ("exec", ["-T", "--as", "alice", "web", "sh"], ["-T", "--user=1001:1002", "web", "sh"]),
    ("docker exec", ["-it", "--as=alice", "c", "sh"], ["-it", "--user=1001:1002", "c", "sh"]),
    # after the service, --as belongs to the command
    ("run", ["web", "tool", "--as", "bob"], ["web", "tool", "--as", "bob"]),
])
def test_as_is_resolved_on_this_host_and_replaced_by_numeric_ids(subcommand, args, rewritten):
    parsed = composeargs.parse(subcommand, args, resolve)
    assert parsed.args == rewritten
    assert parsed.user_given == ("--as" not in rewritten)
    assert parsed.notices == ([] if "--as" in rewritten else ["Resolving user alice to uid 1001, gid 1002"])


def test_as_with_an_unknown_name_is_an_error():
    with pytest.raises(hostusers.UnknownUser):
        composeargs.parse("exec", ["--as", "bob", "web", "sh"], resolve)


def test_a_name_given_to_user_points_to_as():
    with pytest.raises(hostusers.UserError, match="--as NAME runs as a local user"):
        composeargs.parse("exec", ["-u", "postgres", "web", "sh"])


@pytest.mark.parametrize("subcommand", ["run", "exec", "docker exec"])
def test_as_me_is_the_callers_ids(subcommand):
    parsed = composeargs.parse(subcommand, ["-it", "--as-me", "c", "sh"], current_user=(1000, 1001))
    assert parsed.args == ["-it", "--user=1000:1001", "c", "sh"] and parsed.user_given
