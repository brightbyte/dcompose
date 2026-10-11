import pytest

from dcompose import runargs

ME = (4242, 4343)


def parse(*args):
    return runargs.parse(list(args), ME)


def test_plain_command():
    parsed = parse("-it", "--rm", "alpine", "sh", "-c", "echo hi")
    assert parsed.create_args == ["-it", "--rm", "alpine", "sh", "-c", "echo hi"]
    assert (parsed.image, parsed.command, parsed.detach) == ("alpine", ["sh", "-c", "echo hi"], False)


def test_values_are_not_mistaken_for_the_image():
    parsed = parse("--name", "web", "-p", "80:80", "-v", "/a:/b", "-e", "A=1", "--user=1:1", "-w", "/x",
                   "img", "cmd")
    assert parsed.image == "img" and parsed.command == ["cmd"]
    assert parsed.create_args[-2:] == ["img", "cmd"]
    assert parsed.create_args[:2] == ["--name", "web"]


def test_attached_short_values():
    parsed = parse("-p80:80", "-eA=1", "-v/a:/b", "img")
    assert parsed.image == "img"
    assert parsed.create_args == ["-p80:80", "-eA=1", "-v/a:/b", "img"]


@pytest.mark.parametrize("flags, detach, kept", [
    (["-d"], True, []),
    (["--detach"], True, []),
    (["--detach=false"], False, []),
    (["-dit"], True, ["-it"]),
    (["-itd"], True, ["-it"]),
    (["--sig-proxy=false"], False, []),
    (["--detach-keys", "ctrl-x"], False, []),
    (["--detach-keys=ctrl-x"], False, []),
    (["-a", "stdout"], False, []),
    (["--attach=stdin"], False, []),
    (["-dp", "80:80"], True, ["-p", "80:80"]),
])
def test_flags_that_create_lacks_are_dropped(flags, detach, kept):
    parsed = parse(*flags, "img")
    assert parsed.create_args == [*kept, "img"]
    assert parsed.detach is detach


def test_detach_keys_are_remembered():
    assert parse("--detach-keys", "ctrl-x", "img").detach_keys == "ctrl-x"
    assert parse("--detach-keys=ctrl-y", "img").detach_keys == "ctrl-y"


def test_flags_after_the_image_belong_to_the_command():
    parsed = parse("img", "ls", "-d", "--detach", "-a")
    assert parsed.create_args == ["img", "ls", "-d", "--detach", "-a"]
    assert not parsed.detach


def test_double_dash_ends_the_options():
    parsed = parse("--rm", "--", "img", "-d")
    assert parsed.create_args == ["--rm", "--", "img", "-d"]
    assert (parsed.image, parsed.command) == ("img", ["-d"])


@pytest.mark.parametrize("args", [[], ["--rm"], ["-it"], ["--name"], ["-p"], ["-a"]])
def test_incomplete_command_lines_are_errors(args):
    with pytest.raises(runargs.ParseError):
        runargs.parse(args, ME)


@pytest.mark.parametrize("flags", [
    ["--user", "me"], ["--user=me"], ["-u", "me"], ["-ume"], ["--current-user"],
])
def test_me_and_current_user_become_the_callers_ids(flags):
    parsed = parse(*flags, "img")
    assert parsed.create_args == ["--user=4242:4343", "img"]
    assert parsed.user_given


@pytest.mark.parametrize("flags, user", [
    (["--user", "1000:1000"], "1000:1000"),
    (["--user=nobody"], "nobody"),
    (["-u", "0"], "0"),
    (["-itu", "7"], "7"),
])
def test_other_users_are_passed_on_and_recorded(flags, user):
    parsed = parse(*flags, "img")
    assert f"--user={user}" in parsed.create_args
    assert parsed.user_given


def test_a_user_flag_in_a_cluster_keeps_its_neighbours():
    assert parse("-itu", "7", "img").create_args == ["-it", "--user=7", "img"]


def test_user_flags_after_the_image_belong_to_the_command():
    parsed = parse("img", "id", "-u", "--current-user")
    assert not parsed.user_given
    assert parsed.create_args == ["img", "id", "-u", "--current-user"]


def test_no_user_flag_means_not_given():
    assert not parse("-it", "img").user_given
