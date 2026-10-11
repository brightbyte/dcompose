import pytest

from dockscreen import imageuser

PASSWD = """root:x:0:0:root:/root:/bin/bash
app:x:100000:100001:app:/home/app:/bin/sh
daemon:x:1:1::/:/usr/sbin/nologin
nobody:x:65534:65534::/:/usr/sbin/nologin
broken line
"""
GROUP = """root:x:0:
docker:x:999:app
staff:x:100002:app,daemon
nogroup:x:65534:
"""


class Local:
    def __init__(self, uids=(), gids=()):
        self.uids, self.gids = dict(uids), dict(gids)

    def user_name(self, uid):
        return self.uids.get(uid)

    def group_name(self, gid):
        return self.gids.get(gid)


def resolve(spec):
    return imageuser.resolve(spec, PASSWD, GROUP)


def test_names_are_resolved_through_the_images_own_files():
    assert resolve("app") == (100000, 100001, (999, 100002))
    assert resolve("app:staff") == (100000, 100002, (999, 100002))


def test_empty_spec_is_root():
    assert resolve("").uid == 0 and resolve("").gid == 0


def test_numeric_uid_uses_the_passwd_entry_when_there_is_one_and_gid_zero_otherwise():
    assert resolve("100000")[:2] == (100000, 100001)
    assert resolve("424242")[:2] == (424242, 0)
    assert resolve("424242:777") == (424242, 777, ())


def test_unknown_names_are_errors():
    with pytest.raises(ValueError):
        resolve("ghost")
    with pytest.raises(ValueError):
        resolve("app:ghost")


# --- the parser follows moby/sys/user, where a different reading would hand an image root ---------

def test_malformed_numbers_and_short_lines_read_as_zero_like_moby():
    assert imageuser.parse_passwd("a:b\nx:x:one:two\nplus:x:+0:+0\n") == [
        ("a", 0, 0), ("x", 0, 0), ("plus", 0, 0)]
    assert imageuser.parse_group("nogid\nx:x:y\n") == [("nogid", 0, []), ("x", 0, [])]


def test_an_earlier_line_that_reads_as_root_wins_over_a_later_well_formed_one():
    passwd = "app:x\napp:x:70000:70000::/:/bin/sh\n"
    assert imageuser.resolve("app", passwd, "")[:2] == (0, 0)


def test_lines_are_split_on_newlines_only_and_stripped_of_whitespace():
    # python's splitlines() would break at \x1c, \x85 and the like; moby does not
    passwd = "junk\x1capp:x:70000:70000::/:/bin/sh\napp:x:0:0::/:/bin/sh\n"
    assert imageuser.resolve("app", passwd, "")[:2] == (0, 0)
    assert imageuser.resolve("app", "  app:x:0:0\t\napp:x:70000:70000\n", "")[:2] == (0, 0)
    assert imageuser.resolve("app", "app:x:1000:1000\n", "root:x:0:app \n").supplementary == (0,)


def test_what_go_strips_differs_from_what_python_strips():
    # \x1c is whitespace to python's strip() but not to Go's TrimSpace
    assert imageuser.lines("\x1cabc \x85\n\n  \n") == ["\x1cabc"]


def test_a_numeric_spec_is_matched_by_id_only_never_by_name():
    passwd = "1000:x:2000:2000::/:/bin/sh\napp:x:1000:1000::/:/bin/sh\n"
    assert imageuser.resolve("1000", passwd, "")[:2] == (1000, 1000)
    assert imageuser.resolve("app:2000", passwd, "2000:x:5:\n")[:2] == (1000, 2000)


def test_atoi_follows_go_and_ignores_errors():
    texts = ("12", "+7", "-3", "", "x", "1_0", "\u0663", "99999999999999999999")
    assert [imageuser.atoi(t) for t in texts] == [12, 7, -3, 0, 0, 0, 0, 2**63 - 1]


def test_an_image_with_a_negative_id_is_an_error():
    with pytest.raises(ValueError):
        imageuser.resolve("app", "app:x:-5:-5\n", "")


def test_root_is_what_makes_an_identity_fall_back():
    assert imageuser.involves_root(imageuser.Identity(0, 5, ()))
    assert imageuser.involves_root(imageuser.Identity(5, 0, ()))
    assert imageuser.involves_root(imageuser.Identity(5, 5, (0,)))
    assert not imageuser.involves_root(imageuser.Identity(1000, 999, (7,)))


def test_describe():
    assert imageuser.describe(imageuser.Identity(5, 6, ())) == "uid 5, gid 6"
    assert imageuser.describe(imageuser.Identity(5, 6, (7, 8))) == "uid 5, gid 6, supplementary gids 7, 8"


def test_describe_with_the_local_accounts_says_who_the_ids_are():
    local = Local(uids={1000: "daniel"}, gids={1000: "daniel", 999: "docker"})
    assert imageuser.describe(imageuser.Identity(1000, 1000, (999, 4242)), local) == (
        "uid 1000 (local user daniel), gid 1000 (local group daniel), "
        "supplementary gids 999 (local group docker), 4242 (no local group)")
    assert imageuser.describe(imageuser.Identity(100000, 100001, ()), local) == (
        "uid 100000 (no local user), gid 100001 (no local group)")


def test_local_ids_use_nss():
    local = imageuser.LocalIds()
    assert local.user_name(0) == "root" and local.group_name(0) == "root"
    assert local.user_name(2**31 - 3) is None and local.group_name(2**31 - 3) is None
