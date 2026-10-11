import pytest

from dcompose import imageuser

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
        self.uids, self.gids = set(uids), set(gids)

    def uid_exists(self, uid):
        return uid in self.uids

    def gid_exists(self, gid):
        return gid in self.gids


RANGE = (65532, 2**31 - 1)


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


def test_malformed_lines_are_skipped():
    assert imageuser.parse_passwd("a:b\n:::\nx:x:one:two\n") == []
    assert imageuser.parse_group("nogid\nx:x:y\n") == []


def check(identity, local=None):
    return imageuser.check(identity, RANGE, local or Local())


def test_high_unknown_ids_are_accepted():
    assert check(imageuser.Identity(100000, 100001, (100002,))) == []
    assert check(imageuser.Identity(65532, 65532, ())) == []  # distroless nonroot


def test_root_is_what_makes_an_identity_fall_back():
    assert imageuser.involves_root(imageuser.Identity(0, 5, ()))
    assert imageuser.involves_root(imageuser.Identity(5, 0, ()))
    assert imageuser.involves_root(imageuser.Identity(5, 5, (0,)))
    assert not imageuser.involves_root(imageuser.Identity(1000, 999, (7,)))


def test_describe():
    assert imageuser.describe(imageuser.Identity(5, 6, ())) == "uid 5, gid 6"
    assert imageuser.describe(imageuser.Identity(5, 6, (7, 8))) == "uid 5, gid 6, supplementary gids 7, 8"


def test_nobody_is_exempt_everywhere():
    assert check(imageuser.Identity(65534, 65534, (65534,)), Local({65534}, {65534})) == []


@pytest.mark.parametrize("identity, reason", [
    (imageuser.Identity(0, 100001, ()), "uid 0 (root)"),
    (imageuser.Identity(100000, 0, ()), "gid 0 (root)"),
    (imageuser.Identity(100000, 100001, (0,)), "supplementary gid 0 (root)"),
    (imageuser.Identity(1000, 100001, ()), "uid 1000, outside the allowed range"),
    (imageuser.Identity(65531, 100001, ()), "uid 65531, outside the allowed range"),
    (imageuser.Identity(100000, 999, ()), "gid 999, outside the allowed range"),
    (imageuser.Identity(100000, 100001, (999,)), "supplementary gid 999, outside"),
    (imageuser.Identity(2**31, 100001, ()), "outside the allowed range"),
])
def test_refusals_name_the_reason(identity, reason):
    problems = check(identity)
    assert len(problems) == 1 and reason in problems[0]


def test_ids_that_exist_on_this_host_are_refused_even_inside_the_range():
    assert "uid 100000, which exists on this host" in check(
        imageuser.Identity(100000, 100001, ()), Local(uids={100000}))[0]
    assert "gid 100001, which exists on this host" in check(
        imageuser.Identity(100000, 100001, ()), Local(gids={100001}))[0]
    assert "supplementary gid 100002, which exists" in check(
        imageuser.Identity(100000, 100001, (100002,)), Local(gids={100002}))[0]


def test_local_ids_use_nss():
    import os
    local = imageuser.LocalIds()
    assert local.uid_exists(os.getuid()) in (True, False)  # may be absent from passwd in a container
    assert local.uid_exists(0) and local.gid_exists(0)
    assert not local.uid_exists(2**31 - 3)
