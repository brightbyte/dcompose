import os
import stat as stat_module
from types import SimpleNamespace

import pytest

from dockscreen import config


def write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return str(path)


def trusting(path, uid):
    """The tests' files live under /tmp, which is world-writable: strict_modes is tested on its own."""


def load(*paths):
    return config.load(list(paths), os.getuid(), check=trusting)


def test_no_files_means_the_defaults(tmp_path):
    settings = load(str(tmp_path / "missing.toml"))
    assert settings == config.Config()
    assert settings.default_user == (65534, 65534) and settings.nobody_range == (65530, 65534)


def test_every_key(tmp_path):
    path = write(tmp_path / "c.toml", '''
user = "4100:4101"
default_user = "4000:4001"
nobody_range = [70000, 70010]
mount_dirs = ["/data"]
security_opts = ["seccomp=/etc/docker/strict.json"]
docker = "/usr/local/bin/docker"

[images.mariadb]
user = "999:999"
mount_dirs = ["/srv/db"]

[images."ghcr.io/acme/app"]
security_opts = ["apparmor=acme"]

[projects."/home/me/src/shop"]
default_user = "5000:5000"
nobody_range = [80000, 80010]
''')
    settings = load(path)
    assert settings.user == (4100, 4101)
    assert settings.default_user == (4000, 4001)
    assert settings.nobody_range == (70000, 70010)
    assert settings.mount_dirs == ("/data",)
    assert settings.security_opts == ("seccomp=/etc/docker/strict.json",)
    assert settings.docker == "/usr/local/bin/docker"
    assert dict(settings.images) == {
        "docker.io/library/mariadb": config.Section(user=(999, 999), mount_dirs=("/srv/db",)),
        "ghcr.io/acme/app": config.Section(security_opts=("apparmor=acme",))}
    assert dict(settings.projects) == {
        "/home/me/src/shop": config.Section(default_user=(5000, 5000), nobody_range=(80000, 80010))}


def test_the_users_file_overrides_the_system_file_key_by_key_and_section_by_section(tmp_path):
    system = write(tmp_path / "etc.toml", '''
default_user = "4000:4000"
mount_dirs = ["/srv"]
[images.mariadb]
user = "999:999"
[images.redis]
user = "998:998"
mount_dirs = ["/srv/redis"]
''')
    user = write(tmp_path / "user.toml", '''
mount_dirs = ["/data"]
[images.redis]
user = "5000:5000"
''')
    settings = load(system, user)
    assert settings.default_user == (4000, 4000) and settings.mount_dirs == ("/data",)
    assert dict(settings.images) == {
        "docker.io/library/mariadb": config.Section(user=(999, 999)),
        "docker.io/library/redis": config.Section(user=(5000, 5000))}  # the whole section is replaced


def test_effective_settings_apply_the_image_then_the_projects_outermost_first(tmp_path):
    shop = tmp_path / "src" / "shop"
    (shop / "web").mkdir(parents=True)
    settings = config.Config(
        user=(1, 1), mount_dirs=("/top",), security_opts=("a",),
        images={"docker.io/library/mariadb": config.Section(user=(999, 999), mount_dirs=("/img",))},
        projects={str(tmp_path / "src"): config.Section(user=(2, 2), mount_dirs=("/src",)),
                  str(shop): config.Section(security_opts=("b", "a"), default_user=(3, 3))})

    found = config.effective(settings, "docker.io/library/mariadb", str(shop / "web"))
    assert found.user == (2, 2)                       # replaced: the outer project's comes after the image's
    assert found.default_user == (3, 3)
    assert found.mount_dirs == ("/top", "/img", "/src")  # added to, in order, each once
    assert found.security_opts == ("a", "b")
    assert found.images == {} and found.projects == {}

    assert config.effective(settings) == settings._replace(images={}, projects={})
    assert config.effective(settings, None, "/elsewhere").user == (1, 1)
    assert config.effective(settings, "docker.io/library/redis", str(tmp_path)).mount_dirs == ("/top",)


@pytest.mark.parametrize("text, message", [
    ('typo = 1', "unknown key 'typo'"),
    ('default_user = "nobody"', 'default_user must be "uid:gid" with numeric ids'),
    ('default_user = "65534"', 'default_user must be "uid:gid"'),
    ("nobody_range = [65534, 65530]", "nobody_range must be [low, high]"),
    ("nobody_range = [0, 10]", "nobody_range must be [low, high]"),
    ("nobody_range = [65530, 65535]", "nobody_range must be [low, high]"),
    ("nobody_range = [60000, 70000]", "leaving out 65535"),
    ('mount_dirs = ["relative"]', "mount_dirs must be a list of absolute paths"),
    ('docker = "docker"', "docker must be an absolute path"),
    ('[images."mariadb:11"]\nuser = "999:999"', "names a repository; leave out the tag or digest"),
    ('[images."Not A Name"]\nuser = "999:999"', "is not an image reference"),
    ('[images.mariadb]\nuser = "mysql"', 'images \'mariadb\' user must be "uid:gid"'),
    ('[images.mariadb]\ndocker = "/usr/bin/docker"', "images 'mariadb' unknown key 'docker'"),
    ('[images]\nmariadb = "999:999"', "images 'mariadb' must be a table"),
    ('[projects.shop]\nuser = "1:1"', "projects 'shop' must be an absolute directory"),
    ('security_opts = "seccomp=x"', "security_opts must be a list of security options"),
    ('[image_users]\nmariadb = "999:999"', "unknown key 'image_users'"),
    ("default_user = ", "c.toml"),  # not TOML
])
def test_mistakes_are_errors_that_name_the_file(tmp_path, text, message):
    path = write(tmp_path / "c.toml", text)
    with pytest.raises(config.ConfigError, match=None) as raised:
        load(path)
    assert message in str(raised.value) and str(raised.value).startswith(path)


def fake_stat(owners):
    """os.stat for paths whose (uid, mode) are given; everything else is root's and 0755."""
    def stat(path):
        uid, mode = owners.get(path, (0, 0o755))
        return SimpleNamespace(st_uid=uid, st_mode=stat_module.S_IFDIR | mode)
    return stat


PATH = "/home/me/.config/dockscreen/config.toml"
MINE = {"/home/me": (1000, 0o755), "/home/me/.config": (1000, 0o700),
        "/home/me/.config/dockscreen": (1000, 0o700), PATH: (1000, 0o600)}


def test_strict_modes_accept_a_file_that_only_its_owner_or_root_can_write():
    config.strict_modes(PATH, 1000, fake_stat(MINE))


@pytest.mark.parametrize("change, message", [
    ({PATH: (1000, 0o620)}, f"{PATH} is writable by group or others"),
    ({PATH: (1000, 0o602)}, f"{PATH} is writable by group or others"),
    ({"/home/me/.config/dockscreen": (1000, 0o777)}, "dockscreen is writable by group or others"),
    ({"/home": (0, 0o1777)}, "/home is writable by group or others"),  # a file there can be renamed away
    ({PATH: (1001, 0o600)}, "is owned by uid 1001, not by you or root"),
    ({"/home/me": (1001, 0o755)}, "/home/me is owned by uid 1001"),
])
def test_strict_modes_refuse_what_someone_else_could_have_written(change, message):
    with pytest.raises(config.ConfigError, match=message):
        config.strict_modes(PATH, 1000, fake_stat({**MINE, **change}))


def test_a_file_that_fails_strict_modes_is_an_error(tmp_path):
    path = write(tmp_path / "c.toml", "")

    def refuse(path_, uid):
        raise config.ConfigError(f"{path_}: nope")

    with pytest.raises(config.ConfigError, match="nope"):
        config.load([path], os.getuid(), check=refuse)


def test_the_user_file_follows_xdg(tmp_path):
    assert config.user_file({"XDG_CONFIG_HOME": "/x"}, "/home/me") == "/x/dockscreen/config.toml"
    default = "/home/me/.config/dockscreen/config.toml"
    assert config.user_file({}, "/home/me") == default
    assert config.user_file({"XDG_CONFIG_HOME": "relative"}, "/home/me") == default


def test_a_missing_user_file_is_created_with_every_setting_commented_out(tmp_path):
    path = tmp_path / "xdg" / "dockscreen" / "config.toml"
    assert config.create_user_file(str(path))
    assert stat_module.S_IMODE(path.stat().st_mode) == 0o600
    assert stat_module.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert load(str(path)) == config.Config()  # the defaults, and nothing that overrides /etc


def test_the_template_examples_are_valid_settings(tmp_path):
    path = tmp_path / "config.toml"
    config.create_user_file(str(path))
    text = path.read_text()
    for empty in ("#mount_dirs = []\n", "#security_opts = []\n"):
        text = text.replace(empty, "")
    # settings and section headers are commented out as `#key` and `#[section]`, prose as `# text`
    path.write_text("\n".join(line[1:] if line.startswith("#") and not line.startswith("# ") else line
                               for line in text.splitlines()))
    settings = load(str(path))
    assert settings.mount_dirs == ("/srv/shared-data",)
    assert settings.images["docker.io/library/mariadb"].user == (999, 999)
    assert list(settings.projects) == ["/home/me/src/shop"]


def test_an_existing_user_file_is_left_alone(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("mine")
    assert not config.create_user_file(str(path)) and path.read_text() == "mine"
    (tmp_path / "link.toml").symlink_to(tmp_path / "elsewhere.toml")
    assert not config.create_user_file(str(tmp_path / "link.toml"))
    assert not (tmp_path / "elsewhere.toml").exists()
