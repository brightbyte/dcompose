"""dockscreen's configuration: TOML files that only the user or root can write.

The files are trusted completely, so they are only read when nothing but their owner could have put
their content there: the file and every directory above it must be owned by the user or root and not
writable by group or others, as ssh's StrictModes requires. A project cannot configure dockscreen;
environment variables do not configure it either.

The user's file overrides the system file key by key, and image_users entry by entry. A missing user
file is created from config.template.toml, with every setting commented out, so that it shows the
defaults without overriding the system file.
"""

import functools
import importlib.resources
import os
import stat
import tomllib
from types import MappingProxyType
from typing import NamedTuple

from dockscreen import ids, images, messages

SYSTEM_FILE = "/etc/dockscreen/config.toml"
KEYS = frozenset({"default_user", "nobody_range", "mount_dirs", "docker", "image_users"})
# 65535 and 4294967295 are (uid_t)-1 in 16 and 32 bits, which tools read as "no id".
NO_ID = frozenset({65535, 4294967295})


class ConfigError(Exception):
    """A config file cannot be trusted or read; dockscreen refuses to run."""


class Config(NamedTuple):
    default_user: tuple = (65534, 65534)     # (uid, gid) that replaces an image's root user
    nobody_range: tuple = (65530, 65534)     # inclusive: ids any image or project may use
    mount_dirs: tuple = ()                   # absolute directories bind mounts may come from
    docker: str | None = None                # absolute path of the real docker
    image_users: MappingProxyType = MappingProxyType({})  # normalised repository -> (uid, gid)


def user_file(env):
    """$XDG_CONFIG_HOME/dockscreen/config.toml; a relative XDG_CONFIG_HOME is ignored, as XDG says."""
    base = env.get("XDG_CONFIG_HOME", "")
    if not os.path.isabs(base):
        base = os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "dockscreen", "config.toml")


@functools.cache
def current():
    """The configuration for this process, read once."""
    path = user_file(os.environ)
    if create_user_file(path):
        messages.notice(f"created {path}, which shows the defaults")
    return load([SYSTEM_FILE, path])


def create_user_file(path):
    """Write the template to path, with its directories, if nothing is there; True if it did.

    Failing to write it is not an error: dockscreen runs with the defaults. An existing file, or a
    symlink in its place, is never touched.
    """
    template = importlib.resources.files("dockscreen").joinpath("config.template.toml").read_bytes()
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        return False
    with os.fdopen(fd, "wb") as f:
        f.write(template)
    return True


def load(paths, uid=None, check=None):
    """Read and merge the files in paths (later ones win); missing files are skipped.

    check(path, uid) raises ConfigError for a file that cannot be trusted (strict_modes by default).
    """
    uid = os.getuid() if uid is None else uid
    check = check or strict_modes
    merged, image_users = {}, {}
    for path in paths:
        data = read(path, uid, check)
        if data is None:
            continue
        unknown = sorted(set(data) - KEYS)
        if unknown:
            raise ConfigError(f"{path}: unknown key {unknown[0]!r}")
        users = data.pop("image_users", {})
        if not isinstance(users, dict):
            raise ConfigError(f"{path}: image_users must be a table")
        image_users.update({repository_key(path, k): user_value(path, f"image_users {k!r}", v)
                            for k, v in users.items()})
        merged.update({key: (path, value) for key, value in data.items()})
    return build(merged, image_users)


def read(path, uid, check):
    try:
        with open(path, "rb") as f:
            check(path, uid)
            opened, checked = os.fstat(f.fileno()), os.stat(path)
            if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
                raise ConfigError(f"{path}: the file was replaced while it was read")
            return tomllib.load(f)
    except FileNotFoundError:
        return None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None
    except OSError as e:
        raise ConfigError(f"{path}: {e.strerror}") from None


def strict_modes(path, uid, stat_path=os.stat):
    """Like ssh's StrictModes: the file and every directory above it are owned by uid or root, and
    writable by nobody else. Otherwise anyone who could write there could configure dockscreen."""
    current = os.path.realpath(path)
    while True:
        info = stat_path(current)
        if info.st_uid not in (uid, 0):
            raise ConfigError(f"{path}: {current} is owned by uid {info.st_uid}, not by you or root")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ConfigError(f"{path}: {current} is writable by group or others")
        parent = os.path.dirname(current)
        if parent == current:
            return
        current = parent


def build(merged, image_users):
    config = Config()
    if "default_user" in merged:
        path, value = merged["default_user"]
        config = config._replace(default_user=user_value(path, "default_user", value))
    if "nobody_range" in merged:
        config = config._replace(nobody_range=id_range(*merged["nobody_range"]))
    if "mount_dirs" in merged:
        path, value = merged["mount_dirs"]
        if not isinstance(value, list) or not all(isinstance(d, str) and os.path.isabs(d) for d in value):
            raise ConfigError(f"{path}: mount_dirs must be a list of absolute paths")
        config = config._replace(mount_dirs=tuple(value))
    if "docker" in merged:
        path, value = merged["docker"]
        if not isinstance(value, str) or not os.path.isabs(value):
            raise ConfigError(f"{path}: docker must be an absolute path")
        config = config._replace(docker=value)
    return config._replace(image_users=MappingProxyType(image_users))


def user_value(path, key, value):
    """(uid, gid) from "uid:gid"; names are not resolved here, both must be numbers."""
    user = ids.parse_user(value) if isinstance(value, str) else None
    if user is None:
        raise ConfigError(f"{path}: {key} must be \"uid:gid\" with numeric ids, not {value!r}")
    return user


def id_range(path, value):
    """An inclusive (low, high) that leaves out root and the ids that mean "no id"."""
    valid = isinstance(value, list) and len(value) == 2 and all(isinstance(v, int) for v in value)
    if not (valid and 0 < value[0] <= value[1] and not any(value[0] <= n <= value[1] for n in NO_ID)
            and value[1] < max(NO_ID)):
        raise ConfigError(f"{path}: nobody_range must be [low, high] with 0 < low <= high, leaving out 65535")
    return tuple(value)


def repository_key(path, name):
    """The normalised repository an image_users entry names; a tag or digest is an error."""
    try:
        repository, tag, digest = images.split_reference(name)
    except ValueError as e:
        raise ConfigError(f"{path}: image_users {name!r}: {e}") from None
    if tag or digest:
        raise ConfigError(f"{path}: image_users {name!r} names a repository; leave out the tag or digest")
    return repository
