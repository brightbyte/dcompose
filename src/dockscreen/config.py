"""dockscreen's configuration: TOML files that only the user or root can write.

The files are trusted completely, so they are only read when nothing but their owner could have put
their content there: the file and every directory above it must be owned by the user or root and not
writable by group or others, as ssh's StrictModes requires. A project cannot configure dockscreen;
environment variables do not configure it either.

The user's file overrides the system file key by key, and [images] and [projects] section by section.
A missing user file is created from config.template.toml, with every setting commented out, so that it
shows the defaults without overriding the system file.

The settings can also be given per image (`[images."REPOSITORY"]`) and per project
(`[projects."DIRECTORY"]`). They apply in that order, after the top level (effective): a single value
replaces the one before, a list is added to the ones before.
"""

import importlib.resources
import os
import stat
import tomllib
from types import MappingProxyType
from typing import NamedTuple

from dockscreen import ids, images, messages

SYSTEM_FILE = "/etc/dockscreen/config.toml"
# What the top level, an image section and a project section may set.
SETTINGS = frozenset({"user", "default_user", "nobody_range", "mount_dirs", "security_opts"})
KEYS = SETTINGS | {"docker", "images", "projects"}
# 65535 and 4294967295 are (uid_t)-1 in 16 and 32 bits, which tools read as "no id".
NO_ID = frozenset({65535, 4294967295})


class ConfigError(Exception):
    """A config file cannot be trusted or read; dockscreen refuses to run."""


class Section(NamedTuple):
    """The settings an image or project section gives; None and () for those it leaves alone."""
    user: tuple | None = None
    default_user: tuple | None = None
    nobody_range: tuple | None = None
    mount_dirs: tuple = ()
    security_opts: tuple = ()


class Config(NamedTuple):
    user: tuple | None = None                # (uid, gid) an image runs as when nothing chose a user
    default_user: tuple = (65534, 65534)     # (uid, gid) that replaces an image's root user
    nobody_range: tuple = (65530, 65534)     # inclusive: ids any image or project may use
    mount_dirs: tuple = ()                   # absolute directories bind mounts may come from
    security_opts: tuple = ()                # security options allowed besides no-new-privileges
    docker: str | None = None                # absolute path of the real docker
    images: MappingProxyType = MappingProxyType({})    # normalised repository -> Section
    projects: MappingProxyType = MappingProxyType({})  # absolute directory -> Section


def effective(config, repository=None, directory=None):
    """The settings for an image pulled from repository (None: no image section applies), in a project
    in directory (None: no project): the top level, then the image's section, then the sections of the
    projects that directory is in, outermost first. The result has no sections of its own.
    """
    sections = [config.images[repository]] if repository in config.images else []
    if directory is not None:
        real = os.path.realpath(directory)
        matching = [d for d in config.projects if is_inside(real, os.path.realpath(d))]
        sections += [config.projects[d] for d in sorted(matching, key=lambda d: len(os.path.realpath(d)))]
    result = config._replace(images=MappingProxyType({}), projects=MappingProxyType({}))
    for section in sections:
        result = amend(result, section)
    return result


def amend(config, section):
    """config with section applied: single values replaced, lists added to."""
    changes = {key: getattr(section, key) for key in ("user", "default_user", "nobody_range")
               if getattr(section, key) is not None}
    for key in ("mount_dirs", "security_opts"):
        before = getattr(config, key)
        changes[key] = (*before, *(v for v in getattr(section, key) if v not in before))
    return config._replace(**changes)


def is_inside(path, root):
    return os.path.commonpath([path, root]) == root


def all_mount_dirs(config):
    """Every mount dir the config names: the top level's and every section's."""
    sections = [*config.images.values(), *config.projects.values()]
    return tuple(dict.fromkeys([*config.mount_dirs, *(d for s in sections for d in s.mount_dirs)]))


def user_file(env, home):
    """$XDG_CONFIG_HOME/dockscreen/config.toml; a relative XDG_CONFIG_HOME is ignored, as XDG says."""
    base = env.get("XDG_CONFIG_HOME", "")
    if not os.path.isabs(base):
        base = os.path.join(home, ".config")
    return os.path.join(base, "dockscreen", "config.toml")


def load_current(env, home, uid):
    """The configuration of the caller with this environment, home directory and uid."""
    path = user_file(env, home)
    if create_user_file(path):
        messages.notice(f"created {path}, which shows the defaults")
    return load([SYSTEM_FILE, path], uid)


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


def load(paths, uid, check=None):
    """Read and merge the files in paths (later ones win); missing files are skipped.

    check(path, uid) raises ConfigError for a file that cannot be trusted (strict_modes by default).
    """
    check = check or strict_modes
    config = Config()
    for path in paths:
        data = read(path, uid, check)
        if data is not None:
            config = merge(config, path, data)
    return config


def merge(config, path, data):
    """config with the file at path read over it: its keys replace, its sections replace by name."""
    unknown = sorted(set(data) - KEYS)
    if unknown:
        raise ConfigError(f"{path}: unknown key {unknown[0]!r}")
    images_ = {repository_key(path, name): section(path, f"images {name!r}", value)
               for name, value in table(path, "images", data.get("images", {})).items()}
    projects = {project_key(path, name): section(path, f"projects {name!r}", value)
                for name, value in table(path, "projects", data.get("projects", {})).items()}
    top = section(path, "", {k: v for k, v in data.items() if k in SETTINGS})
    changes = {key: value for key, value in top._asdict().items() if key in data}
    if "docker" in data:
        if not isinstance(data["docker"], str) or not os.path.isabs(data["docker"]):
            raise ConfigError(f"{path}: docker must be an absolute path")
        changes["docker"] = data["docker"]
    return config._replace(**changes, images=MappingProxyType({**config.images, **images_}),
                           projects=MappingProxyType({**config.projects, **projects}))


def table(path, key, value):
    if not isinstance(value, dict):
        raise ConfigError(f"{path}: {key} must be a table of sections")
    return value


def section(path, where, data):
    """The Section that data sets; where names it in errors ("" for the top level)."""
    prefix = f"{path}: {where} " if where else f"{path}: "
    if not isinstance(data, dict):
        raise ConfigError(f"{prefix}must be a table")
    unknown = sorted(set(data) - SETTINGS)
    if unknown:
        raise ConfigError(f"{prefix}unknown key {unknown[0]!r}")
    fields = {}
    for key in ("user", "default_user"):
        if key in data:
            fields[key] = user_value(path, f"{where} {key}".strip(), data[key])
    if "nobody_range" in data:
        fields["nobody_range"] = id_range(path, data["nobody_range"])
    if "mount_dirs" in data:
        value = data["mount_dirs"]
        if not isinstance(value, list) or not all(isinstance(d, str) and os.path.isabs(d) for d in value):
            raise ConfigError(f"{prefix}mount_dirs must be a list of absolute paths")
        fields["mount_dirs"] = tuple(value)
    if "security_opts" in data:
        value = data["security_opts"]
        if not isinstance(value, list) or not all(isinstance(o, str) and o for o in value):
            raise ConfigError(f"{prefix}security_opts must be a list of security options")
        fields["security_opts"] = tuple(value)
    return Section(**fields)


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
    """The normalised repository an image section names; a tag or digest is an error."""
    try:
        repository, tag, digest = images.split_reference(name)
    except ValueError as e:
        raise ConfigError(f"{path}: images {name!r}: {e}") from None
    if tag or digest:
        raise ConfigError(f"{path}: images {name!r} names a repository; leave out the tag or digest")
    return repository


def project_key(path, name):
    """The directory a project section names, which must be absolute."""
    if not os.path.isabs(name):
        raise ConfigError(f"{path}: projects {name!r} must be an absolute directory")
    return os.path.normpath(name)
