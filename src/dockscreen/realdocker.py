"""Locating the real docker binary, so that a wrapper named `docker` can sit in front of it."""

import os
import sys

from dockscreen import config

_cached = None


def docker_bin():
    """Path of the real docker, or plain "docker" so that exec reports the usual error."""
    global _cached
    if _cached is None:
        _cached = choose(config.current(), os.environ, {os.path.realpath(sys.argv[0])})
    return _cached


def choose(settings, env, wrappers):
    """The docker the config file names, else the one find() finds, else plain "docker"."""
    return settings.docker or find(env, wrappers) or "docker"


def find(env, wrappers):
    """The first `docker` on PATH that is not one of our wrappers; the config file can name another.

    Empty PATH entries (meaning the current directory) are skipped: a hostile
    project must not be able to supply the binary we run.
    """
    for directory in env.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = os.path.join(directory, "docker")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK) \
                and os.path.realpath(candidate) not in wrappers:
            return candidate
    return None
