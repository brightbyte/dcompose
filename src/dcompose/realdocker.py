"""Locating the real docker binary, so that a wrapper named `docker` can sit in front of it."""

import os
import sys

_cached = None


def docker_bin():
    """Path of the real docker, or plain "docker" so that exec reports the usual error."""
    global _cached
    if _cached is None:
        _cached = find(os.environ, {os.path.realpath(sys.argv[0])}) or "docker"
    return _cached


def find(env, wrappers):
    """DCOMPOSE_DOCKER if set, else the first `docker` on PATH that is not one of our wrappers.

    Empty PATH entries (meaning the current directory) are skipped: a hostile
    project must not be able to supply the binary we run.
    """
    explicit = env.get("DCOMPOSE_DOCKER")
    if explicit:
        return explicit
    for directory in env.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = os.path.join(directory, "docker")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK) \
                and os.path.realpath(candidate) not in wrappers:
            return candidate
    return None
