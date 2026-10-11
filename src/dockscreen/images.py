"""Image references, and whether an image is one the config file names a user for.

An image_users entry names a repository: it trusts the image's maintainer, not one image. A name alone
proves nothing, because anything can be built or tagged locally under any name, so an image matches only
if docker recorded that it was pulled from that repository (a repo digest), and never for a service that
is built from a Dockerfile.
"""

import re
from typing import NamedTuple

DEFAULT_DOMAIN = "docker.io"
LEGACY_DOMAINS = frozenset({"index.docker.io", "registry-1.docker.io"})
# distribution/reference: a path component is lower-case alphanumerics and separators.
COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")


class Match(NamedTuple):
    user: tuple | None    # (uid, gid) from the config, if the image matches
    problem: str | None   # why an entry for the repository does not apply, for audit


def split_reference(reference):
    """(normalised repository, tag, digest) as docker reads a reference: `mariadb` is
    docker.io/library/mariadb. Raises ValueError for something that is not a reference."""
    name, _, digest = reference.partition("@")
    tag = ""
    last_slash = name.rfind("/")
    if ":" in name[last_slash + 1:]:
        name, _, tag = name.rpartition(":")
    first, slash, rest = name.partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        domain, path = first, rest
    else:
        domain, path = DEFAULT_DOMAIN, name
    if domain in LEGACY_DOMAINS:
        domain = DEFAULT_DOMAIN
    if domain == DEFAULT_DOMAIN and "/" not in path:
        path = "library/" + path
    if not path or not all(COMPONENT.match(part) for part in path.split("/")):
        raise ValueError(f"{reference!r} is not an image reference")
    return f"{domain}/{path}", tag, digest


def repository(reference):
    """The normalised repository of a reference, or None if it is not one."""
    try:
        return split_reference(reference)[0]
    except ValueError:
        return None


def configured_user(config, reference, repo_digests, built):
    """The user the config file sets for this image, if it applies.

    reference: the image name the service or command line uses.
    repo_digests: the image's RepoDigests (docker image inspect): where it was pulled from.
    built: the service builds the image from a Dockerfile.
    """
    name = repository(reference)
    user = config.image_users.get(name) if name else None
    if user is None:
        return Match(None, None)
    if built:
        return Match(None, f"the config sets a user for {name}, but the service builds its image")
    if not any(repository(d) == name for d in repo_digests or []):
        return Match(None, f"the config sets a user for {name}, but this image was not pulled from there")
    return Match(user, None)
