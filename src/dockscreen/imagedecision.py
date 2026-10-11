"""Deciding the user a container runs as when the command line or the service does not choose one.

The image is hostile: its own /etc/passwd and /etc/group decide the identity docker would use (see
imageuser), and the id rules decide whether the image may have it (idrules). With no user chosen, in
this order:
- the config file names a user for the image's repository, and the image was pulled from there:
  that user, whatever it is (images.configured_user);
- the image would run as root (uid, gid or a supplementary gid of 0): the configured default user
  instead, nobody unless configured otherwise, with a notice;
- otherwise the image's own user, if the id rules accept it; refused if not.

Whatever is accepted is not left for the runtime to resolve a second time: it runs as `uid:gid`, the
checked numbers (pinned_user), so a difference between our reading of the image's passwd and group
files and the runtime's can at worst refuse a good image, never run root.

Used by `docker run` (gate) and by compose (composeimages) alike.
"""

import enum
from typing import NamedTuple

from dockscreen import ids, images, imageuser


class Context(NamedTuple):
    docker: object
    ids: object      # idrules.Rules
    runtime: object  # runtime.Runtime: the config file, the caller's ids, the host's accounts

    @property
    def local(self):
        return self.ids.local

    @property
    def settings(self):
        return self.runtime.settings

    def allowing_me(self, allow_me):
        """This context with the caller's own ids allowed if allow_me, for --allow-me and --as-me."""
        return self._replace(ids=self.ids._replace(allow_me=True)) if allow_me else self


class Kind(enum.StrEnum):
    EXPLICIT = "explicit"      # the command line chose the user: trusted, not checked
    CONFIGURED = "configured"  # the config file names a user for the image's repository
    OK = "ok"                  # the image's own user, which the id rules accept
    FALLBACK = "fallback"      # the image would run as root: the default user instead
    REFUSED = "refused"


class Assessment(NamedTuple):
    kind: Kind
    problems: list
    identity: imageuser.Identity | None = None
    note: str | None = None  # an image_users entry for the repository that does not apply, and why

    @property
    def refused(self):
        return self.kind is Kind.REFUSED

    @property
    def pins_user(self):
        """Whether dockscreen decided the user, and runs the image as it, spelled as numbers."""
        return self.kind in (Kind.CONFIGURED, Kind.OK, Kind.FALLBACK)

    @property
    def replaces_image_user(self):
        """Whether the user dockscreen decided differs from the one the image chose."""
        return self.kind in (Kind.CONFIGURED, Kind.FALLBACK)


def has_host_mounts(info):
    """Whether the container, as inspected, reaches host files or devices.

    Bind mounts, devices and volumes taken from another container all do. Named volumes live in
    docker's own directory and tmpfs in memory, so the user id means nothing to the host there.
    """
    host = info.get("HostConfig") or {}
    mounts = [*(info.get("Mounts") or []), *(host.get("Mounts") or [])]
    binds = [b for b in host.get("Binds") or [] if str(b).split(":")[0].startswith("/")]
    binds_or_devices = any(m.get("Type") == "bind" for m in mounts) or binds
    return bool(binds_or_devices or host.get("Devices") or host.get("VolumesFrom"))


def assess(ctx, container, info, explicit=None, mounts=None, reference=None, built=False):
    """What the image would be allowed to do.

    explicit: the user was set on the command line, if known.
    mounts: the container reaches host files or devices; worked out from info if not given.
    reference: the image name as the command line or the service gave it (the container's if None).
    built: the image is built from a Dockerfile by the service; the config file never applies then.
    """
    image = ctx.docker.inspect_image(info["Image"])
    spec = info["Config"].get("User") or ""
    if explicit is None:
        explicit = spec != (image["Config"].get("User") or "")
    if explicit:
        return Assessment(Kind.EXPLICIT, [])  # trusted: the person typing the command chose it

    match = images.configured_user(ctx.settings, reference or info["Config"].get("Image") or "",
                                   image.get("RepoDigests"), built)
    if match.user:
        return Assessment(Kind.CONFIGURED, [], imageuser.Identity(*match.user, ()))

    passwd = ctx.docker.read_file(container, "/etc/passwd") or ""
    groups = ctx.docker.read_file(container, "/etc/group") or ""
    try:
        identity = imageuser.resolve(spec, passwd, groups)
    except ValueError as e:
        return Assessment(Kind.REFUSED, [str(e)], note=match.problem)
    if imageuser.involves_root(identity):
        return Assessment(Kind.FALLBACK, [], identity, match.problem)
    if mounts is None:
        mounts = has_host_mounts(info)
    problems = ctx.ids.problems(identity.uid, identity.gid, identity.supplementary, mounts=mounts)
    if problems:
        return Assessment(Kind.REFUSED, [f"the image's {p}" for p in problems], identity, match.problem)
    return Assessment(Kind.OK, [], identity, match.problem)


def default_user_spec(ctx):
    """The `uid:gid` that replaces an image's root user."""
    return ids.format_user(ctx.settings.default_user)


def pinned_user(ctx, assessment):
    """The `uid:gid` a fallback, configured or accepted image user runs as, spelled as numbers."""
    if assessment.kind is Kind.FALLBACK:
        return default_user_spec(ctx)
    return ids.format_user((assessment.identity.uid, assessment.identity.gid))


def root_default_notice(ctx):
    """A notice for every run when the configured default user is root, or None."""
    if 0 in ctx.settings.default_user:
        return (f"the configured default user is {default_user_spec(ctx)}: "
                "images that would run as root run as root")
    return None
