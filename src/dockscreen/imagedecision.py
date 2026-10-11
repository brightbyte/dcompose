"""Deciding the user a container runs as when the command line or the service does not choose one.

The image is hostile: its own /etc/passwd and /etc/group decide the identity docker would use (see
imageuser), and the id rules decide whether the image may have it (idrules). With no user chosen, in
this order:
- the config file names a user for the image's repository, and the image was pulled from there:
  that user, whatever it is (images.section_for, config.effective);
- the image would run as root (uid, gid or a supplementary gid of 0): the configured default user
  instead, nobody unless configured otherwise, with a notice;
- otherwise the image's own user, if the id rules accept it; refused if not.

Whatever is accepted is not left for the runtime to resolve a second time: it runs as `uid:gid`, the
checked numbers (pinned_user), so a difference between our reading of the image's passwd and group
files and the runtime's can at worst refuse a good image, never run root.

Used by `docker run` (gate) and by compose (composeimages) alike.
"""

import enum
from typing import NamedTuple, Protocol, runtime_checkable

from dockscreen import config, idrules, ids, images, imageuser
from dockscreen.runtime import Runtime


@runtime_checkable
class DockerAccess(Protocol):
    """What deciding needs from docker (dockerclient.Docker): a container to look at, never started."""

    def create(self, args):
        """(exit code, container id or None) for `docker create args`."""

    def inspect_container(self, ref):
        """`docker container inspect` of ref; raises dockerclient.DockerError."""

    def inspect_image(self, ref):
        """`docker image inspect` of ref; raises dockerclient.DockerError."""

    def read_file(self, container, path):
        """The text of a file in a container that was not started, or None."""

    def remove(self, container):
        """Remove the container."""

    def context(self):
        """The name of the current docker context, or None."""


class Context(NamedTuple):
    docker: DockerAccess
    ids: idrules.Rules
    runtime: Runtime               # the config file, the caller's ids, the host's accounts
    project_dir: str | None = None  # the compose project's; for docker run, the current directory

    @property
    def local(self):
        return self.ids.local

    @property
    def directory(self):
        return self.project_dir or self.runtime.cwd

    @property
    def settings(self):
        """The settings for this project, without any image section."""
        return config.effective(self.runtime.settings, None, self.directory)

    def for_image(self, repository):
        """(settings, id rules) with the image section for repository applied (None: none applies)."""
        settings = config.effective(self.runtime.settings, repository, self.directory)
        rules = self.ids._replace(nobody_range=settings.nobody_range, default_user=settings.default_user)
        return settings, rules

    def allowing_me(self, allow_me):
        """This context with the caller's own ids allowed if allow_me, for --allow-me and --as-me."""
        return self._replace(ids=self.ids._replace(allow_me=True)) if allow_me else self


class Kind(enum.StrEnum):
    EXPLICIT = "explicit"      # the command line chose the user: trusted, not checked
    CONFIGURED = "configured"  # the config file names the user, for this image, project or every one
    OK = "ok"                  # the image's own user, which the id rules accept
    FALLBACK = "fallback"      # the image would run as root: the default user instead
    REFUSED = "refused"
    FAILED = "failed"          # the image could not be looked at: missing, or docker failed


class Assessment(NamedTuple):
    kind: Kind
    problems: list
    identity: imageuser.Identity | None = None
    note: str | None = None        # a section for the repository that does not apply, and why
    user: tuple | None = None      # the (uid, gid) it runs as, when dockscreen decided it (pins_user)
    section: str | None = None     # the repository whose image section applied, if one did

    @property
    def refused(self):
        """Whether the container must not run: refused, or not assessed at all."""
        return self.kind in (Kind.REFUSED, Kind.FAILED)

    @property
    def failed(self):
        return self.kind is Kind.FAILED

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
    match = images.section_for(ctx.runtime.settings, reference or info["Config"].get("Image") or "",
                               image.get("RepoDigests"), built)
    found = {"note": match.problem, "section": match.repository}
    spec = info["Config"].get("User") or ""
    if explicit is None:
        explicit = spec != (image["Config"].get("User") or "")
    if explicit:
        return Assessment(Kind.EXPLICIT, [], **found)  # trusted: the person typing the command chose it

    settings, rules = ctx.for_image(match.repository)
    if settings.user:
        return Assessment(Kind.CONFIGURED, [], imageuser.Identity(*settings.user, ()), user=settings.user,
                          **found)

    passwd = ctx.docker.read_file(container, "/etc/passwd") or ""
    groups = ctx.docker.read_file(container, "/etc/group") or ""
    try:
        identity = imageuser.resolve(spec, passwd, groups)
    except ValueError as e:
        return Assessment(Kind.REFUSED, [str(e)], **found)
    if imageuser.involves_root(identity):
        return Assessment(Kind.FALLBACK, [], identity, user=settings.default_user, **found)
    if mounts is None:
        mounts = has_host_mounts(info)
    problems = rules.problems(identity.uid, identity.gid, identity.supplementary, mounts=mounts)
    if problems:
        return Assessment(Kind.REFUSED, [f"the image's {p}" for p in problems], identity, **found)
    return Assessment(Kind.OK, [], identity, user=(identity.uid, identity.gid), **found)


def default_user_spec(ctx):
    """The `uid:gid` that replaces an image's root user in this project, without an image section."""
    return ids.format_user(ctx.settings.default_user)


def pinned_user(assessment):
    """The `uid:gid` a fallback, configured or accepted image user runs as, spelled as numbers."""
    return ids.format_user(assessment.user)


def root_default_notice(ctx):
    """A notice for every run when the configured default user is root, or None."""
    if 0 in ctx.settings.default_user:
        return (f"the configured default user is {default_user_spec(ctx)}: "
                "images that would run as root run as root")
    return None
