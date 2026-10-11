"""Fakes for the docker side of dockscreen: images with users, and the compose commands around them."""
import json
import os
import subprocess

from dockscreen import composeimages, config, hostusers, idrules, imagedecision
from dockscreen.dockerclient import DockerError

PASSWD = ("app:x:100000:100001::/:/bin/sh\nroot:x:0:0::/:/bin/sh\nweb:x:1000:1000::/:/bin/sh\n"
          "pg:x:998:998::/:/bin/sh\nnobody:x:65534:65534::/:/bin/sh\n")
GROUP = "app:x:100001:\npg:x:998:\n"


SUBCOMMANDS = ("pull", "build", "up", "run", "create", "watch", "scale")


class NoSubordinate:
    def contains(self, kind, value):
        return False


def rules(me=(4242, 4343), allow_me=False, local=None, settings=None, subordinate=None):
    """idrules.Rules for the host of Accounts, with the default config unless settings says otherwise.

    The caller is 4242:4343 (alice in Accounts), so that 1000 is someone else: daniel, a local account.
    """
    settings = settings or config.Config()
    return idrules.Rules(me, allow_me, settings.nobody_range, settings.default_user, local or Accounts(),
                         subordinate or NoSubordinate())


class Accounts:
    """hostusers.HostAccounts for a host with root, an account `daniel` with uid and gid 1000, the group
    `docker` (999), and nobody.

    By name there is also alice (4242:4343), who has no matching group. Her ids are not listed as local
    accounts: tests use them as the caller's own, which idrules must tell apart from someone else's.
    """

    def user(self, name):
        users = {"root": (0, 0), "nobody": (65534, 65534), "daniel": (1000, 1000), "alice": (4242, 4343)}
        return users.get(name)

    def group(self, name):
        return {"root": 0, "nogroup": 65534, "nobody": 65534, "daniel": 1000, "docker": 999}.get(name)

    def user_name(self, uid):
        return {0: "root", 1000: "daniel"}.get(uid)

    def group_name(self, gid):
        return {0: "root", 1000: "daniel", 999: "docker"}.get(gid)


REAL_RESOLVE = hostusers.resolve_account  # tests that replace it by host_account must not recurse


def host_account(name):
    """hostusers.resolve_account against the host of Accounts."""
    return REAL_RESOLVE(name, Accounts())


class FakeImages:
    """A docker that knows images by name: the user each sets, and which are present locally."""

    def __init__(self, users=None, local=None, digests=None):
        self.users = users or {}
        self.digests = digests or {}  # image name -> RepoDigests: where it was pulled from
        self.local = set(self.users if local is None else local)
        self.calls = []
        self.created = []
        self._containers = {}

    def context(self):
        return "default"

    @staticmethod
    def image_id(name):
        return "sha256:" + name.replace(":", "-")

    def inspect_image(self, ref):
        ref = next((name for name in self.local if self.image_id(name) == ref), ref)  # an id or a name
        if ref not in self.local:
            raise DockerError(f"No such image: {ref}")
        return {"Id": self.image_id(ref), "Config": {"User": self.users.get(ref, "")},
                "RepoDigests": self.digests.get(ref, [])}

    def create(self, args):
        self.calls.append(("create", args))
        image = args[-1]
        if image not in self.local:
            return 1, None
        container = f"c{len(self._containers) + 1}"
        self._containers[container] = image
        self.created.append((image, args))
        return 0, container

    def inspect_container(self, ref):
        image = self._containers[ref]
        config = {"Image": image, "User": self.users.get(image, "")}
        return {"Id": ref, "Image": self.image_id(image), "Config": config}

    def read_file(self, container, path):
        return {"/etc/passwd": PASSWD, "/etc/group": GROUP}[path]

    def remove(self, container):
        self.calls.append(("remove", container))
        self._containers.pop(container, None)


class Recorder:
    """What the tools were asked to run: compose commands, and the config file each one would read."""

    def __init__(self):
        self.children = []
        self.configs = []   # the file behind -f at the moment of each child command
        self.captured = []


def make_tools(images=None, active=("web",), codes=None, on_child=None, reads=None, gate_ctx=None):
    """(tools, recorder). codes: exit code by compose subcommand, default 0; the last child is `up` etc.

    reads: changes the config `docker compose config` reports for a generated file (a compose that
    reads it differently from what was written).
    """
    images = images if images is not None else FakeImages()
    recorder = Recorder()
    codes = codes or {}

    def run_child(cmd):
        recorder.children.append(cmd)
        recorder.configs.append(read_config(cmd))
        if on_child:
            on_child(cmd)
        subcommand = next((token for token in cmd[2:] if token in SUBCOMMANDS), None)
        code = codes.get(subcommand, 0)
        if subcommand in ("pull", "build") and code == 0:
            images.local.update(images.users)  # what was pulled or built is there afterwards
        return code

    def capture(cmd):
        recorder.captured.append(cmd)
        if "--format" in cmd:  # config --format json: what compose makes of the generated file
            config = read_config(cmd)
            return subprocess.CompletedProcess(cmd, 0, json.dumps(reads(config) if reads else config), "")
        return subprocess.CompletedProcess(cmd, 0, "\n".join(active) + "\n", "")

    gate_ctx = gate_ctx or imagedecision.Context(images, rules(), config.Config(), current_user=(1000, 1000))
    return composeimages.Tools(images, gate_ctx, capture, run_child), recorder


def read_config(cmd):
    """The config compose would make of the file behind -f."""
    raw = read_raw(cmd)
    return None if raw is None else json.loads(raw)


def read_raw(cmd):
    """The text of the file behind -f, as written."""
    if "-f" not in cmd or not os.path.exists(cmd[cmd.index("-f") + 1]):
        return None
    with open(cmd[cmd.index("-f") + 1]) as f:
        return f.read()


def install_tools(monkeypatch, tools):
    """Make composerun.default_tools return tools, with --allow-me applied as the real one does."""
    from dockscreen import composerun
    monkeypatch.setattr(composerun, "default_tools", lambda allow_me=False: tools._replace(
        gate_ctx=tools.gate_ctx.allowing_me(allow_me)))
