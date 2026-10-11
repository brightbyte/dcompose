"""The images of services that set no `user`: get them as compose would, then decide as `docker run` does.

A project file is hostile, so a service without `user:` cannot just be assumed to run as root or as
whatever its image says. The image is acquired first, following the project's own pull policy so that
automatic updates keep happening (pull, or build if it is built from a Dockerfile), and then the same
rule as `docker run` is applied to the identity it would run as (gate.assess):

- no bind mounts and an acceptable user of its own: left alone;
- root, or any image user at all if the service has bind mounts: the generated config runs the
  service as nobody instead, and says which ids the image would have used;
- a user of its own that exists on this host, without mounts: refused, set `user:` yourself.

In the generated config only, services that were looked at get `pull_policy: never`, so that compose runs
the image that was checked and does not pull another one in between. It is never written to the files the
project owns or to `harden` output, which would silently turn off the project's updates.

A service that is not started by this command and sets no user is run as nobody if it does get started:
a mistake in working out what starts must fail safe.
"""

import copy
import json
from collections.abc import Callable
from typing import NamedTuple

from dcompose import gate, imageuser
from dcompose.dockerclient import DockerError


class ImageError(Exception):
    pass


class Tools(NamedTuple):
    docker: object        # dockerclient.Docker
    gate_ctx: object      # gate.Context
    capture: Callable     # cmd -> CompletedProcess with text stdout
    run_child: Callable   # cmd -> exit code, with the terminal


class Decision(NamedTuple):
    image: str
    assessment: gate.Assessment


class Prepared(NamedTuple):
    to_run: frozenset
    decisions: dict   # service -> Decision, for the started services that set no user
    problems: list


def has_host_mounts(service):
    """Whether the service reaches host files: bind mounts, secrets and configs (bind-mounted files),
    devices, or the volumes of another container."""
    binds = any(isinstance(m, dict) and m.get("type") == "bind" for m in service.get("volumes") or [])
    others = ("volumes_from", "devices", "secrets", "configs")
    return binds or any(service.get(key) for key in others)


def unset_user_services(config):
    return frozenset(n for n, s in (config.get("services") or {}).items() if not (s or {}).get("user"))


def image_name(config, name, service):
    """The image compose uses: the service's own, or <project>-<service> for one that is built."""
    return service.get("image") or f"{config.get('name', '')}-{name}"


def prepare(command, config, args, tools):
    """Acquire the images of the services that will start and decide about those without a user.

    command: the compose command line (up to the subcommand) on the config to run.
    args: the arguments after the subcommand, which name services and may carry --build or --pull.
    """
    try:
        verify_round_trip(command, config, tools)
        to_run = services_to_run(command, config, args, tools)
        failures = acquire(command, config, to_run, args, tools)
    except ImageError as e:
        return Prepared(frozenset(), {}, [str(e)])
    if failures:
        return Prepared(to_run, {}, failures)

    decisions = decide(config, to_run, tools)
    problems = [
        f"service {name}: image {d.image}: {'; '.join(d.assessment.problems)}; set user: to choose one"
        for name, d in decisions.items() if d.assessment.kind == "refused"
    ]
    return Prepared(to_run, decisions, problems)


def verify_round_trip(command, config, tools):
    """Refuse unless compose, given the generated file, resolves it to exactly the config we checked.

    Compose interpolates the files it reads; a value that comes back different would run
    differently from what the policy saw. Done before anything is pulled or built.
    """
    result = tools.capture([*command, "--profile", "*", "config", "--format", "json", "--no-env-resolution"])
    try:
        resolved = json.loads(result.stdout) if result.returncode == 0 else None
    except ValueError:
        resolved = None
    if resolved is None:
        raise ImageError("docker compose could not read back the config that was checked")
    where = first_difference(config, resolved)
    if where:
        raise ImageError(f"docker compose reads the checked config differently at {where}; not running it")


def first_difference(expected, actual, path="config"):
    """Where two JSON values first differ (a path), or None."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual), key=str):
            if key not in expected or key not in actual:
                return f"{path}.{key}"
            if where := first_difference(expected[key], actual[key], f"{path}.{key}"):
                return where
        return None
    if isinstance(expected, list) and isinstance(actual, list) and len(expected) == len(actual):
        for i, (e, a) in enumerate(zip(expected, actual)):
            if where := first_difference(e, a, f"{path}[{i}]"):
                return where
        return None
    return None if expected == actual and type(expected) is type(actual) else path


def services_to_run(command, config, args, tools):
    """Services in the active profiles, plus any named on the command line."""
    result = tools.capture([*command, "config", "--services"])
    if result.returncode != 0:
        raise ImageError("docker compose config --services failed")
    services = config.get("services") or {}
    return frozenset(set(result.stdout.split()) | {a for a in args if a in services})


def acquire(command, config, to_run, args, tools):
    """Pull and build what `up` would, by the project's policy. Returns a list of failures."""
    pull, build = [], []
    override = cli_option(args, "--pull")
    for name in sorted(to_run):
        service = config["services"][name]
        image = image_name(config, name, service)
        present = image_exists(tools.docker, image)
        if "build" in service:
            wanted = service.get("pull_policy") == "build" or "--build" in args or not present
            if wanted and "--no-build" not in args:
                build.append(name)
            continue
        policy = override or service.get("pull_policy") or "missing"
        if policy == "never":
            continue
        if policy in ("missing", "if_not_present"):
            if not present:
                pull.append(name)
        else:
            pull.append(name)  # always, and the periodic ones: pulling each run never serves stale images
    for subcommand, names in (("pull", pull), ("build", build)):
        if names and tools.run_child([*command, subcommand, *names]) != 0:
            return [f"docker compose {subcommand} {' '.join(names)} failed"]
    return []


def cli_option(args, name):
    """The value of `--name value` or `--name=value` before any `--`, if given."""
    for i, arg in enumerate(args):
        if arg == "--":
            break
        if arg.startswith(name + "="):
            return arg.partition("=")[2]
        if arg == name and i + 1 < len(args):
            return args[i + 1]
    return None


def image_exists(docker, image):
    try:
        docker.inspect_image(image)
    except DockerError:
        return False
    return True


def decide(config, to_run, tools):
    """For each started service without a user: what its image would be allowed to do."""
    decisions = {}
    for name in sorted(to_run & unset_user_services(config)):
        service = config["services"][name]
        image = image_name(config, name, service)
        platform = ["--platform", service["platform"]] if service.get("platform") else []
        _, container = tools.docker.create(["--pull=never", *platform, image])
        if container is None:
            assessment = gate.Assessment("refused", ["the image is not available locally"])
        else:
            try:
                info = tools.docker.inspect_container(container)
                assessment = gate.assess(tools.gate_ctx, container, info, explicit=False,
                                         mounts=has_host_mounts(service))
            except (DockerError, ValueError, KeyError) as e:
                assessment = gate.Assessment("refused", [str(e)])
            finally:
                tools.docker.remove(container)
        decisions[name] = Decision(image, assessment)
    return decisions


def finalize(config, prepared):
    """(config to run, services whose user dcompose set from the vetted image). The input is left alone."""
    final = copy.deepcopy(config)
    vetted = set()
    for name, service in final["services"].items():
        if service.get("user"):
            continue
        decision = prepared.decisions.get(name)
        kind = decision.assessment.kind if decision else "not started"
        if kind in ("fallback", "not started"):
            service["user"] = gate.FALLBACK_USER
        elif kind == "ok":
            # pinned as numbers: the runtime reads neither passwd nor group for `uid:gid`, so it cannot
            # resolve the image's user to anything but what was checked
            service["user"] = gate.image_user_spec(decision.assessment)
            vetted.add(name)
        if decision and kind in ("ok", "fallback"):
            service["pull_policy"] = "never"  # the image that was checked is the one that runs
    return final, frozenset(vetted)


def describe(config, prepared, local=None):
    """One line per service without a user: what dcompose will do about it.

    local: the host's accounts (imageuser.LocalIds), to say which local user an image's ids would be.
    """
    lines = []
    for name in sorted(unset_user_services(config)):
        decision = prepared.decisions.get(name)
        if decision is None:
            lines.append(f"service {name}: no user set and not started by default; "
                         f"dcompose runs it as nobody ({gate.FALLBACK_USER}) if it is started")
        elif decision.assessment.kind == "ok":
            who = imageuser.describe(decision.assessment.identity, local)
            lines.append(f"service {name}: no user set; image {decision.image} runs as {who}; accepted")
        elif decision.assessment.kind == "fallback":
            lines.append(f"service {name}: no user set; {fallback_text(decision, local)}")
    return lines


def fallback_text(decision, local):
    """Why the service is run as nobody, and how to run it as the image's user instead."""
    summary = gate.fallback_summary(f"image {decision.image}", decision.assessment, local, "service")
    text = f"{summary}; dcompose runs it as nobody ({gate.FALLBACK_USER})"
    if decision.assessment.reason == "mounts":
        identity = decision.assessment.identity
        text += (f". To run it as the image's user, set user: \"${{DCOMPOSE_UID}}:${{DCOMPOSE_GID}}\" "
                 f"and run with DCOMPOSE_UID={identity.uid} DCOMPOSE_GID={identity.gid}")
    return text


def notices(prepared, local=None):
    """What a run is about to do that the project did not ask for."""
    return [
        f"service {name}: {fallback_text(d, local)}"
        for name, d in prepared.decisions.items() if d.assessment.kind == "fallback"
    ]
