"""The images of services that set no `user`: get them as compose would, then decide as `docker run` does.

A project file is hostile, so a service without `user:` cannot just be assumed to run as root or as
whatever its image says. The image is acquired first, following the project's own pull policy so that
automatic updates keep happening (pull, or build if it is built from a Dockerfile), and then the same
rule as `docker run` is applied to the identity it would run as (imagedecision.assess):

- the config file names a user for the image's repository, and the image was pulled from there:
  that user;
- root: the configured default user instead (nobody unless configured otherwise), with a notice;
- otherwise the image's own user if the id rules accept it, with the service's mounts; refused if not.

Whatever is accepted is pinned in the generated config as `user: "uid:gid"`.

In the generated config only, services that were looked at get `pull_policy: never` and, unless they are
built, `image:` set to the id of the image that was checked, so that compose runs that image and neither
pulls another one nor follows a tag that something else has moved in between. Neither is written to the files
the project owns or to `harden` output, which would silently turn off the project's updates.

A service that is not started by this command and sets no user is run as the default user if it does get
started: a mistake in working out what starts must fail safe. So is a service whose user the command line
chose (`run -u`), which the command line then overrides.
"""

import copy
import json
from collections.abc import Callable
from typing import NamedTuple

from dockscreen import argscan, imagedecision, imageuser, policy
from dockscreen.dockerclient import DockerError


class ImageError(Exception):
    pass


class Tools(NamedTuple):
    docker: object        # dockerclient.Docker
    gate_ctx: object      # imagedecision.Context
    capture: Callable     # cmd -> CompletedProcess with text stdout
    run_child: Callable   # cmd -> exit code, with the terminal


class Decision(NamedTuple):
    image: str
    assessment: imagedecision.Assessment
    image_id: str | None = None  # what the image name was when it was looked at


class Prepared(NamedTuple):
    to_run: frozenset
    decisions: dict   # service -> Decision, for the started services that set no user
    problems: list


def unset_user_services(config):
    return frozenset(n for n, s in (config.get("services") or {}).items() if not (s or {}).get("user"))


def image_name(config, name, service):
    """The image compose uses: the service's own, or <project>-<service> for one that is built."""
    return service.get("image") or f"{config.get('name', '')}-{name}"


def prepare(command, config, args, tools, chosen=frozenset()):
    """Acquire the images of the services that will start and decide about those without a user.

    command: the compose command line (up to the subcommand) on the config to run.
    args: the arguments after the subcommand, which name services and may carry --build or --pull.
    chosen: services whose user the command line chooses (`run -u`); their images are not decided.
    """
    try:
        verify_round_trip(command, config, tools)
        to_run = services_to_run(command, config, args, tools)
        failures = acquire(command, config, to_run, args, tools)
    except ImageError as e:
        return Prepared(frozenset(), {}, [str(e)])
    if failures:
        return Prepared(to_run, {}, failures)

    decisions = decide(config, to_run - chosen, tools)
    problems = [
        f"service {name}: image {d.image}: {'; '.join(d.assessment.problems)}; set user: to choose one"
        for name, d in decisions.items() if d.assessment.refused
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
    override = argscan.option_value(args, "--pull")
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
        _, container = tools.docker.create(["--pull=never", *platform, "--", image])
        image_id = None
        if container is None:
            assessment = imagedecision.Assessment(
                imagedecision.Kind.REFUSED, ["the image is not available locally"])
        else:
            try:
                info = tools.docker.inspect_container(container)
                image_id = info.get("Image")
                assessment = imagedecision.assess(tools.gate_ctx, container, info, explicit=False,
                                         mounts=policy.has_host_mounts(service), reference=image,
                                         built="build" in service)
            except (DockerError, ValueError, KeyError) as e:
                assessment = imagedecision.Assessment(imagedecision.Kind.REFUSED, [str(e)])
            finally:
                tools.docker.remove(container)
        decisions[name] = Decision(image, assessment, image_id)
    return decisions


def finalize(config, prepared, ctx):
    """(config to run, services whose user dockscreen set from the vetted image). The input is left alone.

    ctx: the imagedecision.Context the decisions were made with, for the default user.
    """
    final = copy.deepcopy(config)
    vetted = set()
    for name, service in final["services"].items():
        if service.get("user"):
            continue
        decision = prepared.decisions.get(name)
        if decision is None:  # not started by this command
            service["user"] = imagedecision.default_user_spec(ctx)  # an allowed id: the policy accepts it
            continue
        if not decision.assessment.pins_user:
            continue
        # pinned as numbers: the runtime reads neither passwd nor group for `uid:gid`, so it cannot
        # resolve the image's user to anything but what was checked
        service["user"] = imagedecision.pinned_user(ctx, decision.assessment)
        if decision.assessment.kind is not imagedecision.Kind.FALLBACK:
            vetted.add(name)  # the default user is an allowed id, and needs no vetting
        service["pull_policy"] = "never"  # the image that was checked is the one that runs
        if decision.image_id and "build" not in service:
            service["image"] = decision.image_id  # ... even if the name is moved to another image
    return final, frozenset(vetted)


def describe(config, prepared, ctx):
    """One line per service without a user: what dockscreen will do about it.

    ctx: the imagedecision.Context the decisions were made with.
    """
    lines = []
    for name in sorted(unset_user_services(config)):
        decision = prepared.decisions.get(name)
        if decision is None:
            lines.append(f"service {name}: no user set and not started by default; dockscreen runs it "
                         f"as the default user ({imagedecision.default_user_spec(ctx)}) if it is started")
            continue
        assessment = decision.assessment
        if assessment.kind is imagedecision.Kind.OK:
            who = imageuser.describe(assessment.identity, ctx.local)
            lines.append(f"service {name}: no user set; image {decision.image} runs as {who}; accepted")
        elif assessment.kind is imagedecision.Kind.CONFIGURED:
            user = imagedecision.pinned_user(ctx, assessment)
            lines.append(f"service {name}: no user set; image {decision.image} runs as {user}, "
                         "the user the config file sets for it")
        elif assessment.kind is imagedecision.Kind.FALLBACK:
            lines.append(f"service {name}: no user set; {fallback_text(ctx, decision)}")
        if assessment.note:
            lines.append(f"service {name}: note: {assessment.note}")
    return lines


def fallback_text(ctx, decision):
    return (f"image {decision.image} would run as root; dockscreen runs it as the default user "
            f"({imagedecision.default_user_spec(ctx)})")


def notices(prepared, ctx):
    """What a run is about to do that the project did not ask for."""
    return [
        f"service {name}: {fallback_text(ctx, d)}"
        for name, d in prepared.decisions.items() if d.assessment.kind is imagedecision.Kind.FALLBACK
    ]
