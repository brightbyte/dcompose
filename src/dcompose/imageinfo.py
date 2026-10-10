"""Informational lookup of the default user baked into images, for `dcompose audit`.

Never feeds the policy verdict: an image's default user is not something a
config may rely on. Lookups never pull an image. Local lookups are the default;
registry lookups (config blob only, no layers) are opt-in.

A Dockerfile's USER is deliberately not looked up for built services: that
needs stage, ARG and --target resolution. If the built image exists locally it
is inspected like any other.
"""

import json
import subprocess


class LookupFailed(Exception):
    pass


def describe(config, remote, run=subprocess.run):
    """One line per service without `user` that has an image, plus a hint if remote lookups would add information."""
    lines = []
    missing_locally = False
    for name, service in sorted(config.get("services", {}).items()):
        if service.get("user"):
            continue  # the image default is irrelevant once the compose file sets a user
        built = "build" in service
        image = service.get("image") or (f"{config.get('name', '')}-{name}" if built else None)
        if image is None:
            continue
        prefix = f"service {name}: image {image}:"
        if str(image).startswith("-"):  # would be parsed as an option; also never a valid reference
            lines.append(f"{prefix} not a valid image name")
            continue

        user = local_user(image, run)
        if user is not None:
            lines.append(f"{prefix} default user {user_text(user)} (local)")
        elif built:
            lines.append(f"{prefix} not built yet (a Dockerfile's USER is not looked up)")
        elif not remote:
            lines.append(f"{prefix} not available locally")
            missing_locally = True
        else:
            lines.append(f"{prefix} {remote_summary(image, run)}")

    if missing_locally:
        lines.append("hint: some images are not available locally; --remote looks up their "
                     "default user in the registry without pulling them.")
    return lines


def user_text(user):
    return user if user else "root (the image sets no user)"


def local_user(image, run):
    """The image's configured user ('' if none), or None if it is not available locally."""
    try:
        result = run(["docker", "image", "inspect", "--format", "{{.Config.User}}", "--", image],
                     capture_output=True, text=True)
    except FileNotFoundError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def remote_summary(image, run):
    try:
        return f"default user {user_text(remote_user(image, run))} (registry)"
    except LookupFailed as e:
        return f"not available locally, registry lookup failed: {e}"


def remote_user(image, run):
    cmd = ["docker", "buildx", "imagetools", "inspect", "--format", "{{json .Image}}", "--", image]
    try:
        result = run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        raise LookupFailed("'docker' not found in PATH")
    if result.returncode != 0:
        raise LookupFailed(result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "unknown error")
    try:
        return user_from_image_json(json.loads(result.stdout))
    except (ValueError, AttributeError) as e:
        raise LookupFailed(f"unexpected output: {e}")


def user_from_image_json(data):
    """The image config, or for a multi-platform index a map of platform to image config."""
    configs = [data] if "config" in data else list(data.values())
    users = {(c.get("config") or {}).get("User", "") for c in configs}
    if len(users) == 1:
        return users.pop()
    return ", ".join(sorted(u or "(none)" for u in users)) + " (varies by platform)"
