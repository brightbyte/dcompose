"""Inspect what docker compose is about to run, and apply the security policy."""

import json
import os
import re
import subprocess
import sys

from dcompose import ids, policy
from dcompose.text import printable

COMPOSE_FILE_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")


class GuardError(Exception):
    """The config could not be inspected; treated as a refusal."""


def inspect(global_args):
    """Return (config, project_dir) for the config selected by global_args."""
    project_dir = project_directory(global_args, os.environ, os.getcwd())
    return load_config(global_args), project_dir


def check(global_args, build_only=False):
    """Return the list of policy problems; failure to inspect counts as a problem."""
    try:
        config, project_dir = inspect(global_args)
        return evaluate(config, project_dir, build_only)
    except GuardError as e:
        return [str(e)]


def evaluate(config, project_dir, build_only=False):
    if build_only:
        return policy.check_build_config(config, project_dir)
    uid, gid = ids.allowed(os.environ)
    return policy.check_config(config, project_dir, uid, gid, extra_mount_dirs(os.environ))


def extra_mount_dirs(env):
    """Directories from DCOMPOSE_DIRS (pathsep-separated) that mounts may come from.

    Read from dcompose's own environment only: the project's .env file is not
    visible here, so a compose project cannot widen its own allowance.
    """
    dirs = [d for d in env.get("DCOMPOSE_DIRS", "").split(os.pathsep) if d]
    for d in dirs:
        if not os.path.isabs(d):
            raise GuardError(f"DCOMPOSE_DIRS entry {d!r} is not an absolute path")
    return dirs


def passes(global_args, build_only=False):
    """check(), reporting problems on stderr."""
    return report(check(global_args, build_only))


def report(problems):
    """Print problems on stderr; True if there were none."""
    for problem in problems:
        print(f"dcompose: refusing: {printable(problem)}", file=sys.stderr)
    return not problems


def load_config(global_args):
    # '*' activates all profiles: `up svc` enables the profile of a named
    # service, which a plain `config` would leave out of the inspected set.
    # --no-env-resolution keeps env_file paths in the output instead of inlining
    # their contents, so the policy can see which files are read.
    cmd = ["docker", "compose", *global_args, "--profile", "*", "config", "--format", "json",
           "--no-env-resolution"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        raise GuardError("'docker' not found in PATH")
    if result.returncode != 0:
        raise GuardError(f"docker compose config failed:\n{result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except ValueError as e:
        raise GuardError(f"cannot parse docker compose config output: {e}")


def project_directory(global_args, env, cwd):
    """Mirror how docker compose picks the project directory."""
    explicit = option_values(global_args, "--project-directory", None)
    if explicit:
        return os.path.realpath(os.path.join(cwd, explicit[-1]))

    files = option_values(global_args, "--file", "-f")
    if not files and env.get("COMPOSE_FILE"):
        files = env["COMPOSE_FILE"].split(env.get("COMPOSE_PATH_SEPARATOR", os.pathsep))
    if "-" in files:
        raise GuardError("a compose file read from stdin cannot be inspected")
    if files:
        return os.path.realpath(os.path.dirname(os.path.join(cwd, files[0])))

    return find_compose_dir(cwd, option_values(global_args, "--env-file", None))


def find_compose_dir(start, env_files=()):
    """Walk up like compose does, refusing if a .env could redirect compose elsewhere."""
    for env_file in env_files:
        refuse_compose_vars_in(os.path.join(start, env_file))
    directory = os.path.realpath(start)
    while True:
        refuse_compose_vars_in(os.path.join(directory, ".env"))
        if any(os.path.exists(os.path.join(directory, n)) for n in COMPOSE_FILE_NAMES):
            return directory
        parent = os.path.dirname(directory)
        if parent == directory:
            raise GuardError("no compose file found")
        directory = parent


COMPOSE_VARS_IN_ENV_FILE = re.compile(r"^\s*(export\s+)?COMPOSE_(FILE|PATH_SEPARATOR)\s*=", re.MULTILINE)


def refuse_compose_vars_in(path):
    """dcompose does not read .env files, so a COMPOSE_FILE there would send compose to a
    different project directory than the one we would check mounts against."""
    try:
        with open(path) as f:
            content = f.read()
    except OSError:
        return
    if COMPOSE_VARS_IN_ENV_FILE.search(content):
        raise GuardError(f"{path} sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR; "
                         "set it in your shell or use -f, so the project directory can be verified")


def option_values(args, long_name, short_name):
    """All values given for an option, in `--opt v`, `--opt=v` and `-ov` forms."""
    values = []
    i = 0
    while i < len(args):
        token = args[i]
        if token in (long_name, short_name) and i + 1 < len(args):
            values.append(args[i + 1])
            i += 1
        elif token.startswith(long_name + "="):
            values.append(token[len(long_name) + 1:])
        elif short_name and token.startswith(short_name) and not token.startswith("--") and len(token) > 2:
            values.append(token[2:])
        i += 1
    return values
