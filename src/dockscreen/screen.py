"""Inspect what docker compose is about to run, and apply the security policy."""

import json
import os
import re
import subprocess

from dockscreen import argscan, config, messages, policy

COMPOSE_FILE_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
COMPOSE_VARS_IN_ENV_FILE = re.compile(r"^\s*(export\s+)?COMPOSE_(FILE|PATH_SEPARATOR)\s*=", re.MULTILINE)
# A directory that equals or contains one of these must not be mounted wholesale.
SENSITIVE_DIRS = ("/", "/etc", "/usr", "/var", "/boot", "/root", "/run", "/proc", "/sys", "/dev")
DOCKER_SOCKET = "/var/run/docker.sock"


class ScreenError(Exception):
    """The project is refused before its config is looked at, or the config could not be inspected."""


class InspectError(ScreenError):
    """The config could not be inspected: no compose file, or compose could not read it."""


def inspect(global_args, runtime):
    """Return (config, project_dir) for the config selected by global_args.

    A project directory that is, or contains, a sensitive path ($HOME, /etc, ...) is refused: everything
    in it can be bind-mounted.
    """
    project_dir = project_directory(global_args, runtime.cwd, runtime)
    found = sensitive_inside(project_dir, runtime)
    if found:
        raise ScreenError(f"the project directory {project_dir} contains {found[0]}; "
                         "move the compose file into a directory of its own")
    return load_config(global_args, runtime.docker.binary), project_dir


def check(global_args, runtime, rules=policy.check_config):
    """Return the problems rules(config, ctx) finds; failure to inspect counts as a problem."""
    try:
        config, project_dir = inspect(global_args, runtime)
        return rules(config, context(project_dir, runtime))
    except ScreenError as e:
        return [str(e)]


def context(project_dir, runtime, allow_me=False):
    """The policy context for project_dir, from the config file; allow_me: --allow-me was given."""
    return policy.Context(project_dir, runtime.rules(allow_me), runtime.settings.mount_dirs,
                          config_file=runtime.config_file)


def sensitive_paths(runtime):
    """Paths whose directories must not be mountable: system directories, the home directory, the
    config files and the docker socket."""
    return [*SENSITIVE_DIRS, runtime.home, config.SYSTEM_FILE, runtime.config_file, DOCKER_SOCKET]


def sensitive_inside(directory, runtime):
    """The sensitive paths that directory equals or contains, compared after resolving symlinks."""
    root = os.path.realpath(directory)
    return [path for path in sensitive_paths(runtime) if policy.is_inside(os.path.realpath(path), root)]


def mount_dir_warnings(runtime):
    """One warning per configured mount dir that equals or contains a sensitive path."""
    return [
        f"warning: the configured mount dir {directory} contains {found[0]}, so containers can mount it"
        for directory in runtime.settings.mount_dirs
        if (found := sensitive_inside(directory, runtime))
    ]


def passes(global_args, runtime, rules=policy.check_config):
    """check(), reporting problems on stderr."""
    return messages.report(check(global_args, runtime, rules))


def load_config(global_args, docker_binary):
    # '*' activates all profiles: `up svc` enables the profile of a named
    # service, which a plain `config` would leave out of the inspected set.
    # --no-env-resolution keeps env_file paths in the output instead of inlining
    # their contents, so the policy can see which files are read.
    cmd = [docker_binary, "compose", *global_args, "--profile", "*", "config", "--format", "json",
           "--no-env-resolution"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise InspectError("'docker' not found in PATH")
    if result.returncode != 0:
        raise InspectError(f"docker compose config failed:\n{result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except ValueError as e:
        raise InspectError(f"cannot parse docker compose config output: {e}")


REMOTE_MESSAGE = "the daemon is not the default local one; ids and paths cannot be checked"


def is_remote(global_args, env, docker):
    """Whether the daemon might not be this host's own, where host ids and paths mean nothing."""
    if argscan.option_values(global_args, "--host", "-H"):
        return True
    if argscan.option_values(global_args, "--context", "-c"):
        return True
    host = env.get("DOCKER_HOST", "")
    if host and not host.startswith("unix://"):
        return True
    if env.get("DOCKER_CONTEXT") not in (None, "", "default"):
        return True
    return docker.context() != "default"


def project_directory(global_args, cwd, runtime):
    """Mirror how docker compose picks the project directory."""
    env = runtime.env
    explicit = argscan.option_values(global_args, "--project-directory", None)
    if explicit:
        return os.path.realpath(os.path.join(cwd, explicit[-1]))

    files = argscan.option_values(global_args, "--file", "-f")
    if not files and env.get("COMPOSE_FILE"):
        files = env["COMPOSE_FILE"].split(env.get("COMPOSE_PATH_SEPARATOR", os.pathsep))
    if "-" in files:
        raise ScreenError("a compose file read from stdin cannot be inspected")
    if files:
        return os.path.realpath(os.path.dirname(os.path.join(cwd, files[0])))

    env_files = argscan.option_values(global_args, "--env-file", None)
    return find_compose_dir(cwd, env_files, runtime.home, runtime.me[0])


def find_compose_dir(start, env_files, home, uid):
    """Walk up like compose does, refusing if a .env could redirect compose elsewhere.

    The walk stops at the home directory and at the first directory not owned by uid: a compose file
    found there was not put there for this project, and is an error. The starting directory is the
    caller's own choice and is not subject to the ownership rule.
    """
    home = os.path.realpath(home)
    for env_file in env_files:
        refuse_compose_vars_in(os.path.join(start, env_file))
    directory = os.path.realpath(start)
    while True:
        has_file = any(os.path.exists(os.path.join(directory, n)) for n in COMPOSE_FILE_NAMES)
        if directory != os.path.realpath(start) and (directory == home or os.stat(directory).st_uid != uid):
            if has_file:
                raise ScreenError(f"the nearest compose file is in {directory}, which is your home directory "
                                 "or not yours; run from the project directory or use -f")
            raise InspectError("no compose file found")
        refuse_compose_vars_in(os.path.join(directory, ".env"))
        if has_file:
            return directory
        parent = os.path.dirname(directory)
        if parent == directory:
            raise InspectError("no compose file found")
        directory = parent


def refuse_compose_vars_in(path):
    """dockscreen does not read .env files, so a COMPOSE_FILE there would send compose to a
    different project directory than the one we would check mounts against."""
    try:
        with open(path) as f:
            content = f.read()
    except OSError:
        return
    if COMPOSE_VARS_IN_ENV_FILE.search(content):
        raise ScreenError(f"{path} sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR; "
                         "set it in your shell or use -f, so the project directory can be verified")
