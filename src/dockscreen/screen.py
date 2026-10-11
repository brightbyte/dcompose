"""Inspect what docker compose is about to run, and apply the security policy."""

import json
import os
import re
import subprocess

from dockscreen import config, idrules, imageuser, messages, policy, realdocker

COMPOSE_FILE_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
COMPOSE_VARS_IN_ENV_FILE = re.compile(r"^\s*(export\s+)?COMPOSE_(FILE|PATH_SEPARATOR)\s*=", re.MULTILINE)
# A directory that equals or contains one of these must not be mounted wholesale.
SENSITIVE_DIRS = ("/", "/etc", "/usr", "/var", "/boot", "/root", "/run", "/proc", "/sys", "/dev")
DOCKER_SOCKET = "/var/run/docker.sock"


class ScreenError(Exception):
    """The config could not be inspected; treated as a refusal."""


def inspect(global_args):
    """Return (config, project_dir) for the config selected by global_args.

    A project directory that is, or contains, a sensitive path ($HOME, /etc, ...) is refused: everything
    in it can be bind-mounted.
    """
    project_dir = project_directory(global_args, os.environ, os.getcwd())
    found = sensitive_inside(project_dir, os.environ)
    if found:
        raise ScreenError(f"the project directory {project_dir} contains {found[0]}; "
                         "move the compose file into a directory of its own")
    return load_config(global_args), project_dir


def check(global_args, rules=policy.check_config):
    """Return the problems rules(config, ctx) finds; failure to inspect counts as a problem."""
    try:
        config, project_dir = inspect(global_args)
        return rules(config, context(project_dir))
    except ScreenError as e:
        return [str(e)]


def context(project_dir, allow_me=False):
    """The policy context for project_dir, from the config file; allow_me: --allow-me was given."""
    rules = idrules.rules(imageuser.LocalIds(), allow_me)
    return policy.Context(project_dir, rules, config.current().mount_dirs)


def sensitive_paths(env):
    """Paths whose directories must not be mountable: system directories, the home directory, the
    config files and the docker socket."""
    home = os.path.expanduser("~")
    return [*SENSITIVE_DIRS, home, config.SYSTEM_FILE, config.user_file(env), DOCKER_SOCKET]


def sensitive_inside(directory, env):
    """The sensitive paths that directory equals or contains, compared after resolving symlinks."""
    root = os.path.realpath(directory)
    return [path for path in sensitive_paths(env) if policy.is_inside(os.path.realpath(path), root)]


def mount_dir_warnings(env):
    """One warning per configured mount dir that equals or contains a sensitive path."""
    return [
        f"warning: the configured mount dir {directory} contains {found[0]}, so containers can mount it"
        for directory in config.current().mount_dirs
        if (found := sensitive_inside(directory, env))
    ]


def passes(global_args, rules=policy.check_config):
    """check(), reporting problems on stderr."""
    return messages.report(check(global_args, rules))


def load_config(global_args):
    # '*' activates all profiles: `up svc` enables the profile of a named
    # service, which a plain `config` would leave out of the inspected set.
    # --no-env-resolution keeps env_file paths in the output instead of inlining
    # their contents, so the policy can see which files are read.
    cmd = [realdocker.docker_bin(), "compose", *global_args, "--profile", "*", "config", "--format", "json",
           "--no-env-resolution"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise ScreenError("'docker' not found in PATH")
    if result.returncode != 0:
        raise ScreenError(f"docker compose config failed:\n{result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except ValueError as e:
        raise ScreenError(f"cannot parse docker compose config output: {e}")


REMOTE_MESSAGE = "the daemon is not the default local one; ids and paths cannot be checked"


def is_remote(global_args, env, docker):
    """Whether the daemon might not be this host's own, where host ids and paths mean nothing."""
    if option_values(global_args, "--host", "-H"):
        return True
    if option_values(global_args, "--context", "-c"):
        return True
    host = env.get("DOCKER_HOST", "")
    if host and not host.startswith("unix://"):
        return True
    if env.get("DOCKER_CONTEXT") not in (None, "", "default"):
        return True
    return docker.context() != "default"


def project_directory(global_args, env, cwd):
    """Mirror how docker compose picks the project directory."""
    explicit = option_values(global_args, "--project-directory", None)
    if explicit:
        return os.path.realpath(os.path.join(cwd, explicit[-1]))

    files = option_values(global_args, "--file", "-f")
    if not files and env.get("COMPOSE_FILE"):
        files = env["COMPOSE_FILE"].split(env.get("COMPOSE_PATH_SEPARATOR", os.pathsep))
    if "-" in files:
        raise ScreenError("a compose file read from stdin cannot be inspected")
    if files:
        return os.path.realpath(os.path.dirname(os.path.join(cwd, files[0])))

    return find_compose_dir(cwd, option_values(global_args, "--env-file", None))


def find_compose_dir(start, env_files=(), home=None, uid=None):
    """Walk up like compose does, refusing if a .env could redirect compose elsewhere.

    The walk stops at the home directory and at the first directory not owned by uid: a compose file
    found there was not put there for this project, and is an error. The starting directory is the
    caller's own choice and is not subject to the ownership rule.
    """
    home = os.path.realpath(home or os.path.expanduser("~"))
    uid = os.getuid() if uid is None else uid
    for env_file in env_files:
        refuse_compose_vars_in(os.path.join(start, env_file))
    directory = os.path.realpath(start)
    while True:
        has_file = any(os.path.exists(os.path.join(directory, n)) for n in COMPOSE_FILE_NAMES)
        if directory != os.path.realpath(start) and (directory == home or os.stat(directory).st_uid != uid):
            if has_file:
                raise ScreenError(f"the nearest compose file is in {directory}, which is your home directory "
                                 "or not yours; run from the project directory or use -f")
            raise ScreenError("no compose file found")
        refuse_compose_vars_in(os.path.join(directory, ".env"))
        if has_file:
            return directory
        parent = os.path.dirname(directory)
        if parent == directory:
            raise ScreenError("no compose file found")
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


def strip_options(args, names):
    """args without the given options, which take a value: `--opt v`, `--opt=v` and `-ov` forms."""
    kept = []
    i = 0
    while i < len(args):
        token = args[i]
        if token in names:
            i += 2
        elif any(token.startswith(n + "=") for n in names if n.startswith("--")) \
                or any(token.startswith(n) for n in names if not n.startswith("--")):
            i += 1
        else:
            kept.append(token)
            i += 1
    return kept
