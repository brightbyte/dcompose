"""Running docker compose from the config we checked, not from the files it would find itself.

The resolved config is hardened, checked, written to a private temporary file
(`config` prints a literal `$` as `$$`, so compose reads the file back to the same values)
and handed to compose as its only file, together with the project directory and
name it came from. What was checked is then exactly what runs: no second
reading of the project's files, no discovery rules to mirror. composeimages.prepare
asks compose for the config of the generated file and refuses if it differs from
what was checked. The price is that
compose runs as a child process (so the file can be removed afterwards) and
shows the temporary file as its config file.
"""

import contextlib
import itertools
import json
import os
import signal
import subprocess
import tempfile

from dockscreen import (
    composeargs,
    composeimages,
    gate,
    hardening,
    hostusers,
    idrules,
    imageuser,
    messages,
    policy,
    realdocker,
    screen,
    shellenv,
)
from dockscreen.dockerclient import Docker

# Options that select the files and the project; ours replace them.
REPLACED_OPTIONS = ("--file", "-f", "--project-directory", "--project-name", "-p")
FORWARDED_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


def run(argv, idx, tools=None, allow_me=False):
    """Harden and check the project, then run argv[idx:] (a subcommand that starts containers) on it.

    The images of services that set no user are acquired first, by the project's pull policy, and
    decided on (composeimages); the config that runs is the one that was checked, with the result.
    allow_me: --allow-me was given, so the caller's own ids are allowed.
    """
    global_args, args = argv[:idx], argv[idx + 1:]
    try:
        parsed = command_line(argv[idx], args)
        args = parsed.args
        config, project_dir = screen.inspect(global_args)
        hardened, additions = hardening.apply(config)
        ctx = screen.context(project_dir, allow_me)
        problems = policy.check_config(hardened, vetting_all(ctx, hardened))
        if not hardened.get("name"):
            problems.append("config has no project name")
        tools = tools or default_tools(allow_me)
        if screen.is_remote(global_args, os.environ, tools.docker):
            problems.append(screen.REMOTE_MESSAGE)
    except (screen.ScreenError, hostusers.UserError, ValueError) as e:
        problems = [str(e)]
    if not messages.report(problems):
        return 1

    lines = [*parsed.notices, *screen.mount_dir_warnings(os.environ),
             gate.root_default_notice(tools.gate_ctx)]
    if additions:
        lines.append(hardening.summary(additions))
    lines += shellenv.describe(hardened, os.environ)
    with generated(global_args, project_dir) as command:
        prepared = composeimages.prepare(command(hardened), hardened, args, tools, chosen(parsed))
        if not messages.report(prepared.problems):
            return 1
        final, vetted = composeimages.finalize(hardened, prepared, tools.gate_ctx)
        if not messages.report(policy.check_config(final, ctx._replace(vetted=vetted))):  # what will run
            return 1
        for line in [*lines, *composeimages.notices(prepared, tools.gate_ctx)]:
            if line:
                messages.notice(line)
        return tools.run_child([*command(final), argv[idx], *args])


def command_line(subcommand, args):
    """args read as composeargs does for `run`, with --as resolved; other subcommands as they are.

    Raises hostusers.UserError for a user that is not numeric `uid:gid`, or an unknown --as name.
    """
    if subcommand != "run":
        return composeargs.Parsed(None, False, args, [])
    return composeargs.parse("run", args)


def chosen(parsed):
    """The services whose user the command line chooses: `run -u uid:gid SERVICE` or `run --as NAME`."""
    return frozenset({parsed.service}) if parsed.user_given and parsed.service else frozenset()


def vetting_all(ctx, config):
    """ctx for the checks that run before any image is looked at: unset users are decided later."""
    return ctx._replace(vetted=composeimages.unset_user_services(config))


@contextlib.contextmanager
def generated(global_args, project_dir):
    """A private temporary directory for generated configs; yields command(config) -> compose command.

    The command is `docker compose` on that config alone, with the project directory and name pinned,
    ready for a subcommand to be appended. Everything is removed afterwards.
    """
    counter = itertools.count()
    with tempfile.TemporaryDirectory(prefix="dockscreen-") as directory:
        def command(config):
            path = os.path.join(directory, f"compose-{next(counter)}.yaml")
            with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                json.dump(config, f)  # JSON is YAML
            return [
                realdocker.docker_bin(), "compose", *screen.strip_options(global_args, REPLACED_OPTIONS),
                "-f", path, "--project-directory", project_dir, "--project-name", config["name"],
            ]
        yield command


def default_tools(allow_me=False):
    docker = Docker()
    gate_ctx = gate.Context(docker, idrules.rules(imageuser.LocalIds(), allow_me))
    return composeimages.Tools(
        docker, gate_ctx, lambda cmd: subprocess.run(cmd, capture_output=True, text=True, check=False),
        run_child)


def run_child(cmd):
    """Run cmd with the terminal and exit code of the real thing.

    Termination signals are passed on; Ctrl-C reaches the child from the terminal itself.
    """
    try:
        process = subprocess.Popen(cmd)
    except FileNotFoundError:
        messages.notice(messages.DOCKER_NOT_FOUND)
        return 127
    def forward(number, frame):
        process.send_signal(number)

    previous = {s: signal.signal(s, forward) for s in FORWARDED_SIGNALS}
    try:
        while True:
            try:
                code = process.wait()
                break
            except KeyboardInterrupt:
                continue  # the terminal sent the same SIGINT to the child
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    return 128 - code if code < 0 else code
