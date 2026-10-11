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
import sys
import tempfile

from dcompose import composeimages, gate, guard, hardening, imageuser, policy, realdocker, shellenv
from dcompose.dockerclient import Docker
from dcompose.text import printable

# Options that select the files and the project; ours replace them.
REPLACED_OPTIONS = ("--file", "-f", "--project-directory", "--project-name", "-p")
FORWARDED_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


def run(argv, idx, tools=None):
    """Harden and check the project, then run argv[idx:] (a subcommand that starts containers) on it.

    The images of services that set no user are acquired first, by the project's pull policy, and
    decided on (composeimages); the config that runs is the one that was checked, with the result.
    """
    global_args, args = argv[:idx], argv[idx + 1:]
    try:
        config, project_dir = guard.inspect(global_args)
        hardened, additions = hardening.apply(config)
        ctx = guard.context(project_dir)
        problems = policy.check_config(hardened, vetting_all(ctx, hardened))
        if not hardened.get("name"):
            problems.append("config has no project name")
        tools = tools or default_tools()
    except (guard.GuardError, ValueError) as e:
        problems = [str(e)]
    if not guard.report(problems):
        return 1

    if additions:
        print(f"dcompose: {printable(hardening.summary(additions))}", file=sys.stderr)
    for line in shellenv.describe(hardened, os.environ):
        print(f"dcompose: {printable(line)}", file=sys.stderr)
    with generated(global_args, project_dir) as command:
        prepared = composeimages.prepare(command(hardened), hardened, args, tools)
        if not guard.report(prepared.problems):
            return 1
        final, vetted = composeimages.finalize(hardened, prepared)
        if not guard.report(policy.check_config(final, ctx._replace(vetted=vetted))):  # what will run
            return 1
        for notice in composeimages.notices(prepared, tools.gate_ctx.local):
            print(f"dcompose: {printable(notice)}", file=sys.stderr)
        return tools.run_child([*command(final), *argv[idx:]])


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
    with tempfile.TemporaryDirectory(prefix="dcompose-") as directory:
        def command(config):
            path = os.path.join(directory, f"compose-{next(counter)}.yaml")
            with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                json.dump(config, f)  # JSON is YAML
            return [
                realdocker.docker_bin(), "compose", *guard.strip_options(global_args, REPLACED_OPTIONS),
                "-f", path, "--project-directory", project_dir, "--project-name", config["name"],
            ]
        yield command


def default_tools():
    docker = Docker()
    gate_ctx = gate.Context(docker, imageuser.LocalIds())
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
        print("dcompose: 'docker' not found in PATH", file=sys.stderr)
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
