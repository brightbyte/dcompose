"""Custom subcommands.

A command is a callable(global_args, args, runtime, allow_me) -> exit code. `global_args` are the
compose-level options that preceded the subcommand (e.g. ["-f", "x.yml"]), so
a command can pass them on when it shells out to docker compose.

A name registered here shadows the docker compose subcommand of the same name.
"""

import subprocess
import sys

from dockscreen import (
    autofix,
    composeimages,
    composerun,
    flags,
    hardening,
    messages,
    patch,
    policy,
    screen,
    shellenv,
    verdict,
)
from dockscreen.dockerclient import DockerNotFound
from dockscreen.text import printable
from dockscreen.verdict import Verdict

COMMANDS = {}
ALIASES = {}  # alias -> command it stands for


def command(name, *aliases):
    def register(fn):
        COMMANDS[name] = fn
        for alias in aliases:
            COMMANDS[alias] = fn
            ALIASES[alias] = name
        return fn
    return register


HARDEN_HINT = "hint: the harden subcommand prints a compose override file with these fixes."


@command("doctor")
def doctor(global_args, args, runtime, allow_me=False):
    """Show the docker compose version that other commands are forwarded to."""
    return subprocess.call([runtime.docker.binary, "compose", *global_args, "version", *args])


@command("audit")
def audit(global_args, args, runtime, allow_me=False):
    """Run the checks that screen `up` without starting anything; pulls and builds images as up would.

    Exit status 0 if `up` would run, 1 if it would refuse, 3 if the audit failed to get that far
    (verdict). --brief prints only the verdict, in one line.
    """
    brief = args == [flags.BRIEF]
    if args and not brief:
        messages.notice(f"usage: dockscreen compose [compose options] audit [{flags.BRIEF}]")
        return 2
    try:
        project = composerun.load_project(global_args, runtime, allow_me)
    except (screen.InspectError, DockerNotFound) as e:
        return verdict.report(Verdict.FAILED, [str(e)], brief)
    except (screen.ScreenError, ValueError) as e:
        return verdict.report(Verdict.REFUSED, [str(e)], brief)

    outcome, problems, lines = audit_images(project, brief)
    if not brief:
        warnings = [*screen.mount_dir_warnings(runtime), *hardening.describe(project.additions),
                    *shellenv.describe(project.hardened, runtime.env)]
        for line in [*(f"{verdict.WARN} {w}" for w in warnings), *lines]:
            print(printable(line))
        if problems or project.additions:
            print(HARDEN_HINT)
    return verdict.report(outcome, problems, brief)


def audit_images(project, brief):
    """(verdict, problems, report lines) for a project: the static checks, then the images if they pass."""
    problems = project.problems()
    if problems:
        return Verdict.REFUSED, problems, [
            "the images were not looked at because of the problems below: nothing was pulled or built"]
    if not brief:
        messages.notice("pulling or building the images as `up` would, to look at the users they run as")
    hardened, tools = project.hardened, project.tools
    with project.generated() as command:
        prepared = composeimages.prepare(command(hardened), hardened, [], tools)
    problems = prepared.problems
    if not problems:  # what `up` checks once more before it runs: image sections need proof now
        final, vetted = composeimages.finalize(hardened, prepared, tools.gate_ctx)
        problems = policy.check_config(final, project.final_ctx(prepared, vetted))
    outcome = Verdict.FAILED if prepared.failed else Verdict.REFUSED if problems else Verdict.PASSED
    return outcome, problems, composeimages.describe(hardened, prepared, tools.gate_ctx)


@command("harden", "fix")
def harden(global_args, args, runtime, allow_me=False):
    """Print a compose override that fixes what can be fixed; exit 1 if problems remain.

    The patch is relative to the merged config as dockscreen will run it, defaults
    included: only what is needed on top of them to pass the audit is written out,
    and one comment says what is added automatically. Mount sources outside the
    project become placeholders to edit; problems without a safe automatic fix are
    listed as comments. Images are pulled and built first, as `up` would, to see
    which services need a user of their own.

    A user that has to be set becomes `${UID}:${GID}`, the caller's own, so the result is checked as
    if --allow-me were given, and the patch says that it needs it.
    """
    try:
        project = composerun.load_project(global_args, runtime, allow_me=True)
    except (screen.ScreenError, ValueError) as e:
        messages.notice(e)
        return 1
    if project.remote:
        messages.notice(screen.REMOTE_MESSAGE)
        return 1

    base, static = project.hardened, project.static_ctx()
    fixed = autofix.fix_config(base, static)
    remaining = policy.check_config(autofix.resolve_user_template(fixed, static), static)
    notes = [hardening.defaults_note()]
    if remaining:
        messages.notice("the images were not looked at because of the problems below: "
                        "nothing was pulled or built")
    else:
        remaining, notes = fix_image_users(project, fixed, notes)

    sys.stdout.write(patch.render(base, fixed, remaining, notes=notes))
    for problem in remaining:
        messages.notice(f"cannot fix automatically: {problem}")
    return 1 if remaining else 0


def fix_image_users(project, fixed, notes):
    """Set a user on the services whose image chose one that is not acceptable. (problems left, notes)."""
    with project.generated() as command:
        prepared = composeimages.prepare(command(fixed), fixed, [], project.tools)
    if not prepared.decisions:
        return prepared.problems, notes  # nothing could be looked at: pulling or building failed
    remaining = []
    for name, decision in prepared.decisions.items():
        if decision.assessment.failed:  # setting a user does not fix an image that could not be read
            remaining.append(composeimages.decision_problem(name, decision))
        elif decision.assessment.refused:
            fixed["services"][name]["user"] = autofix.USER_TEMPLATE
            notes.append(f"service {name}: image {decision.image} chose a user that is not acceptable, "
                         "so user is set explicitly")
    return remaining, notes
