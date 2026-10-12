"""Help for dockscreen and the commands it audits or adds, laid out like docker's own.

An overview lists dockscreen's options and the commands it audits or adds; a topic covers one command.
Docker's (or compose's) own help for the same thing follows ours, except for commands only dockscreen
has. Text is wrapped as the audit report is (messages.report_width): option and command descriptions
under their own column, as docker does.
"""

import textwrap
from typing import NamedTuple

from dockscreen import flags, messages


HELP_FALLBACK_WIDTH = 80


class Option(NamedTuple):
    long: str
    text: str
    short: str = ""
    value: str = ""  # what the option takes, as docker names it: string, list, ...

    def left(self):
        short = f"-{self.short}, " if self.short else "    "
        return f"  {short}{self.long}" + (f" {self.value}" if self.value else "")


class Topic(NamedTuple):
    usage: str
    summary: str               # one line, also in the overview
    notes: tuple = ()          # what dockscreen does: paragraphs, and list items starting with "- "
    options: tuple = ()        # dockscreen's own options for the command
    aliases: tuple = ()
    docker_help: bool = True   # docker (or compose) has its own help for the command, to follow ours


ALLOW_ME = Option(flags.ALLOW_ME, "Allow your own ids as the image's user (--as-me implies it)")
USER_OPTIONS = (
    Option(flags.AS, "Run as the local user NAME, resolved on this host", value="string"),
    Option(flags.AS_ME, "Run as yourself"),
    Option("--user", "Numeric UID:GID only; --as is for names", short="u", value="string"),
)
DEFAULTS = ("It adds --cap-drop=ALL and --security-opt=no-new-privileges:true before your options, which "
            "can override them.")
IMAGE_RULES = (
    "- an image that would run as root runs as the default user instead (nobody unless configured)",
    "- an image user that is an account of this host, or with mounts an id outside the nobody range, is "
    "denied",
    "- a user the config file sets for the image, its project or every image is used",
    "- the user is passed to docker as numbers, so the image's passwd file cannot change it",
)
VERDICT = "The last line dockscreen prints is the verdict: ✔ audit passed, ⊖ denied by audit, or " \
          "✘ audit failed."

DOCKER_OPTIONS = (
    Option(flags.ALLOW_ME, "Allow containers to run as you"),
    Option(flags.SKIP_SCREENING, "Turn all checks off; warns every time"),
    Option(flags.STRICT_SCREEN, "For audit: also deny what the command line asks for that a project or "
                                "image may not have"),
)
COMPOSE_OPTIONS = (
    Option(flags.ALLOW_ME, "Allow services to run as you"),
    Option(flags.SKIP_SCREENING, "Turn all checks off; warns every time"),
)

DOCKER = {
    "run": Topic(
        f"dockscreen [{flags.ALLOW_ME}] run [OPTIONS] IMAGE [COMMAND] [ARG...]",
        "Create and run a container, after checking the user its image runs as",
        ("dockscreen creates the container, checks it, and only then starts it:", *IMAGE_RULES, DEFAULTS,
         VERDICT),
        (ALLOW_ME, *USER_OPTIONS), aliases=("dockscreen container run", "dockscreen run")),
    "create": Topic(
        "dockscreen create [OPTIONS] IMAGE [COMMAND] [ARG...]",
        "Create a container, with the hardening defaults added",
        (DEFAULTS, "The container is checked when dockscreen starts it."),
        USER_OPTIONS, aliases=("dockscreen container create", "dockscreen create")),
    "start": Topic(
        "dockscreen start [OPTIONS] CONTAINER [CONTAINER...]",
        "Start containers, denied if they would fail the check of run",
        ("An existing container cannot be changed, so one whose image's user dockscreen would replace or "
         "deny is denied.", VERDICT),
        aliases=("dockscreen container start", "dockscreen start")),
    "restart": Topic(
        "dockscreen restart [OPTIONS] CONTAINER [CONTAINER...]",
        "Restart containers, denied if they would fail the check of run",
        ("As for start.", VERDICT), aliases=("dockscreen container restart", "dockscreen restart")),
    "exec": Topic(
        "dockscreen exec [OPTIONS] CONTAINER COMMAND [ARG...]",
        "Run a command in a running container; --as and --as-me choose the user",
        (), USER_OPTIONS, aliases=("dockscreen container exec", "dockscreen exec")),
    "audit": Topic(
        f"dockscreen [{flags.ALLOW_ME}] [{flags.STRICT_SCREEN}] audit [{flags.BRIEF}] [RUN OPTIONS] IMAGE "
        "[COMMAND] [ARG...]",
        "Say what run would do with the same arguments, without starting anything",
        ("The container is created as run would create it, pulling the image if run would, judged, and "
         "removed. It also points out what the command line asks for that a compose project or an image "
         "may not have; run allows that, because the command line is trusted.",
         "Exit status: 0 audit passed, 1 denied by audit, 2 usage error, 3 audit failed (no docker, the "
         "image could not be pulled or created)."),
        (Option(flags.BRIEF, "Print only the verdict, in one line"),
         Option(flags.STRICT_SCREEN, "(before audit) Deny for what the command line asks for, too"),
         ALLOW_ME, *USER_OPTIONS),
        docker_help=False),
    "compose": Topic(
        "dockscreen compose [OPTIONS] COMMAND",
        "Docker Compose, with projects audited before they run"),
}

SCREENED_COMPOSE = (
    "dockscreen audits the project first, and runs it from the config it checked:",
    "- bind mounts and files only from the project directory or the configured mount_dirs",
    "- no privileges: privileged, cap_add, devices, host namespaces, other security options",
    "- users the project or its images choose must pass the id rules; images are pulled first",
    "- cap_drop: [ALL] and no-new-privileges added where they are missing",
    VERDICT,
)
BUILD_RULES = ("Builds may not read outside the project, use the host network, run privileged or forward "
               "your SSH agent.", VERDICT)
COMPOSE = {
    "up": Topic("dockscreen compose up [OPTIONS] [SERVICE...]",
                "Create and start containers, after the project passes the audit", SCREENED_COMPOSE),
    "create": Topic("dockscreen compose create [OPTIONS] [SERVICE...]",
                    "Create containers, after the project passes the audit", SCREENED_COMPOSE),
    "run": Topic("dockscreen compose run [OPTIONS] SERVICE [COMMAND] [ARGS...]",
                 "Run a one-off command, after the project passes the audit", SCREENED_COMPOSE,
                 USER_OPTIONS),
    "watch": Topic("dockscreen compose watch [OPTIONS] [SERVICE...]",
                   "Watch the build context and rebuild, after the project passes the audit",
                   SCREENED_COMPOSE),
    "scale": Topic("dockscreen compose scale [SERVICE=REPLICAS...]",
                   "Scale services, after the project passes the audit", SCREENED_COMPOSE),
    "alpha": Topic("dockscreen compose alpha COMMAND", "Experimental commands, audited like up",
                   SCREENED_COMPOSE),
    "build": Topic("dockscreen compose build [OPTIONS] [SERVICE...]",
                   "Build services, after checking what the builds can reach", BUILD_RULES),
    "bake": Topic("dockscreen compose bake [OPTIONS] [SERVICE...]",
                  "Build with bake, after checking what the builds can reach",
                  (*BUILD_RULES, "x- keys in build are refused, because bake reads x-bake.")),
    "exec": Topic("dockscreen compose exec [OPTIONS] SERVICE COMMAND [ARGS...]",
                  "Run a command in a running service; --as and --as-me choose the user", (), USER_OPTIONS),
}
# Options of dockscreen's own compose commands, which their docstrings do not list.
COMMAND_OPTIONS = {"audit": (Option(flags.BRIEF, "Print only the verdict, in one line"),)}


def command_topic(name, fn, aliases=()):
    """The Topic of one of dockscreen's own compose commands (commands.COMMANDS), from its docstring:
    the first line is the summary, each further paragraph a note."""
    summary, _, rest = (fn.__doc__ or "").strip().partition("\n")
    notes = tuple(" ".join(p.split()) for p in rest.split("\n\n") if p.strip())
    names = tuple(f"dockscreen compose {n}" for n in (name, *aliases)) if aliases else ()
    usage = f"dockscreen compose {name}" + (" [OPTIONS]" if name in COMMAND_OPTIONS else "")
    return Topic(usage, summary.strip().rstrip("."), notes, COMMAND_OPTIONS.get(name, ()), names,
                 docker_help=False)


def topic(topic_, follows_name, width):
    """The help for one command, as lines; follows_name: whose help follows ours, if any does."""
    lines = [f"Usage:  {topic_.usage}", "", *paragraph(topic_.summary, width)]
    if topic_.aliases:
        lines += ["", "Aliases:", *paragraph(", ".join(topic_.aliases), width, "  ")]
    if topic_.notes:
        lines += notes(topic_.notes, width)
    if topic_.options:
        lines += ["", "Options:", *table([(o.left(), o.text) for o in topic_.options], width)]
    return lines + follows(topic_.docker_help, follows_name)


def overview(usage, summary, options, sections, more, follows_name, width):
    """The help for dockscreen or compose: options, then each (title, {name: Topic}) section."""
    lines = [f"Usage:  {usage}", "", *paragraph(summary, width), "", "Options:",
             *table([(o.left(), o.text) for o in options], width)]
    for title, topics in sections:
        lines += ["", title, *table([(f"  {n}", t.summary) for n, t in sorted(topics.items())], width)]
    return lines + ["", *paragraph(more, width)] + follows(True, follows_name)


def notes(texts, width):
    """Paragraphs, with a blank line before each, and list items, which follow their paragraph."""
    lines = []
    for text in texts:
        if text.startswith("- "):
            lines += item(text, width)
        else:
            lines += ["", *paragraph(text, width)]
    return lines


def table(rows, width):
    """(left, right) rows, the right column after the widest left one and wrapped under itself."""
    column = max(len(left) for left, _ in rows) + 3
    lines = []
    for left, right in rows:
        if width is None or width - column < 20:
            lines.append(f"{left:<{column}}{right}")
            continue
        wrapped = textwrap.wrap(right, width - column, break_long_words=False, break_on_hyphens=False)
        lines.append(f"{left:<{column}}{wrapped[0]}")
        lines += [" " * column + more for more in wrapped[1:]]
    return lines


def paragraph(text, width, indent=""):
    if width is None:
        return [indent + text]
    return textwrap.wrap(text, width, initial_indent=indent, subsequent_indent=indent,
                         break_long_words=False, break_on_hyphens=False)


def item(text, width):
    """A list item: `  - text`, continued under the text."""
    if width is None:
        return [f"  {text}"]
    return textwrap.wrap(text[2:], width, initial_indent="  - ", subsequent_indent="    ",
                         break_long_words=False, break_on_hyphens=False)


def follows(docker_help, name):
    return ["", f"{name} help follows:", ""] if docker_help and name else []


def docker_overview(width):
    return overview(
        "dockscreen [OPTIONS] COMMAND",
        "Docker with security checks: dockscreen audits the commands that start containers and passes "
        "everything else to docker unchanged. Its own options go before the command, with docker's.",
        DOCKER_OPTIONS,
        [("Commands dockscreen handles:", DOCKER)],
        "Run 'dockscreen COMMAND --help' for more information on a command.",
        "Docker's own", width)


def compose_overview(commands, width):
    """commands: {name: Topic} of dockscreen's own compose commands."""
    return overview(
        "dockscreen compose [OPTIONS] COMMAND",
        "Docker Compose with security checks: dockscreen audits the project before the commands that "
        "start containers, and passes everything else to docker compose unchanged.",
        COMPOSE_OPTIONS,
        [("Commands dockscreen audits:", COMPOSE), ("Commands dockscreen adds:", commands)],
        "Run 'dockscreen compose COMMAND --help' for more information on a command.",
        "Docker Compose's own", width)


def show(build):
    """Print the help that build(width) gives, wrapped as the audit report is, except that without a
    terminal it is wrapped at 80 columns, as docker does: help is read in less more than grepped."""
    # flush: the exec of docker that follows discards unflushed buffers
    print("\n".join(build(messages.report_width(fallback=HELP_FALLBACK_WIDTH))), flush=True)
