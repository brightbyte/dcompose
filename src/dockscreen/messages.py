"""Messages to the person running dockscreen, on stderr.

Every message is one line that starts with PREFIX, so it can be told apart from what docker and compose
print. Text is escaped with printable(), because much of it quotes the untrusted project or image.
Command output that is meant as data (audit reports, harden patches, help) goes to stdout and is not
a message.
"""

import sys

from dockscreen.text import printable

PREFIX = "[dockscreen]"
DOCKER_NOT_FOUND = "'docker' not found in PATH"


def notice(text):
    print(f"{PREFIX} {printable(text)}", file=sys.stderr)


def warning(text):
    notice(f"warning: {text}")


def report(problems):
    """One refusal per problem; True if there were none."""
    for problem in problems:
        notice(f"refusing: {problem}")
    return not problems


def refuse(problems):
    """report(), then exit code 1: called when something is refused, even if no reason was found."""
    report(problems)
    return 1


def fatal(text):
    """Exit with status 1 and text as the message."""
    sys.exit(f"{PREFIX} {printable(text)}")
