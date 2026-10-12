"""Messages to the person running dockscreen, on stderr.

Every message is one line that starts with PREFIX, so it can be told apart from what docker and compose
print. Text is escaped with printable(), because much of it quotes the untrusted project or image.
Command output that is meant as data (audit reports, harden patches, help) goes to stdout and is not
a message.

A line can start with a mark (marked()): a plain text symbol, coloured as docker colours its own when the
line goes to a terminal and NO_COLOR is not set. The line keeps its mark as an attribute, so the same
symbol can stand for different things in different colours.
"""

import os
import sys

from dockscreen.text import printable

PREFIX = "[dockscreen]"
DOCKER_NOT_FOUND = "'docker' not found in PATH"


class Mark(str):
    """A symbol, and the ANSI colour a terminal shows it in, bold."""

    def __new__(cls, glyph, colour):
        mark = super().__new__(cls, glyph)
        mark.colour = colour
        return mark


class Marked(str):
    """`MARK text`, keeping the mark for colouring."""

    def __new__(cls, mark, text):
        line = super().__new__(cls, f"{mark} {text}")
        line.mark, line.text = mark, text
        return line


GREEN, YELLOW, RED, BLUE = "32", "33", "31", "34"
GOOD = Mark("\u25cf", GREEN)    # ● accepted as it is
WARN = Mark("\u25cf", YELLOW)   # ● allowed, but changed by dockscreen or worth a look
BAD = Mark("\u25cf", RED)       # ● refused, or could not be checked
HINT = Mark("\u24d8", BLUE)     # ⓘ how to get past something
PASSED = Mark("\u2714", GREEN)  # ✔
REFUSED = Mark("\u2718", RED)   # ✘
FAILED = Mark("\u26a0", YELLOW)  # ⚠ could not look


def marked(mark, text):
    return Marked(mark, text)


def notice(text):
    print(f"{PREFIX} {paint(text, sys.stderr)}", file=sys.stderr)


def out(text):
    """A line of a report on stdout, escaped and with its mark coloured."""
    print(paint(text, sys.stdout))


def paint(line, stream):
    """line escaped (printable), with its mark coloured if stream is a terminal that wants colour."""
    if not isinstance(line, Marked) or not wants_colour(stream):
        return printable(line)
    return f"\x1b[1;{line.mark.colour}m{line.mark}\x1b[0m {printable(line.text)}"  # bold, for all alike


def wants_colour(stream):
    if "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


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
