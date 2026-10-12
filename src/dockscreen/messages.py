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
import shutil
import sys
import textwrap

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
REFUSED = Mark("\u2296", RED)   # ⊖
FAILED = Mark("\u2718", RED)    # ✘ could not look, as docker marks errors


# Report lines are wrapped to the terminal, but never wider than MAX_WIDTH, and not at all on a
# terminal narrower than MIN_WIDTH, or without one. A tab is TAB_WIDTH columns; continued lines line
# up with the text after the mark.
MAX_WIDTH, MIN_WIDTH, TAB_WIDTH = 120, 20, 8
CONTINUATION = "  "


def marked(mark, text):
    return Marked(mark, text)


def notice(text):
    print(f"{PREFIX} {paint(text, sys.stderr)}", file=sys.stderr)


def out(text, indent=True):
    """A line of a report on stdout, escaped and with its mark coloured.

    indent: after a tab, which sets the report apart from the [dockscreen] messages on stderr that
    interleave with it, and wrapped to the terminal (report_width) with the text lined up after the
    mark. A line that is all of the output (--brief) goes as it is.
    """
    if not indent:
        print(paint(text, sys.stdout))
        return
    for line in wrapped(text, report_width(), wants_colour(sys.stdout)):
        print(f"\t{line}")


def report_width():
    """The width to wrap report lines at: COLUMNS or the terminal's, at most MAX_WIDTH; None (no
    wrapping) when neither is known, as when the output goes to grep, or below MIN_WIDTH."""
    columns = shutil.get_terminal_size((0, 0)).columns  # 0: no COLUMNS, and not a terminal
    return None if columns < MIN_WIDTH else min(columns, MAX_WIDTH)


def wrapped(text, width, colour):
    """text as lines of at most width columns after a tab (TAB_WIDTH), continued under the text after
    the mark (CONTINUATION). Words are never broken: a long path stays whole."""
    lead = f"{text.mark} " if isinstance(text, Marked) else ""
    body = printable(text.text if lead else text)
    if width is None:
        lines = [lead + body]
    else:
        lines = textwrap.wrap(lead + body, width=width - TAB_WIDTH, subsequent_indent=CONTINUATION,
                              break_long_words=False, break_on_hyphens=False) or [""]
    if lead and colour:
        lines[0] = coloured(text.mark) + lines[0][len(text.mark):]
    return lines


def paint(line, stream):
    """line escaped (printable), with its mark coloured if stream is a terminal that wants colour."""
    if not isinstance(line, Marked) or not wants_colour(stream):
        return printable(line)
    return f"{coloured(line.mark)} {printable(line.text)}"


def coloured(mark):
    return f"\x1b[1;{mark.colour}m{mark}\x1b[0m"  # bold, for all alike


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
