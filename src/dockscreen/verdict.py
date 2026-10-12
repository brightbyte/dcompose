"""The outcome of an audit, which is also its exit status, and of the screening before a command runs.

Refused means the policy says no. Failed means the audit could not get far enough to judge: docker,
the image or the compose config was not there, or pulling or building failed. A refusal is about the
project, image or command line; a failure is about getting to them, and may go away when retried.
Exit status 2 is left for usage errors.
"""

import enum

from dockscreen import messages
from dockscreen.imagedecision import Kind
from dockscreen.text import printable


class Verdict(enum.IntEnum):
    PASSED = 0
    REFUSED = 1
    FAILED = 3


# Text symbols, as docker uses them; messages colours them on a terminal.
GOOD, WARN, BAD, HINT = messages.GOOD, messages.WARN, messages.BAD, messages.HINT
ICONS = {Verdict.PASSED: messages.PASSED, Verdict.REFUSED: messages.REFUSED, Verdict.FAILED: messages.FAILED}


def dot(assessment):
    """The dot for a decision about an image's user."""
    if assessment.refused:
        return BAD
    return GOOD if assessment.kind in (Kind.OK, Kind.CONFIGURED) else WARN


# The closing line, the same for an audit, for --brief and for the check before a command runs.
LINES = {Verdict.PASSED: "audit passed", Verdict.REFUSED: "denied by audit", Verdict.FAILED: "audit failed"}


def line(verdict):
    """The closing line of an audit, or of the check before a command runs: mark and verdict."""
    return messages.marked(ICONS[verdict], LINES[verdict])


def brief(verdict, reasons):
    """The verdict in one line, for --brief: the closing line, with the first reason if it did not pass."""
    if verdict is Verdict.PASSED:
        return line(verdict)
    first = printable(reasons[0]) if reasons else "no reason given"
    more = f" (+{len(reasons) - 1} more)" if len(reasons) > 1 else ""
    return messages.marked(ICONS[verdict], f"{LINES[verdict]}: {first}{more}")


def report(verdict, reasons, brief_mode=False):
    """Print the verdict: one line on stdout with brief_mode, else each reason and the closing line on
    stderr. Returns the exit status."""
    if brief_mode:
        messages.out(brief(verdict, reasons), indent=False)
        return int(verdict)
    for reason in reasons:
        messages.notice(messages.marked(BAD, f"refusing: {reason}" if verdict is Verdict.REFUSED else reason))
    messages.notice(line(verdict))
    return int(verdict)


def screened(reasons, failed=False):
    """Report the screening of a command, just before it runs or instead: True if it may run.

    reasons: why it may not; failed: the reasons are failures to look, not refusals.
    """
    outcome = Verdict.FAILED if failed else Verdict.REFUSED if reasons else Verdict.PASSED
    report(outcome, reasons)
    return outcome is Verdict.PASSED
