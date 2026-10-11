"""The outcome of an audit, which is also its exit status.

Refused means the policy says no. Failed means the audit could not get far enough to judge: docker,
the image or the compose config was not there, or pulling or building failed. A refusal is about the
project, image or command line; a failure is about getting to them, and may go away when retried.
Exit status 2 is left for usage errors.
"""

import enum

from dockscreen import messages
from dockscreen.text import printable


class Verdict(enum.IntEnum):
    PASSED = 0
    REFUSED = 1
    FAILED = 3


def brief(verdict, reasons):
    """The verdict in one line, for --brief: `passed`, or the verdict and its first reason."""
    if verdict is Verdict.PASSED:
        return "passed"
    first = printable(reasons[0]) if reasons else "no reason given"
    more = f" (+{len(reasons) - 1} more)" if len(reasons) > 1 else ""
    return f"{verdict.name.lower()}: {first}{more}"


def report(verdict, reasons, brief_mode=False):
    """Print the verdict: one line on stdout with brief_mode, else messages on stderr. Returns the exit
    status."""
    if brief_mode:
        print(brief(verdict, reasons))
    elif verdict is Verdict.REFUSED:
        messages.report(reasons)
    elif verdict is Verdict.FAILED:
        for reason in reasons:
            messages.notice(f"audit failed: {reason}")
    else:
        messages.notice("audit passed")
    return int(verdict)
