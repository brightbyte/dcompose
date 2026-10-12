import pytest

from dockscreen import verdict
from dockscreen.verdict import Verdict


def test_exit_statuses_leave_two_for_usage_errors():
    assert [int(v) for v in Verdict] == [0, 1, 3]


@pytest.mark.parametrize("outcome, reasons, line", [
    (Verdict.PASSED, [], "\u2714 passed"),
    (Verdict.REFUSED, ["a"], "\u2718 refused: a"),
    (Verdict.REFUSED, ["a", "b", "c"], "\u2718 refused: a (+2 more)"),
    (Verdict.FAILED, ["no\nimage"], "\u26a0 failed: no\\x0aimage"),  # still one line
    (Verdict.FAILED, [], "\u26a0 failed: no reason given"),
])
def test_brief(outcome, reasons, line):
    assert verdict.brief(outcome, reasons) == line


def test_report(capsys):
    assert verdict.report(Verdict.REFUSED, ["a"]) == 1
    assert verdict.report(Verdict.FAILED, ["b"]) == 3
    assert verdict.report(Verdict.PASSED, []) == 0
    assert capsys.readouterr().err.splitlines() == [
        f"[dockscreen] {verdict.BAD} refusing: a", "[dockscreen] \u2718 audit refused",
        f"[dockscreen] {verdict.BAD} b", "[dockscreen] \u26a0 audit failed",
        "[dockscreen] \u2714 audit passed",
    ]

    assert verdict.report(Verdict.REFUSED, ["a"], brief_mode=True) == 1
    assert capsys.readouterr() == ("\u2718 refused: a\n", "")
