import pytest

from dockscreen import verdict
from dockscreen.verdict import Verdict


def test_exit_statuses_leave_two_for_usage_errors():
    assert [int(v) for v in Verdict] == [0, 1, 3]


@pytest.mark.parametrize("outcome, reasons, line", [
    (Verdict.PASSED, [], "\u2705 passed"),
    (Verdict.REFUSED, ["a"], "\u274c refused: a"),
    (Verdict.REFUSED, ["a", "b", "c"], "\u274c refused: a (+2 more)"),
    (Verdict.FAILED, ["no\nimage"], "\u2757 failed: no\\x0aimage"),  # still one line
    (Verdict.FAILED, [], "\u2757 failed: no reason given"),
])
def test_brief(outcome, reasons, line):
    assert verdict.brief(outcome, reasons) == line


def test_report(capsys):
    assert verdict.report(Verdict.REFUSED, ["a"]) == 1
    assert verdict.report(Verdict.FAILED, ["b"]) == 3
    assert verdict.report(Verdict.PASSED, []) == 0
    assert capsys.readouterr().err.splitlines() == [
        f"[dockscreen] {verdict.BAD} refusing: a", "[dockscreen] \u274c audit refused",
        f"[dockscreen] {verdict.BAD} b", "[dockscreen] \u2757 audit failed",
        "[dockscreen] \u2705 audit passed",
    ]

    assert verdict.report(Verdict.REFUSED, ["a"], brief_mode=True) == 1
    assert capsys.readouterr() == ("\u274c refused: a\n", "")
