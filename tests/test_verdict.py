import pytest

from dockscreen import verdict
from dockscreen.verdict import Verdict


def test_exit_statuses_leave_two_for_usage_errors():
    assert [int(v) for v in Verdict] == [0, 1, 3]


@pytest.mark.parametrize("outcome, reasons, line", [
    (Verdict.PASSED, [], "passed"),
    (Verdict.REFUSED, ["a"], "refused: a"),
    (Verdict.REFUSED, ["a", "b", "c"], "refused: a (+2 more)"),
    (Verdict.FAILED, ["no\nimage"], "failed: no\\x0aimage"),  # still one line
    (Verdict.FAILED, [], "failed: no reason given"),
])
def test_brief(outcome, reasons, line):
    assert verdict.brief(outcome, reasons) == line


def test_report(capsys):
    assert verdict.report(Verdict.REFUSED, ["a"]) == 1
    assert verdict.report(Verdict.FAILED, ["b"]) == 3
    assert verdict.report(Verdict.PASSED, []) == 0
    assert capsys.readouterr().err == (
        "[dockscreen] refusing: a\n[dockscreen] audit failed: b\n[dockscreen] audit passed\n")

    assert verdict.report(Verdict.REFUSED, ["a"], brief_mode=True) == 1
    assert capsys.readouterr() == ("refused: a\n", "")
