import pytest

from dockscreen import messages


def test_notice_is_one_prefixed_escaped_line(capsys):
    messages.notice("evil\nname")

    assert capsys.readouterr().err == "[dockscreen] evil\\x0aname\n"


def test_warning(capsys):
    messages.warning("careful")

    assert capsys.readouterr().err == "[dockscreen] warning: careful\n"


def test_report(capsys):
    assert messages.report([]) is True
    assert messages.report(["a", "b"]) is False

    assert capsys.readouterr().err == "[dockscreen] refusing: a\n[dockscreen] refusing: b\n"


def test_refuse(capsys):
    assert messages.refuse(["a"]) == 1
    assert messages.refuse([]) == 1  # refused, even without a reason: fails closed

    assert capsys.readouterr().err == "[dockscreen] refusing: a\n"


def test_fatal():
    with pytest.raises(SystemExit) as exited:
        messages.fatal("gone\x1b[2J")

    # SystemExit with a string prints it on stderr and exits with status 1
    assert exited.value.code == "[dockscreen] gone\\x1b[2J"


class Terminal:
    def isatty(self):
        return True


@pytest.mark.parametrize("mark, painted", [
    (messages.PASSED, "\x1b[1;32m\u2714\x1b[0m x"),
    (messages.GOOD, "\x1b[1;32m\u25cf\x1b[0m x"),
    (messages.WARN, "\x1b[1;33m\u25cf\x1b[0m x"),   # the same symbol, by its role
    (messages.BAD, "\x1b[1;31m\u25cf\x1b[0m x"),
    (messages.HINT, "\x1b[1;34m\u24d8\x1b[0m x"),
])
def test_marks_are_coloured_on_a_terminal(monkeypatch, mark, painted):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    assert messages.paint(messages.marked(mark, "x"), Terminal()) == painted
    assert messages.paint("\u2714 x", Terminal()) == "\u2714 x"  # a plain string is not a marked line


def test_no_colour_when_piped_or_asked_not_to(monkeypatch, capsys):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    messages.notice("✔ screening passed")
    assert capsys.readouterr().err == "[dockscreen] ✔ screening passed\n"  # not a terminal

    monkeypatch.setenv("NO_COLOR", "1")
    assert messages.paint("✔ x", Terminal()) == "✔ x"
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert messages.paint("✔ x", Terminal()) == "✔ x"


def test_report_lines_are_escaped_before_they_are_painted(capsys):
    messages.out(messages.marked(messages.BAD, "evil\x1b[2J"))
    assert capsys.readouterr().out == "\t\u25cf evil\\x1b[2J\n"  # a report line: after a tab


def test_untrusted_text_is_escaped_in_coloured_lines_too(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    line = messages.marked(messages.BAD, "evil\x1b[2J")
    assert messages.paint(line, Terminal()) == "\x1b[1;31m\u25cf\x1b[0m evil\\x1b[2J"


def test_a_line_that_is_all_of_the_output_has_no_tab(capsys):
    messages.out(messages.marked(messages.PASSED, "passed"), indent=False)
    assert capsys.readouterr().out == "\u2714 passed\n"
