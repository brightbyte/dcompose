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
