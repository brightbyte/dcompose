import pytest

from dcompose import cli
from dcompose.commands import COMMANDS


@pytest.fixture
def forwarded(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "forward", calls.append)
    return calls


@pytest.mark.parametrize("argv, expected", [
    (["up", "-d"], 0),
    (["-f", "a.yml", "up"], 2),
    (["--file=a.yml", "up"], 1),
    (["-p", "up", "ps"], 2),  # "up" is the project name here
    (["--dry-run", "ps"], 1),
    (["--", "up"], None),
    ([], None),
    (["--help"], None),
])
def test_find_subcommand(argv, expected):
    assert cli.find_subcommand(argv) == expected


def test_unknown_args_are_forwarded_verbatim(forwarded):
    argv = ["-f", "a.yml", "logs", "-f", "--no-such-flag", "svc"]
    cli.main(argv)
    assert forwarded == [argv]


def test_custom_command_gets_global_args_and_is_not_forwarded(forwarded, monkeypatch):
    seen = {}

    def fake(global_args, args):
        seen.update(global_args=global_args, args=args)
        return 7

    monkeypatch.setitem(COMMANDS, "fake", fake)

    assert cli.main(["-f", "a.yml", "fake", "x", "--y"]) == 7
    assert seen == {"global_args": ["-f", "a.yml"], "args": ["x", "--y"]}
    assert forwarded == []


def test_custom_name_as_option_value_is_not_dispatched(forwarded, monkeypatch):
    monkeypatch.setitem(COMMANDS, "fake", lambda global_args, args: 1 / 0)
    cli.main(["-p", "fake", "ps"])
    assert forwarded == [["-p", "fake", "ps"]]


@pytest.mark.parametrize("argv, expect_help", [
    ([], True),
    (["help"], True),
    (["--help"], True),
    (["-f", "a.yml", "help"], True),
    (["help", "up"], False),
    (["up", "--help"], False),
    (["ps"], False),
])
def test_dcompose_help_precedes_forwarding(forwarded, capsys, argv, expect_help):
    cli.main(argv)
    assert forwarded == [argv]
    out = capsys.readouterr().out
    assert ("dcompose commands:" in out) == expect_help
    if expect_help:
        assert "audit" in out and "fix" in out
