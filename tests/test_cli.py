import pytest

from dockscreen import cli, composerun, guard, policy
from dockscreen.commands import COMMANDS


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
def test_dockscreen_help_precedes_forwarding(forwarded, capsys, argv, expect_help):
    cli.main(argv)
    assert forwarded == [argv]
    out = capsys.readouterr().out
    assert ("dockscreen commands:" in out) == expect_help
    if expect_help:
        assert "audit" in out and "fix" in out


@pytest.mark.parametrize("subcommand", sorted(cli.RUNTIME_SUBCOMMANDS))
def test_runtime_subcommands_run_from_the_checked_config(forwarded, monkeypatch, subcommand):
    seen = []
    monkeypatch.setattr(composerun, "run", lambda argv, idx: seen.append((argv, idx)) or 3)

    assert cli.main(["-f", "a.yml", subcommand, "-d"]) == 3

    assert seen == [(["-f", "a.yml", subcommand, "-d"], 2)]
    assert forwarded == []  # composerun runs compose itself, from the hardened config


@pytest.mark.parametrize("subcommand", sorted(cli.BUILD_SUBCOMMANDS))
def test_build_subcommands_get_the_build_rules_and_are_then_forwarded(forwarded, monkeypatch, subcommand):
    seen = []
    monkeypatch.setattr(guard, "passes", lambda global_args, rules: seen.append((global_args, rules)) or True)

    cli.main(["-f", "a.yml", subcommand])

    assert seen == [(["-f", "a.yml"], policy.check_build_config)]
    assert forwarded == [["-f", "a.yml", subcommand]]


def test_build_with_problems_is_not_forwarded(forwarded, monkeypatch):
    monkeypatch.setattr(guard, "passes", lambda global_args, rules: False)
    assert cli.main(["build"]) == 1
    assert forwarded == []


def test_unguarded_subcommand_is_not_inspected(forwarded, monkeypatch):
    monkeypatch.setattr(guard, "passes", lambda global_args, rules: 1 / 0)
    monkeypatch.setattr(composerun, "run", lambda argv, idx: 1 / 0)
    cli.main(["ps"])
    assert forwarded == [["ps"]]


@pytest.mark.parametrize("argv, guarded", [
    (["up"], True),
    (["run", "app", "ls", "-h"], True),
    (["run", "app", "grep", "-h", "foo"], True),
    (["run", "app", "--help"], True),
    (["run", "-e", "--help", "app"], True),  # a flag value, not a help request
    (["up", "-d", "--help"], True),
    (["up", "-h"], True),
    (["up", "--help"], False),
    (["run", "--help"], False),
    (["watch", "--help"], False),
    (["ps"], False),
    (["logs", "-f"], False),
    ([], False),
])
def test_is_guarded(argv, guarded):
    assert cli.is_guarded(argv, cli.find_subcommand(argv)) == guarded
