import pytest

from dcompose import cli, guard, policy
from dcompose.commands import COMMANDS


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


@pytest.mark.parametrize("subcommand", sorted(cli.GUARDED_SUBCOMMANDS))
def test_guarded_subcommand_with_problems_is_not_forwarded(forwarded, monkeypatch, subcommand):
    monkeypatch.setattr(guard, "check", lambda global_args, rules: ["privileged is not allowed"])
    assert cli.main(["-f", "a.yml", subcommand]) == 1
    assert forwarded == []


def test_guarded_subcommand_without_problems_is_forwarded(forwarded, monkeypatch):
    seen = []
    monkeypatch.setattr(guard, "check", lambda global_args, rules: seen.append((global_args, rules)) or [])
    cli.main(["-f", "a.yml", "up", "-d"])
    assert seen == [(["-f", "a.yml"], policy.check_config)]
    assert forwarded == [["-f", "a.yml", "up", "-d"]]


def test_unguarded_subcommand_is_not_inspected(forwarded, monkeypatch):
    monkeypatch.setattr(guard, "check", lambda global_args, rules: 1 / 0)
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


@pytest.mark.parametrize("subcommand, rules", [
    ("up", policy.check_config),
    ("run", policy.check_config),
    ("build", policy.check_build_config),
    ("bake", policy.check_build_config),
])
def test_build_subcommands_get_the_build_rules(forwarded, monkeypatch, subcommand, rules):
    seen = []
    monkeypatch.setattr(guard, "check", lambda global_args, rules: seen.append(rules) or [])
    cli.main([subcommand])
    assert seen == [rules]
    assert forwarded == [[subcommand]]
