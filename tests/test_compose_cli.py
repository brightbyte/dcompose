import os

import pytest

from dockscreen import argscan, compose_cli, composerun, hostusers, policy, screen
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
    assert argscan.find_subcommand(argv, compose_cli.GLOBAL_OPTS_WITH_VALUE) == expected


def test_unknown_args_are_forwarded_verbatim(forwarded):
    argv = ["-f", "a.yml", "logs", "-f", "--no-such-flag", "svc"]
    compose_cli.main(argv)
    assert forwarded == [argv]


def test_custom_command_gets_global_args_and_is_not_forwarded(forwarded, monkeypatch):
    seen = {}

    def fake(global_args, args, allow_me=False):
        seen.update(global_args=global_args, args=args)
        return 7

    monkeypatch.setitem(COMMANDS, "fake", fake)

    assert compose_cli.main(["-f", "a.yml", "fake", "x", "--y"]) == 7
    assert seen == {"global_args": ["-f", "a.yml"], "args": ["x", "--y"]}
    assert forwarded == []


def test_custom_name_as_option_value_is_not_dispatched(forwarded, monkeypatch):
    monkeypatch.setitem(COMMANDS, "fake", lambda global_args, args: 1 / 0)
    compose_cli.main(["-p", "fake", "ps"])
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
    compose_cli.main(argv)
    assert forwarded == [argv]
    out = capsys.readouterr().out
    assert ("dockscreen commands:" in out) == expect_help
    if expect_help:
        assert "audit" in out and "fix" in out


@pytest.mark.parametrize("subcommand", sorted(compose_cli.RUNTIME_SUBCOMMANDS))
def test_runtime_subcommands_run_from_the_checked_config(forwarded, monkeypatch, subcommand):
    seen = []
    monkeypatch.setattr(composerun, "run",
                        lambda argv, idx, allow_me: seen.append((argv, idx, allow_me)) or 3)

    assert compose_cli.main(["-f", "a.yml", subcommand, "-d"]) == 3

    assert seen == [(["-f", "a.yml", subcommand, "-d"], 2, False)]
    assert forwarded == []  # composerun runs compose itself, from the hardened config


@pytest.mark.parametrize("subcommand", sorted(compose_cli.BUILD_SUBCOMMANDS))
def test_build_subcommands_get_the_build_rules_and_are_then_forwarded(forwarded, monkeypatch, subcommand):
    seen = []
    monkeypatch.setattr(screen, "passes",
                        lambda global_args, rules: seen.append((global_args, rules)) or True)

    compose_cli.main(["-f", "a.yml", subcommand])

    assert seen == [(["-f", "a.yml"], policy.check_build_config)]
    assert forwarded == [["-f", "a.yml", subcommand]]


def test_build_with_problems_is_not_forwarded(forwarded, monkeypatch):
    monkeypatch.setattr(screen, "passes", lambda global_args, rules: False)
    assert compose_cli.main(["build"]) == 1
    assert forwarded == []


def test_unscreened_subcommand_is_not_inspected(forwarded, monkeypatch):
    monkeypatch.setattr(screen, "passes", lambda global_args, rules: 1 / 0)
    monkeypatch.setattr(composerun, "run", lambda argv, idx, allow_me: 1 / 0)
    compose_cli.main(["ps"])
    assert forwarded == [["ps"]]


@pytest.mark.parametrize("argv, screened", [
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
def test_is_screened(argv, screened):
    assert compose_cli.is_screened(argv, argscan.find_subcommand(argv, compose_cli.GLOBAL_OPTS_WITH_VALUE)) == screened


# --- dockscreen's own options and the config file ------------------------------------

def test_allow_me_before_the_subcommand_reaches_the_checks_and_not_compose(forwarded, monkeypatch):
    seen = []
    monkeypatch.setattr(composerun, "run", lambda argv, idx, allow_me: seen.append((argv, allow_me)) or 0)
    compose_cli.main(["--allow-me", "-f", "a.yml", "up"])
    assert seen == [(["-f", "a.yml", "up"], True)]


def test_as_me_before_the_subcommand_is_refused(forwarded, capsys):
    assert compose_cli.main(["--as-me", "up"]) == 2
    assert "--as-me goes after run or exec" in capsys.readouterr().err and forwarded == []


def test_exec_as_me_reaches_compose_as_the_callers_ids(forwarded):
    assert compose_cli.main(["exec", "--as-me", "web", "sh"]) is None
    assert forwarded == [["exec", f"--user={os.getuid()}:{os.getgid()}", "web", "sh"]]


@pytest.mark.parametrize("argv, code", [
    (["exec", "-u", "0:0", "web", "sh"], None), (["exec", "web", "sh"], None),
    (["exec", "-u", "postgres", "web", "sh"], 1), (["exec", "--user=1000", "web", "sh"], 1),
])
def test_exec_takes_numeric_users_only(forwarded, capsys, argv, code):
    assert compose_cli.main(argv) == code
    assert forwarded == ([] if code else [argv])


def test_exec_as_a_local_user_reaches_compose_as_numeric_ids(forwarded, monkeypatch, capsys):
    monkeypatch.setattr(hostusers, "resolve_account",
                        lambda name: ("1001:1002", [f"Resolving user {name} to uid 1001, gid 1002"]))
    assert compose_cli.main(["exec", "--as", "alice", "web", "sh"]) is None
    assert forwarded == [["exec", "--user=1001:1002", "web", "sh"]]
    assert "Resolving user alice" in capsys.readouterr().err


def test_a_config_file_that_cannot_be_trusted_stops_everything(forwarded, monkeypatch, capsys):
    from dockscreen import config

    def broken():
        raise config.ConfigError("/home/me/.config/dockscreen/config.toml: /home/me is writable by others")
    monkeypatch.setattr(config, "current", broken)

    assert compose_cli.main(["ps"]) == 1
    assert "refusing: config file /home/me/.config" in capsys.readouterr().err and forwarded == []
