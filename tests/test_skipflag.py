import pytest

from dcompose import cli, docker_cli, skipflag

FLAG = "--skip-security-gate"


@pytest.mark.parametrize("argv, found, rest", [
    ([FLAG, "up"], True, ["up"]),
    (["-f", "a.yml", FLAG, "up", "-d"], True, ["-f", "a.yml", "up", "-d"]),
    ([FLAG, "--dry-run", FLAG, "ps"], True, ["--dry-run", "ps"]),
    (["up", FLAG], False, ["up", FLAG]),               # after the subcommand: not ours, docker rejects it
    (["run", "img", FLAG], False, ["run", "img", FLAG]),
    (["-f", FLAG, "up"], False, ["-f", FLAG, "up"]),   # a value, not the flag
    (["--", FLAG], False, ["--", FLAG]),
    ([], False, []),
])
def test_only_a_global_option_counts(argv, found, rest):
    assert skipflag.strip(argv, cli.GLOBAL_OPTS_WITH_VALUE) == (found, rest)


def test_banner_goes_to_stderr(capsys):
    skipflag.banner()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "security gate is disabled" in captured.err and "no defaults are added" in captured.err


def test_dcompose_with_the_flag_is_plain_compose_with_a_warning(forwarded, monkeypatch, capsys):
    monkeypatch.setattr(cli.composerun, "run", lambda argv, idx: 1 / 0)
    monkeypatch.setattr(cli.guard, "passes", lambda *a: 1 / 0)

    cli.main([FLAG, "-f", "a.yml", "up", "-d"])

    assert forwarded == [["-f", "a.yml", "up", "-d"]]
    assert "security gate is disabled" in capsys.readouterr().err


def test_dcompose_flag_also_skips_the_extra_subcommands(forwarded):
    cli.main([FLAG, "audit"])
    assert forwarded == [["audit"]]  # compose gets it unchanged; nothing of ours runs


@pytest.mark.parametrize("argv, expected", [
    ([FLAG, "run", "--privileged", "img"], ["run", "--privileged", "img"]),
    ([FLAG, "compose", "up"], ["compose", "up"]),
    (["-H", "tcp://x", FLAG, "create", "img"], ["-H", "tcp://x", "create", "img"]),
])
def test_docker_with_the_flag_is_plain_docker_with_a_warning(monkeypatch, capsys, argv, expected):
    calls = []
    monkeypatch.setattr(docker_cli, "passthrough", lambda a: calls.append(a) or 0)
    monkeypatch.setattr(docker_cli.cli, "main", lambda a: 1 / 0)

    docker_cli.main(argv)

    assert calls == [expected]  # no defaults added, no gate, no dcompose
    assert "security gate is disabled" in capsys.readouterr().err


def test_docker_without_a_global_flag_gets_no_exemption(monkeypatch):
    calls = []
    monkeypatch.setattr(docker_cli, "passthrough", lambda a: calls.append(a) or 0)
    docker_cli.main(["create", "img", FLAG])  # belongs to the command
    assert calls == [["create", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "img", FLAG]]
