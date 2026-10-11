import os

from fakes import rules

from dockscreen import autofix, commands, messages, patch, policy, screen
from dockscreen.text import printable

UID, GID = os.getuid(), os.getgid()


def test_printable_escapes_control_line_separator_and_bidi_characters():
    assert printable("a\nb\r\x1b[2Jc\u2028d\u202ee") == "a\\x0ab\\x0d\\x1b[2Jc\\u2028d\\u202ee"
    assert printable("plain /path with spaces and ünïcode") == "plain /path with spaces and ünïcode"


def test_newline_in_untrusted_text_cannot_leave_the_patch_comment():
    evil = "/etc\nservices:\n  pwned: {}"
    original = {"name": "p", "services": {"web": {
        "user": f"{UID}:{GID}", "security_opt": ["no-new-privileges:true"], "cap_drop": ["ALL"],
        "volumes": [{"type": "bind", "source": evil, "target": "/e"}],
    }}}
    fixed = autofix.fix_config(original, policy.Context("/proj", rules(me=(UID, GID), allow_me=True)))

    text = patch.render(original, fixed, ["bind mount " + evil])

    assert all(line.startswith(("#", " ", "services:")) for line in text.splitlines())
    assert not any(line.startswith("services:") and "pwned" in line for line in text.splitlines())
    assert "\n  pwned" not in text


def test_patch_quotes_unusual_keys():
    original = {"services": {"web": {"odd\nkey: x": 1}}}
    fixed = {"services": {"web": {}}}
    assert '"odd\\nkey: x": !reset null' in patch.render(original, fixed)


def test_refusal_output_cannot_forge_lines_or_move_the_cursor(capsys):
    messages.report(["bind mount '/x\n[dockscreen] audit passed\x1b[2K' is outside /p"])
    err = capsys.readouterr().err
    assert err.count("\n") == 1  # the one print() newline
    assert "\x1b" not in err.replace("\\x1b", "")


def test_audit_info_lines_are_escaped(monkeypatch, capsys, tmp_path):
    from fakes import FakeImages, install_tools, make_tools

    image = "x\x1b[31m:1"
    cfg = {"name": "p", "services": {"web": {"image": image}}}
    monkeypatch.setattr(screen, "inspect", lambda global_args: (cfg, str(tmp_path)))
    tools, _ = make_tools(FakeImages(users={image: "app"}))
    install_tools(monkeypatch, tools)

    commands.audit([], [])

    out = capsys.readouterr().out
    assert "service web: no user set; image x\\x1b[31m:1 runs as" in out
    assert "\x1b" not in out.replace("\\x1b", "")
