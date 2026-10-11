import os

from dcompose import commands, guard, hardening, patch, policy

UID, GID = os.getuid(), os.getgid()


def config(**service):
    return {"name": "p", "services": {"web": {"user": f"{UID}:{GID}", **service}}}


def test_missing_defaults_are_added_and_described():
    hardened, additions = hardening.apply(config())

    web = hardened["services"]["web"]
    assert web["cap_drop"] == ["ALL"] and web["security_opt"] == ["no-new-privileges:true"]
    assert hardening.describe(additions) == [
        'service web: cap_drop is not set; dcompose adds cap_drop: ["ALL"]',
        'service web: security_opt is not set; dcompose adds security_opt: ["no-new-privileges:true"]',
    ]
    assert hardening.summary(additions) == "hardening defaults added: web (cap_drop, security_opt)"


def test_existing_entries_are_kept_and_only_the_missing_one_is_added():
    hardened, additions = hardening.apply(config(cap_drop=["NET_RAW"], security_opt=["seccomp=unconfined"]))

    web = hardened["services"]["web"]
    assert web["cap_drop"] == ["NET_RAW", "ALL"]
    assert web["security_opt"] == ["seccomp=unconfined", "no-new-privileges:true"]
    assert hardening.describe(additions) == [
        'service web: cap_drop does not include ALL; dcompose adds cap_drop: ["ALL"]',
        ('service web: security_opt does not include no-new-privileges; '
         'dcompose adds security_opt: ["no-new-privileges:true"]'),
    ]


def test_a_compliant_service_is_left_alone_and_the_input_is_not_modified():
    original = config(cap_drop=["all"], security_opt=["no-new-privileges"])
    hardened, additions = hardening.apply(original)
    assert hardened == original and additions == []

    bare = config()
    hardening.apply(bare)
    assert "cap_drop" not in bare["services"]["web"]


def test_a_project_cannot_weaken_the_defaults():
    # Appending true does not undo false: the policy still refuses the config.
    hardened, _ = hardening.apply(config(security_opt=["no-new-privileges:false"], cap_add=["SYS_ADMIN"]))
    problems = policy.check_config(hardened, policy.Context("/p", UID, GID))
    assert "service web: security_opt 'no-new-privileges:false' is not allowed" in problems
    assert "service web: cap_add is not allowed" in problems


def test_a_config_without_the_keys_passes_the_policy_once_hardened():
    hardened, _ = hardening.apply(config())
    assert policy.check_config(hardened, policy.Context("/p", UID, GID)) == []
    assert policy.check_config(config(), policy.Context("/p", UID, GID))  # but not as it stands


def test_audit_reports_the_additions_and_hints_at_harden(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(guard, "inspect", lambda global_args: (config(), str(tmp_path)))

    assert commands.audit([], []) == 0

    captured = capsys.readouterr()
    assert "audit passed" in captured.err
    assert 'service web: cap_drop is not set; dcompose adds cap_drop: ["ALL"]' in captured.out
    assert "the harden subcommand prints a compose override" in captured.out


def test_audit_of_a_clean_project_has_no_hint(monkeypatch, capsys, tmp_path):
    clean = config(cap_drop=["ALL"], security_opt=["no-new-privileges:true"])
    monkeypatch.setattr(guard, "inspect", lambda global_args: (clean, str(tmp_path)))
    assert commands.audit([], []) == 0
    assert "harden" not in capsys.readouterr().out


def two_services(**web):
    return {"name": "p", "services": {
        "web": {"user": f"{UID}:{GID}", **web},
        "db": {"user": f"{UID}:{GID}"},
    }}


def test_harden_leaves_out_what_dcompose_adds_and_says_so_once(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(guard, "inspect", lambda global_args: (two_services(), str(tmp_path)))

    assert commands.harden([], []) == 0

    out = capsys.readouterr().out
    assert "cap_drop:" not in out.replace("# note", "").split("services:")[-1]
    assert "security_opt:" not in out.split("services:")[-1]
    assert out.splitlines()[-1] == "services: {}"  # nothing else was needed to pass the audit
    notes = [line for line in out.splitlines() if "also adds cap_drop" in line]
    assert len(notes) == 1  # once, however many services there are
    assert 'cap_drop: ["ALL"]' in notes[0] and 'security_opt: ["no-new-privileges:true"]' in notes[0]


def test_harden_writes_only_what_is_needed_on_top_of_the_defaults(monkeypatch, capsys, tmp_path):
    # user and a disallowed security option cannot be fixed by the defaults: appending
    # no-new-privileges leaves seccomp=unconfined in place, so the list has to be replaced.
    config = two_services(user="0:0", security_opt=["seccomp=unconfined"], cap_drop=["NET_RAW"])
    monkeypatch.setattr(guard, "inspect", lambda global_args: (config, str(tmp_path)))

    commands.harden([], [])

    body = capsys.readouterr().out.split("services:", 1)[1]
    assert '    user: "${DCOMPOSE_UID}:${DCOMPOSE_GID}"' in body
    assert '    security_opt: !override ["no-new-privileges:true"]' in body
    assert "cap_drop" not in body  # [NET_RAW, ALL] after the default: already fine
    assert '"db"' not in body       # a service with nothing to fix is not mentioned


def test_the_audit_still_reports_every_service(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(guard, "inspect", lambda global_args: (two_services(), str(tmp_path)))

    commands.audit([], [])

    out = capsys.readouterr().out
    for service in ("web", "db"):
        assert f'service {service}: cap_drop is not set; dcompose adds cap_drop: ["ALL"]' in out
        assert f"service {service}: security_opt is not set" in out


def test_fix_is_an_alias_of_harden_and_is_listed_once_in_the_help():
    assert commands.COMMANDS["fix"] is commands.COMMANDS["harden"]
    assert commands.ALIASES == {"fix": "harden"}


def test_patch_header_names_the_command():
    assert "`dcompose harden`" in patch.HEADER
