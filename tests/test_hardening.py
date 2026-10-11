import pytest
from fakes import Accounts, rules

from dockscreen import commands, hardening, patch, policy, screen

NOBODY = "65534:65534"


def config(**service):
    return {"name": "p", "services": {"web": {"user": NOBODY, **service}}}


def test_missing_defaults_are_added_and_described():
    hardened, additions = hardening.apply(config())

    web = hardened["services"]["web"]
    assert web["cap_drop"] == ["ALL"] and web["security_opt"] == ["no-new-privileges:true"]
    assert hardening.describe(additions) == [
        'service web: cap_drop is not set; dockscreen adds cap_drop: ["ALL"]',
        'service web: security_opt is not set; dockscreen adds security_opt: ["no-new-privileges:true"]',
    ]
    assert hardening.summary(additions) == "hardening defaults added: web (cap_drop, security_opt)"


def test_existing_entries_are_kept_and_only_the_missing_one_is_added():
    hardened, additions = hardening.apply(config(cap_drop=["NET_RAW"], security_opt=["seccomp=unconfined"]))

    web = hardened["services"]["web"]
    assert web["cap_drop"] == ["NET_RAW", "ALL"]
    assert web["security_opt"] == ["seccomp=unconfined", "no-new-privileges:true"]
    assert hardening.describe(additions) == [
        'service web: cap_drop does not include ALL; dockscreen adds cap_drop: ["ALL"]',
        ('service web: security_opt does not include no-new-privileges; '
         'dockscreen adds security_opt: ["no-new-privileges:true"]'),
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
    problems = policy.check_config(hardened, policy.Context("/p", rules()))
    assert "service web: security_opt 'no-new-privileges:false' is not allowed" in problems
    assert "service web: cap_add is not allowed" in problems


def test_a_config_without_the_keys_passes_the_policy_once_hardened():
    hardened, _ = hardening.apply(config())
    assert policy.check_config(hardened, policy.Context("/p", rules())) == []
    assert policy.check_config(config(), policy.Context("/p", rules()))  # but not as it stands


def test_audit_reports_the_additions_and_hints_at_harden(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(screen, "inspect", lambda global_args: (config(), str(tmp_path)))

    assert commands.audit([], []) == 0

    captured = capsys.readouterr()
    assert "audit passed" in captured.err
    assert 'service web: cap_drop is not set; dockscreen adds cap_drop: ["ALL"]' in captured.out
    assert "the harden subcommand prints a compose override" in captured.out


def test_audit_of_a_clean_project_has_no_hint(monkeypatch, capsys, tmp_path):
    clean = config(cap_drop=["ALL"], security_opt=["no-new-privileges:true"])
    monkeypatch.setattr(screen, "inspect", lambda global_args: (clean, str(tmp_path)))
    assert commands.audit([], []) == 0
    assert "harden" not in capsys.readouterr().out


def two_services(**web):
    return {"name": "p", "services": {
        "web": {"user": NOBODY, **web},
        "db": {"user": NOBODY},
    }}


def test_harden_leaves_out_what_dockscreen_adds_and_says_so_once(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(screen, "inspect", lambda global_args: (two_services(), str(tmp_path)))

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
    monkeypatch.setattr(screen, "inspect", lambda global_args: (config, str(tmp_path)))

    commands.harden([], [])

    body = capsys.readouterr().out.split("services:", 1)[1]
    assert '    user: "${UID}:${GID}"' in body
    assert '    security_opt: !override ["no-new-privileges:true"]' in body
    assert "cap_drop" not in body  # [NET_RAW, ALL] after the default: already fine
    assert '"db"' not in body       # a service with nothing to fix is not mentioned


def test_the_audit_still_reports_every_service(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(screen, "inspect", lambda global_args: (two_services(), str(tmp_path)))

    commands.audit([], [])

    out = capsys.readouterr().out
    for service in ("web", "db"):
        assert f'service {service}: cap_drop is not set; dockscreen adds cap_drop: ["ALL"]' in out
        assert f"service {service}: security_opt is not set" in out


def test_fix_is_an_alias_of_harden_and_is_listed_once_in_the_help():
    assert commands.COMMANDS["fix"] is commands.COMMANDS["harden"]
    assert commands.ALIASES == {"fix": "harden"}


def test_patch_header_names_the_command():
    assert "`dockscreen harden`" in patch.HEADER


# --- names in `user:`, hook users and group_add -------------------------------------

@pytest.mark.parametrize("spec, resolved", [
    ("nobody", "65534:65534"),
    ("nobody:nogroup", "65534:65534"),
    ("root", "0:0"),
    ("root:root", "0:0"),
    ("1000:nogroup", "1000:65534"),
    ("nobody:1000", "65534:1000"),
    ("1000:root", "1000:0"),
    ("alice", "4242:4343"),          # a name brings its primary group
    ("alice:docker", "4242:999"),
])
def test_names_are_resolved_on_this_host(spec, resolved):
    original = config(user=spec)

    hardened, additions = hardening.apply(original, Accounts())

    assert hardened["services"]["web"]["user"] == resolved
    assert original["services"]["web"]["user"] == spec  # the input is left alone
    # the first line: the same service also lacks the other defaults
    assert hardening.describe(additions)[0] == (
        f'service web: user "{spec}" names an account on this host; dockscreen resolves it to "{resolved}"')


@pytest.mark.parametrize("spec", ["1000:1000", "65534:65534", "app", "app:app", "1000", "1000:staff"])
def test_numbers_and_unknown_names_are_left_for_the_policy(spec):
    hardened, additions = hardening.apply(config(user=spec), Accounts())
    assert hardened["services"]["web"]["user"] == spec
    assert not any(a.key == "user" for a in additions)


def test_names_unknown_on_this_host_are_refused_even_if_the_image_defines_them():
    ctx = policy.Context("/p", rules())
    keep = {"cap_drop": ["ALL"], "security_opt": ["no-new-privileges"]}
    for spec, part in (("app", "user 'app'"), ("app:app", "user 'app'"), ("1000:staff", "group 'staff'")):
        hardened, _ = hardening.apply(config(user=spec, **keep), Accounts())
        problems = policy.check_config(hardened, ctx)
        assert any(f"{part} does not exist on this host" in p for p in problems), spec


def test_nobody_passes_and_root_is_refused_once_resolved():
    ctx = policy.Context("/p", rules())
    keep = {"cap_drop": ["ALL"], "security_opt": ["no-new-privileges"]}
    nobody, _ = hardening.apply(config(user="nobody", **keep), Accounts())
    root, _ = hardening.apply(config(user="root", **keep), Accounts())
    assert policy.check_config(nobody, ctx) == []
    assert policy.check_config(root, ctx) == ["service web: user '0:0': uid 0 is root",
                                              "service web: user '0:0': gid 0 is root"]


def test_hook_users_and_group_add_are_resolved_too():
    original = config(post_start=[{"command": "x", "user": "alice"}], group_add=["docker", "4000", "staff"])

    hardened, additions = hardening.apply(original, Accounts())

    web = hardened["services"]["web"]
    assert web["post_start"] == [{"command": "x", "user": "4242:4343"}]
    assert web["group_add"] == ["999", "4000", "staff"]  # an unknown name stays, for the policy
    assert {a.key for a in additions} >= {"post_start", "group_add"}


def test_the_audit_reports_the_resolution_and_harden_does_not_repeat_it(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(screen, "inspect", lambda global_args: (config(user="nobody"), str(tmp_path)))

    commands.audit([], [])
    audit_out = capsys.readouterr().out
    commands.harden([], [])
    harden_out = capsys.readouterr().out

    assert ('service web: user "nobody" names an account on this host; '
            'dockscreen resolves it to "65534:65534"') in audit_out
    assert harden_out.splitlines()[-1] == "services: {}"  # automatic, like the other defaults
    assert "resolves user and group names to ids on this host" in harden_out
