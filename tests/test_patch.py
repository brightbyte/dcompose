import os

from dcompose import autofix, commands, guard, patch, policy

UID = os.getuid()
GID = os.getgid()


def config(**service):
    return {"name": "proj", "services": {"web": service}}


def compliant(**service):
    return config(user=f"{UID}:{GID}", security_opt=["no-new-privileges:true"], cap_drop=["ALL"], **service)


def test_patch_resets_removed_keys_and_overrides_changed_ones():
    original = config(user="0:0", privileged=True, group_add=["0", str(GID)], image="x")
    fixed = autofix.fix_config(original, policy.Context('/proj', UID, GID))

    lines = patch.render(original, fixed).splitlines()

    assert '    user: "${DCOMPOSE_UID}:${DCOMPOSE_GID}"' in lines
    assert any("DCOMPOSE_UID" in line and line.startswith("# note") for line in lines)
    assert "    privileged: !reset null" in lines
    assert f'    group_add: !override ["{GID}"]' in lines
    # untouched keys are not repeated
    assert not any("image" in line for line in lines)


def test_patch_for_compliant_config_is_empty():
    original = compliant()
    fixed = autofix.fix_config(original, policy.Context('/proj', UID, GID))
    assert patch.render(original, fixed).splitlines()[-1] == "services: {}"


def test_unfixed_problems_are_listed_as_comments():
    original = compliant()
    assert "# not fixed: bind mount /etc" in patch.render(original, original, ["bind mount /etc"])


def test_fix_command_prints_patch_and_fails_when_problems_remain(monkeypatch, capsys, tmp_path):
    original = config(user="0:0", build={"context": "/"})
    monkeypatch.setattr(guard, "inspect", lambda global_args: (original, str(tmp_path)))

    assert commands.fix([], []) == 1

    captured = capsys.readouterr()
    assert "services:" in captured.out and "user:" in captured.out
    assert "cannot fix automatically" in captured.err


def test_patch_replaces_mount_list_and_tells_user_to_edit_placeholders(tmp_path):
    original = compliant(volumes=[{"type": "bind", "source": "/etc", "target": "/e"}])
    fixed = autofix.fix_config(original, policy.Context(str(tmp_path), UID, GID))

    text = patch.render(original, fixed)

    assert '    volumes: !override [{"type": "bind", "source": "./ETC", "target": "/e"}]' in text
    assert "# edit: service web: mount source /etc was replaced by the placeholder ./ETC" in text
