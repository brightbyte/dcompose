from fakes import rules

from dockscreen import policy, runpolicy

HARDENED = {"CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"]}


def container(user="", **host):
    return {"Config": {"User": user}, "HostConfig": {**HARDENED, **host}}


def findings(info, explicit_user=False):
    return runpolicy.findings(info, explicit_user, policy.Context("/work", rules()))


def test_a_hardened_container_with_nothing_else_has_no_findings():
    assert findings(container(NetworkMode="default", IpcMode="private", Runtime="runc")) == []


def test_bind_mounts_from_v_and_mount_are_judged_once_each():
    info = container(Binds=["/etc:/etc:ro", "/work/src:/src", "data:/data"],
                     Mounts=[{"Type": "bind", "Source": "/srv", "Target": "/srv"}])
    info["Mounts"] = [{"Type": "bind", "Source": "/etc", "Destination": "/etc"},
                      {"Type": "volume", "Source": "/var/lib/docker/volumes/data/_data",
                       "Destination": "/data"}]

    assert findings(info) == ["bind mount '/etc' is outside /work", "bind mount '/srv' is outside /work"]


def test_volumes_from_and_devices_are_found():
    info = container(VolumesFrom=["db"], Devices=[{"PathOnHost": "/dev/kvm"}])
    assert findings(info) == ["devices is not allowed", "volumes_from 'container:db' reaches a container "
                                                        "outside the project"]


def test_a_user_is_judged_only_when_the_command_line_chose_it():
    assert findings(container(user="0:0")) == []  # the image's: run decides that one, not this
    assert findings(container(user="0:0"), explicit_user=True) == ["user '0:0': uid 0 is root",
                                                                   "user '0:0': gid 0 is root"]
