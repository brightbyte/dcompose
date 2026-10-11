import copy
import subprocess

import pytest
from fakes import FakeImages, make_tools, rules

from dockscreen import autofix, composeimages, gate, policy
from dockscreen import config as configuration
from dockscreen.dockerclient import DockerError
from dockscreen.gate import Kind

NOBODY = "65534:65534"
COMMAND = ["docker", "compose", "-f", "/gen/compose-0.yaml"]  # what prepare is given; only the tail matters


def project(**services):
    """A config whose services set no user unless told to."""
    return {"name": "proj", "services": {
        name: {"image": f"{name}:1", **fields} for name, fields in (services or {"web": {}}).items()}}


def prepare(config, images, args=(), active=("web",), codes=None, settings=None, chosen=frozenset()):
    gate_ctx = gate_context(images, settings)
    tools, recorder = make_tools(images, active=active, codes=codes, reads=lambda _: config,
                                 gate_ctx=gate_ctx)
    return composeimages.prepare(COMMAND, config, list(args), tools, chosen), recorder, images


def gate_context(images, settings=None):
    settings = settings or configuration.Config()
    return gate.Context(images, rules(settings=settings), settings)


def subcommands(recorder):
    return [cmd[len(COMMAND):] for cmd in recorder.children]


# --- which services, and acquiring their images ---------------------------------

def test_services_to_run_are_the_active_ones_plus_those_named():
    config = project(web={}, db={}, debug={})
    tools, recorder = make_tools(active=("web", "db"))
    assert composeimages.services_to_run(COMMAND, config, ["-d", "debug", "--", "nope"], tools) == {
        "web", "db", "debug"}
    assert recorder.captured == [[*COMMAND, "config", "--services"]]


@pytest.mark.parametrize("policy_, present, pulled", [
    (None, False, True),          # the default is missing: pulled when absent
    (None, True, False),          # ... and left alone when there
    ("missing", False, True),
    ("if_not_present", True, False),
    ("always", True, True),       # updates keep happening
    ("daily", True, True),        # periodic policies: pulled every run, never stale
    ("weekly", True, True),
    ("every_12h", True, True),
    ("never", False, False),
])
def test_images_are_pulled_by_the_projects_pull_policy(policy_, present, pulled):
    fields = {"pull_policy": policy_} if policy_ else {}
    images = FakeImages(users={"web:1": "app"}, local={"web:1"} if present else set())

    prepared, recorder, _ = prepare(project(web=fields), images)

    assert subcommands(recorder) == ([["pull", "web"]] if pulled else [])
    assert prepared.to_run == {"web"}


def test_the_command_line_pull_policy_overrides_the_projects():
    images = FakeImages(users={"web:1": "app"})
    _, recorder, _ = prepare(project(web={"pull_policy": "never"}), images, ["--pull", "always"])
    assert subcommands(recorder) == [["pull", "web"]]
    _, recorder, _ = prepare(project(web={"pull_policy": "always"}), images, ["--pull=never"])
    assert subcommands(recorder) == []


@pytest.mark.parametrize("fields, args, present, built", [
    ({}, [], False, True),                          # not there: built, as up would
    ({}, [], True, False),                          # there: used
    ({}, ["--build"], True, True),                  # up --build
    ({"pull_policy": "build"}, [], True, True),     # policy build: always rebuilt
    ({}, ["--no-build"], False, False),
])
def test_built_images_are_built_when_up_would_build_them(fields, args, present, built):
    config = project(web={"build": {"context": "/p"}, **fields})
    config["services"]["web"].pop("image")
    images = FakeImages(users={"proj-web": "app"}, local={"proj-web"} if present else set())

    _, recorder, _ = prepare(config, images, args)

    assert subcommands(recorder) == ([["build", "web"]] if built else [])


def test_pulling_before_building_and_failure_stops_everything():
    config = project(web={}, app={"build": {"context": "/p"}})
    config["services"]["app"].pop("image")
    images = FakeImages(users={"web:1": "app", "proj-app": "app"}, local=set())
    _, recorder, _ = prepare(config, images, active=("web", "app"))
    assert subcommands(recorder) == [["pull", "web"], ["build", "app"]]

    prepared, recorder, images = prepare(config, FakeImages(users={}, local=set()), active=("web", "app"),
                                         codes={"pull": 1})
    assert prepared.problems == ["docker compose pull web failed"]
    assert prepared.decisions == {} and subcommands(recorder) == [["pull", "web"]]  # build never started
    assert images.calls == []  # and nothing was created


def test_listing_the_services_can_fail_closed():
    config = project()
    tools, _ = make_tools(reads=lambda _: config)
    capture = tools.capture

    def failing_listing(cmd):
        if "--services" in cmd:
            return subprocess.CompletedProcess(cmd, 1, "", "boom")
        return capture(cmd)

    prepared = composeimages.prepare(COMMAND, config, [], tools._replace(capture=failing_listing))
    assert prepared.problems == ["docker compose config --services failed"]


# --- compose must read back what was checked ----------------------------------------

def test_a_config_that_compose_reads_differently_is_refused_before_anything_is_pulled():
    config = project(web={"pid": "${P:-host}"})
    images = FakeImages(users={"web:1": "app"})

    interpolated = {**config, "services": {"web": {**config["services"]["web"], "pid": "host"}}}
    tools, recorder = make_tools(images, reads=lambda _: interpolated)
    prepared = composeimages.prepare(COMMAND, config, [], tools)

    assert prepared.problems == [
        "docker compose reads the checked config differently at config.services.web.pid; not running it"]
    assert recorder.children == [] and images.created == []


def test_a_config_that_cannot_be_read_back_is_refused():
    tools, _ = make_tools()
    tools = tools._replace(capture=lambda cmd: subprocess.CompletedProcess(cmd, 1, "", "boom"))
    prepared = composeimages.prepare(COMMAND, project(), [], tools)
    assert prepared.problems == ["docker compose could not read back the config that was checked"]


@pytest.mark.parametrize("expected, actual, where", [
    ({"a": [1, {"b": 2}]}, {"a": [1, {"b": 3}]}, "config.a[1].b"),
    ({"a": 1}, {"a": 1, "b": 2}, "config.b"),
    ({"a": [1]}, {"a": [1, 2]}, "config.a"),
    ({"a": 1}, {"a": True}, "config.a"),
    ({"a": [1, "x"]}, {"a": [1, "x"]}, None),
])
def test_first_difference_names_the_path(expected, actual, where):
    assert composeimages.first_difference(expected, actual) == where


# --- deciding about the images ---------------------------------------------------

@pytest.mark.parametrize("image_user, kind", [
    ("app", Kind.OK),          # 100000:100001, high and unknown to the host
    ("", Kind.FALLBACK),       # no USER: root
    ("root", Kind.FALLBACK),
    ("0:0", Kind.FALLBACK),
    ("web", Kind.REFUSED),     # 1000: low, and the host has it
    ("ghost", Kind.REFUSED),   # not defined in the image
])
def test_the_images_own_user_is_judged_as_docker_run_does(image_user, kind):
    prepared, _, images = prepare(project(), FakeImages(users={"web:1": image_user}))

    assessment = prepared.decisions["web"].assessment
    assert assessment.kind is kind
    assert (prepared.problems != []) == (kind is Kind.REFUSED)
    assert [call for call in images.calls if call[0] == "remove"] == [("remove", "c1")]  # nothing is left


def test_refusals_say_what_to_do():
    prepared, _, _ = prepare(project(), FakeImages(users={"web:1": "web"}))
    assert len(prepared.problems) == 1  # one line per service, however many ids are the problem
    assert "service web: image web:1: the image's uid 1000 exists on this host" in prepared.problems[0]
    assert "gid 1000" in prepared.problems[0]
    assert prepared.problems[0].endswith("set user: to choose one")


def test_services_with_a_user_are_not_looked_at():
    images = FakeImages(users={"web:1": ""})
    prepared, _, _ = prepare(project(web={"user": "1:1"}), images)
    assert prepared.decisions == {} and images.created == []


def test_only_started_services_are_looked_at_and_the_platform_is_passed():
    config = project(web={"platform": "linux/arm64"}, debug={})
    images = FakeImages(users={"web:1": "app", "debug:1": ""})
    prepared, _, _ = prepare(config, images, active=("web",))
    assert set(prepared.decisions) == {"web"}
    assert images.created == [("web:1", ["--pull=never", "--platform", "linux/arm64", "--", "web:1"])]


def test_an_image_that_is_not_there_is_refused():
    prepared, _, _ = prepare(project(web={"pull_policy": "never"}), FakeImages(users={}, local=set()))
    assert prepared.problems == [
        "service web: image web:1: the image is not available locally; set user: to choose one"]


def test_inspection_errors_are_refusals_and_the_container_is_still_removed():
    images = FakeImages(users={"web:1": "app"})
    images.inspect_container = lambda ref: (_ for _ in ()).throw(DockerError("boom"))
    prepared, _, _ = prepare(project(), images)
    assert prepared.decisions["web"].assessment.problems == ["boom"]
    assert ("remove", "c1") in images.calls


# --- the config that runs ---------------------------------------------------------

def decided(config, images, active=("web",), settings=None, **kwargs):
    prepared, _, _ = prepare(config, images, active=active, settings=settings, **kwargs)
    return prepared, *composeimages.finalize(config, prepared, gate_context(images, settings))


def test_root_images_run_as_the_default_user_and_acceptable_ones_keep_their_own():
    config = project(web={}, db={}, user_set={"user": "7:7"})
    images = FakeImages(users={"web:1": "", "db:1": "app", "user_set:1": ""})

    _, final, vetted = decided(config, images, active=("web", "db", "user_set"))

    services = final["services"]
    assert services["web"]["user"] == NOBODY
    assert services["db"]["user"] == "100000:100001" and vetted == {"db"}  # pinned as numbers
    assert services["user_set"]["user"] == "7:7"


def test_looked_at_images_are_pinned_in_the_generated_config_only():
    config = project(web={}, db={}, other={"user": "7:7"})
    images = FakeImages(users={"web:1": "", "db:1": "app"})
    original = copy.deepcopy(config)

    _, final, _ = decided(config, images, active=("web", "db", "other"))

    assert final["services"]["web"]["pull_policy"] == "never"
    assert final["services"]["db"]["pull_policy"] == "never"
    assert "pull_policy" not in final["services"]["other"]  # not looked at: the project's policy stands
    assert config == original                                # the input is untouched


def test_a_service_that_is_not_started_runs_as_the_default_user_in_case_it_is():
    config = project(web={}, debug={})
    _, final, vetted = decided(config, FakeImages(users={"web:1": "app"}), active=("web",))
    assert final["services"]["debug"]["user"] == NOBODY
    assert "pull_policy" not in final["services"]["debug"]
    assert vetted == {"web"}


def test_the_final_config_passes_the_policy_with_exactly_the_vetted_services():
    config = project(web={}, db={}, debug={})
    for name in config["services"]:
        config["services"][name].update(cap_drop=["ALL"], security_opt=["no-new-privileges:true"])
    _, final, vetted = decided(config, FakeImages(users={"web:1": "", "db:1": "app"}),
                               active=("web", "db"))
    ctx = policy.Context("/p", rules())

    assert policy.check_config(final, ctx._replace(vetted=vetted)) == []
    # the vetting is what lets a configured user pass that the rules alone would refuse
    settings = configuration.Config(image_users={"docker.io/library/db": (1000, 1000)})
    images = FakeImages(users={"db:1": ""}, digests={"db:1": ["db@sha256:x"]})
    _, final, vetted = decided(config, images, active=("db",), settings=settings)
    assert final["services"]["db"]["user"] == "1000:1000" and "db" in vetted
    assert policy.check_config(final, ctx._replace(vetted=vetted)) == []
    assert [p for p in policy.check_config(final, ctx) if p.startswith("service db: user")] == [
        "service db: user '1000:1000': uid 1000 exists on this host (local user daniel)",
        "service db: user '1000:1000': gid 1000 exists on this host (local group daniel)"]


def test_descriptions_and_notices():
    config = project(web={}, db={}, debug={}, set_={"user": "1:1"})
    images = FakeImages(users={"web:1": "", "db:1": "app"})
    prepared, _, _ = prepare(config, images, active=("web", "db", "set_"))
    ctx = gate_context(images)

    assert composeimages.describe(config, prepared, ctx) == [
        ("service db: no user set; image db:1 runs as uid 100000 (no local user), gid 100001 "
         "(no local group); accepted"),
        ("service debug: no user set and not started by default; "
         "dockscreen runs it as the default user (65534:65534) if it is started"),
        ("service web: no user set; image web:1 would run as root; dockscreen runs it as the default user "
         "(65534:65534)"),
    ]
    assert composeimages.notices(prepared, ctx) == [
        "service web: image web:1 would run as root; dockscreen runs it as the default user (65534:65534)"]


def test_a_refusal_names_the_local_account_that_the_images_id_would_be():
    refused, _, _ = prepare(project(web={}), FakeImages(users={"web:1": "web"}))
    assert refused.problems == [
        ("service web: image web:1: the image's uid 1000 exists on this host (local user daniel); "
         "the image's gid 1000 exists on this host (local group daniel); set user: to choose one")]


# --- services with mounts ----------------------------------------------------------

BIND = {"volumes": [{"type": "bind", "source": "/p/data", "target": "/data"}]}


@pytest.mark.parametrize("fields, mounts", [
    ({}, False),
    (BIND, True),
    ({"volumes": [{"type": "volume", "source": "d", "target": "/d"}, {"type": "tmpfs", "target": "/t"}]},
     False),
    ({"secrets": [{"source": "s"}]}, True),
    ({"configs": [{"source": "c"}]}, True),
    ({"volumes_from": ["other"]}, True),
    ({"devices": ["/dev/dri:/dev/dri"]}, True),
    ({"volumes": ["/short/syntax:/not-normalized"]}, False),  # config output is always the long form
])
def test_which_services_reach_host_files(fields, mounts):
    assert policy.has_host_mounts(fields) is mounts


def test_with_mounts_an_image_user_outside_the_nobody_range_is_refused():
    prepared, _, _ = prepare(project(web=BIND), FakeImages(users={"web:1": "app"}))
    assert prepared.decisions["web"].assessment.kind is Kind.REFUSED
    assert "the image's uid 100000 is not in the nobody range 65530-65534" in prepared.problems[0]


def test_without_mounts_a_low_unknown_id_is_accepted_and_with_mounts_it_is_not():
    images = FakeImages(users={"web:1": "pg"})
    plain, _, _ = prepare(project(web={}), images)
    mounted, _, _ = prepare(project(web=BIND), images)
    assert plain.decisions["web"].assessment.kind is Kind.OK
    assert mounted.decisions["web"].assessment.kind is Kind.REFUSED


def test_with_mounts_a_root_image_still_runs_as_the_default_user():
    config = project(web=BIND)
    _, final, _ = decided(config, FakeImages(users={"web:1": ""}))
    assert final["services"]["web"]["user"] == NOBODY


# --- users the config file sets ----------------------------------------------------

MARIADB = configuration.Config(image_users={"docker.io/library/mariadb": (999, 999)})


def mariadb_project(**fields):
    return {"name": "proj", "services": {"db": {"image": "mariadb:11", **fields}}}


def test_a_configured_user_applies_to_an_image_pulled_from_that_repository():
    images = FakeImages(users={"mariadb:11": ""}, digests={"mariadb:11": ["mariadb@sha256:abc"]})
    prepared, final, vetted = decided(mariadb_project(**BIND), images, active=("db",), settings=MARIADB)

    assert prepared.decisions["db"].assessment.kind is Kind.CONFIGURED
    assert final["services"]["db"]["user"] == "999:999" and vetted == {"db"}
    assert composeimages.notices(prepared, gate_context(images, MARIADB)) == []  # configured: no notice
    assert composeimages.describe(mariadb_project(), prepared, gate_context(images, MARIADB)) == [
        "service db: no user set; image mariadb:11 runs as 999:999, the user the config file sets for it"]


@pytest.mark.parametrize("fields, digests, why", [
    ({}, [], "this image was not pulled from there"),                     # tagged locally
    ({}, ["evil.example/mariadb@sha256:abc"], "this image was not pulled from there"),
    ({"build": {"context": "."}}, ["mariadb@sha256:abc"], "the service builds its image"),
])
def test_a_configured_user_does_not_apply_to_an_image_that_only_has_the_name(fields, digests, why):
    images = FakeImages(users={"mariadb:11": ""}, digests={"mariadb:11": digests})
    config = mariadb_project(**fields)
    prepared, _, _ = prepare(config, images, active=("db",), settings=MARIADB)

    assessment = prepared.decisions["db"].assessment
    assert assessment.kind is Kind.FALLBACK  # the normal rules: root runs as the default user
    lines = composeimages.describe(config, prepared, gate_context(images, MARIADB))
    assert lines[-1] == f"service db: note: the config sets a user for docker.io/library/mariadb, but {why}"


def test_services_whose_user_the_command_line_chooses_are_not_decided():
    images = FakeImages(users={"web:1": "web"})  # would be refused
    prepared, _, _ = prepare(project(), images, chosen=frozenset({"web"}))
    assert prepared.problems == [] and prepared.decisions == {}


def test_the_vetting_belongs_to_dockscreen_not_to_the_project():
    # No key in a compose file can mark a service as vetted: it lives in the Context only.
    config = project(web={"x-vetted": True, "vetted": True})
    problems = policy.check_config(config, policy.Context("/p", rules()))
    assert "service web: key 'vetted' is not on the allow list" in problems
    assert "service web: user is not set, the image default may be root" in problems


def test_autofix_leaves_a_vetted_unset_user_alone_and_fixes_the_rest():
    config = project(web={}, db={})
    ctx = policy.Context("/p", rules(), vetted=frozenset({"web"}))
    fixed = autofix.fix_config(config, ctx)
    assert "user" not in fixed["services"]["web"]
    assert fixed["services"]["db"]["user"] == autofix.USER_TEMPLATE


def test_gate_assessment_is_what_decides():
    # the decision is gate.assess's: nothing here duplicates the rule
    assert composeimages.gate is gate


def test_an_image_name_that_looks_like_an_option_is_not_read_as_one():
    images = FakeImages(users={"-x": "app"})
    prepare(project(web={"image": "-x"}), images)
    assert images.created[0][1][-2:] == ["--", "-x"]


def test_a_looked_at_image_is_pinned_by_id_so_a_moved_tag_cannot_change_what_runs():
    config = project(web={}, db={}, other={"user": "7:7"}, built={"build": {"context": "."}})
    images = FakeImages(users={"web:1": "app", "db:1": "", "other:1": "app", "proj-built": "app"})
    original = copy.deepcopy(config)
    config["services"]["built"].pop("image")  # a built service has no image: compose names it itself

    _, final, _ = decided(config, images, active=("web", "db", "built"))

    services = final["services"]
    assert services["web"]["image"] == FakeImages.image_id("web:1")
    assert services["db"]["image"] == FakeImages.image_id("db:1")  # the fallback pins it too
    assert services["other"]["image"] == "other:1"                  # not looked at: the project's name
    assert "image" not in services["built"] and services["built"]["pull_policy"] == "never"
    assert original["services"]["web"]["image"] == "web:1"
