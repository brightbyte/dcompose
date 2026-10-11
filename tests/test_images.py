import pytest

from dockscreen import config, images


@pytest.mark.parametrize("reference, split", [
    ("mariadb", ("docker.io/library/mariadb", "", "")),
    ("mariadb:11", ("docker.io/library/mariadb", "11", "")),
    ("library/mariadb", ("docker.io/library/mariadb", "", "")),
    ("docker.io/mariadb", ("docker.io/library/mariadb", "", "")),
    ("index.docker.io/library/mariadb:11", ("docker.io/library/mariadb", "11", "")),
    ("someone/mariadb", ("docker.io/someone/mariadb", "", "")),
    ("ghcr.io/acme/app:1.2", ("ghcr.io/acme/app", "1.2", "")),
    ("localhost/app", ("localhost/app", "", "")),
    ("registry:5000/team/app:tag", ("registry:5000/team/app", "tag", "")),
    ("mariadb@sha256:abc", ("docker.io/library/mariadb", "", "sha256:abc")),
    ("mariadb:11@sha256:abc", ("docker.io/library/mariadb", "11", "sha256:abc")),
])
def test_references_are_normalised_as_docker_does(reference, split):
    assert images.split_reference(reference) == split


@pytest.mark.parametrize("reference", ["", "Mariadb", "a b", "x/", "-x"])
def test_what_is_not_a_reference_is_an_error(reference):
    with pytest.raises(ValueError):
        images.split_reference(reference)
    assert images.repository(reference) is None


SETTINGS = config.Config(image_users={"docker.io/library/mariadb": (999, 999)})


def test_an_image_pulled_from_the_configured_repository_gets_its_user():
    match = images.configured_user(SETTINGS, "mariadb:11", ["mariadb@sha256:abc"], built=False)
    assert match == images.Match((999, 999), None)
    # the digest may be recorded under any spelling of the repository
    match = images.configured_user(SETTINGS, "docker.io/library/mariadb",
                                   ["docker.io/library/mariadb@sha256:a"], built=False)
    assert match.user == (999, 999)


@pytest.mark.parametrize("reference, digests, built, problem", [
    ("mariadb:11", [], False, "this image was not pulled from there"),
    ("mariadb:11", ["evil.example/mariadb@sha256:abc"], False, "this image was not pulled from there"),
    ("mariadb:11", ["mariadb@sha256:abc"], True, "the service builds its image"),
])
def test_an_image_that_only_has_the_name_does_not_get_the_user(reference, digests, built, problem):
    match = images.configured_user(SETTINGS, reference, digests, built)
    assert match.user is None and match.problem.endswith(problem)


@pytest.mark.parametrize("reference", ["redis", "evil.example/mariadb", "someone/mariadb", "sha256:abc"])
def test_other_repositories_have_no_setting(reference):
    match = images.configured_user(SETTINGS, reference, ["x@sha256:a"], built=False)
    assert match == images.Match(None, None)
