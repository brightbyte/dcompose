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


SETTINGS = config.Config(images={"docker.io/library/mariadb": config.Section(user=(999, 999))})


def test_an_image_pulled_from_the_sections_repository_gets_the_section():
    match = images.section_for(SETTINGS, "mariadb:11", ["mariadb@sha256:abc"], built=False)
    assert match == images.Match("docker.io/library/mariadb", None)
    # the digest may be recorded under any spelling of the repository
    match = images.section_for(SETTINGS, "docker.io/library/mariadb",
                               ["docker.io/library/mariadb@sha256:a"], built=False)
    assert match.repository == "docker.io/library/mariadb"


@pytest.mark.parametrize("reference, digests, built, problem", [
    ("mariadb:11", [], False, "this image was not pulled from there"),
    ("mariadb:11", ["evil.example/mariadb@sha256:abc"], False, "this image was not pulled from there"),
    ("mariadb:11", ["mariadb@sha256:abc"], True, "the service builds its image"),
])
def test_an_image_that_only_has_the_name_does_not_get_the_section(reference, digests, built, problem):
    match = images.section_for(SETTINGS, reference, digests, built)
    assert match.repository is None and match.problem.endswith(problem)
    # before the image is there, the name alone points to the section, unless the service builds it
    assert images.name_matches(SETTINGS, reference, built) == (None if built else "docker.io/library/mariadb")


@pytest.mark.parametrize("reference", ["redis", "evil.example/mariadb", "someone/mariadb", "sha256:abc"])
def test_other_repositories_have_no_section(reference):
    match = images.section_for(SETTINGS, reference, ["x@sha256:a"], built=False)
    assert match == images.Match(None, None)


@pytest.mark.parametrize("repository, shown", [
    ("docker.io/library/mariadb", "mariadb"), ("docker.io/bitnami/redis", "bitnami/redis"),
    ("ghcr.io/acme/app", "ghcr.io/acme/app"),
])
def test_shown(repository, shown):
    assert images.shown(repository) == shown
