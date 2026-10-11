# dcompose

A drop-in for `docker compose`, and optionally for `docker`. It refuses compose projects and images that would reach outside the project directory or run with privileges. It also adds `cap_drop: [ALL]` and `no-new-privileges` to what it lets through. Everything else goes to the real docker unchanged.

It protects you from what you download, the compose project and its images. It does not protect you from your own command line. For how it works and why, see [docs/design.md](docs/design.md).

    pip install -e '.[dev]'
    dcompose up -d
    pytest

## What gets refused

`up`, `create`, `run`, `watch`, `scale` and `alpha` refuse a project that:

- mounts or reads files outside the project directory, or outside the directories in `DCOMPOSE_DIRS`;
- runs as a user other than you (or `DCOMPOSE_UID`/`DCOMPOSE_GID`) or nobody, or names the user instead of giving numeric ids;
- asks for privileges: `privileged`, `cap_add`, devices, host namespaces;
- uses volumes or networks that are external or belong to another project;
- uses a compose key that dcompose doesn't know yet. The policy is an allowlist.

`build` and `bake` only check what building can reach: no SSH agent, no host network or privileged builds, and contexts and secrets inside the project.

When refusing, dcompose says why. `dcompose harden` prints a compose override file that fixes what can be fixed.

## Services without `user:`

Before starting anything, dcompose pulls or builds each image as `up` would, and looks at the user the image would run as:

- If the image would run as root, or the service mounts host files: the service runs as nobody (65534:65534), and a notice says which ids the image wanted.
- Otherwise the image's own user is kept, unless that id belongs to an account on this host: then the run is refused.

An accepted image user is passed on as numbers (`user: "uid:gid"`, `docker run --user uid:gid`), never as the image's name for it. The runtime then reads nothing from the image's `/etc/passwd` or `/etc/group`, so a difference between how dcompose and docker parse those files cannot give the container another identity. The price: the image's supplementary groups are not applied.

Compose interpolates the files it reads, so the generated file is written as `docker compose config` printed it (a literal `$` is `$$`, which reads back as a literal `$`). Before anything is pulled or built, dcompose asks compose for the config of that file and refuses unless it equals the config that was checked.

To run as the image's user with mounts, set `user: "${DCOMPOSE_UID}:${DCOMPOSE_GID}"` and set `DCOMPOSE_UID` and `DCOMPOSE_GID` to the image's ids.

## Variables from your shell

`environment: [FOO]` takes FOO from your shell. dcompose does not refuse it, but `audit` and every run that starts containers say which services get which variables (names only, never values). The resolved config does not record where a value came from, so a pass-through is recognised by the value being your shell's own under the same name: `X: ${FOO}` is not noticed, and `FOO: bar` is reported if your shell has `FOO=bar`. `UID`, `GID` and `DCOMPOSE_*` are left out.

## Commands

| Command | |
|---|---|
| `dcompose audit` | run the checks and report, without starting anything (it pulls and builds) |
| `dcompose harden` (also `fix`) | print a compose override that fixes what can be fixed; the rest is listed as comments |
| `dcompose doctor` | show the compose version in use |

## Settings

Read from your environment, never from the project's `.env`:

| Variable | |
|---|---|
| `DCOMPOSE_UID`, `DCOMPOSE_GID` | the ids containers may run as, besides nobody; your own by default |
| `DCOMPOSE_DIRS` | extra directories mounts may come from, separated by `:` |
| `DCOMPOSE_DOCKER` | the real docker binary, if it is not the next one on `PATH` |

dcompose exports `UID`, `GID`, `DCOMPOSE_UID` and `DCOMPOSE_GID`, for compose files to use.

`--skip-security-gate`, before the subcommand, turns off all checks and defaults, and prints a warning each time.

## Wrapping `docker`

Put `bin/docker` (or the installed `ddocker`) ahead of the real docker on your `PATH`.

- `docker compose` goes to dcompose.
- `docker run` checks the image's user like this:
  - the container is created, checked, then started;
  - an image that would run as root, or a container with bind mounts or devices, runs as nobody unless you choose a user;
  - an image whose user is an account on this host is refused;
  - an accepted image user is passed to docker as `--user uid:gid` (the container is created a second time with it).
- `start` and `restart` refuse existing containers that would fail that check.
- `create` gets the hardening defaults.
- Remote daemons are refused.

Choosing a user skips the image check. These options go before the image name:

| Option | |
|---|---|
| `--user UID:GID` / `-u UID:GID` | numeric `uid:gid` only (a uid alone would leave the group to the image) |
| `--as NAME` | a local user, resolved on this host |
| `--as-me` | yourself |

`docker audit [--user UID:GID | --as NAME | --as-me] IMAGE` says what `docker run` would do with a local image, without starting it.

Images that start as root and drop privileges themselves, such as postgres or redis, usually need `--user` or `user:`.

Only commands that go through the wrapper are checked. Scripts, IDEs and anything else that talks to the docker socket directly bypass it.
