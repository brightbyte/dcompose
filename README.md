# dockscreen

A drop-in for `docker`. `dockscreen compose` refuses compose projects that would reach outside the project directory or run with privileges, and `dockscreen run` refuses images that would. It also adds `cap_drop: [ALL]` and `no-new-privileges` to what it lets through. Everything else goes to the real docker unchanged.

It protects you from what you download, the compose project and its images. It does not protect you from your own command line. For how it works and why, see [docs/design.md](docs/design.md).

    pip install -e '.[dev]'
    dockscreen compose up -d
    pytest

## What gets refused

For `dockscreen compose`: `up`, `create`, `run`, `watch`, `scale` and `alpha` refuse a project that:

- mounts or reads files outside the project directory, or outside the configured `mount_dirs`;
- runs as a user the project may not choose (see [Users](#users));
- asks for privileges: `privileged`, `cap_add`, devices, host namespaces;
- uses volumes or networks that are external or belong to another project;
- uses a compose key that dockscreen doesn't know yet. The policy is an allowlist.

`build` and `bake` only check what building can reach: no SSH agent, no host network or privileged builds, and contexts and secrets inside the project.

When refusing, dockscreen says why. `dockscreen compose harden` prints a compose override file that fixes what can be fixed.

## Users

Containers don't run as root or as you unless you say so.

- An image that would run as root runs as nobody (the configured `default_user`) instead, with a notice.
- A project or an image may not pick root, an id of a local account, an id from `/etc/subuid` or `/etc/subgid`, or 65535 and 4294967295. That applies to the uid, the gid and supplementary groups.
- With host mounts (bind mounts, devices, `volumes_from`, secrets, configs), the id must be in the nobody range (65530–65534 unless configured), the default user, a user configured for the image, or you with `--allow-me`.
- To run services as yourself: `dockscreen --allow-me compose up`, with `user: "${UID}:${GID}"` on those services. dockscreen sets `UID` and `GID` to your real ids.
- To give an image a user of its own, such as mariadb's 999, set it in `[image_users]` in the config file.
- Names in `user:` and `--as` are resolved on this host, not in the image. A name unknown here is refused, and so is a uid without a group.

The full rules are in [docs/design.md](docs/design.md#users-and-groups).

## Services without `user:`

Before starting anything, dockscreen pulls or builds each image as `up` would, and decides its user as described under [Users](#users).

An accepted image user is passed on as numbers (`user: "uid:gid"`, `docker run --user uid:gid`), never as the image's name for it. The runtime then reads nothing from the image's `/etc/passwd` or `/etc/group`, so a difference between how dockscreen and docker parse those files cannot give the container another identity. The price: the image's supplementary groups are not applied.

A service whose image was looked at also gets `pull_policy: never` and, unless it is built from a Dockerfile, `image:` set to the checked image's id, in the generated file only. Something else retagging the image between the check and the run cannot change what starts. `docker compose ps` therefore shows the id instead of the name.

Compose interpolates the files it reads, so the generated file is written as `docker compose config` printed it (a literal `$` is `$$`, which reads back as a literal `$`). Before anything is pulled or built, dockscreen asks compose for the config of that file and refuses unless it equals the config that was checked.

## Variables from your shell

`environment: [FOO]` takes FOO from your shell. dockscreen does not refuse it, but `audit` and every run that starts containers say which services get which variables (names only, never values). The resolved config does not record where a value came from, so a pass-through is recognised by the value being your shell's own under the same name: `X: ${FOO}` is not noticed, and `FOO: bar` is reported if your shell has `FOO=bar`. `UID` and `GID` are left out.

## Commands

| Command | |
|---|---|
| `dockscreen compose audit` | run the checks and report, without starting anything (it pulls and builds) |
| `dockscreen compose harden` (also `fix`) | print a compose override that fixes what can be fixed; the rest is listed as comments |
| `dockscreen compose doctor` | show the compose version in use |
| `dockscreen audit IMAGE` | say what `dockscreen run` would do with a local image (see [Images](#images)) |

## Configuration

dockscreen reads `/etc/dockscreen/config.toml` and then `~/.config/dockscreen/config.toml` (or `$XDG_CONFIG_HOME/dockscreen/config.toml`), which overrides it key by key. If your file doesn't exist, dockscreen creates it with every setting commented out, showing the defaults. Environment variables and the project's `.env` do not configure it. Whatever the files say is trusted, so they are only read if the file and every directory above it are owned by you or root and writable by nobody else; otherwise dockscreen refuses to run. Unknown keys are an error.

```toml
default_user = "65534:65534"       # replaces an image's root user
nobody_range = [65530, 65534]      # ids any project or image may use, mounts or not
mount_dirs = ["/srv/shared-data"]  # where bind mounts may come from, besides the project
docker = "/usr/bin/docker"         # the real docker, if not the next one on PATH

[image_users]                      # a user for every image pulled from a repository
"mariadb" = "999:999"
```

An `image_users` entry names a repository, without tag: it trusts the image's maintainer. It applies only to an image that docker records as pulled from that repository, and never to a service that builds its image, because anything can be tagged locally under any name.

A `mount_dirs` entry that contains your home directory, a system directory, the config file or the docker socket gets a warning on every run. A project directory that contains one of them is refused, and the search for a compose file stops at your home directory and at the first directory that is not yours.

## Options

Before the subcommand, such as `dockscreen --allow-me compose up` or `dockscreen --allow-me run IMAGE`:

| Option | |
|---|---|
| `--allow-me` | containers may run as you: in `user:`, and as an image's own user |
| `--skip-screening` | turns off all checks and defaults, and prints a warning each time |

After `run` or `exec` (compose or docker, and `create` and `audit`), before the service, image or container:

| Option | |
|---|---|
| `--user UID:GID` / `-u UID:GID` | numeric ids only |
| `--as NAME` | a local user, resolved on this host |
| `--as-me` | yourself; for `run` and `audit` (not compose), also `--allow-me` |

`up` takes none of these; `--as-me` before the subcommand is refused.

## Images

- `dockscreen run` checks the image's user like this:
  - the container is created, checked, then started;
  - an image that would run as root runs as the default user unless you choose a user;
  - an image user that the [rules](#users) refuse, with the container's mounts, is refused;
  - a user the config file sets for the image's repository is used, as for compose;
  - an accepted image user is passed to docker as `--user uid:gid` (the container is created a second time with it).
- `start` and `restart` refuse existing containers that would fail that check.
- `create` gets the hardening defaults.
- Remote daemons are refused, here and for `dockscreen compose`.

Choosing a user (see [Options](#options)) skips the image check. `--allow-me` also works before the image name.

`dockscreen audit [--allow-me] [--user UID:GID | --as NAME | --as-me] IMAGE` says what `dockscreen run` would do with a local image, without and with mounts, without starting it.

Images that start as root and drop privileges themselves, such as postgres or redis, usually need `--user`, `user:` or an `image_users` entry.

## Wrapping `docker`

To screen every `docker` command you type, put `bin/docker`, or a symlink named `docker` to `dockscreen`, ahead of the real docker on your `PATH`. dockscreen skips itself when it looks for the real docker.

Only commands that go through the wrapper are checked. Scripts, IDEs and anything else that talks to the docker socket directly bypass it.
