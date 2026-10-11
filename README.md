# dcompose

Drop-in wrapper for `docker compose`. Unknown arguments are forwarded untouched
(via `exec`, so tty, signals and exit codes behave as with the real thing);
custom subcommands in `src/dcompose/commands.py` take precedence.

    pip install -e '.[dev]'
    dcompose up -d
    pytest

Only the subcommand position is parsed (`cli.find_subcommand`). If docker
compose adds a global option that takes a value, add it to
`GLOBAL_OPTS_WITH_VALUE`.

## Users, mounts and defaults

`up`, `create`, `run`, `watch`, `scale` and `alpha` are refused unless every
service runs as an allowed user and mounts only from the project directory or
`DCOMPOSE_DIRS`. `build` and `bake` get only the build checks: no SSH agent
forwarding, no host or privileged build, no cache or output destinations, no
`x-bake`, and build contexts and secret files inside the project.

dcompose adds `cap_drop: [ALL]` and `no-new-privileges:true` to every service
that lacks them, so a project does not have to set them. It cannot weaken
them: `cap_add` and `no-new-privileges:false` are still refused. To make the
added keys the checked ones, dcompose runs compose from the resolved config
(`docker compose config`) instead of the project's files: the config is
hardened, checked, written to a private temporary file and passed to compose
as its only file, with the project directory and name pinned. What was checked
is exactly what runs. Compose shows that temporary file as its config file, and
runs as a child process so the file can be removed afterwards.

An explicit `user:` in a compose file must be numeric and your own id (or
`DCOMPOSE_UID`) or nobody: the project is hostile. The names `nobody` and `root`
(and `nogroup`) are resolved to ids by dcompose first, in the file it runs; any
other name is refused, because the image would resolve it. A service that sets no user
is decided from its image, as `docker run` does (see below):

1. Its image is acquired first, as `up` would: pulled by the service's
   `pull_policy` (`always` and the periodic policies each time, `missing` only
   when absent, `never` not at all; `--pull` overrides), or built if it has a
   `build:` section and the image is missing, `--build` is given or the policy is
   `build`. Automatic updates keep happening.
2. Then the same rule as `docker run` (see below) decides, using what the
   service mounts: bind mounts, secrets and configs (which are bind-mounted
   files), devices, or `volumes_from`. Named volumes and tmpfs do not count. A
   root image, or any image at all if the service has such mounts, runs as
   nobody (`65534:65534`), and the notice says which ids the image would have
   used. To run the image's own user anyway, set `user:
   "${DCOMPOSE_UID}:${DCOMPOSE_GID}"` and run with `DCOMPOSE_UID` and
   `DCOMPOSE_GID` set to those ids: an explicit user in a compose file must be
   your own id, `DCOMPOSE_UID`, or nobody. Without mounts, the image's own
   non-root user is left alone, unless this host has an account with that id
   (the container would share that account's kernel limits): then the run is
   refused and you set `user:`.
3. In the generated file only, the services that were looked at get
   `pull_policy: never`, so compose runs the image that was checked and not one
   pulled in between. This is never written to the project's files or to
   `harden` output: it would switch off the project's updates.

A service that is not started by the command and sets no user is run as nobody
if it does get started: a mistake in working out what starts must fail safe.
Pulling and building happen after the static checks (including the build
checks), so a project that fails them is neither pulled nor built.

dcompose exports, for use in compose files:

- `UID`, `GID`: the real current user (always).
- `DCOMPOSE_UID`, `DCOMPOSE_GID`: the id containers must run as. Defaults to
  the real ids; if set beforehand, only that id is accepted and the real user
  is refused (`nobody`, 65534, is always accepted).

Extra subcommands:

- `audit` runs the checks alone, after the same pulling and building as `up`
  (none if the static checks already fail). It lists, per service, the keys that
  would be added and how, and what happens to services without `user:`.
- `harden` (also `fix`) prints a compose override file with what is needed on
  top of the defaults above to pass the audit: user, privileges, mounts outside
  the project turned into placeholders to edit, and a user for services whose
  image chose one that is not acceptable. The defaults themselves are not
  repeated, only mentioned in one comment. What it could not fix is listed as
  comments. It pulls and builds first, like `audit`.

`--skip-security-gate`, as a global option before the subcommand, turns every
check and default off, for `dcompose` and `docker` alike. A warning is printed
every time. After the subcommand it is not recognised, so docker rejects it.

## Threat model

dcompose protects you from a malicious compose project: its compose files,
`.env`, env files, images and anything it includes or extends. Your command
line and your shell environment are trusted; someone who controls them could
call `docker compose` directly.

Consequences:

- The policy is an allowlist (`src/dcompose/policy.py`). A compose key that is
  not listed is refused, so new Compose features stay denied until reviewed.
  If a legitimate key is refused, check that it is inert and add it to the
  matching list.
- Settings that widen the policy (`DCOMPOSE_DIRS`, `DCOMPOSE_UID`,
  `DCOMPOSE_GID`) are read from dcompose's own environment, never from the
  project's `.env`.
- Text from the project is escaped before it is printed or written into a
  `harden` patch.

Not covered: command-line overrides such as `run -v` or `exec --privileged`,
network exposure (`ports`, `extra_hosts`), and `${VAR}` interpolation, which
can copy variables from your shell into a container.

## Wrapping `docker`

`bin/docker` (or the `ddocker` script) goes in front of the real docker on your
`PATH`. `docker compose` goes to dcompose, `run`, `start` and `restart` (also as
`docker container ...`) go through a gate, `create` gets hardening defaults,
`docker audit IMAGE` predicts what `run` would do, and everything else is
exec'd to the real docker unchanged. The real docker is the next `docker` on
`PATH` that is not the wrapper, or `DCOMPOSE_DOCKER`.

Here the threat is the image, not the command line: you are trusted, the image
is not. `docker run` is run as `create`, `inspect`, check, `start`, so the daemon
parses the command line and the check looks at the container that will run.

The identity the container would run as is resolved through the image's own
`/etc/passwd` and `/etc/group`. Then, if you did not choose a user:

- **Root** (uid or gid 0, also as a supplementary group), for example an image
  that sets no `USER`: the container is run as nobody (`65534:65534`) instead,
  with a notice. Images that start as root and drop privileges themselves
  (postgres, mariadb, redis) will usually fail on their data directories; pass
  `--user` for those.
- **A container that reaches host files**: with bind mounts, devices or
  `--volumes-from`, a user must be chosen explicitly, because what the container
  may read and write on the host depends on its uid and gid. Without one it is
  run as nobody, and the notice echoes the ids the image would have used, so
  that you know what to pass: `To run it as the image's user, pass --user
  999:999`. Named volumes and tmpfs are not host files.
- **No such mounts**: the image's own non-root user is kept, whatever its id,
  unless this host has an account with that id: then it would share that
  account's kernel limits (processes, inotify watches), and the container is
  refused, with the local user named. Cgroups bound a container's share of these
  limits, they do not separate them.
- You choose the user with one of these, and the check is skipped. They are
  only recognised before the image name; after it they belong to the command.
  - `--user ID` (or `-u`) takes a numeric `uid` or `uid:gid` and nothing else.
    Docker would resolve a name inside the image, where a hostile image can map
    it to root, so a name is refused with a pointer to `--as`.
  - `--as NAME` takes a local user name, resolved on this host to that
    account's `uid:gid`, with a message such as `Resolving user alice to uid
    1000, gid 1000`. Docker never sees the name.
  - `--as-me` stands for your own `uid:gid`.

  `--user 0` against an image that already says `root` looks like the image's
  choice and falls back; write `--user 0:0`.
- `--cap-drop=ALL --security-opt=no-new-privileges:true` are put before your
  arguments, so anything you pass after them overrides them.
- `start` and `restart` apply the same check to existing containers, which
  cannot be rewritten, so a root one is refused.
- Remote daemons (`-H`, `--context`, `DOCKER_HOST`, a non-default context) are
  refused: host ids and paths mean nothing there.

`docker audit [--user ID | --as NAME | --as-me] IMAGE` creates a container without
starting it and without pulling anything, reads the image's user files, and
reports, without and with bind mounts or devices, one of: accepted, would run as
nobody (with the `--user` to pass for the image's own user), or would be refused
(exit 1). It
says which local user or group each id of the image would be on this host (for
example `uid 1000 (local user daniel)`), also when it refuses. The image must be
local; `docker pull` does not run it.

`--skip-security-gate` before the subcommand makes `docker` plain docker again,
with a warning.

Only a wrapper in front of the real docker: scripts, IDEs and anything talking
to the socket directly bypass it.
