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
`DCOMPOSE_UID`) or nobody: the project is hostile. A service that sets no user
is decided from its image, as `docker run` does (see below):

1. Its image is acquired first, as `up` would: pulled by the service's
   `pull_policy` (`always` and the periodic policies each time, `missing` only
   when absent, `never` not at all; `--pull` overrides), or built if it has a
   `build:` section and the image is missing, `--build` is given or the policy is
   `build`. Automatic updates keep happening.
2. If the image would run as root, the service runs as nobody (`65534:65534`)
   with a notice. If it has an acceptable user of its own (see the id range
   below) it is left alone. If it chose some other user itself, the run is
   refused: set `user:`.
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
`/etc/passwd` and `/etc/group`. Then:

- Root (uid or gid 0, also as a supplementary group), for example an image
  that sets no `USER`: the container is run as nobody (`65534:65534`) instead,
  with a notice. Images that start as root and drop privileges themselves
  (postgres, mariadb, redis) will usually fail on their data directories; pass
  `--user` for those.
- An image that chose its own non-root user outside the allowed range, or one
  that exists on this host: refused. Overriding a deliberate choice silently
  would only break it in a more confusing way. The range is
  `65532-2147483647` (65532 admits distroless and Chainguard images); set
  `DCOMPOSE_ID_RANGE=low-high` to change it. 65534 (nobody) is always accepted.
- `--user USER` skips the check: you chose. `--user me` and `--current-user`
  stand for your own `uid:gid` (only before the image name; after it they
  belong to the command). `--user root` against an image that already says
  `root` looks like the image's choice and falls back; write `0:0`.
- `--cap-drop=ALL --security-opt=no-new-privileges:true` are put before your
  arguments, so anything you pass after them overrides them.
- `start` and `restart` apply the same check to existing containers, which
  cannot be rewritten, so a root one is refused.
- Remote daemons (`-H`, `--context`, `DOCKER_HOST`, a non-default context) are
  refused: host ids and paths mean nothing there.

`docker audit [--user USER | --current-user] IMAGE` creates a container without
starting it and without pulling anything, reads the image's user files, and
reports one of: accepted, would run as nobody, or would be refused (exit 1). The
image must be local; `docker pull` does not run it.

`--skip-security-gate` before the subcommand makes `docker` plain docker again,
with a warning.

Only a wrapper in front of the real docker: scripts, IDEs and anything talking
to the socket directly bypass it.
