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

## Users and mounts

`up`, `create`, `run`, `watch`, `scale` and `alpha` are refused unless every
service runs as an allowed user and mounts only from the project directory or
`DCOMPOSE_DIRS`. `build` and `bake` get only the build checks: no SSH agent
forwarding, no host or privileged build, no cache or output destinations, no
`x-bake`, and build contexts and secret files inside the project.

dcompose exports, for use in compose files:

- `UID`, `GID`: the real current user (always).
- `DCOMPOSE_UID`, `DCOMPOSE_GID`: the id containers must run as. Defaults to
  the real ids; if set beforehand, only that id is accepted and the real user
  is refused (`nobody`, 65534, is always accepted).

`dcompose audit` runs the checks alone; `dcompose fix` prints a compose
override that repairs what it can.

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
  `fix` patch.

Not covered: command-line overrides such as `run -v` or `exec --privileged`,
network exposure (`ports`, `extra_hosts`), and `${VAR}` interpolation, which
can copy variables from your shell into a container.
