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

`up`, `create` and `run` are refused unless every service runs as an allowed
user and mounts only from the project directory or `DCOMPOSE_DIRS`.

dcompose exports, for use in compose files:

- `UID`, `GID`: the real current user (always).
- `DCOMPOSE_UID`, `DCOMPOSE_GID`: the id containers must run as. Defaults to
  the real ids; if set beforehand, only that id is accepted and the real user
  is refused (`nobody`, 65534, is always accepted).

`dcompose audit` runs the checks alone; `dcompose fix` prints a compose
override that repairs what it can.
