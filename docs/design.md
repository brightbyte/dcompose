# dockscreen design

Audience: people who change dockscreen or review its security. Users want the README.

## Purpose

`docker compose up` on a project you just cloned gives that project whatever access the docker daemon has: in effect root on the host. The same goes for `docker run` on an image you just pulled. dockscreen sits in front of `docker compose`, and optionally in front of `docker`. It refuses a project or image that would reach outside its own directory or run with privileges, and adds hardening defaults to what it lets through. Everything it does not need to look at is passed to the real docker unchanged.

## Threat model

| Party | Trusted | Why |
|---|---|---|
| Compose project: compose files, `.env`, env files, `include` and `extends` fragments, build contexts | no | it is what you just cloned |
| Images, including their `/etc/passwd` and `/etc/group` | no | anyone can publish one |
| Your command line | yes | anyone who controls it can call `docker` directly |
| Your shell environment | yes | same reason; it does not configure dockscreen, though |
| The config files, `/etc/dockscreen/config.toml` and `~/.config/dockscreen/config.toml` | yes, if only you or root can write them | they are the only place that widens the policy |
| The docker daemon and the real `docker` binary | yes | they are what is being protected |

Who a container runs as is the core of the policy; see [Users and groups](#users-and-groups).

Out of scope:

- Network exposure (`ports`, `extra_hosts`, `dns`).
- Anything chosen on the command line (`run -v`, `exec --privileged`).
- `${VAR}` interpolation copying values from your shell into a container.
- Clients that talk to the docker socket directly: scripts, IDEs, other tools. dockscreen is a wrapper, not a daemon plugin.

## Approach

1. Let docker parse its own input. dockscreen never parses compose files or mirrors `docker run`'s option handling to decide safety. It asks the real tool what it would do (`docker compose config`, `docker create` then `docker inspect`) and checks the result.
2. Check exactly what will run. For compose, the checked config is written to a file and handed to compose as its only input. For `docker run`, the created container is checked before it is started.
3. Allowlist, fail closed. A compose key that is not listed is refused, so a new Compose feature stays denied until someone reviews it. Any error while inspecting counts as a refusal.
4. Decide users by ids, never by names. Docker resolves names in the image's own `/etc/passwd`, which a hostile image controls; dockscreen resolves names on the host and hands docker numbers.
5. Fix what has a safe fix, refuse the rest. Missing hardening is added, an image that would run as root is run as the default user, and everything else is refused with a message that says how to proceed.
6. Whatever the config file says is trusted, so the file is only read when nobody but its owner or root can have written it.

## Users and groups

Who a container runs as is the decision dockscreen spends most of its effort on. Root is rare and strictly opt-in. Running as the caller ("me") is common and easy, but never automatic. Every substitution is visible.

### Sources of ids

| Source | Trusted | Checked |
|---|---|---|
| Command line: `--user`/`-u`, `--as`, `--as-me`, `--allow-me` | yes | form only (see [Forms](#forms)) |
| Config file: `default_user`, `nobody_range`, `[image_users]` | yes | the file's ownership and permissions (see [Configuration](#configuration-and-options-config)) |
| Compose file: `user:`, hook `user:`, `group_add`, including values from `.env` | no | all rules |
| Image: its `USER`, `/etc/passwd` and `/etc/group` | no | all rules |

### Terms

- **me**: the caller's real uid and gid.
- **nobody range**: ids any project or image may use, mounts or not. `nobody_range`, 65530–65534 by default.
- **default user**: what replaces an image's root user. `default_user`, 65534:65534 by default.
- **configured image user**: a `uid:gid` that `[image_users]` sets for an image repository.
- **allowed ids**: the nobody range, the default user, the configured image user that applies, and me when `--allow-me` was given (`--as-me` implies it for `docker run`).
- **host mounts**: bind mounts, devices, `volumes_from`, secrets and configs. Named volumes and tmpfs are not.

### Forms

| Form | `--user`, `-u` | `--as` | `user:`, hook `user:` | Meaning |
|---|---|---|---|---|
| `uid:gid` | yes | no | yes | as given |
| `uid` alone | no | no | no | refused: docker would take the group and supplementary groups from the image; deriving them here would change what the value means |
| `name` | no | yes | yes | an account on this host, with its primary group |
| `name:group` | no | no | yes | account and group on this host |
| `${UID}:${GID}` and other variables | | | yes | interpolated by compose first, then read as the resulting form |

`--user` and `-u` take numbers only, so that what dockscreen accepts means the same to docker. Docker resolves a name in the image, or for `exec` in the running container's `/etc/passwd`, which the container may have rewritten; resolving it on this host instead would quietly give `--user` a meaning docker does not have. A name is refused with a pointer to `--as`.

Names in `--as` and `user:` are resolved on this host, through NSS. A name unknown here is refused, even if the image defines it (`user: node`, `user: postgres`). Docker never sees a name: whatever runs is pinned as numeric `uid:gid`, and with a numeric group docker adds no supplementary groups from the image.

### Ids the project and the image may not choose

These apply to the uid, the gid and every supplementary gid, from `user:`, hooks, `group_add` and the image. Allowed ids are exempt.

| Id | Why |
|---|---|
| 0 | root is never the project's or the image's choice |
| a user or group on this host (NSS) | the container would share that account's kernel limits (processes, inotify watches), and own its files in anything it mounts |
| in `/etc/subuid` or `/etc/subgid`, any owner | files with these ids belong to rootless containers on this host |
| 65535 or 4294967295 | `(uid_t)-1`: many tools read it as "no id" |
| anything else, with host mounts | the id decides which host files the container can write, so it must be an allowed id |

### Deciding the user

Compose services:

1. **The service sets `user:`.** It is resolved (see [Forms](#forms)) and checked. If the rules refuse it, the run is refused: the project asked for this id, so there is no fallback.
2. **No `user:`, and a configured image user applies** (see below): that user, root included, without a notice.
3. **No `user:` otherwise:** the image's own user.
   - root in any position (uid, gid or a supplementary gid): the default user, with a notice;
   - anything else: checked with the service's mounts, and the run is refused if the rules refuse it.

Hook users follow step 1. Services that will not start get the default user, so a mistake in working out what starts fails safe.

`docker run`, and `docker compose run` for the service it names: a user from the command line is used as given. Otherwise, steps 2 and 3 apply.

`docker start` and `restart`: an existing container cannot be rewritten, so one whose user steps 2 and 3 would replace or refuse is refused. Compose `start` and `restart` take no user and are not checked: they start containers that `up` or `create` made.

`exec` (`docker exec`, `compose exec`): a user from the command line is used as given. Without one, the process runs as the container's own user, which was checked when the container started, if dockscreen started it.

### Configured image users

An `[image_users]` entry names a repository: it trusts the image's maintainer, not one image. It applies when all of these hold:

- The repository is the same after normalisation: registry and namespace are filled in, so `mariadb` means `docker.io/library/mariadb` and does not match `evil.example/mariadb` or `someone/mariadb`. The tag plays no part.
- The image was pulled from that repository: its `RepoDigests` contain an entry for it. A project, or an earlier run, can build or tag a local image under any name, and such an image has no repo digest for the repository.
- The service has no `build:`.

`audit` names the entry that applied, and says why when an entry for the repository exists but did not apply.

### Command-line options

| Option | Where | Effect |
|---|---|---|
| `--user uid:gid`, `-u uid:gid` | `docker run`, `create`, `exec`, `audit`; compose `run`, `exec` | that user, as given |
| `--as NAME` | the same | `--user=uid:gid` of that account on this host |
| `--as-me` | the same | `--user=` my `uid:gid`; for `docker run` and `audit` it also implies `--allow-me` |
| `--allow-me` | before the subcommand; for `docker run` and `audit` also before the image | me becomes an allowed id: in `user:` (literal, name or `${UID}`), and as an image's own user |

`--as`, `--as-me` and `--allow-me` are dockscreen's own: docker and compose never see them. The user options go after the subcommand and before the image, service or container.

`--as-me` before a compose subcommand is refused with a pointer to `--allow-me`: choosing one user for every service of `up` at once makes no sense. A project says which services run as the caller with `user: "${UID}:${GID}"`; dockscreen exports `UID` and `GID` as the real ids, overwriting any already set, and the rules refuse them unless `--allow-me` was given.

### Notices

- The default user replaced an image's root user: one line per service, on every run.
- The configured default user is root: one line on every run.
- A configured image user, root included, gets no per-run notice; `audit` lists it.
- A name resolved on this host (`--as`, `user:`): one line naming the ids.

## Mechanisms

### Compose (`cli`, `screen`, `hardening`, `policy`, `composeimages`, `composerun`)

For `up`, `create`, `run`, `watch`, `scale` and `alpha`:

1. `screen.inspect` runs `docker compose config --format json --no-env-resolution --profile '*'`. All profiles are included so that a service named on the command line is checked too. Without env resolution, `env_file` paths stay visible to the policy instead of being inlined. The project directory is worked out the way compose does it. A `.env` that sets `COMPOSE_FILE` is refused, because it could send compose to a different directory than the one checked.
2. `hardening.apply` adds `cap_drop: [ALL]` and `no-new-privileges:true` where they are missing. It resolves names in `user:`, hook users and `group_add` to ids on this host (`hostusers.Accounts`); a name unknown here stays a name, which the policy refuses.
3. `policy.check_config` applies the allowlist (below), and the id rules (`idrules`) to every id the project gives. Services that set no `user:` are exempt for now: their images decide.
4. `composeimages.prepare`:
   - asks compose which services will start (`config --services`);
   - pulls or builds their images by the project's own `pull_policy`, so automatic updates keep working;
   - for each one without `user:`, creates a container with `--pull=never`, reads its passwd and group files, and decides as `docker run` does (below);
   - skips the service that `run -u uid:gid` names: the command line chose its user.
5. `composeimages.finalize`:
   - every decided user is pinned as numeric `user: "uid:gid"`, so the runtime resolves nothing in the image;
   - services that fall back, and services that will not start, get the default user, so a mistake in working out what starts fails safe;
   - services whose image was looked at get `pull_policy: never` and, unless built, `image:` set to the checked image id, so neither a pull nor a moved tag changes what runs;
   - the policy runs again on the result.
6. Before anything is pulled or built, compose is asked for the config of the generated file, and the run is refused unless it equals the config that was checked: compose interpolates the files it reads.
7. `composerun` writes the final config to a mode 0600 file in a private temporary directory. It runs `docker compose -f FILE --project-directory DIR --project-name NAME SUBCOMMAND …` as a child process, then removes the file.

`build` and `bake` get only `policy.check_build_config`, with no runtime checks:

- build contexts, Dockerfiles and secret files must be inside the project;
- no `ssh`, no host network, no `privileged`;
- no `x-` keys in `build`, because `buildx bake` reads `x-bake` and can write to the host.

`audit` runs steps 1–4 and reports. `harden` prints a compose override that fixes what has a mechanical fix (`autofix`) and lists the rest as comments.

### The policy (`policy.py`)

Every structure has its own key list: service, mount, build, volume, network, secret, deploy, develop, hooks and top level. A key is either harmless, so any value passes, or has a check function in `SERVICE_CHECKS`.

| Area | Rule |
|---|---|
| `user`, `group_add`, hook `user` | `uid:gid` after hardening resolved names (a uid alone is refused); each id passes the id rules below, with the service's mounts |
| privileges | `privileged`, `cap_add`, `devices`, `gpus`, `cgroup_parent`, device reservations: refused; `cap_drop` must include `ALL`; `security_opt` must be exactly no-new-privileges; `runtime` only `runc` |
| namespaces | `pid`, `ipc`, `uts`, `userns_mode`, `cgroup`, `network_mode`: no `host`, no `container:` |
| mounts | bind sources, after `realpath`, inside the project or the configured `mount_dirs`; types `volume`, `tmpfs` and `image` allowed |
| files read on the host | `env_file`, `label_file`, secret and config `file`, build contexts, `develop.watch` paths: inside the project |
| volumes and networks | named `<project>_<key>`, not `external`; volumes use the local driver, and `driver_opts` may not turn one into a bind or network mount; networks use `bridge` or `none` |
| `develop.watch` | no `sync+exec`, which runs a command in the container |
| `x-` keys | ignored, as compose does, except in `build` |

### Users (`idrules`, `hostusers`, `images`, `imageuser`, `gate.assess`)

`idrules.Rules` implements [the id rules](#ids-the-project-and-the-image-may-not-choose). It reads `/etc/subuid` and `/etc/subgid` when it checks, and looks up local accounts through NSS, so LDAP and sssd accounts count.

`gate.assess` implements [steps 2 and 3](#deciding-the-user) for compose and `docker run` alike. `images.configured_user` matches `[image_users]`. Otherwise the image's identity is resolved from its `/etc/passwd` and `/etc/group`, the way moby does it, which are copied out of a container that is created but never started (`docker cp`, capped at 1 MiB). Because the result is pinned as numbers, docker reads neither file at run time, so a difference between this reading and docker's can at worst refuse a good image.

### The `docker` wrapper (`docker_cli`, `runargs`, `gate`, `hostusers`)

- `run` becomes `create`, `inspect`, check, `start`:
  - The daemon parses the command line. `runargs` reads only far enough to find the image and the `run`-only flags.
  - `gate.verify_split` refuses if that reading disagrees with what the daemon created.
  - Anything accepted removes the container and creates it again with `--user=uid:gid` as numbers: the default user, the configured image user, or the image's own ids.
- `create` gets the defaults and user resolution. Its container is checked when it is started.
- `start` and `restart` check existing containers. These can't be rewritten, so a container whose user would be replaced (default or configured user) is refused.
- `exec` checks only the form of the user (see [Forms](#forms)).
- `audit IMAGE` predicts the outcome, with and without mounts, without pulling or starting anything.
- Every `create` gets `--cap-drop=ALL --security-opt=no-new-privileges:true` placed before the user's arguments, so the command line can override them.
- Users chosen on the command line: see [Command-line options](#command-line-options).
- A daemon that is not the local default is refused (`-H`, `--context`, a non-unix `DOCKER_HOST`, a non-default context): host ids and paths mean nothing there.
- `docker compose` goes to dockscreen. Everything else is exec'd to the real docker unchanged. The real docker is the configured `docker`, or else the next `docker` on `PATH` that is not the wrapper. Empty `PATH` entries are skipped, so the current directory cannot supply it.

### Configuration and options (`config`)

The config files are TOML, read with `tomllib`. The user's file overrides `/etc` key by key, and `image_users` entry by entry. Unknown keys are an error. A missing user file is created from `config.template.toml`, mode 0600 in a 0700 directory, with every setting commented out: active defaults there would override `/etc`.

| Key | Default | Effect |
|---|---|---|
| `default_user` | `65534:65534` | replaces an image's root user; a notice on every run if it is root |
| `nobody_range` | `[65530, 65534]` | ids any project or image may use, mounts or not; may not include 65535 |
| `mount_dirs` | none | absolute directories, besides the project, that bind mounts may come from |
| `docker` | the next `docker` on `PATH` | absolute path of the real docker |
| `[image_users]` | none | repository (no tag) → `uid:gid` |

Strict modes, as ssh does it: the file and every directory above it must be owned by the caller or root and not writable by group or others, or dockscreen refuses to run. Strict modes cannot stop an agent that runs as the caller; only a root-owned file in `/etc` does. They do not cover the `docker` binary the file names either.

Mount dirs and the project directory are checked against sensitive paths (system directories, `$HOME`, the config files, the docker socket), after resolving symlinks: a mount dir that contains one gets a warning on every run, a project directory that contains one is refused. The upward search for a compose file stops at `$HOME` and at the first directory that the caller does not own.

| Option, before the subcommand | Effect |
|---|---|
| `--allow-me` | the caller's own ids become allowed ids, for this run |
| `--skip-screening` | no checks, no defaults, and a warning on every use |

Text from the project or the image is escaped (`text.printable`) before it is printed or written into a `harden` patch, so it cannot forge output lines or send terminal control sequences.

## Tradeoffs and decisions

| Decision | Alternative rejected | Cost accepted |
|---|---|---|
| Allowlist of keys | denylist of known-bad keys | false refusals until a new key is reviewed and listed |
| Run compose from the generated config | re-run compose on the project's own files | compose runs as a child, not via `exec`, and shows a temporary file as its config |
| Ask docker (`config`, `create` + `inspect`) | parse compose files and run options ourselves | an extra daemon round trip per image; depends on compose's output format |
| The default user (nobody) for root images | refuse | images that start as root and drop privileges (postgres, redis) fail on their data directories until a user is configured or chosen |
| With mounts, only allowed ids | accept any non-root image user | more images are refused; `image_users` and `--user` are the way out |
| Names resolved on the host, never in the image | let docker resolve them | `user: postgres` means the host's postgres, or is refused, unlike plain compose |
| A uid without a group is refused | derive the gid | a silent change in behaviour would be confusing |
| `image_users` by repository, checked by repo digest | by name only; by digest | trusts the maintainer, not one image; locally built images cannot be configured yet |
| One config file, trusted completely | environment variables | the file needs strict ownership; an agent running as the caller can still edit it |
| `pull_policy: never` only in the generated file | pin in the project or in `harden` output | none; pinning in the project would silently stop its updates |
| Pull and build before deciding | decide only on images already present | `up`, `audit` and `harden` can pull and build, but only after the static checks pass |
| Wrapper on `PATH` | daemon authorization plugin | anything that talks to the socket directly is not covered |
| Remote daemons refused | check anyway | dockscreen does not work with remote contexts |

## Known gaps

- Compose `start` and `restart` are passed through unchecked. A container that plain `docker compose create` made, without dockscreen, can be started through them.
- An explicit `user:` is checked without the configured image user: a service that sets `user: "999:999"` for an image configured as 999 is still judged by the id rules alone. Leaving `user:` out gives the configured user.
- `image_users` cannot name a locally built image; pinning by digest or image id is not implemented.
- `harden` writes `user: "${UID}:${GID}"` where an image's user is refused, which needs `--allow-me` to run.

## Maintaining

- A legitimate key is refused: check that it can't reach the host, then add it to the matching list in `policy.py`, or give it a check function. Never switch to refusing only known-bad keys.
- Compose adds a global option that takes a value: add it to `cli.GLOBAL_OPTS_WITH_VALUE`, or the subcommand is misread. For `docker`, the list is `docker_cli.DOCKER_OPTS_WITH_VALUE`, and for `run`/`create` it is `runargs.LONG_VALUE_FLAGS`.
