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
| Your shell environment | yes | same reason; so settings that widen the policy are read only from there |
| The docker daemon and the real `docker` binary | yes | they are what is being protected |

Who a container runs as:

- Root must be rare and strictly opt-in: only the command line can choose it.
- Running as the calling user ("me") is common and should be easy, but must not happen automatically: the command line chooses it, not the project or the image.
- Any other id the image picks is acceptable when it cannot reach host files and does not collide with a local account.

Out of scope:

- Network exposure (`ports`, `extra_hosts`, `dns`).
- Anything chosen on the command line (`run -v`, `exec --privileged`).
- `${VAR}` interpolation copying values from your shell into a container.
- Clients that talk to the docker socket directly: scripts, IDEs, other tools. dockscreen is a wrapper, not a daemon plugin.

## Approach

1. Let docker parse its own input. dockscreen never parses compose files or mirrors `docker run`'s option handling to decide safety. It asks the real tool what it would do (`docker compose config`, `docker create` then `docker inspect`) and checks the result.
2. Check exactly what will run. For compose, the checked config is written to a file and handed to compose as its only input. For `docker run`, the created container is checked before it is started.
3. Allowlist, fail closed. A compose key that is not listed is refused, so a new Compose feature stays denied until someone reviews it. Any error while inspecting counts as a refusal.
4. Decide users by ids, never by names. Docker resolves names in the image's own `/etc/passwd`, which a hostile image controls.
5. Fix what has a safe fix, refuse the rest. Missing hardening is added, an image that would run as root is run as nobody, and everything else is refused with a message that says how to proceed.

## Mechanisms

### Compose (`cli`, `guard`, `hardening`, `policy`, `composeimages`, `composerun`)

For `up`, `create`, `run`, `watch`, `scale` and `alpha`:

1. `guard.inspect` runs `docker compose config --format json --no-env-resolution --profile '*'`. All profiles are included so that a service named on the command line is checked too. Without env resolution, `env_file` paths stay visible to the policy instead of being inlined. The project directory is worked out the way compose does it. A `.env` that sets `COMPOSE_FILE` is refused, because it could send compose to a different directory than the one checked.
2. `hardening.apply` adds `cap_drop: [ALL]` and `no-new-privileges:true` where they are missing. In `user:` it resolves the names `root`, `nobody` and `nogroup` to ids.
3. `policy.check_config` applies the allowlist (below). Services that set no `user:` are exempt for now: their images decide.
4. `composeimages.prepare`:
   - asks compose which services will start (`config --services`);
   - pulls or builds their images by the project's own `pull_policy`, so automatic updates keep working;
   - for each one without `user:`, creates a container with `--pull=never`, reads its passwd and group files, and decides as `docker run` does (below).
5. `composeimages.finalize`:
   - services that fall back, and services that will not start, get `user: 65534:65534`, so a mistake in working out what starts fails safe;
   - services whose image was looked at get `pull_policy: never`, so compose cannot pull a different image between the check and the run;
   - the policy runs again on the result.
6. `composerun` writes the final config to a mode 0600 file in a private temporary directory. It runs `docker compose -f FILE --project-directory DIR --project-name NAME SUBCOMMAND …` as a child process, then removes the file.

`build` and `bake` get only `policy.check_build_config`, with no runtime checks:

- build contexts, Dockerfiles and secret files must be inside the project;
- no `ssh`, no host network, no `privileged`;
- no `x-` keys in `build`, because `buildx bake` reads `x-bake` and can write to the host.

`audit` runs steps 1–4 and reports. `harden` prints a compose override that fixes what has a mechanical fix (`autofix`) and lists the rest as comments.

### The policy (`policy.py`)

Every structure has its own key list: service, mount, build, volume, network, secret, deploy, develop, hooks and top level. A key is either harmless, so any value passes, or has a check function in `SERVICE_CHECKS`.

| Area | Rule |
|---|---|
| `user`, `group_add`, hook `user` | numeric `uid:gid`; each id is the allowed one (`DOCKSCREEN_UID`/`DOCKSCREEN_GID`, by default the real user) or 65534 |
| privileges | `privileged`, `cap_add`, `devices`, `gpus`, `cgroup_parent`, device reservations: refused; `cap_drop` must include `ALL`; `security_opt` must be exactly no-new-privileges; `runtime` only `runc` |
| namespaces | `pid`, `ipc`, `uts`, `userns_mode`, `cgroup`, `network_mode`: no `host`, no `container:` |
| mounts | bind sources, after `realpath`, inside the project or `DOCKSCREEN_DIRS`; types `volume`, `tmpfs` and `image` allowed |
| files read on the host | `env_file`, `label_file`, secret and config `file`, build contexts, `develop.watch` paths: inside the project |
| volumes and networks | named `<project>_<key>`, not `external`; volumes use the local driver, and `driver_opts` may not turn one into a bind or network mount; networks use `bridge` or `none` |
| `develop.watch` | no `sync+exec`, which runs a command in the container |
| `x-` keys | ignored, as compose does, except in `build` |

### Image users (`gate.assess`, `imageuser`)

The image's identity is resolved from its `/etc/passwd` and `/etc/group`. These are copied out of a container that is created but never started (`docker cp`, capped at 1 MiB). Then:

| Image would run as | No host mounts | Bind mounts, devices, `volumes_from`, secrets or configs |
|---|---|---|
| root (uid, gid or a supplementary gid of 0) | run as nobody, with a notice | run as nobody, with a notice |
| an id that exists on this host | refused | run as nobody, with a notice |
| any other id | accepted | run as nobody; the notice gives the ids to choose explicitly |
| nobody | accepted | accepted |

Why each rule:

- Root is never the image's choice.
- With host mounts, the uid decides which host files the container can write, so a person has to choose it.
- A container that shares a uid with a local account also shares that account's kernel limits (processes, inotify watches), and owns its files in anything it mounts.
- Falling back to nobody rather than refusing keeps the common case of an image that sets no `USER` working.

### The `docker` wrapper (`docker_cli`, `runargs`, `gate`, `hostusers`)

- `run` becomes `create`, `inspect`, check, `start`:
  - The daemon parses the command line. `runargs` reads only far enough to find the image and the `run`-only flags.
  - `gate.verify_split` refuses if that reading disagrees with what the daemon created.
  - A fallback removes the container and creates it again with `--user=65534:65534`.
- `create` gets the defaults and user resolution. Its container is checked when it is started.
- `start` and `restart` check existing containers. These can't be rewritten, so a fallback is a refusal there.
- `audit IMAGE` predicts the outcome, with and without mounts, without pulling or starting anything.
- Every `create` gets `--cap-drop=ALL --security-opt=no-new-privileges:true` placed before the user's arguments, so the command line can override them.
- Users chosen on the command line:

  | Option | Becomes | Why |
  |---|---|---|
  | `--user` / `-u` | numeric `uid` or `uid:gid` only | a name would be resolved in the image |
  | `--as NAME` | `--user=uid:gid` of that local account | Docker never sees the name |
  | `--as-me` | `--user=` your own `uid:gid` | |

- A daemon that is not the local default is refused (`-H`, `--context`, a non-unix `DOCKER_HOST`, a non-default context): host ids and paths mean nothing there.
- `docker compose` goes to dockscreen. Everything else is exec'd to the real docker unchanged. The real docker is `DOCKSCREEN_DOCKER`, or else the next `docker` on `PATH` that is not the wrapper. Empty `PATH` entries are skipped, so the current directory cannot supply it.

### Configuration and escape hatch

| Setting | Effect |
|---|---|
| `DOCKSCREEN_UID`, `DOCKSCREEN_GID` | the one id that compose files may name besides nobody; defaults to the real user |
| `DOCKSCREEN_DIRS` | extra absolute directories that bind mounts may come from |
| `DOCKSCREEN_DOCKER` | path of the real docker |
| `--skip-security-gate` | before the subcommand only: no checks, no defaults, and a warning on every use |

These are read from dockscreen's own environment, never from the project's `.env`. dockscreen exports `UID`, `GID`, `DOCKSCREEN_UID` and `DOCKSCREEN_GID` for compose files to interpolate.

Text from the project or the image is escaped (`text.printable`) before it is printed or written into a `harden` patch, so it cannot forge output lines or send terminal control sequences.

## Tradeoffs and decisions

| Decision | Alternative rejected | Cost accepted |
|---|---|---|
| Allowlist of keys | denylist of known-bad keys | false refusals until a new key is reviewed and listed |
| Run compose from the generated config | re-run compose on the project's own files | compose runs as a child, not via `exec`, and shows a temporary file as its config |
| Ask docker (`config`, `create` + `inspect`) | parse compose files and run options ourselves | an extra daemon round trip per image; depends on compose's output format |
| Nobody as the fallback for root images | refuse | images that start as root and drop privileges (postgres, redis) fail on their data directories until a user is chosen |
| Mounts require a chosen user | accept any non-root image user | more images run as nobody by default |
| Numeric ids only in compose files and `--user` | allow names | less readable; `--as` covers local names on the command line |
| `pull_policy: never` only in the generated file | pin in the project or in `harden` output | none; pinning in the project would silently stop its updates |
| Pull and build before deciding | decide only on images already present | `up`, `audit` and `harden` can pull and build, but only after the static checks pass |
| Wrapper on `PATH` | daemon authorization plugin | anything that talks to the socket directly is not covered |
| Remote daemons refused (`docker` wrapper) | check anyway | dockscreen does not work with remote contexts |

## Known gaps

- Compose interpolates the generated config again, so a `$$` in the project survives the check as `$` and expands at run time. Point 2 of the approach holds only once `$` is escaped in the generated file.
- A compose file can still choose the calling user's ids without any command-line opt-in. The threat model says this should be the command line's choice.
- The image identity is checked, but the generated config and the `docker run` path do not pin it as numbers, so the runtime resolves the user again from the image's files.
- `composerun` does not refuse remote daemons the way the `docker` wrapper does.
- Images are pinned by tag, not by id, between the check and the run.

## Maintaining

- A legitimate key is refused: check that it can't reach the host, then add it to the matching list in `policy.py`, or give it a check function. Never switch to refusing only known-bad keys.
- Compose adds a global option that takes a value: add it to `cli.GLOBAL_OPTS_WITH_VALUE`, or the subcommand is misread. For `docker`, the list is `docker_cli.DOCKER_OPTS_WITH_VALUE`, and for `run`/`create` it is `runargs.LONG_VALUE_FLAGS`.
