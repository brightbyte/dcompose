# Ideas for later

Not planned work: things worth doing once there is a need for them. Each says why it is not done yet.

## Strict screening for run and friends

`--strict-screen` makes `audit` treat the command line as untrusted: what it asks for that a compose project or an image may not have (privileged, cap_add, devices, host namespaces, other security options, bind mounts outside the current directory, a user the id rules refuse) fails the audit. The same could refuse those things at execution time, for `run` first. `runpolicy.findings` already computes them from the created container, so `gate.run` would only need to remove the container and refuse.

Why it is not done yet:

- The threat model trusts the command line, because whoever controls it can call docker directly. Strict execution only adds protection when the command line comes from somewhere less trusted than the person running it (a README, a project's Makefile or scripts, an agent) and dockscreen is installed as `docker`, so that those commands reach it.
- A script will not pass `--strict-screen` itself. To protect against untrusted scripts it would have to be a config setting (`strict_screen = true` in the config file), with the flag only for one-off use.
- Strict `run` alone leaves gaps: `create`, `start` of a container created elsewhere, `exec --privileged`, `compose run -v` and `--cap-add`, `docker cp`. Each needs its own decision, or strict mode promises more than it does.

Until then, `--strict-screen` is refused for every subcommand except `audit`, so that nobody gets lenient screening while asking for strict.
