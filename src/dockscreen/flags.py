"""dockscreen's own options, which docker and compose never see.

Before the subcommand (strip() takes them out):
- --skip-screening runs the real thing with no checks and no defaults. After the subcommand it is
  not recognised, so docker or compose rejects it, which is the safe direction. The warning is
  printed every time and cannot be silenced, because the flag may have been copied into a script or
  an alias.
- --allow-me lets services and images run as the caller's own ids (see idrules).
- --strict-screen treats the command line as untrusted too: what it asks for that a project or an
  image may not have (see runpolicy) is refused. Only `audit` supports it so far; everything else
  refuses to run with it, rather than ignore it.

After `audit`, for compose and docker alike: --brief prints only the verdict, in one line.

After `run` or `exec` (composeargs and runargs replace them by `--user=uid:gid`):
- --as NAME: a local user by name, resolved on this host.
- --as-me: the caller's own ids; with `docker run` it implies --allow-me.
"""

from dockscreen import messages

SKIP_SCREENING = "--skip-screening"
ALLOW_ME = "--allow-me"
AS = "--as"
AS_ME = "--as-me"
STRICT_SCREEN = "--strict-screen"
BRIEF = "--brief"
AS_ME_MESSAGE = ("--as-me goes after run or exec, before the service; for up, give --allow-me before the "
                 "subcommand, and user: \"${UID}:${GID}\" to the services that should run as you")


def strip(argv, value_opts, flag=SKIP_SCREENING):
    """(whether flag was given, argv without it). Only options before the subcommand count."""
    kept = []
    found = False
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            break
        if token == flag:
            found = True
            i += 1
        elif token in value_opts:
            kept += argv[i:i + 2]
            i += 2
        elif token.startswith("-"):
            kept.append(token)
            i += 1
        else:
            break
    return found, [*kept, *argv[i:]]


def banner():
    messages.warning(f"{SKIP_SCREENING} given: screening is disabled.")
    messages.warning("nothing in this command is checked, and no defaults are added.")
