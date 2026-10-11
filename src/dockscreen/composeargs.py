"""The arguments of `docker compose run` and `exec` (and `docker exec`), read just far enough to find
the user and the service.

The command line is trusted, so the user it gives is not checked against the id rules, only for its
form: numeric `uid:gid`, which docker uses as it stands. A name would be resolved in the image (for
`exec`, in the running container's /etc/passwd, which the container may have rewritten), and a uid
alone takes its group from the image. `--as NAME` names an account on this host instead; it is
replaced by `--user=uid:gid` before compose or docker sees it. So is `--as-me`, for the caller's own ids.

A misreading cannot loosen anything: a user that is missed reaches compose as typed, which the command
line could have done with plain compose anyway, and a service that is missed has its image decided as
if no user had been chosen.
"""

import os
from typing import NamedTuple

from dockscreen import flags, hostusers, ids

# Options of `docker compose run` and `exec` that take a value in the next argument.
VALUE_FLAGS = {
    "run": frozenset({
        "--cap-add", "--cap-drop", "-e", "--env", "--env-from-file", "--entrypoint", "-l", "--label",
        "--name", "-p", "--publish", "--pull", "-u", "--user", "-v", "--volume", "-w", "--workdir",
    }),
    "exec": frozenset({"-e", "--env", "--index", "-u", "--user", "-w", "--workdir"}),
    # plain `docker exec`, which has no service but a container: the same reading applies
    "docker exec": frozenset({
        "--detach-keys", "-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir",
    }),
}


class Parsed(NamedTuple):
    service: str | None
    user_given: bool  # --user, -u or --as before the service
    args: list        # args with --as NAME replaced by --user=uid:gid
    notices: list     # what resolving user names on this host did, for the caller to print


def parse(subcommand, args, resolve=None, current_user=None):
    """The service named in args, and whether a user is given; raises hostusers.UserError for a user
    that is not numeric `uid:gid`, or an --as that does not name a local user.

    resolve: turns the name given to --as into "uid:gid" (hostusers.resolve_account), with messages.
    current_user: the (uid, gid) that --as-me stands for; the caller's by default.
    """
    resolve = resolve or hostusers.resolve_account
    value_flags = VALUE_FLAGS[subcommand]
    short_values = {flag[1] for flag in value_flags if len(flag) == 2}
    user_given = False
    kept, notices = [], []
    i = 0
    while i < len(args):
        start, token = i, args[i]
        if token == "--":
            service = args[i + 1] if i + 1 < len(args) else None
            return Parsed(service, user_given, [*kept, *args[i:]], notices)
        if token == flags.AS_ME:
            kept.append(f"--user={ids.format_user(current_user or (os.getuid(), os.getgid()))}")
            user_given = True
            i += 1
            continue
        if token.startswith("--"):
            name, has_value, value = token.partition("=")
            if (name in value_flags or name == flags.AS) and not has_value:
                i += 1
                value = args[i] if i < len(args) else ""
            if name == "--user":
                hostusers.require_numeric(value)
                user_given = True
            elif name == flags.AS:
                resolved, messages = resolve(value)
                notices += messages
                user_given = True
                kept.append(f"--user={resolved}")
                i += 1
                continue
        elif token.startswith("-") and token != "-":
            for j, char in enumerate(token[1:], start=1):
                if char in short_values:
                    value = token[j + 1:]
                    if not value:
                        i += 1
                        value = args[i] if i < len(args) else ""
                    if char == "u":
                        hostusers.require_numeric(value)
                        user_given = True
                    break
        else:
            return Parsed(token, user_given, [*kept, *args[i:]], notices)
        kept += args[start:i + 1]
        i += 1
    return Parsed(None, user_given, kept, notices)
