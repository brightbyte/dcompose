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

from typing import NamedTuple

from dockscreen import flags, hostusers

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


def parse(subcommand, args, current_user, resolve):
    """The service named in args, and whether a user is given; raises hostusers.UserError for a user
    that is not numeric `uid:gid`, or an --as that does not name a local user.

    current_user: the (uid, gid) that --as-me stands for.
    resolve: turns the name given to --as into "uid:gid" (hostusers.resolve_account), with messages.
    """
    users = hostusers.UserOptions(current_user, resolve)
    value_flags = VALUE_FLAGS[subcommand]
    kept = []
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            service = args[i + 1] if i + 1 < len(args) else None
            return Parsed(service, users.user_given, [*kept, *args[i:]], users.notices)
        if token == flags.AS_ME:
            kept.append(users.me())
            i += 1
        elif token.startswith("--"):
            i = parse_long(args, i, value_flags, users, kept)
        elif token.startswith("-") and token != "-":
            i = parse_short(args, i, value_flags, users, kept)
        else:
            return Parsed(token, users.user_given, [*kept, *args[i:]], users.notices)
    return Parsed(None, users.user_given, kept, users.notices)


def parse_long(args, i, value_flags, users, kept):
    """Read the --option at args[i] into kept, with --as replaced; returns the index after it."""
    name, has_value, value = args[i].partition("=")
    end = i
    if (name in value_flags or name == flags.AS) and not has_value:
        end = i + 1
        value = args[end] if end < len(args) else ""
    if name == flags.AS:
        kept.append(users.account(value))
        return end + 1
    if name == "--user":
        users.numeric(value)
    kept += args[i:end + 1]
    return end + 1


def parse_short(args, i, value_flags, users, kept):
    """Read the cluster at args[i] (such as -it or -u0:0) into kept; returns the index after it."""
    token = args[i]
    short_values = {flag[1] for flag in value_flags if len(flag) == 2}
    end = i
    for j, char in enumerate(token[1:], start=1):
        if char not in short_values:
            continue
        value = token[j + 1:]
        if not value:
            end = i + 1
            value = args[end] if end < len(args) else ""
        if char == "u":
            users.numeric(value)
        break
    kept += args[i:end + 1]
    return end + 1
