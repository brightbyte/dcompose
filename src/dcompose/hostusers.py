"""Users given on the command line: ids as typed, or a local account resolved here.

Docker resolves a user name in the container's own /etc/passwd, where a hostile image can map it
to root. So `--user` takes only numbers, which mean the same everywhere, and `--as NAME` takes the
name of an account on this host and turns it into ids before docker sees it.
"""

import pwd


class UserError(Exception):
    """A user given on the command line cannot be used."""


class UnknownUser(UserError):
    pass


def require_numeric(spec):
    """`uid:gid`, as typed; anything else is an error that says what to use instead.

    A uid alone would leave the group to the image: docker takes it, and the supplementary groups,
    from the image's own passwd and group files, which can say root.
    """
    user, colon, group = spec.partition(":")
    if _is_id(user) and colon and _is_id(group):
        return spec
    hint = "; give the group too, as uid:gid" if _is_id(user) and not colon else ""
    raise UserError(f"--user takes numeric ids as uid:gid, not {spec!r}{hint}; "
                    "--as NAME runs as a local user, --as-me as yourself")


def resolve_account(name, getpwnam=pwd.getpwnam):
    """(`uid:gid`, messages) for the account called name on this host, with its primary group."""
    if not name or ":" in name or _is_id(name):
        raise UserError(f"--as takes the name of a local user, not {name!r}; use --user for ids")
    try:
        account = getpwnam(name)
    except KeyError:
        raise UnknownUser(
            f"user {name!r} does not exist on this host; use --user with a numeric id") from None
    return (f"{account.pw_uid}:{account.pw_gid}",
            [f"Resolving user {name} to uid {account.pw_uid}, gid {account.pw_gid}"])


def _is_id(text):
    return text.isascii() and text.isdigit()
