"""The accounts on this host, and users given on the command line: ids as typed, or a local account.

Docker resolves a user name in the container's own /etc/passwd, where a hostile image can map it
to root. So `--user` takes only numbers, which mean the same everywhere, and `--as NAME` takes the
name of an account on this host and turns it into ids before docker sees it.
"""

import grp
import pwd

from dockscreen import ids


class UserError(Exception):
    """A user given on the command line cannot be used."""


class UnknownUser(UserError):
    pass


DOCKER_ALTERNATIVES = "; --as NAME runs as a local user, --as-me as yourself"


def require_numeric(spec, alternatives=DOCKER_ALTERNATIVES):
    """`uid:gid`, as typed; anything else is an error that says what to use instead.

    A uid alone would leave the group to the image: docker takes it, and the supplementary groups,
    from the image's own passwd and group files, which can say root.
    """
    if ids.parse_user(spec):
        return spec
    hint = "; give the group too, as uid:gid" if ids.is_id(spec) else ""
    raise UserError(f"--user takes numeric ids as uid:gid, not {spec!r}{hint}{alternatives}")


def resolve_account(name, accounts=None):
    """(`uid:gid`, messages) for the account called name on this host, with its primary group.

    accounts: where to look the name up (HostAccounts, this host's).
    """
    if not name or ":" in name or ids.is_id(name):
        raise UserError(f"--as takes the name of a local user, not {name!r}; use --user for ids")
    account = (accounts or HostAccounts()).user(name)
    if account is None:
        raise UnknownUser(f"user {name!r} does not exist on this host; use --user with a numeric id")
    uid, gid = account
    return ids.format_user(account), [f"Resolving user {name} to uid {uid}, gid {gid}"]


class UserOptions:
    """The ways a command line gives a user, each turned into `--user=uid:gid` for docker.

    Records whether a user was given, whether the caller's own ids are allowed (--as-me), and the
    notices that resolving names produced.
    """

    def __init__(self, current_user, resolve):
        """current_user: the (uid, gid) --as-me stands for; resolve: like resolve_account."""
        self.current_user = current_user
        self.resolve = resolve
        self.user_given = False
        self.allow_me = False
        self.notices = []

    def numeric(self, spec):
        """--user or -u: numeric ids only."""
        self.user_given = True
        return f"--user={require_numeric(spec)}"

    def account(self, name):
        """--as: a local account, as ids."""
        self.user_given = True
        resolved, messages = self.resolve(name)
        self.notices += messages
        return f"--user={resolved}"

    def me(self):
        """--as-me: the caller's own ids, which are then allowed."""
        self.user_given = self.allow_me = True
        return f"--user={ids.format_user(self.current_user)}"


class HostAccounts:
    """Users and groups on this host, through NSS (so LDAP and sssd accounts count)."""

    def user(self, name):
        """(uid, primary gid) of the user called name, or None."""
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            return None
        return account.pw_uid, account.pw_gid

    def group(self, name):
        """The gid of the group called name, or None."""
        try:
            return grp.getgrnam(name).gr_gid
        except KeyError:
            return None

    def user_name(self, uid):
        """The name of the user with this uid, or None."""
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return None

    def group_name(self, gid):
        """The name of the group with this gid, or None."""
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return None
