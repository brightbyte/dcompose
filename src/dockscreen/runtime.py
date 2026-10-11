"""What dockscreen takes from the process it runs in, gathered once by the entry point.

Everything below the entry points gets these as a Runtime, so none of it reads the config file, the
caller's ids, the environment or the host's accounts on its own.
"""

import os
from collections.abc import MutableMapping
from typing import NamedTuple

from dockscreen import config, hostusers, idrules, realdocker
from dockscreen.dockerclient import Docker


class Runtime(NamedTuple):
    settings: config.Config
    docker: Docker                          # the real docker
    accounts: hostusers.Accounts
    subordinate: idrules.SubordinateRanges  # ranges in /etc/subuid and /etc/subgid
    me: tuple                               # the caller's real (uid, gid)
    env: MutableMapping                     # the environment, which compose and docker inherit
    home: str                               # the caller's home directory

    def rules(self, allow_me=False):
        """The id rules; allow_me: --allow-me was given, so the caller's own ids are allowed."""
        return idrules.Rules(self.me, allow_me, self.settings.nobody_range, self.settings.default_user,
                             self.accounts, self.subordinate)

    def resolve_account(self, name):
        """hostusers.resolve_account with this host's accounts."""
        return hostusers.resolve_account(name, self.accounts)


def load_runtime():
    """The Runtime of this process. Raises config.ConfigError for a config file that cannot be trusted."""
    env, home, me = os.environ, os.path.expanduser("~"), (os.getuid(), os.getgid())
    settings = config.load_current(env, home, me[0])
    return Runtime(
        settings=settings,
        docker=Docker(realdocker.locate(settings, env)),
        accounts=hostusers.HostAccounts(),
        subordinate=idrules.Subordinate(),
        me=me,
        env=env,
        home=home,
    )
