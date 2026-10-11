"""The uid and gid compose files see.

dockscreen exports UID and GID, the real ids of the caller, for compose files to interpolate
(`user: "${UID}:${GID}"`); values already in the environment are overwritten. Running as these ids is
not allowed unless --allow-me is given (see idrules): exporting them only makes the project's intent
readable.
"""

import os

EXPORTED = ("UID", "GID")


def export(env):
    """Set UID and GID in env to the real ids. Idempotent."""
    env["UID"] = str(os.getuid())
    env["GID"] = str(os.getgid())
