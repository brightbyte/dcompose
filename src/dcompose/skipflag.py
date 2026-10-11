"""--skip-security-gate: run the real thing with no checks and no defaults.

A global option only, in front of the subcommand. After the subcommand it is
not recognised, so docker or compose rejects it, which is the safe direction.
The warning is printed every time and cannot be silenced, because the flag may
have been copied into a script or an alias.
"""

import sys

FLAG = "--skip-security-gate"


def strip(argv, value_opts):
    """(whether the flag was given, argv without it). Only options before the subcommand count."""
    kept = []
    found = False
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            break
        if token == FLAG:
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
    print(f"dcompose: warning: {FLAG} given: the security gate is disabled.", file=sys.stderr)
    print("dcompose: warning: nothing in this command is checked, and no defaults are added.",
          file=sys.stderr)
