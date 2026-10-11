"""--skip-screening: run the real thing with no checks and no defaults.

A global option only, in front of the subcommand. After the subcommand it is
not recognised, so docker or compose rejects it, which is the safe direction.
The warning is printed every time and cannot be silenced, because the flag may
have been copied into a script or an alias.
"""

import sys

FLAG = "--skip-screening"


def strip(argv, value_opts, flag=FLAG):
    """(whether flag was given, argv without it). Only options before the subcommand count.

    Also used for the other dockscreen options that go before the subcommand, such as --allow-me.
    """
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
    print(f"dockscreen: warning: {FLAG} given: screening is disabled.", file=sys.stderr)
    print("dockscreen: warning: nothing in this command is checked, and no defaults are added.",
          file=sys.stderr)
