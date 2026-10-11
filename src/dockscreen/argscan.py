"""Reading docker and compose command lines just far enough to find one thing in them.

None of these is a full parser: each knows which options take a value only from the set it is given,
and the callers are written so that a misreading refuses or changes nothing.
"""


def find_subcommand(argv, value_opts):
    """Return the index of the subcommand in argv, or None. value_opts: options that take a value."""
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            return None
        if token in value_opts:
            i += 2
        elif token.startswith("-"):
            i += 1
        else:
            return i
    return None


def option_values(args, long_name, short_name):
    """All values given for an option, in `--opt v`, `--opt=v` and `-ov` forms."""
    values = []
    i = 0
    while i < len(args):
        token = args[i]
        if token in (long_name, short_name) and i + 1 < len(args):
            values.append(args[i + 1])
            i += 1
        elif token.startswith(long_name + "="):
            values.append(token[len(long_name) + 1:])
        elif short_name and token.startswith(short_name) and not token.startswith("--") and len(token) > 2:
            values.append(token[2:])
        i += 1
    return values


def option_value(args, name):
    """The value of `--name value` or `--name=value` before any `--`, if given."""
    for i, arg in enumerate(args):
        if arg == "--":
            break
        if arg.startswith(name + "="):
            return arg.partition("=")[2]
        if arg == name and i + 1 < len(args):
            return args[i + 1]
    return None


def strip_options(args, names):
    """args without the given options, which take a value: `--opt v`, `--opt=v` and `-ov` forms."""
    kept = []
    i = 0
    while i < len(args):
        token = args[i]
        if token in names:
            i += 2
        elif any(token.startswith(n + "=") for n in names if n.startswith("--")) \
                or any(token.startswith(n) for n in names if not n.startswith("--")):
            i += 1
        else:
            kept.append(token)
            i += 1
    return kept


def positionals(args, long_values, short_values):
    """The arguments that are not options or their values.

    long_values: long options that take a value; short_values: letters of short options that do.
    """
    found = []
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            found += args[i + 1:]
            break
        if token.startswith("--"):
            i += 1 if "=" in token or token not in long_values else 2
        elif token.startswith("-") and token != "-":
            i += 2 if token[-1] in short_values else 1
        else:
            found.append(token)
            i += 1
    return found
