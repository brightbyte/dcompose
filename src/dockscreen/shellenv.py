"""Which environment variables of the shell end up in which service.

`environment: [FOO]` takes FOO from the shell. The resolved config shows it like any other value, so a
pass-through is recognised by the value being the shell's own under the same name. That also catches
`FOO: bar` when the shell happens to have FOO=bar, and misses `X: ${FOO}`, which copies the value under
another name. The variables dockscreen exports for compose files are left out. Values are never shown.
"""

from dockscreen import ids


def copied(config, env):
    """{service: [variable names]} for the service environment values that are the shell's own."""
    found = {}
    for name, service in sorted((config.get("services") or {}).items()):
        environment = (service or {}).get("environment")
        if not isinstance(environment, dict):
            continue
        names = sorted(
            key for key, value in environment.items()
            if value and key not in ids.EXPORTED and env.get(key) == value
        )
        if names:
            found[name] = names
    return found


def describe(config, env):
    """One line per service that gets variables from the shell."""
    return [
        f"service {name}: environment variables taken from your shell: {', '.join(names)}"
        for name, names in copied(config, env).items()
    ]
