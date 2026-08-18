"""Check modules. Importing this package registers every check."""
from importlib import import_module

# Order here controls category display order.
_MODULES = [
    "login",
    "firewall",
    "ssl",
    "accounts",
    "backups",
    "database_php",
    "intrusion",
    "updates",
    "ddos",
    "audits",
]

_loaded = False


def load_all():
    """Import every check module, registering the checks it defines.

    Idempotent. Runs on import so that ``import auditor.checks`` alone is
    enough, and is exposed as a function so callers can state the dependency
    explicitly rather than relying on an import that looks unused.
    """
    global _loaded
    if _loaded:
        return
    for name in _MODULES:
        # Relative to this package, so the tree can be vendored under any name.
        import_module("." + name, __name__)
    _loaded = True


load_all()
