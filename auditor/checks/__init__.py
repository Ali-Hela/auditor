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

for _m in _MODULES:
    import_module("auditor.checks." + _m)
