import os
import sys

_DEBUG_ENABLED = bool(os.getenv("SKRY_DEBUG"))


def debug(*args, **kwargs):
    if _DEBUG_ENABLED:
        prefix = "\033[1m[DEBUG]\033[0m"
        print(prefix, *args, file=sys.stderr, **kwargs)


def info(*args, **kwargs):
    prefix = "\033[1;34m[INFO]\033[0m"
    print(prefix, *args, file=sys.stderr, **kwargs)


def warn(*args, **kwargs):
    prefix = "\033[1;33m[WARNING]\033[0m"
    print(prefix, *args, file=sys.stderr, **kwargs)


def error(*args, **kwargs):
    prefix = "\033[1;31m[ERROR]\033[0m"
    print(prefix, *args, file=sys.stderr, **kwargs)


# FQN (fully qualified name) utilities


def get_simple_name(name: str) -> str:
    """Extract simple name from qualified name (module::name -> name)."""
    return name.split("::")[-1] if "::" in name else name


def get_module_path(name: str) -> str | None:
    """Extract module path from FQN (module::pkg::func -> module::pkg)."""
    if "::" in name:
        parts = name.rsplit("::", 1)
        return parts[0] if len(parts) == 2 else None
    return None
