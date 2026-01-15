import os
import sys
from pathlib import Path

import pytest


# Ensure the project `src` directory is on sys.path so tests can import
# modules like `facts`, `matcher`, `semantic_evaluator`, etc.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path):
    """Use isolated cache directory for each test to prevent test pollution."""
    cache_dir = tmp_path / "skry_cache"
    cache_dir.mkdir()
    old_cache_dir = os.environ.get("SKRY_CACHE_DIR")
    os.environ["SKRY_CACHE_DIR"] = str(cache_dir)

    # Reload cache module to pick up new CACHE_DIR
    import core.cache
    core.cache.CACHE_DIR = str(cache_dir)

    yield

    # Restore original
    if old_cache_dir is not None:
        os.environ["SKRY_CACHE_DIR"] = old_cache_dir
    else:
        os.environ.pop("SKRY_CACHE_DIR", None)


