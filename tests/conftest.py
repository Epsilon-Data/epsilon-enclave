"""Pytest configuration for enclave tests.

The repo root has an __init__.py used for deployed-enclave package loading.
That __init__.py uses relative imports that break in dev-time test runs.
Make this tests/ directory pytest's rootdir so it doesn't walk up into the
root __init__.py during test discovery.
"""
import os
import sys

# Add repo root to sys.path so tests can do `from implementations... import ...`
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
