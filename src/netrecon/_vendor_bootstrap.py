"""Bootstrap vendored dependencies.

Adds the project-level vendor/ directory to sys.path so that all
third-party packages bundled there are importable without a virtual
environment.  The vendor/ path is inserted near the front of sys.path
(after the implicit '' entry) so it takes priority over system-wide
packages but still allows local/editable installs to win.

This module is imported by netrecon/__init__.py before any other
imports.
"""

import sys
from pathlib import Path


def _bootstrap_vendor():
    # Locate vendor/ relative to the project root.
    # Layout: <project>/src/netrecon/_vendor_bootstrap.py
    #         <project>/vendor/
    package_dir = Path(__file__).resolve().parent          # src/netrecon/
    src_dir = package_dir.parent                           # src/
    project_root = src_dir.parent                          # <project>/
    vendor_dir = project_root / "vendor"

    if vendor_dir.is_dir():
        vendor_str = str(vendor_dir)
        if vendor_str not in sys.path:
            # Insert after '' (cwd) if present, otherwise at position 0
            try:
                idx = sys.path.index("") + 1
            except ValueError:
                idx = 0
            sys.path.insert(idx, vendor_str)


_bootstrap_vendor()
