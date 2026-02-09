"""NetRecon - A beginner-friendly network security tools suite."""

import sys

if not getattr(sys, "frozen", False):
    import netrecon._vendor_bootstrap  # noqa: F401  (adds vendor/ to sys.path)

__version__ = "0.1.0"
