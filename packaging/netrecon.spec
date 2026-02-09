# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec file for NetRecon macOS .app bundle."""

from pathlib import Path

block_cipher = None

PROJECT_ROOT = Path(SPECPATH).parent  # packaging/ -> project root
SRC_DIR = PROJECT_ROOT / "src"

a = Analysis(
    # Entry point script
    [str(SRC_DIR / "netrecon" / "gui" / "app.py")],
    pathex=[str(SRC_DIR)],
    binaries=[],
    datas=[],
    hiddenimports=[
        # --- netrecon's own modules (all must be discoverable) ---
        "netrecon",
        "netrecon.cli",
        "netrecon.explain",
        "netrecon.utils",
        "netrecon.warnings",
        "netrecon.gui",
        "netrecon.gui.app",
        "netrecon.gui.panels",
        "netrecon.gui.workers",
        "netrecon.tools",
        "netrecon.tools.banner_grab",
        "netrecon.tools.dns_lookup",
        "netrecon.tools.header_inspector",
        "netrecon.tools.log_parser",
        "netrecon.tools.pcap_viewer",
        "netrecon.tools.ping_sweep",
        "netrecon.tools.port_scanner",
        "netrecon.tools.ssl_checker",
        "netrecon.tools.subnet_calc",
        "netrecon.tools.traceroute",
        "netrecon.tools.whois_lookup",
        # --- Third-party libraries with lazy/dynamic imports ---
        # scapy: massive package with dynamic layer loading
        "scapy",
        "scapy.all",
        "scapy.layers",
        "scapy.layers.inet",
        "scapy.layers.l2",
        "scapy.layers.dns",
        "scapy.layers.http",
        # dnspython
        "dns",
        "dns.resolver",
        "dns.rdatatype",
        "dns.name",
        # httpx and its async backend
        "httpx",
        "httpx._transports",
        "httpx._transports.default",
        "anyio",
        "anyio._backends",
        "anyio._backends._asyncio",
        "h11",
        # python-whois
        "whois",
        # cryptography (used by ssl_checker indirectly via stdlib ssl)
        "cryptography",
        "cryptography.hazmat",
        "cryptography.hazmat.backends",
        "cryptography.hazmat.backends.openssl",
        "cryptography.x509",
        "_cffi_backend",
        # typer / click / rich (used by tool modules at import time)
        "typer",
        "typer.main",
        "click",
        "rich",
        "rich.console",
        "rich.table",
        "rich.panel",
        "rich.text",
        "rich.markup",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude test frameworks and dev tools from the bundle
        "pytest",
        "ruff",
        "black",
        "setuptools",
        "pip",
        "hatchling",
        # Exclude tkinter (not needed, saves space)
        "tkinter",
        "_tkinter",
        "Tkinter",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,  # one-folder mode
    name="NetRecon",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX can break Qt dylibs on macOS
    console=False,  # --windowed: no terminal window
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="NetRecon",
)

app = BUNDLE(
    coll,
    name="NetRecon.app",
    icon=None,  # Add path to .icns file here for a custom icon
    bundle_identifier="com.netrecon.app",
    info_plist={
        "CFBundleName": "NetRecon",
        "CFBundleDisplayName": "NetRecon",
        "CFBundleShortVersionString": "0.1.0",
        "CFBundleVersion": "0.1.0",
        "NSHighResolutionCapable": True,
        "NSRequiresAquaSystemAppearance": False,  # Support dark mode
        "LSMinimumSystemVersion": "10.15",
        # Network access description (for macOS privacy prompts)
        "NSLocalNetworkUsageDescription": (
            "NetRecon needs local network access for its "
            "security scanning tools."
        ),
    },
)
