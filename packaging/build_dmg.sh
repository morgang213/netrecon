#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# build_dmg.sh — Build NetRecon.app and package it into a .dmg
# ─────────────────────────────────────────────────────────────
# Usage:   ./packaging/build_dmg.sh
# Requires: Python venv at .venv/
# Outputs:  dist/NetRecon.dmg
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_ROOT/.venv"
DIST_DIR="$PROJECT_ROOT/dist"
BUILD_DIR="$PROJECT_ROOT/build"
APP_NAME="NetRecon"
DMG_NAME="NetRecon"
VOLUME_NAME="NetRecon Installer"

echo "═══════════════════════════════════════════════"
echo "  NetRecon macOS Build"
echo "═══════════════════════════════════════════════"

# ── Step 1: Verify Python venv ────────────────────────────────
echo ""
echo "▸ Step 1: Checking Python environment..."

if [ ! -f "$VENV_DIR/bin/python" ]; then
    echo "  ERROR: Virtual environment not found at $VENV_DIR"
    echo "  Create it with: python3 -m venv .venv"
    exit 1
fi

PYTHON="$VENV_DIR/bin/python"
PIP="$VENV_DIR/bin/pip"

PY_VERSION=$("$PYTHON" --version 2>&1 | awk '{print $2}')
echo "  Python version: $PY_VERSION"

# ── Step 2: Install build dependencies ────────────────────────
echo ""
echo "▸ Step 2: Installing PyInstaller and project dependencies..."

"$PIP" install --upgrade pip --quiet
"$PIP" install pyinstaller --quiet

# Install project in editable mode so netrecon package is importable
"$PIP" install -e "$PROJECT_ROOT" --quiet

echo "  PyInstaller version: $("$VENV_DIR/bin/pyinstaller" --version)"

# ── Step 3: Clean previous builds ─────────────────────────────
echo ""
echo "▸ Step 3: Cleaning previous build artifacts..."

rm -rf "$BUILD_DIR" "$DIST_DIR"
echo "  Cleaned build/ and dist/"

# ── Step 4: Run PyInstaller ───────────────────────────────────
echo ""
echo "▸ Step 4: Building $APP_NAME.app with PyInstaller..."

"$VENV_DIR/bin/pyinstaller" \
    --noconfirm \
    --clean \
    --distpath "$DIST_DIR" \
    --workpath "$BUILD_DIR" \
    "$SCRIPT_DIR/netrecon.spec"

APP_PATH="$DIST_DIR/$APP_NAME.app"

if [ ! -d "$APP_PATH" ]; then
    echo "  ERROR: $APP_NAME.app was not created."
    echo "  Check PyInstaller output above for errors."
    exit 1
fi

APP_SIZE=$(du -sh "$APP_PATH" | awk '{print $1}')
echo "  Built: $APP_PATH ($APP_SIZE)"

# ── Step 5: Quick smoke test ──────────────────────────────────
echo ""
echo "▸ Step 5: Smoke-testing the .app bundle..."

# Test that the binary exists and is executable
if [ -x "$APP_PATH/Contents/MacOS/$APP_NAME" ]; then
    echo "  Smoke test: binary exists and is executable"
else
    echo "  WARNING: Binary not found or not executable at:"
    echo "    $APP_PATH/Contents/MacOS/$APP_NAME"
fi

# ── Step 6: Create .dmg ──────────────────────────────────────
echo ""
echo "▸ Step 6: Creating $DMG_NAME.dmg..."

DMG_PATH="$DIST_DIR/$DMG_NAME.dmg"
DMG_TEMP="$DIST_DIR/${DMG_NAME}_temp.dmg"

# Remove stale dmg files
rm -f "$DMG_PATH" "$DMG_TEMP"

# Create a temporary read-write DMG
hdiutil create \
    -srcfolder "$APP_PATH" \
    -volname "$VOLUME_NAME" \
    -fs HFS+ \
    -fsargs "-c c=64,a=16,e=16" \
    -format UDRW \
    "$DMG_TEMP" \
    -quiet

# Mount it
MOUNT_OUTPUT=$(hdiutil attach -readwrite -noverify "$DMG_TEMP" 2>&1)
MOUNT_POINT=$(echo "$MOUNT_OUTPUT" | grep '/Volumes/' | sed 's/.*\(\/Volumes\/.*\)/\1/' | xargs)

if [ -z "$MOUNT_POINT" ]; then
    echo "  ERROR: Failed to mount temporary DMG"
    echo "  Output: $MOUNT_OUTPUT"
    exit 1
fi

echo "  Mounted at: $MOUNT_POINT"

# Add a symlink to /Applications for drag-install
ln -s /Applications "$MOUNT_POINT/Applications"

# Set Finder view options via AppleScript
osascript <<APPLESCRIPT || true
tell application "Finder"
    tell disk "$VOLUME_NAME"
        open
        set current view of container window to icon view
        set toolbar visible of container window to false
        set statusbar visible of container window to false
        set the bounds of container window to {200, 200, 700, 450}
        set viewOptions to the icon view options of container window
        set arrangement of viewOptions to not arranged
        set icon size of viewOptions to 80
        set position of item "$APP_NAME.app" of container window to {130, 120}
        set position of item "Applications" of container window to {370, 120}
        close
        open
        update without registering applications
    end tell
end tell
APPLESCRIPT

# Wait for Finder to finish
sleep 2

# Unmount
hdiutil detach "$MOUNT_POINT" -quiet || hdiutil detach "$MOUNT_POINT" -force -quiet

# Convert to compressed, read-only DMG
hdiutil convert "$DMG_TEMP" \
    -format UDZO \
    -imagekey zlib-level=9 \
    -o "$DMG_PATH" \
    -quiet

rm -f "$DMG_TEMP"

DMG_SIZE=$(du -sh "$DMG_PATH" | awk '{print $1}')
echo "  Created: $DMG_PATH ($DMG_SIZE)"

# ── Done ─────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════"
echo "  Build complete!"
echo "  .app:  $APP_PATH"
echo "  .dmg:  $DMG_PATH"
echo "═══════════════════════════════════════════════"
