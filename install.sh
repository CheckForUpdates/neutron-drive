#!/usr/bin/env bash
# Source-checkout installer and uninstaller for Neutron Drive
# (unofficial Linux client for Proton Drive)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PREFIX=""
UNINSTALL=0
UPDATE_MODE=0
CHECK_ONLY=0
PURGE_DATA=0
CONFIRM_PURGE=0

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]
Options:
  --prefix <dir>   Installation prefix (default: ~/.local or /usr/local for root)
  --check          Validate Linux/FUSE/build/runtime prerequisites without writing files
  --update         Rebuild native binaries, stop running daemon via installed launcher,
                   replace binaries atomically, refresh caches, and restart daemon if active
  --uninstall      Remove only Neutron Drive prefix-owned files and disable user-service/
                   autostart entries while preserving config, credentials, metadata, and cache
  --purge-data     Separately remove local config, credentials, metadata, and cache after
                   explicit confirmation (never implied by --uninstall)
  --confirm-purge  Explicit non-interactive confirmation for --purge-data
  -h, --help       Show this help message
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            if [ -z "${2:-}" ]; then
                echo "Error: --prefix requires a directory argument." >&2
                exit 1
            fi
            PREFIX="$2"
            shift 2
            ;;
        --prefix=*)
            PREFIX="${1#*=}"
            if [ -z "$PREFIX" ]; then
                echo "Error: --prefix requires a directory argument." >&2
                exit 1
            fi
            shift
            ;;
        --update)
            UPDATE_MODE=1
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --check)
            CHECK_ONLY=1
            shift
            ;;
        --purge-data)
            PURGE_DATA=1
            shift
            ;;
        --confirm-purge)
            CONFIRM_PURGE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

MODE_COUNT=$((CHECK_ONLY + UPDATE_MODE + UNINSTALL + PURGE_DATA))
if [ "$MODE_COUNT" -gt 1 ]; then
    echo "Error: --check, --update, --uninstall, and --purge-data are mutually exclusive." >&2
    if [ "$UNINSTALL" -eq 1 ] && [ "$PURGE_DATA" -eq 1 ]; then
        echo "Run --uninstall first, then run --purge-data separately if you intend to delete local data." >&2
    fi
    exit 1
fi

if [ "$CONFIRM_PURGE" -eq 1 ] && [ "$PURGE_DATA" -eq 0 ]; then
    echo "Error: --confirm-purge can only be used with --purge-data." >&2
    exit 1
fi

DESTDIR_VAL="${DESTDIR:-}"
DESTDIR_CLEAN="${DESTDIR_VAL%/}"

if [ "$PURGE_DATA" -eq 1 ] && [ -n "$DESTDIR_VAL" ]; then
    echo "Error: --purge-data cannot be used with DESTDIR." >&2
    exit 1
fi

if [ -z "$PREFIX" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        PREFIX="/usr/local"
    else
        PREFIX="${HOME}/.local"
    fi
fi

# Normalize trailing slash (keep "/" intact)
if [ "$PREFIX" != "/" ]; then
    PREFIX="${PREFIX%/}"
fi

# Target directory with optional DESTDIR staging prefix
TARGET_PREFIX="${DESTDIR_CLEAN}${PREFIX}"
BIN_DIR="${TARGET_PREFIX}/bin"
SHARE_DIR="${TARGET_PREFIX}/share"
DESKTOP_DIR="${SHARE_DIR}/applications"
ICONS_BASE="${SHARE_DIR}/icons/hicolor"

XDG_CONFIG_ROOT="${XDG_CONFIG_HOME:-${HOME}/.config}"
XDG_DATA_ROOT="${XDG_DATA_HOME:-${HOME}/.local/share}"
XDG_CACHE_ROOT="${XDG_CACHE_HOME:-${HOME}/.cache}"
AUTOSTART_FILE="${XDG_CONFIG_ROOT}/autostart/neutron-drive.desktop"
CONFIG_DIR="${XDG_CONFIG_ROOT}/neutron-drive"
DATA_DIR="${XDG_DATA_ROOT}/neutron-drive"
CACHE_DIR="${XDG_CACHE_ROOT}/neutron-drive"
MOUNT_DIR="${HOME}/NeutronDrive"

if [ -n "$DESTDIR_VAL" ]; then
    SYSTEMD_USER_DIR="${SHARE_DIR}/systemd/user"
elif [ "$PREFIX" = "${HOME}/.local" ]; then
    SYSTEMD_USER_DIR="${XDG_CONFIG_ROOT}/systemd/user"
else
    SYSTEMD_USER_DIR="${SHARE_DIR}/systemd/user"
fi

refresh_desktop_caches() {
    if [ -n "$DESTDIR_VAL" ]; then
        return 0
    fi

    if command -v update-desktop-database >/dev/null 2>&1; then
        if [ -d "$DESKTOP_DIR" ]; then
            if ! update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1; then
                echo "Warning: update-desktop-database failed for $DESKTOP_DIR; desktop entry cache may be stale." >&2
            fi
        fi
    else
        echo "Warning: update-desktop-database not found; skipped desktop entry cache refresh." >&2
    fi

    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        if [ -d "$ICONS_BASE" ]; then
            if ! gtk-update-icon-cache -f -t "$ICONS_BASE" >/dev/null 2>&1; then
                echo "Warning: gtk-update-icon-cache failed for $ICONS_BASE; icon cache may be stale." >&2
            fi
        fi
    else
        echo "Warning: gtk-update-icon-cache not found; skipped icon cache refresh." >&2
    fi
}

reload_systemd_user() {
    if [ -n "$DESTDIR_VAL" ]; then
        return 0
    fi

    if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl --user daemon-reload >/dev/null 2>&1; then
            echo "Warning: systemctl --user daemon-reload failed; skipped systemd user unit reload." >&2
        fi
    else
        echo "Warning: systemctl not found; skipped systemd user service integration." >&2
    fi
}

stop_daemon_via_launcher() {
    local launcher=""
    if [ -x "$BIN_DIR/neutron-drive" ]; then
        launcher="$BIN_DIR/neutron-drive"
    elif [ -x "$BIN_DIR/neutron-drive-daemon" ]; then
        launcher="$BIN_DIR/neutron-drive-daemon"
    elif command -v neutron-drive >/dev/null 2>&1; then
        launcher="$(command -v neutron-drive)"
    fi

    if [ -n "$launcher" ]; then
        "$launcher" stop >/dev/null 2>&1 || true
    fi
}

if [ "$CHECK_ONLY" -eq 1 ]; then
    CHECK_FAILURES=0

    check_required() {
        local label="$1"
        shift
        if "$@" >/dev/null 2>&1; then
            echo "  ✓ ${label}"
        else
            echo "  ✗ ${label}" >&2
            CHECK_FAILURES=1
        fi
    }

    check_optional() {
        local label="$1"
        shift
        if "$@" >/dev/null 2>&1; then
            echo "  ✓ ${label} (optional)"
        else
            echo "  ! Warning: ${label} not found (optional integration will be skipped)" >&2
        fi
    }

    echo "Neutron Drive installation preflight"
    check_required "Linux host" test "$(uname -s)" = "Linux"
    check_required "cargo" command -v cargo
    check_required "rustc" command -v rustc
    check_required "cmake" command -v cmake
    check_required "C++ compiler" command -v c++
    check_required "pkg-config" command -v pkg-config
    check_required "Qt6 Core, Gui, Widgets, Network, and Test development packages" \
        pkg-config --exists Qt6Core Qt6Gui Qt6Widgets Qt6Network Qt6Test
    if command -v fusermount3 >/dev/null 2>&1 || command -v fusermount >/dev/null 2>&1; then
        echo "  ✓ FUSE mount helper"
    else
        echo "  ✗ FUSE mount helper (install fuse3 or fuse)" >&2
        CHECK_FAILURES=1
    fi

    check_optional "systemctl" command -v systemctl
    check_optional "update-desktop-database" command -v update-desktop-database
    check_optional "gtk-update-icon-cache" command -v gtk-update-icon-cache

    if [ "$CHECK_FAILURES" -ne 0 ]; then
        echo "Preflight failed. Install the missing prerequisites and run --check again." >&2
        exit 1
    fi

    echo "Preflight passed. No files were written."
    exit 0
fi

if [ "$PURGE_DATA" -eq 1 ]; then
    echo "Neutron Drive local data purge"
    echo "The following local directories will be permanently deleted:"
    echo "  Config & credentials: ${CONFIG_DIR}"
    echo "  Metadata database:    ${DATA_DIR}"
    echo "  Local cache:          ${CACHE_DIR}"
    echo "Preserved (will NOT be deleted):"
    echo "  Mount folder:         ${MOUNT_DIR}"
    echo "  Remote Proton Drive cloud files"

    if [ "$CONFIRM_PURGE" -ne 1 ]; then
        if [ -t 0 ]; then
            printf "Type 'PURGE' to permanently delete these local directories: "
            read -r CONFIRM_INPUT || CONFIRM_INPUT=""
            if [ "$CONFIRM_INPUT" != "PURGE" ]; then
                echo "Purge aborted. No user data was removed."
                exit 1
            fi
        else
            echo "Error: --purge-data requires explicit confirmation. Run interactively and type 'PURGE', or pass --confirm-purge." >&2
            exit 1
        fi
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user stop neutron-drive.service >/dev/null 2>&1 || true
    fi
    stop_daemon_via_launcher

    for dir in "$CONFIG_DIR" "$DATA_DIR" "$CACHE_DIR"; do
        if [ -z "$dir" ] || [ "$dir" = "/" ]; then
            echo "Error: Refusing to delete unsafe path '$dir'." >&2
            exit 1
        fi
        if [ -e "$dir" ]; then
            rm -rf -- "$dir"
            echo "  ✓ Removed $dir"
        else
            echo "  - Not present: $dir"
        fi
    done

    echo ""
    echo "Local data purge complete."
    echo "Preserved mount folder: ${MOUNT_DIR}"
    exit 0
fi

if [ "$UNINSTALL" -eq 1 ]; then
    echo "Uninstalling Neutron Drive from ${TARGET_PREFIX}..."

    if [ -z "$DESTDIR_VAL" ]; then
        if command -v systemctl >/dev/null 2>&1; then
            if ! systemctl --user disable --now neutron-drive.service >/dev/null 2>&1; then
                echo "Warning: systemctl --user disable --now neutron-drive.service did not complete (service may already be disabled or user systemd unavailable)." >&2
            fi
        else
            echo "Warning: systemctl not found; skipped disabling systemd user service." >&2
        fi
        stop_daemon_via_launcher
    fi

    rm -f "$BIN_DIR/neutron-drive"
    rm -f "$BIN_DIR/neutron-drive-daemon"
    rm -f "$BIN_DIR/neutron-drive-gui"
    rm -f "$BIN_DIR/proton-drive-linux"
    rm -f "$BIN_DIR/proton-drive"
    rm -f "$BIN_DIR/proton-drive-daemon"
    rm -f "$BIN_DIR/proton-drive-gui"
    echo "  ✓ Executables removed from $BIN_DIR"

    rm -f "$DESKTOP_DIR/neutron-drive.desktop"
    rm -f "$DESKTOP_DIR/proton-drive.desktop"
    echo "  ✓ Desktop entry removed from $DESKTOP_DIR"

    rm -f "$SYSTEMD_USER_DIR/neutron-drive.service"
    rm -f "$SYSTEMD_USER_DIR/proton-drive.service"
    rm -f "${SHARE_DIR}/systemd/user/neutron-drive.service"
    rm -f "${SHARE_DIR}/systemd/user/proton-drive.service"
    echo "  ✓ Systemd service removed"

    if [ -z "$DESTDIR_VAL" ]; then
        rm -f "$AUTOSTART_FILE"
        echo "  ✓ XDG autostart entry removed from $AUTOSTART_FILE"
    fi

    for sz in 16 24 32 48 64 128 256 512; do
        rm -f "$ICONS_BASE/${sz}x${sz}/apps/neutron-drive.png"
        rm -f "$ICONS_BASE/${sz}x${sz}/apps/proton-drive.png"
    done
    rm -f "$ICONS_BASE/scalable/apps/neutron-drive.svg"
    echo "  ✓ Application icons removed from $ICONS_BASE"

    reload_systemd_user
    refresh_desktop_caches

    echo ""
    echo "Uninstallation complete!"
    if [ -z "$DESTDIR_VAL" ]; then
        echo "Preserved user data (not removed by --uninstall):"
        echo "  Config & credentials: ${CONFIG_DIR}"
        echo "  Metadata database:    ${DATA_DIR}"
        echo "  Local cache:          ${CACHE_DIR}"
        echo "  Default mount folder: ${MOUNT_DIR}"
        echo "Run './install.sh --purge-data' separately only if you intend to delete local configuration, credentials, metadata, and cache."
    fi
    exit 0
fi

install_binary_atomic() {
    local src="$1"
    local dst="$2"
    local tmp_dst="${dst}.tmp.$$"
    cp "$src" "$tmp_dst"
    chmod 755 "$tmp_dst"
    mv -f "$tmp_dst" "$dst"
}

# Compile native binaries if not yet built (or always rebuild on --update)
DAEMON_SRC_BIN="$SCRIPT_DIR/crates/proton-drive-daemon/target/release/neutron-drive-daemon"
GUI_SRC_BIN="$SCRIPT_DIR/build/neutron-drive-gui"

if [ "$UPDATE_MODE" -eq 1 ] || [ ! -f "$DAEMON_SRC_BIN" ]; then
    echo "Compiling Rust Neutron Drive daemon..."
    if command -v cargo >/dev/null 2>&1; then
        cargo build --release --manifest-path "$SCRIPT_DIR/crates/proton-drive-daemon/Cargo.toml"
    else
        echo "Error: cargo is required to compile neutron-drive-daemon but was not found." >&2
        exit 1
    fi
fi

if [ "$UPDATE_MODE" -eq 1 ] || [ ! -f "$GUI_SRC_BIN" ]; then
    echo "Compiling native GUI with CMake..."
    if command -v cmake >/dev/null 2>&1; then
        cmake -B "$SCRIPT_DIR/build" -S "$SCRIPT_DIR"
        cmake --build "$SCRIPT_DIR/build" --target neutron-drive-gui
    else
        echo "Error: cmake is required to compile neutron-drive-gui but was not found." >&2
        exit 1
    fi
fi

WAS_DAEMON_RUNNING=0
if [ "$UPDATE_MODE" -eq 1 ] && [ -z "$DESTDIR_VAL" ]; then
    INSTALLED_LAUNCHER=""
    if [ -x "$BIN_DIR/neutron-drive" ]; then
        INSTALLED_LAUNCHER="$BIN_DIR/neutron-drive"
    elif [ -x "$BIN_DIR/neutron-drive-daemon" ]; then
        INSTALLED_LAUNCHER="$BIN_DIR/neutron-drive-daemon"
    fi

    if [ -n "$INSTALLED_LAUNCHER" ]; then
        if "$INSTALLED_LAUNCHER" status --json 2>/dev/null | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"'; then
            echo "Stopping running Neutron Drive daemon before update via ${INSTALLED_LAUNCHER}..."
            "$INSTALLED_LAUNCHER" stop >/dev/null 2>&1 || true
            WAS_DAEMON_RUNNING=1
        fi
    fi
fi

echo "Installing Neutron Drive to ${TARGET_PREFIX}..."

# 1. Install native binaries atomically and retire any legacy bundled CLI binary
mkdir -p "$BIN_DIR"
install_binary_atomic "$DAEMON_SRC_BIN" "$BIN_DIR/neutron-drive-daemon"
install_binary_atomic "$GUI_SRC_BIN" "$BIN_DIR/neutron-drive-gui"
install_binary_atomic "$SCRIPT_DIR/bin/neutron-drive" "$BIN_DIR/neutron-drive"
rm -f "$BIN_DIR/proton-drive"
echo "  ✓ Native binaries installed to $BIN_DIR"

# 2. Install desktop application launcher
mkdir -p "$DESKTOP_DIR"
cp "$SCRIPT_DIR/desktop/neutron-drive.desktop" "$DESKTOP_DIR/neutron-drive.desktop"
chmod 644 "$DESKTOP_DIR/neutron-drive.desktop"
echo "  ✓ Desktop entry installed to $DESKTOP_DIR"

# 3. Install icons into hicolor icon theme
for sz in 16 24 32 48 64 128 256 512; do
    if [ -f "$SCRIPT_DIR/assets/icons/icon-${sz}.png" ]; then
        DEST_DIR="$ICONS_BASE/${sz}x${sz}/apps"
        mkdir -p "$DEST_DIR"
        cp "$SCRIPT_DIR/assets/icons/icon-${sz}.png" "$DEST_DIR/neutron-drive.png"
        chmod 644 "$DEST_DIR/neutron-drive.png"
    fi
done
if [ -f "$SCRIPT_DIR/assets/icons/neutron-drive.svg" ]; then
    SCALABLE_DIR="$ICONS_BASE/scalable/apps"
    mkdir -p "$SCALABLE_DIR"
    cp "$SCRIPT_DIR/assets/icons/neutron-drive.svg" "$SCALABLE_DIR/neutron-drive.svg"
    chmod 644 "$SCALABLE_DIR/neutron-drive.svg"
fi
echo "  ✓ Application icons installed to $ICONS_BASE"

# 4. Install systemd user service unit
mkdir -p "$SYSTEMD_USER_DIR"
cp "$SCRIPT_DIR/desktop/neutron-drive.service" "$SYSTEMD_USER_DIR/neutron-drive.service"
chmod 644 "$SYSTEMD_USER_DIR/neutron-drive.service"
echo "  ✓ Systemd user service installed to $SYSTEMD_USER_DIR"

# 5. Refresh desktop/icon caches and systemd user daemon if available
refresh_desktop_caches
reload_systemd_user

# 6. Restart daemon if it was stopped for --update
if [ "$WAS_DAEMON_RUNNING" -eq 1 ]; then
    echo "Restarting Neutron Drive daemon..."
    "$BIN_DIR/neutron-drive" start
fi

echo ""
if [ "$UPDATE_MODE" -eq 1 ]; then
    echo "Update complete!"
else
    echo "Installation complete!"
fi
echo "Run 'neutron-drive status' to verify."
echo "Run 'neutron-drive gui' to start the system tray application."
