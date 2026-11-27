# Distribution Packaging & Desktop Integration

This guide covers community distribution packaging recipes and desktop environment integration for **Neutron Drive**.

---

## 1. Distribution Packaging Recipes

### Arch Linux (AUR)
The recipe in [`packaging/arch/PKGBUILD`](../packaging/arch/PKGBUILD) builds Neutron Drive from a release source tarball, executes the headless `ctest` suite in `check()`, and installs binaries, desktop entries, icons, systemd user unit, and GPL-3.0-or-later license.

Before pushing a release to AUR:
1. Update `pkgver` and `pkgrel` in [`packaging/arch/PKGBUILD`](../packaging/arch/PKGBUILD).
2. Point `source=()` to the tagged GitHub release tarball and replace `sha256sums=('SKIP')` with the verified SHA-256 checksum from `SHA256SUMS.txt`.
3. Regenerate `.SRCINFO` via `makepkg --printsrcinfo > .SRCINFO` in your AUR package repository.

### Fedora / RHEL (RPM / COPR)
[`packaging/rpm/neutron-drive.spec`](../packaging/rpm/neutron-drive.spec) provides a complete RPM spec for COPR or `rpmbuild` using `qt6-qtbase-devel`, `cargo`, `rust`, `cmake`, and `fuse3-devel`, running `QT_QPA_PLATFORM=offscreen ctest` in `%check`.

### Flatpak (Experimental)
[`packaging/flatpak/io.github.CheckForUpdates.NeutronDrive.yml`](../packaging/flatpak/io.github.CheckForUpdates.NeutronDrive.yml) provides a starting Flatpak manifest using `org.kde.Platform//6.8` and `org.freedesktop.Sdk.Extension.rust-stable`.

> **Sandbox Caveat:** Kernel `/dev/fuse` mounts from inside a Flatpak sandbox require `--device=all` and `--filesystem=home`, and host file-manager visibility depends on host FUSE mount propagation (`fusermount3`). For most desktop users, native `.deb`, `.rpm`, or Arch packages are recommended over Flatpak.

---

## 2. File Manager Context Actions (Offline Pinning)

### KDE Dolphin Service Menu
Install [`packaging/dolphin/neutron-drive.servicemenu.desktop`](../packaging/dolphin/neutron-drive.servicemenu.desktop) into KDE's service menu directory:
```bash
mkdir -p ~/.local/share/kio/servicemenus
cp packaging/dolphin/neutron-drive.servicemenu.desktop ~/.local/share/kio/servicemenus/
chmod +x ~/.local/share/kio/servicemenus/neutron-drive.servicemenu.desktop
```
Right-clicking files or folders inside `~/NeutronDrive` in Dolphin exposes **Neutron Drive → Pin for Offline Access** and **Unpin Offline Copy**.

### GNOME Files (Nautilus) Scripts
Install the Nautilus scripts from [`packaging/nautilus/`](../packaging/nautilus/):
```bash
mkdir -p ~/.local/share/nautilus/scripts/"Neutron Drive"
cp packaging/nautilus/neutron-drive-pin.sh ~/.local/share/nautilus/scripts/"Neutron Drive"/"Pin for Offline Access"
cp packaging/nautilus/neutron-drive-unpin.sh ~/.local/share/nautilus/scripts/"Neutron Drive"/"Unpin Offline Copy"
chmod +x ~/.local/share/nautilus/scripts/"Neutron Drive"/*
```

---

## 3. Wayland, System Tray & Secret Service Notes

- **GNOME (Wayland):** Standard GNOME Shell hides legacy XEmbed tray icons unless the **AppIndicator and KStatusNotifierItem Support** extension (`gnome-shell-extension-appindicator`) is enabled.
- **KDE Plasma / Sway / Hyprland:** Uses `StatusNotifierItem` (`org.kde.StatusNotifierWatcher`) cleanly when `waybar` (with `tray` module) or Plasma's system tray widget is active.
- **Secret Service (`zbus`):** `SessionVault` uses `org.freedesktop.secrets` (GNOME Keyring or KWallet Secret Service) when unlocked, and falls back to encrypted local vault storage (`0600`) on headless or minimal window-manager sessions without an active keyring daemon.
