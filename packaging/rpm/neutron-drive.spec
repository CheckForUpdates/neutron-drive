Name:           neutron-drive
Version:        3.0.3
Release:        1%{?dist}
Summary:        Unofficial third-party Linux desktop client and FUSE filesystem for Proton Drive

License:        GPL-3.0-or-later
URL:            https://github.com/CheckForUpdates/neutron-drive
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake >= 3.22
BuildRequires:  gcc-c++
BuildRequires:  qt6-qtbase-devel
BuildRequires:  cargo
BuildRequires:  rust >= 1.70
BuildRequires:  fuse3-devel

Requires:       qt6-qtbase
Requires:       qt6-qtbase-gui
Requires:       fuse3

%description
Neutron Drive is an independent, unofficial native Linux desktop client and
kernel FUSE virtual filesystem for Proton Drive featuring streaming OpenPGP
hydration, transactional SQLite metadata storage, offline pinning, and a native
Qt6 system tray.

%prep
%autosetup -n %{name}-%{version}

%build
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=%{_prefix} \
    -DBUILD_TESTS=ON
cmake --build build %{?_smp_mflags}

%check
QT_QPA_PLATFORM=offscreen ctest --test-dir build --output-on-failure

%install
DESTDIR=%{buildroot} cmake --install build

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/neutron-drive
%{_bindir}/neutron-drive-daemon
%{_bindir}/neutron-drive-gui
%{_datadir}/applications/neutron-drive.desktop
%{_datadir}/icons/hicolor/*/apps/neutron-drive.*
%{_userunitdir}/neutron-drive.service
