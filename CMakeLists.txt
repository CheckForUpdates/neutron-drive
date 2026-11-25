cmake_minimum_required(VERSION 3.22)
project(NeutronDrive VERSION 3.0.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network Test)

# Find Cargo for Rust backend
find_program(CARGO_EXECUTABLE cargo REQUIRED)

# Options
option(BUILD_TESTS "Build and run test suite" ON)

message(STATUS "Configuring ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS "Qt6 version: ${Qt6_VERSION}")
message(STATUS "Cargo executable: ${CARGO_EXECUTABLE}")

# -------------------------------------------------------------
# C++ Qt6 Frontend: neutron-drive-gui
# -------------------------------------------------------------
add_executable(neutron-drive-gui
    src/gui-cpp/main.cpp
    src/gui-cpp/IpcClient.cpp
    src/gui-cpp/QuotaWidget.cpp
    src/gui-cpp/PreferencesDialog.cpp
    src/gui-cpp/OnboardingDialog.cpp
    src/gui-cpp/TrayCoordinator.cpp
)

target_link_libraries(neutron-drive-gui PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)

# -------------------------------------------------------------
# Rust Backend: neutron-drive-daemon
# -------------------------------------------------------------
add_custom_target(cargo_backend ALL
    COMMAND ${CARGO_EXECUTABLE} build --release
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/crates/proton-drive-daemon
    COMMENT "Compiling Rust Neutron Drive daemon & backend"
)

# -------------------------------------------------------------
# Testing
# -------------------------------------------------------------
if(BUILD_TESTS)
    enable_testing()
    
    # Rust unit & integration tests (authoritative)
    add_test(
        NAME rust_backend_tests
        COMMAND ${CARGO_EXECUTABLE} test --all-targets
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/crates/proton-drive-daemon
    )

    # Qt IPC and UI asynchronous test
    add_executable(test_ipc_async
        tests/test_ipc_async.cpp
        src/gui-cpp/IpcClient.cpp
        src/gui-cpp/TrayCoordinator.cpp
        src/gui-cpp/QuotaWidget.cpp
        src/gui-cpp/PreferencesDialog.cpp
        src/gui-cpp/OnboardingDialog.cpp
    )
    target_link_libraries(test_ipc_async PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Network
        Qt6::Test
    )
    target_include_directories(test_ipc_async PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/gui-cpp
    )
    add_test(
        NAME qt_ipc_async_tests
        COMMAND test_ipc_async
    )

    # Qt guided onboarding test
    add_executable(test_onboarding
        tests/test_onboarding.cpp
        src/gui-cpp/IpcClient.cpp
        src/gui-cpp/QuotaWidget.cpp
        src/gui-cpp/PreferencesDialog.cpp
        src/gui-cpp/OnboardingDialog.cpp
        src/gui-cpp/TrayCoordinator.cpp
    )
    target_link_libraries(test_onboarding PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Network
        Qt6::Test
    )
    target_include_directories(test_onboarding PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/gui-cpp
    )
    add_test(
        NAME qt_onboarding_tests
        COMMAND test_onboarding
    )

    set_tests_properties(rust_backend_tests qt_ipc_async_tests qt_onboarding_tests PROPERTIES LABELS "native;authoritative")
endif()

# -------------------------------------------------------------
# Installation rules
# -------------------------------------------------------------
include(GNUInstallDirs)

# Binaries
install(
    TARGETS neutron-drive-gui
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    PROGRAMS
        ${CMAKE_CURRENT_SOURCE_DIR}/crates/proton-drive-daemon/target/release/neutron-drive-daemon
        ${CMAKE_CURRENT_SOURCE_DIR}/bin/neutron-drive
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Desktop entry
install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/desktop/neutron-drive.desktop
    DESTINATION ${CMAKE_INSTALL_DATADIR}/applications
)

# Systemd service
install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/desktop/neutron-drive.service
    DESTINATION ${CMAKE_INSTALL_DATADIR}/systemd/user
)

# Icons
foreach(SIZE 16 24 32 48 64 128 256 512)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/assets/icons/icon-${SIZE}.png")
        install(
            FILES "${CMAKE_CURRENT_SOURCE_DIR}/assets/icons/icon-${SIZE}.png"
            DESTINATION "${CMAKE_INSTALL_DATADIR}/icons/hicolor/${SIZE}x${SIZE}/apps"
            RENAME "neutron-drive.png"
        )
    endif()
endforeach()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/assets/icons/neutron-drive.svg")
    install(
        FILES "${CMAKE_CURRENT_SOURCE_DIR}/assets/icons/neutron-drive.svg"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps"
        RENAME "neutron-drive.svg"
    )
endif()

# -------------------------------------------------------------
# Packaging (CPack: .deb, .rpm, .tar.gz)
# -------------------------------------------------------------
set(CPACK_PACKAGE_NAME "neutron-drive")
set(CPACK_PACKAGE_VENDOR "Neutron Drive Contributors")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Unofficial Linux desktop client and FUSE virtual filesystem for Proton Drive")
set(CPACK_PACKAGE_DESCRIPTION
    "Unofficial third-party Rust FUSE daemon and Qt6 C++ system tray client for Proton Drive on Linux, featuring files-on-demand, transactional SQLite metadata caching, and pure-Rust OpenPGP/SRP-6a integration.")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_CONTACT "CheckForUpdates <checkforupdates@proton.me>")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set(CPACK_GENERATOR "DEB;RPM;TGZ")

# Debian / Ubuntu (.deb)
set(CPACK_DEBIAN_PACKAGE_NAME "neutron-drive")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "fuse3")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

# Fedora / RHEL (.rpm)
set(CPACK_RPM_PACKAGE_NAME "neutron-drive")
set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0-or-later")
set(CPACK_RPM_PACKAGE_GROUP "Applications/Internet")
set(CPACK_RPM_PACKAGE_REQUIRES "fuse3, qt6-qtbase, qt6-qtbase-gui")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

include(CPack)
