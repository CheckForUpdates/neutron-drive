#include <QApplication>
#include <QMessageBox>
#include <QSystemTrayIcon>
#include <QIcon>
#include <QFile>
#include <QTimer>

#include "IpcClient.hpp"
#include "OnboardingDialog.hpp"
#include "TrayCoordinator.hpp"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setOrganizationName(OnboardingDialog::kSettingsOrganization);
    app.setApplicationName("neutron-drive-gui");
    app.setApplicationDisplayName("Neutron Drive");
    app.setApplicationVersion("3.0.3");
    app.setQuitOnLastWindowClosed(false);

    QString iconPath = "./assets/icons/icon-64.png";
    if (QFile::exists(iconPath)) {
        app.setWindowIcon(QIcon(iconPath));
    }

    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        QMessageBox::critical(
            nullptr,
            "Neutron Drive",
            "System tray is not available on this desktop environment."
        );
        return 1;
    }

    auto *client = new IpcClient(QString(), &app);
    const QString noAutostart = qEnvironmentVariable("PROTON_DRIVE_NO_AUTOSTART_DAEMON").trimmed();
    if (noAutostart != "1" && noAutostart.compare("true", Qt::CaseInsensitive) != 0) {
        client->ensureDaemonRunning();
    }
    auto *tray = new TrayCoordinator(client, &app);
    tray->initTray();
    QTimer::singleShot(0, tray, [tray]() {
        tray->runOnboardingIfNeeded(true);
    });

    return app.exec();
}
