#include "TrayCoordinator.hpp"
#include <QApplication>
#include <QDesktopServices>
#include <QUrl>
#include <QPainter>
#include <QPixmap>
#include <QFileInfo>
#include <QDir>
#include <QPointer>
#include <QCoreApplication>
#include <QStandardPaths>
#include <QFile>
#include <algorithm>

namespace {

QPixmap loadAppPixmap(int size = 32) {
    // 1. QIcon::fromTheme("neutron-drive")
    if (QIcon::hasThemeIcon("neutron-drive")) {
        QIcon themeIcon = QIcon::fromTheme("neutron-drive");
        if (!themeIcon.isNull()) {
            QPixmap px = themeIcon.pixmap(size, size);
            if (!px.isNull()) {
                return px;
            }
        }
    }

    // 2. Search QStandardPaths::locate(QStandardPaths::GenericDataLocation, "icons/hicolor/64x64/apps/neutron-drive.png") (and 32x32, etc.)
    QStringList preferredSizes = {
        QString("%1x%1").arg(size),
        "32x32", "64x64", "48x48", "128x128", "256x256", "16x16"
    };
    preferredSizes.removeDuplicates();

    for (const QString &sz : preferredSizes) {
        QString relPath = QString("icons/hicolor/%1/apps/neutron-drive.png").arg(sz);
        QString found = QStandardPaths::locate(QStandardPaths::GenericDataLocation, relPath);
        if (!found.isEmpty() && QFile::exists(found)) {
            QPixmap px(found);
            if (!px.isNull()) {
                return px.scaled(size, size, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            }
        }
    }

    // 3. Search next to executable (QCoreApplication::applicationDirPath() + "/../share/icons/..." or ./assets/icons/...)
    QString appDir = QCoreApplication::applicationDirPath();
    for (const QString &sz : preferredSizes) {
        QString installedPath = appDir + QString("/../share/icons/hicolor/%1/apps/neutron-drive.png").arg(sz);
        if (QFile::exists(installedPath)) {
            QPixmap px(installedPath);
            if (!px.isNull()) {
                return px.scaled(size, size, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            }
        }
    }

    QStringList assetCandidates = {
        appDir + QString("/../assets/icons/icon-%1.png").arg(size),
        appDir + "/../assets/icons/icon-32.png",
        appDir + "/../assets/icons/icon-64.png",
        QString("./assets/icons/icon-%1.png").arg(size),
        "./assets/icons/icon-32.png",
        "./assets/icons/icon-64.png"
    };
    for (const QString &p : assetCandidates) {
        if (QFile::exists(p)) {
            QPixmap px(p);
            if (!px.isNull()) {
                return px.scaled(size, size, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            }
        }
    }

    // 4. Fallback to programmatic Neutron Drive emblem
    QPixmap fallback(size, size);
    fallback.fill(Qt::transparent);
    QPainter p(&fallback);
    p.setRenderHint(QPainter::Antialiasing);
    p.setBrush(QColor("#0e7490"));
    p.setPen(Qt::NoPen);
    int m = std::max(2, size / 16);
    int r = std::max(4, size / 5);
    p.drawRoundedRect(m, m, size - 2 * m, size - 2 * m, r, r);
    p.setBrush(Qt::NoBrush);
    p.setPen(QPen(QColor("#e0f2fe"), std::max(1.5, size / 14.0)));
    int ringPad = std::max(5, size / 4);
    p.drawEllipse(ringPad, ringPad, size - 2 * ringPad, size - 2 * ringPad);
    p.setBrush(QColor("#ffffff"));
    p.setPen(Qt::NoPen);
    int dotR = std::max(2, size / 8);
    p.drawEllipse(QPoint(size / 2, size / 2), dotR, dotR);
    p.end();

    return fallback;
}

} // namespace

TrayCoordinator::TrayCoordinator(IpcClient *client, QObject *parent, QSettings *settings)
    : QObject(parent)
    , m_client(client)
    , m_trayIcon(new QSystemTrayIcon(this))
    , m_menu(new QMenu())
    , m_timer(new QTimer(this))
    , m_quotaWidget(nullptr)
    , m_quotaAction(nullptr)
    , m_actOpenFolder(nullptr)
    , m_actPauseResume(nullptr)
    , m_actRefresh(nullptr)
    , m_actPreferences(nullptr)
    , m_actQuit(nullptr)
    , m_prefDialog(nullptr)
    , m_onboardingDialog(nullptr)
    , m_settings(settings)
    , m_mountPoint(QDir::homePath() + "/NeutronDrive")
    , m_isPaused(false)
    , m_lastStatus("idle")
    , m_statusInflight(false)
    , m_hasSeenAuthSuccess(false)
    , m_authExpiredNotified(false)
    , m_lastErrorCount(0)
    , m_notificationCount(0)
{
}

TrayCoordinator::~TrayCoordinator() {
    if (m_trayIcon) {
        m_trayIcon->setContextMenu(nullptr);
    }
    delete m_onboardingDialog;
    m_onboardingDialog = nullptr;
    delete m_prefDialog;
    m_prefDialog = nullptr;
    delete m_menu;
    m_menu = nullptr;
}

void TrayCoordinator::initTray() {
    m_quotaWidget = new QuotaWidget();
    m_quotaAction = new QWidgetAction(m_menu);
    m_quotaAction->setDefaultWidget(m_quotaWidget);

    m_menu->addAction(m_quotaAction);
    m_menu->addSeparator();

    m_actOpenFolder = m_menu->addAction("Open Neutron Drive Folder", this, &TrayCoordinator::onOpenFolder);
    m_actPauseResume = m_menu->addAction("Pause Syncing", this, &TrayCoordinator::onTogglePause);
    m_actRefresh = m_menu->addAction("Refresh", this, &TrayCoordinator::onRefresh);
    m_menu->addSeparator();

    m_actPreferences = m_menu->addAction("Preferences...", this, &TrayCoordinator::onShowPreferences);
    m_menu->addSeparator();

    m_actQuit = m_menu->addAction("Quit Neutron Drive", qApp, &QCoreApplication::quit);

    m_trayIcon->setContextMenu(m_menu);
    m_trayIcon->setIcon(createStatusIcon("idle"));
    m_trayIcon->setToolTip("Neutron Drive - Initializing...");
    m_trayIcon->show();

    connect(m_trayIcon, &QSystemTrayIcon::activated, this, &TrayCoordinator::onTrayActivated);
    connect(m_trayIcon, &QSystemTrayIcon::messageClicked, this, &TrayCoordinator::onShowPreferences);

    connect(m_timer, &QTimer::timeout, this, &TrayCoordinator::pollStatus);
    m_timer->start(3000);
    pollStatus();
}

void TrayCoordinator::showTrayNotification(
    const QString &title,
    const QString &message,
    QSystemTrayIcon::MessageIcon icon
) {
    m_notificationCount++;
    m_lastNotificationTitle = title;
    m_lastNotificationMessage = message;
    emit notificationShown(title, message);
    if (m_trayIcon) {
        m_trayIcon->showMessage(title, message, icon, 8000);
    }
}

QIcon TrayCoordinator::createStatusIcon(const QString &status) {
    QPixmap pixmap = loadAppPixmap(32);

    // Paint status dot on bottom-right corner
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);

    QColor badgeColor;
    if (status == "syncing") {
        badgeColor = QColor("#00aaff"); // Blue
    } else if (status == "paused") {
        badgeColor = QColor("#ffa500"); // Orange
    } else if (status == "error") {
        badgeColor = QColor("#ff4444"); // Red
    } else if (status == "offline") {
        badgeColor = QColor("#888888"); // Grey
    } else {
        badgeColor = QColor("#22cc66"); // Green / Synced
    }

    painter.setBrush(badgeColor);
    painter.setPen(QPen(Qt::white, 1.5));
    painter.drawEllipse(20, 20, 10, 10);
    painter.end();

    return QIcon(pixmap);
}

void TrayCoordinator::pollStatus() {
    if (m_statusInflight) {
        return;
    }
    m_statusInflight = true;

    QPointer<TrayCoordinator> self(this);
    m_client->sendCommandAsync("status", [this, self](const QJsonObject &res) {
        if (!self) {
            return;
        }
        m_statusInflight = false;

        if (res.value("status").toString() != "ok") {
            m_lastStatus = "offline";
            if (m_trayIcon) {
                m_trayIcon->setIcon(createStatusIcon("offline"));
                m_trayIcon->setToolTip("Neutron Drive - Daemon Offline");
            }
            return;
        }

        QString syncStatus = res.value("sync_status").toString("idle");
        m_isPaused = res.value("is_paused").toBool(false);
        m_mountPoint = res.value("mount_point").toString(m_mountPoint);

        if (m_actPauseResume) {
            if (m_isPaused) {
                m_actPauseResume->setText("Resume Syncing");
            } else {
                m_actPauseResume->setText("Pause Syncing");
            }
        }

        bool offlineMode = res.value("offline_mode").toBool(false);
        int pendingUploads = res.value("pending_uploads").toInt(0);
        int errorCount = res.value("error_count").toInt(0);
        QString lastError = res.value("last_error").toString();

        bool hasAuthField = res.contains("authenticated");
        bool authenticated = res.value("authenticated").toBool(true);
        QString authMessage = res.value("auth_message").toString();

        if (hasAuthField) {
            if (authenticated) {
                m_hasSeenAuthSuccess = true;
                m_authExpiredNotified = false;
            } else {
                bool indicatesExpiration =
                    authMessage.contains("expired", Qt::CaseInsensitive)
                    || authMessage.contains("revoked", Qt::CaseInsensitive);
                if ((m_hasSeenAuthSuccess || indicatesExpiration) && !m_authExpiredNotified) {
                    m_authExpiredNotified = true;
                    QString body = authMessage.isEmpty()
                        ? QString("Your Neutron Drive session expired. Open Preferences to sign in again.")
                        : QString("Authentication expired: %1. Open Preferences to sign in again.").arg(authMessage);
                    showTrayNotification("Neutron Drive - Session Expired", body, QSystemTrayIcon::Warning);
                }
            }
        }

        if (errorCount > 0) {
            if (errorCount > m_lastErrorCount || (!lastError.isEmpty() && lastError != m_lastNotifiedError)) {
                QString body = lastError.isEmpty()
                    ? QString("%1 sync/upload error(s) occurred. Open Preferences to retry or clear errors.")
                          .arg(errorCount)
                    : QString("%1 (%2 error(s) total)").arg(lastError).arg(errorCount);
                showTrayNotification("Neutron Drive - Sync Error", body, QSystemTrayIcon::Warning);
                m_lastNotifiedError = lastError;
            }
        } else {
            m_lastNotifiedError.clear();
        }
        m_lastErrorCount = errorCount;

        QString displayStatus = offlineMode
            ? QString("offline")
            : (m_isPaused ? QString("paused")
                : (errorCount > 0 ? QString("error") : syncStatus));

        QString tooltip = QString("Neutron Drive - %1")
            .arg(displayStatus.at(0).toUpper() + displayStatus.mid(1));
        if (hasAuthField && !authenticated) {
            tooltip += QString(" (Not Authenticated)");
        }
        if (pendingUploads > 0 || errorCount > 0) {
            tooltip += QString(" (Pending: %1, Errors: %2)")
                .arg(pendingUploads)
                .arg(errorCount);
        }
        if (!lastError.isEmpty()) {
            tooltip += QString("\nLast error: %1").arg(lastError);
        }

        if (displayStatus != m_lastStatus) {
            m_lastStatus = displayStatus;
            if (m_trayIcon) {
                m_trayIcon->setIcon(createStatusIcon(displayStatus));
            }
        }
        if (m_trayIcon) {
            m_trayIcon->setToolTip(tooltip);
        }

        if (res.contains("quota") && res.value("quota").isObject()) {
            QJsonObject q = res.value("quota").toObject();
            quint64 used = static_cast<quint64>(q.value("used_bytes").toDouble());
            quint64 total = static_cast<quint64>(q.value("total_bytes").toDouble());
            double pct = q.value("percent_used").toDouble();
            if (m_quotaWidget) {
                m_quotaWidget->updateQuota(used, total, pct);
            }
        }
    });
}

void TrayCoordinator::onOpenFolder() {
    QDesktopServices::openUrl(QUrl::fromLocalFile(m_mountPoint));
}

void TrayCoordinator::onTogglePause() {
    QString cmd = m_isPaused ? "resume" : "pause";
    QPointer<TrayCoordinator> self(this);
    m_client->sendCommandAsync(cmd, [this, self](const QJsonObject &) {
        if (!self) {
            return;
        }
        pollStatus();
    });
}

void TrayCoordinator::onRefresh() {
    QPointer<TrayCoordinator> self(this);
    m_client->sendCommandAsync("refresh", [this, self](const QJsonObject &) {
        if (!self) {
            return;
        }
        pollStatus();
    });
}

PreferencesDialog *TrayCoordinator::preferencesDialog() {
    if (!m_prefDialog) {
        m_prefDialog = new PreferencesDialog(m_client);
    }
    return m_prefDialog;
}

bool TrayCoordinator::shouldShowOnboarding() const {
    if (m_settings) {
        return OnboardingDialog::shouldShowOnboarding(*m_settings);
    }
    auto defaultSettings = OnboardingDialog::createDefaultSettings();
    return OnboardingDialog::shouldShowOnboarding(*defaultSettings);
}

bool TrayCoordinator::runOnboardingIfNeeded(bool blocking) {
    if (!shouldShowOnboarding()) {
        return false;
    }

    if (m_onboardingDialog) {
        delete m_onboardingDialog;
        m_onboardingDialog = nullptr;
    }

    m_onboardingDialog = new OnboardingDialog(preferencesDialog(), m_settings);
    connect(m_onboardingDialog, &QDialog::finished, this, [this](int) {
        pollStatus();
    });

    if (blocking) {
        m_onboardingDialog->exec();
        pollStatus();
    } else {
        m_onboardingDialog->show();
        m_onboardingDialog->raise();
        m_onboardingDialog->activateWindow();
    }
    return true;
}

void TrayCoordinator::onShowPreferences() {
    PreferencesDialog *prefs = preferencesDialog();
    prefs->refreshData();
    prefs->show();
    prefs->raise();
    prefs->activateWindow();
}

void TrayCoordinator::onTrayActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::DoubleClick) {
        onOpenFolder();
    }
}
