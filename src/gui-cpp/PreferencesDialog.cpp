#include "PreferencesDialog.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QFileDialog>
#include <QMessageBox>
#include <QStandardPaths>
#include <QIcon>
#include <QDir>
#include <QPointer>
#include <QCoreApplication>
#include <QPainter>
#include <QPixmap>
#include <QFile>
#include <QFileInfo>
#include <QInputDialog>
#include <QDialogButtonBox>
#include <QSpinBox>
#include <QDesktopServices>
#include <QUrl>
#include <algorithm>

namespace {

QIcon loadPreferencesAppIcon(int size = 64) {
    // 1. QIcon::fromTheme("neutron-drive")
    if (QIcon::hasThemeIcon("neutron-drive")) {
        QIcon themeIcon = QIcon::fromTheme("neutron-drive");
        if (!themeIcon.isNull()) {
            return themeIcon;
        }
    }

    // 2. Search QStandardPaths::locate(QStandardPaths::GenericDataLocation, "icons/hicolor/64x64/apps/neutron-drive.png") (and 32x32, etc.)
    QStringList sizes = {
        QString("%1x%1").arg(size),
        "64x64", "128x128", "256x256", "48x48", "32x32", "16x16"
    };
    sizes.removeDuplicates();

    for (const QString &sz : sizes) {
        QString relPath = QString("icons/hicolor/%1/apps/neutron-drive.png").arg(sz);
        QString found = QStandardPaths::locate(QStandardPaths::GenericDataLocation, relPath);
        if (!found.isEmpty() && QFile::exists(found)) {
            return QIcon(found);
        }
    }

    // 3. Search next to executable (QCoreApplication::applicationDirPath() + "/../share/icons/..." or ./assets/icons/...)
    QString appDir = QCoreApplication::applicationDirPath();
    for (const QString &sz : sizes) {
        QString installedPath = appDir + QString("/../share/icons/hicolor/%1/apps/neutron-drive.png").arg(sz);
        if (QFile::exists(installedPath)) {
            return QIcon(installedPath);
        }
    }

    QStringList assetCandidates = {
        appDir + QString("/../assets/icons/icon-%1.png").arg(size),
        appDir + "/../assets/icons/icon-64.png",
        appDir + "/../assets/icons/icon-32.png",
        QString("./assets/icons/icon-%1.png").arg(size),
        "./assets/icons/icon-64.png",
        "./assets/icons/icon-32.png"
    };
    for (const QString &p : assetCandidates) {
        if (QFile::exists(p)) {
            return QIcon(p);
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

    return QIcon(fallback);
}

} // namespace

PreferencesDialog::PreferencesDialog(IpcClient *client, QWidget *parent)
    : QDialog(parent)
    , m_client(client)
    , m_authenticated(false)
    , m_isMounted(false)
    , m_mountPoint("~/NeutronDrive")
    , m_lastPollInterval(30)
    , m_lastCacheMaxMb(5120)
    , m_lastCacheTtlHours(168)
    , m_browserPollTimer(nullptr)
{
    setWindowTitle("Neutron Drive - Preferences");
    resize(520, 420);

    QIcon appIcon = loadPreferencesAppIcon(64);
    if (!appIcon.isNull()) {
        setWindowIcon(appIcon);
    }

    initUi();
    refreshData();
}

void PreferencesDialog::initUi() {
    auto *mainLayout = new QVBoxLayout(this);

    m_tabs = new QTabWidget(this);
    mainLayout->addWidget(m_tabs);

    // --- Tab 1: Account ---
    auto *tabAccount = new QWidget(this);
    auto *layoutAccount = new QVBoxLayout(tabAccount);

    auto *grpAccount = new QGroupBox("Proton Account", tabAccount);
    auto *formAccount = new QFormLayout(grpAccount);

    m_lblAuthStatus = new QLabel("Checking...", grpAccount);
    formAccount->addRow("Status:", m_lblAuthStatus);

    m_lblSyncSummary = new QLabel("Sync: checking...", grpAccount);
    m_lblSyncSummary->setWordWrap(true);
    formAccount->addRow("Sync Activity:", m_lblSyncSummary);

    m_accountQuota = new QuotaWidget(grpAccount);
    formAccount->addRow(m_accountQuota);

    auto *lblThirdParty = new QLabel(
        "This is a third-party application not officially supported by Proton. "
        "Passwords are never stored locally.",
        grpAccount
    );
    lblThirdParty->setWordWrap(true);
    lblThirdParty->setStyleSheet("color: #555; font-size: 11px;");
    formAccount->addRow("", lblThirdParty);

    auto *rowAccountActions = new QHBoxLayout();
    m_btnLogin = new QPushButton("Log In", grpAccount);
    m_btnLogin->setFixedWidth(120);
    connect(m_btnLogin, &QPushButton::clicked, this, &PreferencesDialog::onLogin);

    m_btnLogout = new QPushButton("Log Out", grpAccount);
    m_btnLogout->setFixedWidth(120);
    connect(m_btnLogout, &QPushButton::clicked, this, &PreferencesDialog::onLogout);

    rowAccountActions->addWidget(m_btnLogin);
    rowAccountActions->addWidget(m_btnLogout);
    rowAccountActions->addStretch();
    formAccount->addRow("", rowAccountActions);

    auto *rowErrorRecovery = new QHBoxLayout();
    m_btnRetryErrors = new QPushButton("Retry Failed", grpAccount);
    m_btnRetryErrors->setFixedWidth(120);
    m_btnRetryErrors->setEnabled(false);
    connect(m_btnRetryErrors, &QPushButton::clicked, this, &PreferencesDialog::onRetryErrors);

    m_btnClearErrors = new QPushButton("Clear Errors", grpAccount);
    m_btnClearErrors->setFixedWidth(120);
    m_btnClearErrors->setEnabled(false);
    connect(m_btnClearErrors, &QPushButton::clicked, this, &PreferencesDialog::onClearErrors);

    rowErrorRecovery->addWidget(m_btnRetryErrors);
    rowErrorRecovery->addWidget(m_btnClearErrors);
    rowErrorRecovery->addStretch();
    formAccount->addRow("Recovery:", rowErrorRecovery);

    layoutAccount->addWidget(grpAccount);
    layoutAccount->addStretch();
    m_tabs->addTab(tabAccount, "Account");

    // --- Tab 2: Sync ---
    auto *tabSync = new QWidget(this);
    auto *layoutSync = new QVBoxLayout(tabSync);

    auto *grpMount = new QGroupBox("Virtual Filesystem", tabSync);
    auto *layoutMount = new QVBoxLayout(grpMount);

    auto *rowMount = new QHBoxLayout();
    m_lblMountPoint = new QLabel("~/NeutronDrive", grpMount);
    m_btnChangeMount = new QPushButton("Change...", grpMount);
    connect(m_btnChangeMount, &QPushButton::clicked, this, &PreferencesDialog::onChangeMountPoint);
    rowMount->addWidget(m_lblMountPoint, 1);
    rowMount->addWidget(m_btnChangeMount);
    layoutMount->addLayout(rowMount);

    m_chkAutoMount = new QCheckBox("Automatically mount on startup", grpMount);
    m_chkAutoMount->setChecked(true);
    connect(m_chkAutoMount, &QCheckBox::toggled, this, &PreferencesDialog::onAutoMountToggled);
    layoutMount->addWidget(m_chkAutoMount);

    m_chkStartAtLogin = new QCheckBox("Start Neutron Drive on login", grpMount);
    m_chkStartAtLogin->setChecked(true);
    connect(m_chkStartAtLogin, &QCheckBox::toggled, this, &PreferencesDialog::onStartAtLoginToggled);
    layoutMount->addWidget(m_chkStartAtLogin);

    m_chkOfflineMode = new QCheckBox("Offline mode (pause remote polling and uploads)", grpMount);
    m_chkOfflineMode->setChecked(false);
    connect(m_chkOfflineMode, &QCheckBox::toggled, this, &PreferencesDialog::onOfflineModeToggled);
    layoutMount->addWidget(m_chkOfflineMode);

    auto *rowPoll = new QHBoxLayout();
    auto *lblPoll = new QLabel("Sync poll interval:", grpMount);
    m_spinPollInterval = new QSpinBox(grpMount);
    m_spinPollInterval->setRange(5, 3600);
    m_spinPollInterval->setValue(m_lastPollInterval);
    m_spinPollInterval->setSuffix(" s");

    m_btnApplySync = new QPushButton("Apply", grpMount);
    connect(m_btnApplySync, &QPushButton::clicked, this, &PreferencesDialog::onApplySyncSettings);

    rowPoll->addWidget(lblPoll);
    rowPoll->addWidget(m_spinPollInterval);
    rowPoll->addWidget(m_btnApplySync);
    rowPoll->addStretch();
    layoutMount->addLayout(rowPoll);

    layoutSync->addWidget(grpMount);
    layoutSync->addStretch();
    m_tabs->addTab(tabSync, "Sync");

    // --- Tab 3: Cache ---
    auto *tabCache = new QWidget(this);
    auto *layoutCache = new QVBoxLayout(tabCache);

    auto *grpCache = new QGroupBox("Local Cache Storage", tabCache);
    auto *layoutCacheInner = new QVBoxLayout(grpCache);

    QString cachePath = QStandardPaths::writableLocation(QStandardPaths::CacheLocation) + "/neutron-drive/blocks";
    m_lblCachePath = new QLabel(QString("Cache Location: %1").arg(cachePath), grpCache);
    m_lblCachePath->setWordWrap(true);
    layoutCacheInner->addWidget(m_lblCachePath);

    auto *formCachePolicy = new QFormLayout();
    m_spinCacheMaxMb = new QSpinBox(grpCache);
    m_spinCacheMaxMb->setRange(0, 1048576);
    m_spinCacheMaxMb->setValue(m_lastCacheMaxMb);
    m_spinCacheMaxMb->setSuffix(" MB");
    m_spinCacheMaxMb->setSpecialValueText("Unlimited (0 MB)");
    formCachePolicy->addRow("Max cache size:", m_spinCacheMaxMb);

    m_spinCacheTtlHours = new QSpinBox(grpCache);
    m_spinCacheTtlHours->setRange(0, 8760);
    m_spinCacheTtlHours->setValue(m_lastCacheTtlHours);
    m_spinCacheTtlHours->setSuffix(" hours");
    m_spinCacheTtlHours->setSpecialValueText("Never expire (0 hours)");
    formCachePolicy->addRow("Cache TTL:", m_spinCacheTtlHours);

    layoutCacheInner->addLayout(formCachePolicy);

    auto *rowCacheButtons = new QHBoxLayout();
    m_btnApplyCache = new QPushButton("Apply Policy", grpCache);
    m_btnApplyCache->setFixedWidth(140);
    connect(m_btnApplyCache, &QPushButton::clicked, this, &PreferencesDialog::onApplyCacheSettings);

    m_btnClearCache = new QPushButton("Clear Cache", grpCache);
    m_btnClearCache->setFixedWidth(140);
    connect(m_btnClearCache, &QPushButton::clicked, this, &PreferencesDialog::onClearCache);

    rowCacheButtons->addWidget(m_btnApplyCache);
    rowCacheButtons->addWidget(m_btnClearCache);
    rowCacheButtons->addStretch();
    layoutCacheInner->addLayout(rowCacheButtons);

    layoutCache->addWidget(grpCache);
    layoutCache->addStretch();
    m_tabs->addTab(tabCache, "Cache");

    // --- Tab 4: About ---
    auto *tabAbout = new QWidget(this);
    auto *layoutAbout = new QVBoxLayout(tabAbout);

    auto *lblTitle = new QLabel("Neutron Drive", tabAbout);
    QFont f = lblTitle->font();
    f.setPointSize(14);
    f.setBold(true);
    lblTitle->setFont(f);

    auto *lblVer = new QLabel("Version 3.0.3", tabAbout);
    auto *lblDesc = new QLabel(
        "Unofficial third-party Linux desktop client and virtual filesystem for Proton Drive.\n"
        "Built with a native Rust FUSE daemon and Qt6 user interface.\n\n"
        "This is a third-party application not officially supported by Proton.",
        tabAbout
    );
    lblDesc->setWordWrap(true);

    layoutAbout->addWidget(lblTitle);
    layoutAbout->addWidget(lblVer);
    layoutAbout->addWidget(lblDesc);
    layoutAbout->addStretch();
    m_tabs->addTab(tabAbout, "About");

    // Close button
    auto *rowBottom = new QHBoxLayout();
    rowBottom->addStretch();
    auto *btnClose = new QPushButton("Close", this);
    connect(btnClose, &QPushButton::clicked, this, &QDialog::accept);
    rowBottom->addWidget(btnClose);
    mainLayout->addLayout(rowBottom);
}

void PreferencesDialog::refreshData() {
    QPointer<PreferencesDialog> self(this);
    m_client->sendCommandAsync("get-config", [this, self](const QJsonObject &cfgRes) {
        if (!self) {
            return;
        }

        if (cfgRes.value("status").toString() != "ok") {
            m_lblAuthStatus->setText("Daemon not responding");
            m_lblSyncSummary->setText("Daemon not responding");
            if (m_btnRetryErrors) m_btnRetryErrors->setEnabled(false);
            if (m_btnClearErrors) m_btnClearErrors->setEnabled(false);
            emit daemonUnavailable("Daemon not responding");
            return;
        }

        QJsonObject cfg = cfgRes.value("config").isObject()
            ? cfgRes.value("config").toObject()
            : cfgRes;

        m_chkAutoMount->blockSignals(true);
        m_chkStartAtLogin->blockSignals(true);
        m_chkOfflineMode->blockSignals(true);
        m_spinPollInterval->blockSignals(true);
        m_spinCacheMaxMb->blockSignals(true);
        m_spinCacheTtlHours->blockSignals(true);

        if (cfg.contains("auto_mount_on_start")) {
            m_chkAutoMount->setChecked(cfg.value("auto_mount_on_start").toBool());
        }
        if (cfg.contains("start_at_login")) {
            m_chkStartAtLogin->setChecked(cfg.value("start_at_login").toBool());
        }
        if (cfg.contains("offline_mode")) {
            m_chkOfflineMode->setChecked(cfg.value("offline_mode").toBool());
        }
        if (cfg.contains("event_poll_interval_sec")) {
            m_lastPollInterval = std::clamp(cfg.value("event_poll_interval_sec").toInt(30), 5, 3600);
            m_spinPollInterval->setValue(m_lastPollInterval);
        }
        if (cfg.contains("cache_max_size_mb")) {
            m_lastCacheMaxMb = std::max(0, cfg.value("cache_max_size_mb").toInt(5120));
            m_spinCacheMaxMb->setValue(m_lastCacheMaxMb);
        }
        if (cfg.contains("cache_ttl_hours")) {
            m_lastCacheTtlHours = std::max(0, cfg.value("cache_ttl_hours").toInt(168));
            m_spinCacheTtlHours->setValue(m_lastCacheTtlHours);
        }

        m_chkAutoMount->blockSignals(false);
        m_chkStartAtLogin->blockSignals(false);
        m_chkOfflineMode->blockSignals(false);
        m_spinPollInterval->blockSignals(false);
        m_spinCacheMaxMb->blockSignals(false);
        m_spinCacheTtlHours->blockSignals(false);

        if (cfg.contains("mount_point")) {
            m_mountPoint = cfg["mount_point"].toString();
            m_lblMountPoint->setText(m_mountPoint);
        }

        emit configLoaded(cfg);
        emit mountPointChanged(mountPoint());
        emit autoMountChanged(isAutoMountChecked());
        emit startAtLoginChanged(isStartAtLoginChecked());

        m_client->sendCommandAsync("status", [this, self](const QJsonObject &res) {
            if (!self) {
                return;
            }

            if (res.value("status").toString() != "ok") {
                m_lblAuthStatus->setText("Daemon not responding");
                m_lblSyncSummary->setText("Daemon not responding");
                if (m_btnRetryErrors) m_btnRetryErrors->setEnabled(false);
                if (m_btnClearErrors) m_btnClearErrors->setEnabled(false);
                emit daemonUnavailable("Daemon not responding");
                return;
            }

            bool auth = res.value("authenticated").toBool();
            QString authMsg = res.value("auth_message").toString();
            m_authenticated = auth;
            m_authMessage = authMsg;
            m_isMounted = res.value("is_mounted").toBool(false);
            if (auth) {
                m_lblAuthStatus->setText(
                    authMsg.startsWith("Authenticated") ? authMsg : QString("Authenticated")
                );
            } else {
                m_lblAuthStatus->setText(QString("Not Authenticated"));
            }
            m_btnLogin->setEnabled(!auth);
            m_btnLogout->setEnabled(auth);

            if ((m_mountPoint.isEmpty() || m_mountPoint == "~/NeutronDrive") && res.contains("mount_point")) {
                const QString statusMount = res.value("mount_point").toString();
                if (!statusMount.isEmpty()) {
                    m_mountPoint = statusMount;
                    m_lblMountPoint->setText(m_mountPoint);
                    emit mountPointChanged(m_mountPoint);
                }
            }

            QString syncState = res.value("sync_status").toString("idle");
            bool offline = res.value("offline_mode").toBool(false);
            int pendingUploads = res.value("pending_uploads").toInt(0);
            int errorCount = res.value("error_count").toInt(0);
            QString summary = QString("%1 | Pending uploads: %2 | Errors: %3")
                .arg(offline ? QString("offline") : syncState)
                .arg(pendingUploads)
                .arg(errorCount);
            QString lastError = res.value("last_error").toString();
            if (!lastError.isEmpty()) {
                summary += QString("\nLast error: %1").arg(lastError);
            }
            m_lblSyncSummary->setText(summary);
            if (m_btnRetryErrors) {
                m_btnRetryErrors->setEnabled(errorCount > 0);
            }
            if (m_btnClearErrors) {
                m_btnClearErrors->setEnabled(errorCount > 0);
            }

            if (res.contains("quota") && res.value("quota").isObject()) {
                QJsonObject q = res.value("quota").toObject();
                quint64 used = static_cast<quint64>(q.value("used_bytes").toDouble());
                quint64 total = static_cast<quint64>(q.value("total_bytes").toDouble());
                double pct = q.value("percent_used").toDouble();
                m_accountQuota->updateQuota(used, total, pct);
            }

            emit statusUpdated(
                m_authenticated,
                m_lblAuthStatus->text(),
                m_isMounted,
                mountPoint(),
                errorCount,
                lastError
            );
        });
    });
}

void PreferencesDialog::updateBooleanPreference(
    const QString &key,
    QCheckBox *checkbox,
    bool checked,
    bool previousValue,
    const QString &fallbackError,
    bool interactiveDialogs
) {
    QJsonObject args;
    args[key] = checked;
    QPointer<PreferencesDialog> self(this);
    m_client->sendCommandAsync("update-config", args, [this, self, key, checkbox, checked, previousValue, fallbackError, interactiveDialogs](const QJsonObject &res) {
        if (!self) {
            return;
        }

        if (res.value("status").toString() != "ok") {
            if (checkbox) {
                checkbox->blockSignals(true);
                checkbox->setChecked(previousValue);
                checkbox->blockSignals(false);
            }

            if (key == "auto_mount_on_start") {
                emit autoMountChanged(previousValue);
            } else if (key == "start_at_login") {
                emit startAtLoginChanged(previousValue);
            }

            QString message = res.value("message").toString();
            if (message.isEmpty()) {
                message = fallbackError;
            }
            emit configUpdateFinished(key, false, message, false);
            if (interactiveDialogs) {
                QMessageBox::warning(this, "Preferences Error", message);
            }
            return;
        }

        if (key == "auto_mount_on_start") {
            emit autoMountChanged(checked);
        } else if (key == "start_at_login") {
            emit startAtLoginChanged(checked);
        }
        emit configUpdateFinished(key, true, QString(), false);
    });
}

void PreferencesDialog::setAutoMountOnStart(bool enabled, bool interactiveDialogs) {
    const bool previousValue = isAutoMountChecked();
    if (m_chkAutoMount) {
        m_chkAutoMount->blockSignals(true);
        m_chkAutoMount->setChecked(enabled);
        m_chkAutoMount->blockSignals(false);
    }
    updateBooleanPreference(
        "auto_mount_on_start",
        m_chkAutoMount,
        enabled,
        previousValue,
        "Failed to update auto mount preference",
        interactiveDialogs
    );
}

void PreferencesDialog::setStartAtLogin(bool enabled, bool interactiveDialogs) {
    const bool previousValue = isStartAtLoginChecked();
    if (m_chkStartAtLogin) {
        m_chkStartAtLogin->blockSignals(true);
        m_chkStartAtLogin->setChecked(enabled);
        m_chkStartAtLogin->blockSignals(false);
    }
    updateBooleanPreference(
        "start_at_login",
        m_chkStartAtLogin,
        enabled,
        previousValue,
        "Failed to update start at login preference",
        interactiveDialogs
    );
}

void PreferencesDialog::onAutoMountToggled(bool checked) {
    updateBooleanPreference("auto_mount_on_start", m_chkAutoMount, checked, !checked, "Failed to update auto mount preference", true);
}

void PreferencesDialog::onStartAtLoginToggled(bool checked) {
    updateBooleanPreference("start_at_login", m_chkStartAtLogin, checked, !checked, "Failed to update start at login preference", true);
}

void PreferencesDialog::onOfflineModeToggled(bool checked) {
    updateBooleanPreference("offline_mode", m_chkOfflineMode, checked, !checked, "Failed to update offline mode preference", true);
}

void PreferencesDialog::onApplySyncSettings() {
    int nextPoll = m_spinPollInterval->value();
    QJsonObject args;
    args["event_poll_interval_sec"] = nextPoll;
    QPointer<PreferencesDialog> self(this);
    m_client->sendCommandAsync("update-config", args, [this, self, nextPoll](const QJsonObject &res) {
        if (!self) {
            return;
        }

        if (res.value("status").toString() != "ok") {
            m_spinPollInterval->blockSignals(true);
            m_spinPollInterval->setValue(m_lastPollInterval);
            m_spinPollInterval->blockSignals(false);

            QString message = res.value("message").toString();
            if (message.isEmpty()) {
                message = "Failed to update sync poll interval";
            }
            QMessageBox::warning(this, "Preferences Error", message);
            return;
        }

        m_lastPollInterval = nextPoll;
    });
}

void PreferencesDialog::onApplyCacheSettings() {
    int nextMaxMb = m_spinCacheMaxMb->value();
    int nextTtlHours = m_spinCacheTtlHours->value();
    QJsonObject args;
    args["cache_max_size_mb"] = nextMaxMb;
    args["cache_ttl_hours"] = nextTtlHours;
    QPointer<PreferencesDialog> self(this);
    m_client->sendCommandAsync("update-config", args, [this, self, nextMaxMb, nextTtlHours](const QJsonObject &res) {
        if (!self) {
            return;
        }

        if (res.value("status").toString() != "ok") {
            m_spinCacheMaxMb->blockSignals(true);
            m_spinCacheTtlHours->blockSignals(true);
            m_spinCacheMaxMb->setValue(m_lastCacheMaxMb);
            m_spinCacheTtlHours->setValue(m_lastCacheTtlHours);
            m_spinCacheMaxMb->blockSignals(false);
            m_spinCacheTtlHours->blockSignals(false);

            QString message = res.value("message").toString();
            if (message.isEmpty()) {
                message = "Failed to update cache policy settings";
            }
            QMessageBox::warning(this, "Preferences Error", message);
            return;
        }

        m_lastCacheMaxMb = nextMaxMb;
        m_lastCacheTtlHours = nextTtlHours;
    });
}

void PreferencesDialog::chooseMountPoint(QWidget *dialogParent, bool interactiveDialogs) {
    QString dir = QFileDialog::getExistingDirectory(
        dialogParent ? dialogParent : this,
        "Select Neutron Drive Mount Point",
        mountPoint()
    );
    if (dir.isEmpty()) {
        return;
    }
    applyMountPoint(dir, interactiveDialogs);
}

void PreferencesDialog::applyMountPoint(const QString &dir, bool interactiveDialogs) {
    if (dir.trimmed().isEmpty()) {
        emit configUpdateFinished("mount_point", false, "Mount point cannot be empty", false);
        return;
    }

    const QString previousMountPoint = mountPoint();
    QJsonObject args;
    args["mount_point"] = dir;
    QPointer<PreferencesDialog> self(this);
    m_client->sendCommandAsync("update-config", args, [this, self, dir, previousMountPoint, interactiveDialogs](const QJsonObject &res) {
        if (!self) {
            return;
        }

        if (res.value("status").toString() != "ok") {
            m_mountPoint = previousMountPoint;
            if (m_lblMountPoint) {
                m_lblMountPoint->setText(previousMountPoint);
            }
            QString message = res.value("message").toString();
            if (message.isEmpty()) {
                message = "Failed to update mount point";
            }
            emit mountPointChanged(previousMountPoint);
            emit configUpdateFinished("mount_point", false, message, false);
            if (interactiveDialogs) {
                QMessageBox::warning(this, "Mount Error", message);
            }
            return;
        }

        m_mountPoint = dir;
        if (m_lblMountPoint) {
            m_lblMountPoint->setText(dir);
        }

        const bool remountRequired = res.value("remount_required").toBool();
        const QString infoMsg = remountRequired
            ? QString("The mount point has been updated and will take effect on next mount / restart.")
            : QString();

        emit mountPointChanged(dir);
        emit configUpdateFinished("mount_point", true, infoMsg, remountRequired);

        if (interactiveDialogs && remountRequired) {
            QMessageBox::information(this, "Mount Point Updated", infoMsg);
        }
    });
}

void PreferencesDialog::onChangeMountPoint() {
    chooseMountPoint(this, true);
}

void PreferencesDialog::onClearCache() {
    QPointer<PreferencesDialog> self(this);
    m_client->sendCommandAsync("clear-cache", [this, self](const QJsonObject &res) {
        if (!self) {
            return;
        }

        if (res.value("status").toString() == "ok") {
            int evicted = res.value("evicted").toInt();
            QMessageBox::information(this, "Cache Cleared", QString("Successfully evicted %1 cached block files.").arg(evicted));
        } else {
            QString message = res.value("message").toString();
            if (message.isEmpty()) {
                message = "Failed to clear cache";
            }
            QMessageBox::warning(this, "Cache Clear Error", message);
        }
    });
}

void PreferencesDialog::onRetryErrors() {
    if (m_btnRetryErrors) m_btnRetryErrors->setEnabled(false);
    if (m_btnClearErrors) m_btnClearErrors->setEnabled(false);

    QPointer<PreferencesDialog> self(this);
    m_client->sendCommandAsync("retry-errors", [this, self](const QJsonObject &res) {
        if (!self) {
            return;
        }
        if (res.value("status").toString() != "ok") {
            QString message = res.value("message").toString();
            if (message.isEmpty()) {
                message = "Failed to retry sync errors";
            }
            if (qEnvironmentVariable("QT_QPA_PLATFORM") != QString("offscreen")) {
                QMessageBox::warning(this, "Retry Errors", message);
            }
        }
        refreshData();
    });
}

void PreferencesDialog::onClearErrors() {
    if (m_btnRetryErrors) m_btnRetryErrors->setEnabled(false);
    if (m_btnClearErrors) m_btnClearErrors->setEnabled(false);

    QPointer<PreferencesDialog> self(this);
    m_client->sendCommandAsync("clear-errors", [this, self](const QJsonObject &res) {
        if (!self) {
            return;
        }
        if (res.value("status").toString() != "ok") {
            QString message = res.value("message").toString();
            if (message.isEmpty()) {
                message = "Failed to clear sync errors";
            }
            if (qEnvironmentVariable("QT_QPA_PLATFORM") != QString("offscreen")) {
                QMessageBox::warning(this, "Clear Errors", message);
            }
        }
        refreshData();
    });
}

void PreferencesDialog::openNativeLoginPrompt(QWidget *dialogParent) {
    promptNativeLogin(QString(), QString(), false, QString(), dialogParent);
}

void PreferencesDialog::submitNativeLogin(
    const QString &user,
    const QString &pass,
    const QString &totp,
    bool interactiveDialogs,
    QWidget *dialogParent
) {
    QJsonObject args;
    args["username"] = user;
    args["password"] = pass;
    if (!totp.isEmpty()) {
        args["totp"] = totp;
    }

    QPointer<PreferencesDialog> self(this);
    QPointer<QWidget> modalParent(dialogParent ? dialogParent : this);
    m_btnLogin->setEnabled(false);
    m_lblAuthStatus->setText("Signing in...");
    emit loginStatusMessageChanged("Signing in...");

    m_client->sendCommandAsync("login", args, [this, self, modalParent, user, pass, interactiveDialogs](const QJsonObject &res) {
        if (!self) {
            return;
        }
        m_btnLogin->setEnabled(true);
        const QString status = res.value("status").toString();
        const QString msg = res.value("message").toString();
        if (status == "ok") {
            emit loginFinished(true, "ok", msg);
            refreshData();
            return;
        }
        if (status == "2fa_required") {
            const QString notice = msg.isEmpty()
                ? QString("Enter your 2FA TOTP code to finish signing in.")
                : msg;
            m_lblAuthStatus->setText("2FA Required");
            emit loginStatusMessageChanged(notice);
            emit loginFinished(false, "2fa_required", notice);
            if (interactiveDialogs) {
                promptNativeLogin(user, pass, true, notice, modalParent ? modalParent.data() : this);
            }
            return;
        }
        const QString errMsg = msg.isEmpty() ? QString("Authentication failed.") : msg;
        emit loginStatusMessageChanged(errMsg);
        emit loginFinished(false, status.isEmpty() ? QString("error") : status, errMsg);
        if (interactiveDialogs) {
            QMessageBox::warning(
                modalParent ? modalParent.data() : this,
                "Neutron Drive Login",
                errMsg
            );
        }
        refreshData();
    });
}

void PreferencesDialog::cancelBrowserSsoLogin() {
    if (m_browserPollTimer) {
        m_browserPollTimer->stop();
        m_browserPollTimer->deleteLater();
        m_browserPollTimer = nullptr;
    }
    if (m_btnLogin && !m_authenticated) {
        m_btnLogin->setEnabled(true);
    }
}

void PreferencesDialog::startBrowserSsoLogin(int pollIntervalMs, bool interactiveDialogs) {
    cancelBrowserSsoLogin();

    QPointer<PreferencesDialog> self(this);
    m_btnLogin->setEnabled(false);
    m_lblAuthStatus->setText("Starting browser login...");
    emit loginStatusMessageChanged("Starting browser login...");

    m_client->sendCommandAsync("start-browser-login", [this, self, pollIntervalMs, interactiveDialogs](const QJsonObject &res) {
        if (!self) {
            return;
        }
        if (res.value("status").toString() != "ok") {
            m_btnLogin->setEnabled(true);
            const QString msg = res.value("message").toString();
            const QString errMsg = msg.isEmpty() ? QString("Failed starting browser sign-in.") : msg;
            emit loginStatusMessageChanged(errMsg);
            emit loginFinished(false, "error", errMsg);
            if (interactiveDialogs && qEnvironmentVariable("QT_QPA_PLATFORM") != QString("offscreen")) {
                QMessageBox::warning(
                    this,
                    "Browser SSO Login",
                    errMsg
                );
            }
            refreshData();
            return;
        }

        const QString loginUrl = res.value("login_url").toString();
        const QString userCode = res.value("user_code").toString();
        const QString waitMsg = userCode.isEmpty()
            ? QString("Waiting for browser login (third-party app not officially supported by Proton)...")
            : QString("Waiting for browser login (third-party app; code: %1)...").arg(userCode);
        m_lblAuthStatus->setText(waitMsg);
        emit loginStatusMessageChanged(waitMsg);
        if (!loginUrl.isEmpty() && qEnvironmentVariable("QT_QPA_PLATFORM") != QString("offscreen")) {
            QDesktopServices::openUrl(QUrl(loginUrl));
        }

        auto *timer = new QTimer(this);
        timer->setInterval(std::max(10, pollIntervalMs));
        m_browserPollTimer = timer;
        auto pollInflight = std::make_shared<bool>(false);
        connect(timer, &QTimer::timeout, this, [this, self, timer, pollInflight, interactiveDialogs]() {
            if (!self || timer != m_browserPollTimer) {
                return;
            }
            if (*pollInflight) {
                return;
            }
            *pollInflight = true;
            m_client->sendCommandAsync("poll-browser-login", [this, self, timer, pollInflight, interactiveDialogs](const QJsonObject &pollRes) {
                *pollInflight = false;
                if (!self || timer != m_browserPollTimer) {
                    return;
                }
                const QString st = pollRes.value("status").toString();
                if (st == "pending") {
                    return;
                }
                timer->stop();
                timer->deleteLater();
                m_browserPollTimer = nullptr;
                m_btnLogin->setEnabled(true);

                if (st == "ok") {
                    emit loginFinished(true, "ok", pollRes.value("message").toString());
                    refreshData();
                    return;
                }
                const QString msg = pollRes.value("message").toString();
                const QString errMsg = msg.isEmpty() ? QString("Browser sign-in failed.") : msg;
                emit loginStatusMessageChanged(errMsg);
                emit loginFinished(false, st.isEmpty() ? QString("error") : st, errMsg);
                if (interactiveDialogs && qEnvironmentVariable("QT_QPA_PLATFORM") != QString("offscreen")) {
                    QMessageBox::warning(
                        this,
                        "Browser SSO Login",
                        errMsg
                    );
                }
                refreshData();
            });
        });
        timer->start();
    });
}

void PreferencesDialog::promptNativeLogin(
    const QString &initialUser,
    const QString &initialPass,
    bool requireTotp,
    const QString &notice,
    QWidget *dialogParent
) {
    QWidget *effectiveParent = dialogParent ? dialogParent : this;
    QDialog dlg(effectiveParent);
    dlg.setWindowTitle("Sign In via Neutron Drive");
    dlg.setMinimumWidth(380);

    auto *layout = new QVBoxLayout(&dlg);
    auto *lblDisclosure = new QLabel(
        "This is a third-party application not officially supported by Proton.\n"
        "Your password is used locally for authentication and is never stored.",
        &dlg
    );
    lblDisclosure->setWordWrap(true);
    lblDisclosure->setStyleSheet("color: #555; font-size: 11px;");
    layout->addWidget(lblDisclosure);

    if (!notice.isEmpty()) {
        auto *lblNotice = new QLabel(notice, &dlg);
        lblNotice->setWordWrap(true);
        layout->addWidget(lblNotice);
    }

    auto *form = new QFormLayout();
    auto *editUser = new QLineEdit(initialUser, &dlg);
    editUser->setPlaceholderText("user@proton.me");
    auto *editPass = new QLineEdit(initialPass, &dlg);
    editPass->setEchoMode(QLineEdit::Password);
    auto *editTotp = new QLineEdit(&dlg);
    editTotp->setPlaceholderText(requireTotp ? "6-digit 2FA code (required)" : "Optional 2FA TOTP code");

    form->addRow("Username:", editUser);
    form->addRow("Password:", editPass);
    form->addRow("2FA Code:", editTotp);
    layout->addLayout(form);

    if (requireTotp) {
        editTotp->setFocus();
    } else if (!initialUser.isEmpty()) {
        editPass->setFocus();
    }

    bool useBrowserSso = false;
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    auto *btnBrowser = buttons->addButton("Sign In via Browser...", QDialogButtonBox::ActionRole);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    connect(btnBrowser, &QPushButton::clicked, &dlg, [&dlg, &useBrowserSso]() {
        useBrowserSso = true;
        dlg.reject();
    });
    layout->addWidget(buttons);

    const int execResult = dlg.exec();
    if (useBrowserSso) {
        startBrowserSsoLogin(1500, true);
        return;
    }
    if (execResult != QDialog::Accepted) {
        return;
    }

    const QString user = editUser->text().trimmed();
    const QString pass = editPass->text();
    const QString totp = editTotp->text().trimmed();
    if (user.isEmpty() || pass.isEmpty()) {
        QMessageBox::warning(effectiveParent, "Neutron Drive Login", "Username and password are required.");
        return;
    }

    submitNativeLogin(user, pass, totp, true, effectiveParent);
}

void PreferencesDialog::onLogin() {
    openNativeLoginPrompt(this);
}

void PreferencesDialog::performLogout(bool skipConfirmation) {
    cancelBrowserSsoLogin();
    if (!skipConfirmation) {
        auto reply = QMessageBox::question(this, "Log Out", "Are you sure you want to log out of Neutron Drive?");
        if (reply != QMessageBox::Yes) {
            return;
        }
    }
    QPointer<PreferencesDialog> self(this);
    m_client->sendCommandAsync("logout", [this, self, skipConfirmation](const QJsonObject &res) {
        if (!self) {
            return;
        }

        const bool ok = res.value("status").toString() == "ok";
        if (!ok && !skipConfirmation) {
            QString message = res.value("message").toString();
            if (message.isEmpty()) {
                message = "Failed to log out of Neutron Drive";
            }
            QMessageBox::warning(this, "Logout Error", message);
        }
        if (ok) {
            m_authenticated = false;
        }
        emit logoutFinished(ok);
        refreshData();
    });
}

void PreferencesDialog::onLogout() {
    performLogout(false);
}
