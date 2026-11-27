#pragma once

#include <QDialog>
#include <QTabWidget>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QLineEdit>
#include <QSpinBox>
#include <QTimer>
#include <QJsonObject>

#include "IpcClient.hpp"
#include "QuotaWidget.hpp"

class PreferencesDialog : public QDialog {
    Q_OBJECT
public:
    explicit PreferencesDialog(IpcClient *client, QWidget *parent = nullptr);

    void refreshData();

    bool isAuthenticated() const { return m_authenticated; }
    bool isMounted() const { return m_isMounted; }
    QString mountPoint() const { return m_lblMountPoint ? m_lblMountPoint->text() : m_mountPoint; }
    bool isAutoMountChecked() const { return m_chkAutoMount && m_chkAutoMount->isChecked(); }
    bool isStartAtLoginChecked() const { return m_chkStartAtLogin && m_chkStartAtLogin->isChecked(); }
    QString authStatusText() const { return m_lblAuthStatus ? m_lblAuthStatus->text() : QString(); }
    QString syncSummaryText() const { return m_lblSyncSummary ? m_lblSyncSummary->text() : QString(); }
    bool isOfflineModeChecked() const { return m_chkOfflineMode && m_chkOfflineMode->isChecked(); }
    int pollIntervalSec() const { return m_spinPollInterval ? m_spinPollInterval->value() : 0; }
    int cacheMaxSizeMb() const { return m_spinCacheMaxMb ? m_spinCacheMaxMb->value() : 0; }
    int cacheTtlHours() const { return m_spinCacheTtlHours ? m_spinCacheTtlHours->value() : 0; }

    QCheckBox *autoMountCheckBox() const { return m_chkAutoMount; }
    QCheckBox *startAtLoginCheckBox() const { return m_chkStartAtLogin; }
    QPushButton *changeMountButton() const { return m_btnChangeMount; }
    QCheckBox *offlineModeCheckBox() const { return m_chkOfflineMode; }
    QSpinBox *pollIntervalSpinBox() const { return m_spinPollInterval; }
    QSpinBox *cacheMaxMbSpinBox() const { return m_spinCacheMaxMb; }
    QSpinBox *cacheTtlHoursSpinBox() const { return m_spinCacheTtlHours; }
    QPushButton *applySyncButton() const { return m_btnApplySync; }
    QPushButton *applyCacheButton() const { return m_btnApplyCache; }
    QPushButton *loginButton() const { return m_btnLogin; }
    QPushButton *logoutButton() const { return m_btnLogout; }
    QPushButton *retryErrorsButton() const { return m_btnRetryErrors; }
    QPushButton *clearErrorsButton() const { return m_btnClearErrors; }
    QPushButton *resolveErrorsButton() const { return m_btnResolveErrors; }

    void resolveConflict(const QString &path, const QString &strategy, bool interactiveDialogs = true);

    void openNativeLoginPrompt(QWidget *dialogParent = nullptr);
    void submitNativeLogin(
        const QString &user,
        const QString &pass,
        const QString &totp = QString(),
        bool interactiveDialogs = true,
        QWidget *dialogParent = nullptr
    );
    void startBrowserSsoLogin(int pollIntervalMs = 1500, bool interactiveDialogs = true);
    void cancelBrowserSsoLogin();
    void performLogout(bool skipConfirmation = false);
    void chooseMountPoint(QWidget *dialogParent = nullptr, bool interactiveDialogs = true);
    void applyMountPoint(const QString &dir, bool interactiveDialogs = true);
    void setAutoMountOnStart(bool enabled, bool interactiveDialogs = true);
    void setStartAtLogin(bool enabled, bool interactiveDialogs = true);

signals:
    void configLoaded(const QJsonObject &config);
    void statusUpdated(
        bool authenticated,
        const QString &authMessage,
        bool isMounted,
        const QString &mountPoint,
        int errorCount,
        const QString &lastError
    );
    void daemonUnavailable(const QString &message);
    void loginStatusMessageChanged(const QString &message);
    void loginFinished(bool ok, const QString &status, const QString &message);
    void logoutFinished(bool ok);
    void configUpdateFinished(const QString &field, bool ok, const QString &message, bool remountRequired);
    void mountPointChanged(const QString &mountPoint);
    void autoMountChanged(bool enabled);
    void startAtLoginChanged(bool enabled);
    void conflictResolved(bool ok, const QString &path, const QString &strategy, const QString &message);

private slots:
    void onChangeMountPoint();
    void onClearCache();
    void onRetryErrors();
    void onClearErrors();
    void onResolveErrors();
    void onLogin();
    void onLogout();
    void onAutoMountToggled(bool checked);
    void onStartAtLoginToggled(bool checked);
    void onOfflineModeToggled(bool checked);
    void onApplySyncSettings();
    void onApplyCacheSettings();

private:
    void initUi();
    void promptNativeLogin(
        const QString &initialUser = QString(),
        const QString &initialPass = QString(),
        bool requireTotp = false,
        const QString &notice = QString(),
        QWidget *dialogParent = nullptr
    );
    void updateBooleanPreference(
        const QString &key,
        QCheckBox *checkbox,
        bool checked,
        bool previousValue,
        const QString &fallbackError,
        bool interactiveDialogs = true
    );

    IpcClient *m_client;
    QTabWidget *m_tabs;
    bool m_authenticated;
    bool m_isMounted;
    QString m_authMessage;
    QString m_mountPoint;

    // Account Tab
    QLabel *m_lblAuthStatus;
    QLabel *m_lblSyncSummary;
    QuotaWidget *m_accountQuota;
    QPushButton *m_btnLogin;
    QPushButton *m_btnLogout;
    QPushButton *m_btnRetryErrors;
    QPushButton *m_btnClearErrors;
    QPushButton *m_btnResolveErrors;

    // Sync Tab
    QLabel *m_lblMountPoint;
    QPushButton *m_btnChangeMount;
    QCheckBox *m_chkAutoMount;
    QCheckBox *m_chkStartAtLogin;
    QCheckBox *m_chkOfflineMode;
    QSpinBox *m_spinPollInterval;
    QPushButton *m_btnApplySync;
    int m_lastPollInterval;

    // Cache Tab
    QLabel *m_lblCachePath;
    QSpinBox *m_spinCacheMaxMb;
    QSpinBox *m_spinCacheTtlHours;
    QPushButton *m_btnApplyCache;
    QPushButton *m_btnClearCache;
    int m_lastCacheMaxMb;
    int m_lastCacheTtlHours;
    QTimer *m_browserPollTimer;
};
