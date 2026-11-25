#pragma once

#include <QObject>
#include <QSettings>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QTimer>
#include <QWidgetAction>

#include "IpcClient.hpp"
#include "QuotaWidget.hpp"
#include "PreferencesDialog.hpp"
#include "OnboardingDialog.hpp"

class TrayCoordinator : public QObject {
    Q_OBJECT
public:
    explicit TrayCoordinator(
        IpcClient *client,
        QObject *parent = nullptr,
        QSettings *settings = nullptr
    );
    ~TrayCoordinator() override;

    void initTray();

    PreferencesDialog *preferencesDialog();
    OnboardingDialog *onboardingDialog() const { return m_onboardingDialog; }
    bool shouldShowOnboarding() const;
    bool runOnboardingIfNeeded(bool blocking = true);

    bool isStatusInflight() const { return m_statusInflight; }
    QString lastStatus() const { return m_lastStatus; }
    int notificationCount() const { return m_notificationCount; }
    QString lastNotificationTitle() const { return m_lastNotificationTitle; }
    QString lastNotificationMessage() const { return m_lastNotificationMessage; }

signals:
    void notificationShown(const QString &title, const QString &message);

public slots:
    void pollStatus();

private slots:
    void onOpenFolder();
    void onTogglePause();
    void onRefresh();
    void onShowPreferences();
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);

private:
    QIcon createStatusIcon(const QString &status);
    void showTrayNotification(
        const QString &title,
        const QString &message,
        QSystemTrayIcon::MessageIcon icon = QSystemTrayIcon::Warning
    );

    IpcClient *m_client;
    QSystemTrayIcon *m_trayIcon;
    QMenu *m_menu;
    QTimer *m_timer;

    QuotaWidget *m_quotaWidget;
    QWidgetAction *m_quotaAction;
    QAction *m_actOpenFolder;
    QAction *m_actPauseResume;
    QAction *m_actRefresh;
    QAction *m_actPreferences;
    QAction *m_actQuit;

    PreferencesDialog *m_prefDialog;
    OnboardingDialog *m_onboardingDialog;
    QSettings *m_settings;
    QString m_mountPoint;
    bool m_isPaused;
    QString m_lastStatus;
    bool m_statusInflight;
    bool m_hasSeenAuthSuccess;
    bool m_authExpiredNotified;
    int m_lastErrorCount;
    QString m_lastNotifiedError;
    int m_notificationCount;
    QString m_lastNotificationTitle;
    QString m_lastNotificationMessage;
};
