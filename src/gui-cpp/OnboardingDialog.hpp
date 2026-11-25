#pragma once

#include <QCheckBox>
#include <QDialog>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QSettings>
#include <QStackedWidget>
#include <memory>

#include "IpcClient.hpp"
#include "PreferencesDialog.hpp"

class OnboardingDialog : public QDialog {
    Q_OBJECT
public:
    enum Step {
        WelcomeStep = 0,
        AccountStep = 1,
        MountStep = 2,
        ReadyStep = 3
    };

    enum class Outcome {
        Pending,
        Skipped,
        Completed
    };

    static constexpr int kSchemaVersion = 1;
    static constexpr const char *kSettingsOrganization = "neutron-drive";
    static constexpr const char *kSettingsApplication = "neutron-drive-gui";
    static constexpr const char *kSchemaVersionKey = "onboarding/schemaVersion";
    static constexpr const char *kCompletedKey = "onboarding/onboardingCompleted";

    static std::unique_ptr<QSettings> createDefaultSettings();
    static bool isOnboardingCompleted(const QSettings &settings);
    static bool shouldShowOnboarding(const QSettings &settings);
    static void persistOnboardingCompleted(QSettings &settings);

    explicit OnboardingDialog(
        PreferencesDialog *preferences,
        QSettings *settings = nullptr,
        QWidget *parent = nullptr
    );
    explicit OnboardingDialog(
        IpcClient *client,
        QSettings *settings = nullptr,
        QWidget *parent = nullptr
    );

    Step currentStep() const;
    Outcome outcome() const { return m_outcome; }
    bool isAuthenticated() const { return m_authenticated; }
    QString mountPoint() const;
    bool isAutoMountChecked() const;
    bool isStartAtLoginChecked() const;

    QString welcomeNoticeText() const { return m_lblWelcomeNotice ? m_lblWelcomeNotice->text() : QString(); }
    QString accountStatusText() const { return m_lblAccountStatus ? m_lblAccountStatus->text() : QString(); }
    QString accountFeedbackText() const { return m_lblAccountFeedback ? m_lblAccountFeedback->text() : QString(); }
    QString mountFeedbackText() const { return m_lblMountFeedback ? m_lblMountFeedback->text() : QString(); }
    QString readyMountPathText() const { return m_lblReadyMountPath ? m_lblReadyMountPath->text() : QString(); }
    QString readyRecoveryText() const { return m_lblReadyRecovery ? m_lblReadyRecovery->text() : QString(); }

    QPushButton *skipButton() const { return m_btnSkip; }
    QPushButton *backButton() const { return m_btnBack; }
    QPushButton *nextButton() const { return m_btnNext; }
    QPushButton *finishButton() const { return m_btnFinish; }
    QPushButton *nativeLoginButton() const { return m_btnNativeLogin; }
    QPushButton *browserSsoButton() const { return m_btnBrowserSso; }
    QPushButton *changeMountButton() const { return m_btnChangeMount; }
    QCheckBox *autoMountCheckBox() const { return m_chkAutoMount; }
    QCheckBox *startAtLoginCheckBox() const { return m_chkStartAtLogin; }
    PreferencesDialog *preferencesDialog() const { return m_preferences.data(); }

    void submitNativeLogin(
        const QString &user,
        const QString &pass,
        const QString &totp = QString(),
        bool interactiveDialogs = false
    );
    void startBrowserSsoLogin(int pollIntervalMs = 1500);
    void applyMountPoint(const QString &dir, bool interactiveDialogs = false);

public slots:
    void skipForNow();
    void finishOnboarding();
    void reject() override;

signals:
    void onboardingCompleted();

private slots:
    void onBackClicked();
    void onNextClicked();
    void onLoginStatusMessageChanged(const QString &message);
    void onLoginFinished(bool ok, const QString &status, const QString &message);
    void onLogoutFinished(bool ok);
    void onStatusUpdated(
        bool authenticated,
        const QString &authMessage,
        bool isMounted,
        const QString &mountPoint,
        int errorCount,
        const QString &lastError
    );
    void onDaemonUnavailable(const QString &message);
    void onMountPointChanged(const QString &mountPoint);
    void onAutoMountChanged(bool enabled);
    void onStartAtLoginChanged(bool enabled);
    void onConfigUpdateFinished(
        const QString &field,
        bool ok,
        const QString &message,
        bool remountRequired
    );

private:
    void init(PreferencesDialog *preferences, QSettings *settings);
    void initUi();
    void connectPreferences();
    void syncFromPreferences();
    void updateNavigationState();
    void updateReadySummary();
    QSettings *activeSettings() const;

    QPointer<PreferencesDialog> m_preferences;
    QSettings *m_settings;
    std::unique_ptr<QSettings> m_ownedSettings;

    QStackedWidget *m_stack;
    QLabel *m_lblStepTitle;
    QLabel *m_lblWelcomeNotice;
    QLabel *m_lblAccountStatus;
    QLabel *m_lblAccountFeedback;
    QPushButton *m_btnNativeLogin;
    QPushButton *m_btnBrowserSso;

    QLabel *m_lblMountPoint;
    QPushButton *m_btnChangeMount;
    QCheckBox *m_chkAutoMount;
    QCheckBox *m_chkStartAtLogin;
    QLabel *m_lblMountFeedback;

    QLabel *m_lblReadyMountPath;
    QLabel *m_lblReadyRecovery;

    QPushButton *m_btnSkip;
    QPushButton *m_btnBack;
    QPushButton *m_btnNext;
    QPushButton *m_btnFinish;

    Outcome m_outcome;
    bool m_authenticated;
    bool m_justLoggedIn;
    bool m_isMounted;
    int m_configUpdatesInflight;
};
