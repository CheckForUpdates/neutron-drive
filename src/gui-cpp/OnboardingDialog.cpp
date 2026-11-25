#include "OnboardingDialog.hpp"

#include <QFont>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QSignalBlocker>
#include <QVBoxLayout>
#include <algorithm>

std::unique_ptr<QSettings> OnboardingDialog::createDefaultSettings() {
    return std::make_unique<QSettings>(
        QSettings::IniFormat,
        QSettings::UserScope,
        kSettingsOrganization,
        kSettingsApplication
    );
}

bool OnboardingDialog::isOnboardingCompleted(const QSettings &settings) {
    return settings.value(kSchemaVersionKey, 0).toInt() == kSchemaVersion
        && settings.value(kCompletedKey, false).toBool();
}

bool OnboardingDialog::shouldShowOnboarding(const QSettings &settings) {
    return !isOnboardingCompleted(settings);
}

void OnboardingDialog::persistOnboardingCompleted(QSettings &settings) {
    settings.setValue(kSchemaVersionKey, kSchemaVersion);
    settings.setValue(kCompletedKey, true);
    settings.sync();
}

OnboardingDialog::OnboardingDialog(
    PreferencesDialog *preferences,
    QSettings *settings,
    QWidget *parent
)
    : QDialog(parent)
    , m_settings(nullptr)
    , m_stack(nullptr)
    , m_lblStepTitle(nullptr)
    , m_lblWelcomeNotice(nullptr)
    , m_lblAccountStatus(nullptr)
    , m_lblAccountFeedback(nullptr)
    , m_btnNativeLogin(nullptr)
    , m_btnBrowserSso(nullptr)
    , m_lblMountPoint(nullptr)
    , m_btnChangeMount(nullptr)
    , m_chkAutoMount(nullptr)
    , m_chkStartAtLogin(nullptr)
    , m_lblMountFeedback(nullptr)
    , m_lblReadyMountPath(nullptr)
    , m_lblReadyRecovery(nullptr)
    , m_btnSkip(nullptr)
    , m_btnBack(nullptr)
    , m_btnNext(nullptr)
    , m_btnFinish(nullptr)
    , m_outcome(Outcome::Pending)
    , m_authenticated(false)
    , m_justLoggedIn(false)
    , m_isMounted(false)
    , m_configUpdatesInflight(0)
{
    init(preferences, settings);
}

OnboardingDialog::OnboardingDialog(
    IpcClient *client,
    QSettings *settings,
    QWidget *parent
)
    : QDialog(parent)
    , m_settings(nullptr)
    , m_stack(nullptr)
    , m_lblStepTitle(nullptr)
    , m_lblWelcomeNotice(nullptr)
    , m_lblAccountStatus(nullptr)
    , m_lblAccountFeedback(nullptr)
    , m_btnNativeLogin(nullptr)
    , m_btnBrowserSso(nullptr)
    , m_lblMountPoint(nullptr)
    , m_btnChangeMount(nullptr)
    , m_chkAutoMount(nullptr)
    , m_chkStartAtLogin(nullptr)
    , m_lblMountFeedback(nullptr)
    , m_lblReadyMountPath(nullptr)
    , m_lblReadyRecovery(nullptr)
    , m_btnSkip(nullptr)
    , m_btnBack(nullptr)
    , m_btnNext(nullptr)
    , m_btnFinish(nullptr)
    , m_outcome(Outcome::Pending)
    , m_authenticated(false)
    , m_justLoggedIn(false)
    , m_isMounted(false)
    , m_configUpdatesInflight(0)
{
    auto *prefs = new PreferencesDialog(client, this);
    init(prefs, settings);
}

void OnboardingDialog::init(PreferencesDialog *preferences, QSettings *settings) {
    m_preferences = preferences;
    if (settings) {
        m_settings = settings;
    } else {
        m_ownedSettings = createDefaultSettings();
        m_settings = m_ownedSettings.get();
    }

    setModal(true);
    setWindowModality(Qt::ApplicationModal);
    setWindowTitle("Neutron Drive - Setup");
    setMinimumSize(540, 420);
    if (m_preferences && !m_preferences->windowIcon().isNull()) {
        setWindowIcon(m_preferences->windowIcon());
    }

    initUi();
    connectPreferences();
    syncFromPreferences();
    if (m_preferences) {
        m_preferences->refreshData();
    }
    updateNavigationState();
}

void OnboardingDialog::initUi() {
    auto *rootLayout = new QVBoxLayout(this);
    rootLayout->setSpacing(12);

    m_lblStepTitle = new QLabel("Welcome to Neutron Drive", this);
    QFont titleFont = m_lblStepTitle->font();
    titleFont.setPointSize(13);
    titleFont.setBold(true);
    m_lblStepTitle->setFont(titleFont);
    rootLayout->addWidget(m_lblStepTitle);

    auto *topSep = new QFrame(this);
    topSep->setFrameShape(QFrame::HLine);
    topSep->setFrameShadow(QFrame::Sunken);
    rootLayout->addWidget(topSep);

    m_stack = new QStackedWidget(this);
    rootLayout->addWidget(m_stack, 1);

    // Step 0: Welcome & Risk Notice
    auto *pageWelcome = new QWidget(this);
    auto *layoutWelcome = new QVBoxLayout(pageWelcome);
    m_lblWelcomeNotice = new QLabel(
        "This is a third-party application not officially supported by Proton.\n\n"
        "Pre-release data-safety notice:\n"
        "Neutron Drive is unofficial pre-release software for Proton Drive on Linux. "
        "Please test first with a disposable Proton account or non-critical files and "
        "maintain independent backups of important data. Passwords are used locally for "
        "authentication and are never stored.\n\n"
        "This guided setup will walk you through:\n"
        "1. Signing in to your Proton account (password/2FA or browser SSO).\n"
        "2. Choosing your virtual drive mount folder and startup behavior.\n"
        "3. Reviewing your mount location and error-recovery options.",
        pageWelcome
    );
    m_lblWelcomeNotice->setWordWrap(true);
    layoutWelcome->addWidget(m_lblWelcomeNotice);
    layoutWelcome->addStretch();
    m_stack->addWidget(pageWelcome);

    // Step 1: Account Sign-In
    auto *pageAccount = new QWidget(this);
    auto *layoutAccount = new QVBoxLayout(pageAccount);
    auto *lblAuthDisclosure = new QLabel(
        "This is a third-party application not officially supported by Proton. "
        "Passwords are never stored locally.",
        pageAccount
    );
    lblAuthDisclosure->setWordWrap(true);
    lblAuthDisclosure->setStyleSheet("color: #555; font-size: 11px;");
    layoutAccount->addWidget(lblAuthDisclosure);

    auto *grpAccount = new QGroupBox("Proton Account Sign-In", pageAccount);
    auto *layoutAccountBox = new QVBoxLayout(grpAccount);

    m_lblAccountStatus = new QLabel("Checking authentication status...", grpAccount);
    m_lblAccountStatus->setWordWrap(true);
    layoutAccountBox->addWidget(m_lblAccountStatus);

    m_lblAccountFeedback = new QLabel(grpAccount);
    m_lblAccountFeedback->setWordWrap(true);
    m_lblAccountFeedback->setStyleSheet("color: #b45309;");
    layoutAccountBox->addWidget(m_lblAccountFeedback);

    auto *rowLoginButtons = new QHBoxLayout();
    m_btnNativeLogin = new QPushButton("Sign In with Password...", grpAccount);
    connect(m_btnNativeLogin, &QPushButton::clicked, this, [this]() {
        if (m_preferences) {
            m_preferences->openNativeLoginPrompt(this);
        }
    });

    m_btnBrowserSso = new QPushButton("Sign In via Browser SSO...", grpAccount);
    connect(m_btnBrowserSso, &QPushButton::clicked, this, [this]() {
        if (m_preferences) {
            m_preferences->startBrowserSsoLogin(1500, false);
        }
    });

    rowLoginButtons->addWidget(m_btnNativeLogin);
    rowLoginButtons->addWidget(m_btnBrowserSso);
    rowLoginButtons->addStretch();
    layoutAccountBox->addLayout(rowLoginButtons);

    layoutAccount->addWidget(grpAccount);
    layoutAccount->addStretch();
    m_stack->addWidget(pageAccount);

    // Step 2: Mount & Startup Selection
    auto *pageMount = new QWidget(this);
    auto *layoutMount = new QVBoxLayout(pageMount);

    auto *grpMount = new QGroupBox("Virtual Filesystem & Startup", pageMount);
    auto *layoutMountBox = new QVBoxLayout(grpMount);

    auto *rowMount = new QHBoxLayout();
    auto *lblMountTitle = new QLabel("Mount folder:", grpMount);
    m_lblMountPoint = new QLabel("~/NeutronDrive", grpMount);
    m_lblMountPoint->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_btnChangeMount = new QPushButton("Change...", grpMount);
    connect(m_btnChangeMount, &QPushButton::clicked, this, [this]() {
        if (m_preferences) {
            m_preferences->chooseMountPoint(this, false);
        }
    });
    rowMount->addWidget(lblMountTitle);
    rowMount->addWidget(m_lblMountPoint, 1);
    rowMount->addWidget(m_btnChangeMount);
    layoutMountBox->addLayout(rowMount);

    m_chkAutoMount = new QCheckBox("Automatically mount on startup", grpMount);
    m_chkAutoMount->setChecked(true);
    connect(m_chkAutoMount, &QCheckBox::toggled, this, [this](bool checked) {
        if (!m_preferences) {
            return;
        }
        m_configUpdatesInflight++;
        m_lblMountFeedback->setText("Saving preference...");
        updateNavigationState();
        m_preferences->setAutoMountOnStart(checked, false);
    });
    layoutMountBox->addWidget(m_chkAutoMount);

    m_chkStartAtLogin = new QCheckBox("Start Neutron Drive on login", grpMount);
    m_chkStartAtLogin->setChecked(true);
    connect(m_chkStartAtLogin, &QCheckBox::toggled, this, [this](bool checked) {
        if (!m_preferences) {
            return;
        }
        m_configUpdatesInflight++;
        m_lblMountFeedback->setText("Saving preference...");
        updateNavigationState();
        m_preferences->setStartAtLogin(checked, false);
    });
    layoutMountBox->addWidget(m_chkStartAtLogin);

    m_lblMountFeedback = new QLabel(grpMount);
    m_lblMountFeedback->setWordWrap(true);
    m_lblMountFeedback->setStyleSheet("color: #0e7490;");
    layoutMountBox->addWidget(m_lblMountFeedback);

    auto *lblMountNote = new QLabel(
        "You can change these preferences at any time from Preferences.",
        grpMount
    );
    lblMountNote->setWordWrap(true);
    lblMountNote->setStyleSheet("color: #555; font-size: 11px;");
    layoutMountBox->addWidget(lblMountNote);

    layoutMount->addWidget(grpMount);
    layoutMount->addStretch();
    m_stack->addWidget(pageMount);

    // Step 3: Ready Screen
    auto *pageReady = new QWidget(this);
    auto *layoutReady = new QVBoxLayout(pageReady);

    auto *grpSummary = new QGroupBox("Setup Summary", pageReady);
    auto *layoutSummary = new QVBoxLayout(grpSummary);
    m_lblReadyMountPath = new QLabel(grpSummary);
    m_lblReadyMountPath->setWordWrap(true);
    m_lblReadyMountPath->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layoutSummary->addWidget(m_lblReadyMountPath);
    layoutReady->addWidget(grpSummary);

    auto *grpRecovery = new QGroupBox("Error Recovery & Next Steps", pageReady);
    auto *layoutRecovery = new QVBoxLayout(grpRecovery);
    m_lblReadyRecovery = new QLabel(
        "Error recovery and preferences:\n"
        "• If sync or authentication errors occur, open Preferences → Account to click "
        "\"Retry Failed\", \"Clear Errors\", or sign in again.\n"
        "• You can also inspect or control the daemon from a terminal with "
        "`neutron-drive status` and `neutron-drive mount`.\n"
        "• All account, mount, and cache settings remain editable in Preferences.",
        grpRecovery
    );
    m_lblReadyRecovery->setWordWrap(true);
    layoutRecovery->addWidget(m_lblReadyRecovery);
    layoutReady->addWidget(grpRecovery);

    layoutReady->addStretch();
    m_stack->addWidget(pageReady);

    // Footer buttons
    auto *bottomSep = new QFrame(this);
    bottomSep->setFrameShape(QFrame::HLine);
    bottomSep->setFrameShadow(QFrame::Sunken);
    rootLayout->addWidget(bottomSep);

    auto *rowButtons = new QHBoxLayout();
    m_btnSkip = new QPushButton("Skip for now", this);
    connect(m_btnSkip, &QPushButton::clicked, this, &OnboardingDialog::skipForNow);

    m_btnBack = new QPushButton("Back", this);
    connect(m_btnBack, &QPushButton::clicked, this, &OnboardingDialog::onBackClicked);

    m_btnNext = new QPushButton("Next", this);
    connect(m_btnNext, &QPushButton::clicked, this, &OnboardingDialog::onNextClicked);

    m_btnFinish = new QPushButton("Finish", this);
    connect(m_btnFinish, &QPushButton::clicked, this, &OnboardingDialog::finishOnboarding);

    rowButtons->addWidget(m_btnSkip);
    rowButtons->addStretch();
    rowButtons->addWidget(m_btnBack);
    rowButtons->addWidget(m_btnNext);
    rowButtons->addWidget(m_btnFinish);
    rootLayout->addLayout(rowButtons);

    m_stack->setCurrentIndex(WelcomeStep);
}

void OnboardingDialog::connectPreferences() {
    if (!m_preferences) {
        return;
    }

    connect(m_preferences, &PreferencesDialog::loginStatusMessageChanged,
            this, &OnboardingDialog::onLoginStatusMessageChanged);
    connect(m_preferences, &PreferencesDialog::loginFinished,
            this, &OnboardingDialog::onLoginFinished);
    connect(m_preferences, &PreferencesDialog::logoutFinished,
            this, &OnboardingDialog::onLogoutFinished);
    connect(m_preferences, &PreferencesDialog::statusUpdated,
            this, &OnboardingDialog::onStatusUpdated);
    connect(m_preferences, &PreferencesDialog::daemonUnavailable,
            this, &OnboardingDialog::onDaemonUnavailable);
    connect(m_preferences, &PreferencesDialog::mountPointChanged,
            this, &OnboardingDialog::onMountPointChanged);
    connect(m_preferences, &PreferencesDialog::autoMountChanged,
            this, &OnboardingDialog::onAutoMountChanged);
    connect(m_preferences, &PreferencesDialog::startAtLoginChanged,
            this, &OnboardingDialog::onStartAtLoginChanged);
    connect(m_preferences, &PreferencesDialog::configUpdateFinished,
            this, &OnboardingDialog::onConfigUpdateFinished);
}

void OnboardingDialog::syncFromPreferences() {
    if (!m_preferences) {
        return;
    }

    m_authenticated = m_preferences->isAuthenticated();
    m_isMounted = m_preferences->isMounted();
    if (m_lblAccountStatus && !m_preferences->authStatusText().isEmpty()) {
        m_lblAccountStatus->setText(m_preferences->authStatusText());
    }
    if (m_lblMountPoint && !m_preferences->mountPoint().isEmpty()) {
        m_lblMountPoint->setText(m_preferences->mountPoint());
    }
    if (m_chkAutoMount) {
        QSignalBlocker blocker(m_chkAutoMount);
        m_chkAutoMount->setChecked(m_preferences->isAutoMountChecked());
    }
    if (m_chkStartAtLogin) {
        QSignalBlocker blocker(m_chkStartAtLogin);
        m_chkStartAtLogin->setChecked(m_preferences->isStartAtLoginChecked());
    }
    updateReadySummary();
}

OnboardingDialog::Step OnboardingDialog::currentStep() const {
    if (!m_stack) {
        return WelcomeStep;
    }
    return static_cast<Step>(m_stack->currentIndex());
}

QString OnboardingDialog::mountPoint() const {
    if (m_lblMountPoint) {
        return m_lblMountPoint->text();
    }
    return m_preferences ? m_preferences->mountPoint() : QString();
}

bool OnboardingDialog::isAutoMountChecked() const {
    return m_chkAutoMount && m_chkAutoMount->isChecked();
}

bool OnboardingDialog::isStartAtLoginChecked() const {
    return m_chkStartAtLogin && m_chkStartAtLogin->isChecked();
}

QSettings *OnboardingDialog::activeSettings() const {
    return m_settings ? m_settings : m_ownedSettings.get();
}

void OnboardingDialog::submitNativeLogin(
    const QString &user,
    const QString &pass,
    const QString &totp,
    bool interactiveDialogs
) {
    if (m_preferences) {
        m_preferences->submitNativeLogin(user, pass, totp, interactiveDialogs, this);
    }
}

void OnboardingDialog::startBrowserSsoLogin(int pollIntervalMs) {
    if (m_preferences) {
        m_preferences->startBrowserSsoLogin(pollIntervalMs, false);
    }
}

void OnboardingDialog::applyMountPoint(const QString &dir, bool interactiveDialogs) {
    if (!m_preferences) {
        return;
    }
    m_configUpdatesInflight++;
    m_lblMountFeedback->setText("Saving preference...");
    updateNavigationState();
    m_preferences->applyMountPoint(dir, interactiveDialogs);
}

void OnboardingDialog::skipForNow() {
    if (m_preferences) {
        m_preferences->cancelBrowserSsoLogin();
    }
    m_outcome = Outcome::Skipped;
    QDialog::reject();
}

void OnboardingDialog::reject() {
    if (m_preferences) {
        m_preferences->cancelBrowserSsoLogin();
    }
    if (m_outcome == Outcome::Pending) {
        m_outcome = Outcome::Skipped;
    }
    QDialog::reject();
}

void OnboardingDialog::finishOnboarding() {
    if (currentStep() != ReadyStep) {
        return;
    }
    if (QSettings *s = activeSettings()) {
        persistOnboardingCompleted(*s);
    }
    m_outcome = Outcome::Completed;
    emit onboardingCompleted();
    QDialog::accept();
}

void OnboardingDialog::onBackClicked() {
    const int idx = m_stack->currentIndex();
    if (idx > WelcomeStep) {
        m_stack->setCurrentIndex(idx - 1);
        updateNavigationState();
    }
}

void OnboardingDialog::onNextClicked() {
    const int idx = m_stack->currentIndex();
    if (idx >= ReadyStep) {
        return;
    }
    if (idx == AccountStep && !m_authenticated) {
        return;
    }
    if (idx == MountStep && m_configUpdatesInflight > 0) {
        return;
    }
    m_stack->setCurrentIndex(idx + 1);
    if (m_stack->currentIndex() == ReadyStep) {
        updateReadySummary();
    }
    updateNavigationState();
}

void OnboardingDialog::onLoginStatusMessageChanged(const QString &message) {
    if (m_lblAccountStatus) {
        m_lblAccountStatus->setText(message);
    }
    if (m_lblAccountFeedback
        && (message == "Signing in..."
            || message == "Starting browser login..."
            || message.startsWith("Waiting for browser login"))) {
        m_lblAccountFeedback->clear();
    }
}

void OnboardingDialog::onLoginFinished(bool ok, const QString &status, const QString &message) {
    if (ok) {
        m_authenticated = true;
        m_justLoggedIn = true;
        if (m_lblAccountFeedback) {
            m_lblAccountFeedback->clear();
        }
        if (m_lblAccountStatus) {
            m_lblAccountStatus->setText(message.isEmpty() ? QString("Authenticated") : message);
        }
    } else {
        m_authenticated = false;
        m_justLoggedIn = false;
        if (status == "2fa_required" && m_lblAccountStatus) {
            m_lblAccountStatus->setText("2FA Required");
        }
        if (m_lblAccountFeedback) {
            m_lblAccountFeedback->setText(message);
        }
    }
    updateNavigationState();
}

void OnboardingDialog::onLogoutFinished(bool ok) {
    if (ok) {
        m_authenticated = false;
        m_justLoggedIn = false;
        updateNavigationState();
    }
}

void OnboardingDialog::onStatusUpdated(
    bool authenticated,
    const QString &authMessage,
    bool isMounted,
    const QString &mountPoint,
    int errorCount,
    const QString &lastError
) {
    Q_UNUSED(errorCount);
    Q_UNUSED(lastError);

    m_isMounted = isMounted;
    if (!mountPoint.isEmpty() && m_lblMountPoint) {
        m_lblMountPoint->setText(mountPoint);
    }

    if (authenticated) {
        m_authenticated = true;
        m_justLoggedIn = false;
        if (m_lblAccountStatus) {
            m_lblAccountStatus->setText(authMessage);
        }
        if (m_lblAccountFeedback) {
            m_lblAccountFeedback->clear();
        }
    } else if (!m_justLoggedIn) {
        m_authenticated = false;
        if (m_lblAccountStatus) {
            m_lblAccountStatus->setText(authMessage);
        }
    }

    updateReadySummary();
    updateNavigationState();
}

void OnboardingDialog::onDaemonUnavailable(const QString &message) {
    if (m_lblAccountStatus) {
        m_lblAccountStatus->setText(message);
    }
    if (m_lblAccountFeedback && !m_authenticated) {
        m_lblAccountFeedback->setText(
            "Start the Neutron Drive daemon before signing in, or skip setup and configure later from Preferences."
        );
    }
}

void OnboardingDialog::onMountPointChanged(const QString &mountPoint) {
    if (m_lblMountPoint) {
        m_lblMountPoint->setText(mountPoint);
    }
    updateReadySummary();
}

void OnboardingDialog::onAutoMountChanged(bool enabled) {
    if (m_chkAutoMount) {
        QSignalBlocker blocker(m_chkAutoMount);
        m_chkAutoMount->setChecked(enabled);
    }
    updateReadySummary();
}

void OnboardingDialog::onStartAtLoginChanged(bool enabled) {
    if (m_chkStartAtLogin) {
        QSignalBlocker blocker(m_chkStartAtLogin);
        m_chkStartAtLogin->setChecked(enabled);
    }
    updateReadySummary();
}

void OnboardingDialog::onConfigUpdateFinished(
    const QString &field,
    bool ok,
    const QString &message,
    bool remountRequired
) {
    if (field != "mount_point" && field != "auto_mount_on_start" && field != "start_at_login") {
        return;
    }

    m_configUpdatesInflight = std::max(0, m_configUpdatesInflight - 1);
    if (m_lblMountFeedback) {
        if (ok) {
            if (remountRequired && !message.isEmpty()) {
                m_lblMountFeedback->setText(message);
            } else {
                m_lblMountFeedback->setText("Preferences saved.");
            }
        } else {
            m_lblMountFeedback->setText(
                message.isEmpty() ? QString("Failed to update preference; reverted.") : message
            );
        }
    }
    updateReadySummary();
    updateNavigationState();
}

void OnboardingDialog::updateReadySummary() {
    if (!m_lblReadyMountPath) {
        return;
    }
    const QString mp = mountPoint();
    const QString autoMountText = isAutoMountChecked() ? "Enabled" : "Disabled";
    const QString startLoginText = isStartAtLoginChecked() ? "Enabled" : "Disabled";
    const QString mountedText = m_isMounted
        ? "Mounted"
        : "Not currently mounted (will mount automatically if enabled or from tray/CLI)";
    m_lblReadyMountPath->setText(
        QString("Mount folder: %1\n"
                "Mount status: %2\n"
                "Auto-mount on startup: %3\n"
                "Start on login: %4")
            .arg(mp, mountedText, autoMountText, startLoginText)
    );
}

void OnboardingDialog::updateNavigationState() {
    const Step step = currentStep();
    if (m_lblStepTitle) {
        switch (step) {
        case WelcomeStep:
            m_lblStepTitle->setText("Welcome to Neutron Drive");
            break;
        case AccountStep:
            m_lblStepTitle->setText("Sign In to Your Proton Account");
            break;
        case MountStep:
            m_lblStepTitle->setText("Mount Folder and Startup Options");
            break;
        case ReadyStep:
            m_lblStepTitle->setText("Neutron Drive Is Ready");
            break;
        }
    }

    m_btnSkip->setVisible(step != ReadyStep);
    m_btnBack->setVisible(step != WelcomeStep);
    m_btnBack->setEnabled(step != WelcomeStep);
    m_btnNext->setVisible(step != ReadyStep);
    m_btnFinish->setVisible(step == ReadyStep);
    m_btnFinish->setDefault(step == ReadyStep);

    if (step == WelcomeStep) {
        m_btnNext->setEnabled(true);
        m_btnNext->setDefault(true);
    } else if (step == AccountStep) {
        m_btnNext->setEnabled(m_authenticated);
        m_btnNext->setDefault(m_authenticated);
    } else if (step == MountStep) {
        const bool canProceed = (m_configUpdatesInflight == 0);
        m_btnNext->setEnabled(canProceed);
        m_btnNext->setDefault(canProceed);
    } else {
        m_btnFinish->setEnabled(true);
    }
}
