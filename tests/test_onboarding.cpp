#include <QApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QSettings>
#include <QStringList>
#include <QTemporaryDir>
#include <QTest>

#include "src/gui-cpp/IpcClient.hpp"
#include "src/gui-cpp/OnboardingDialog.hpp"
#include "src/gui-cpp/PreferencesDialog.hpp"
#include "src/gui-cpp/TrayCoordinator.hpp"

class TestOnboarding : public QObject {
    Q_OBJECT

private slots:
    void testFirstRunOnboardingStepFlowAndCompletionPersistence();
    void testSkipForNowLeavesSettingsUnsetAndReopensNextLaunch();
    void testFailedLoginTwoFactorBrowserSsoAndConfigRollback();
    void testSchemaVersionMismatchReopensOnboarding();
};

void TestOnboarding::testFirstRunOnboardingStepFlowAndCompletionPersistence() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());

    const QString socketPath = tempDir.filePath("first_run.sock");
    const QString settingsPath = tempDir.filePath("gui.conf");

    QLocalServer server;
    QVERIFY(server.listen(socketPath));

    bool authenticated = false;
    QString mountPoint = "/tmp/initial-mount";
    bool autoMount = true;
    bool startAtLogin = true;
    int updateConfigCount = 0;
    QStringList updateKeys;

    connect(&server, &QLocalServer::newConnection, [&]() {
        while (QLocalSocket *sock = server.nextPendingConnection()) {
            connect(sock, &QLocalSocket::readyRead, [&, sock]() {
                const QByteArray reqBytes = sock->readAll();
                const QJsonObject req = QJsonDocument::fromJson(reqBytes).object();
                const QString cmd = req.value("command").toString();
                const QJsonObject args = req.value("args").toObject();

                QJsonObject resp;
                if (cmd == "get-config") {
                    resp["status"] = "ok";
                    QJsonObject cfg;
                    cfg["mount_point"] = mountPoint;
                    cfg["auto_mount_on_start"] = autoMount;
                    cfg["start_at_login"] = startAtLogin;
                    cfg["offline_mode"] = false;
                    cfg["event_poll_interval_sec"] = 30;
                    cfg["cache_max_size_mb"] = 5120;
                    cfg["cache_ttl_hours"] = 168;
                    resp["config"] = cfg;
                } else if (cmd == "status") {
                    resp["status"] = "ok";
                    resp["authenticated"] = authenticated;
                    resp["auth_message"] = authenticated
                        ? QString("Authenticated (alice@proton.me)")
                        : QString("Not authenticated");
                    resp["sync_status"] = "idle";
                    resp["is_mounted"] = authenticated;
                    resp["mount_point"] = mountPoint;
                } else if (cmd == "login") {
                    if (args.value("username").toString() == "alice@proton.me"
                        && args.value("password").toString() == "secret") {
                        authenticated = true;
                        resp["status"] = "ok";
                        resp["message"] = "Authenticated as alice@proton.me";
                    } else {
                        resp["status"] = "error";
                        resp["message"] = "Invalid credentials";
                    }
                } else if (cmd == "update-config") {
                    updateConfigCount++;
                    for (auto it = args.begin(); it != args.end(); ++it) {
                        updateKeys << it.key();
                    }
                    bool remountRequired = false;
                    if (args.contains("mount_point")) {
                        mountPoint = args.value("mount_point").toString();
                        remountRequired = true;
                    }
                    if (args.contains("auto_mount_on_start")) {
                        autoMount = args.value("auto_mount_on_start").toBool();
                    }
                    if (args.contains("start_at_login")) {
                        startAtLogin = args.value("start_at_login").toBool();
                    }
                    resp["status"] = "ok";
                    if (remountRequired) {
                        resp["remount_required"] = true;
                    }
                    QJsonObject cfg;
                    cfg["mount_point"] = mountPoint;
                    cfg["auto_mount_on_start"] = autoMount;
                    cfg["start_at_login"] = startAtLogin;
                    resp["config"] = cfg;
                } else {
                    resp["status"] = "ok";
                }

                sock->write(QJsonDocument(resp).toJson(QJsonDocument::Compact) + "\n");
                sock->flush();
                sock->disconnectFromServer();
            });
            connect(sock, &QLocalSocket::disconnected, sock, &QObject::deleteLater);
        }
    });

    QSettings settings(settingsPath, QSettings::IniFormat);
    IpcClient client(socketPath);
    TrayCoordinator tray(&client, nullptr, &settings);

    QVERIFY(tray.shouldShowOnboarding());
    QVERIFY(tray.runOnboardingIfNeeded(false));

    OnboardingDialog *dlg = tray.onboardingDialog();
    QVERIFY(dlg != nullptr);
    QVERIFY(dlg->isModal());
    QCOMPARE(dlg->windowModality(), Qt::ApplicationModal);
    QCOMPARE(dlg->currentStep(), OnboardingDialog::WelcomeStep);
    QVERIFY(dlg->welcomeNoticeText().contains("third-party application not officially supported by Proton"));
    QVERIFY(dlg->welcomeNoticeText().contains("pre-release", Qt::CaseInsensitive));
    QVERIFY(dlg->welcomeNoticeText().contains("never stored", Qt::CaseInsensitive));
    QVERIFY(dlg->skipButton()->isVisible());
    QVERIFY(!dlg->backButton()->isVisible());
    QVERIFY(dlg->nextButton()->isVisible());
    QVERIFY(dlg->nextButton()->isEnabled());
    QVERIFY(!dlg->finishButton()->isVisible());

    // Advance to Account step
    dlg->nextButton()->click();
    QCOMPARE(dlg->currentStep(), OnboardingDialog::AccountStep);
    QTRY_COMPARE_WITH_TIMEOUT(dlg->accountStatusText(), QString("Not Authenticated"), 2000);
    QVERIFY(!dlg->isAuthenticated());
    QVERIFY(!dlg->nextButton()->isEnabled());

    // Authenticate via native login pass-through
    dlg->submitNativeLogin("alice@proton.me", "secret", QString(), false);
    QTRY_VERIFY_WITH_TIMEOUT(dlg->isAuthenticated(), 2000);
    QTRY_VERIFY_WITH_TIMEOUT(dlg->nextButton()->isEnabled(), 2000);
    QVERIFY(dlg->accountStatusText().contains("Authenticated"));

    // Advance to Mount & Startup step
    dlg->nextButton()->click();
    QCOMPARE(dlg->currentStep(), OnboardingDialog::MountStep);
    QCOMPARE(dlg->mountPoint(), QString("/tmp/initial-mount"));
    QCOMPARE(dlg->isAutoMountChecked(), true);
    QCOMPARE(dlg->isStartAtLoginChecked(), true);

    // Update mount folder and startup options via IPC-backed controls
    dlg->applyMountPoint("/tmp/custom-mount", false);
    QTRY_COMPARE_WITH_TIMEOUT(dlg->mountPoint(), QString("/tmp/custom-mount"), 2000);
    QCOMPARE(tray.preferencesDialog()->mountPoint(), QString("/tmp/custom-mount"));

    dlg->autoMountCheckBox()->setChecked(false);
    dlg->startAtLoginCheckBox()->setChecked(false);
    QTRY_VERIFY_WITH_TIMEOUT(updateConfigCount == 3 && dlg->nextButton()->isEnabled(), 2000);
    QCOMPARE(autoMount, false);
    QCOMPARE(startAtLogin, false);
    QCOMPARE(dlg->isAutoMountChecked(), false);
    QCOMPARE(dlg->isStartAtLoginChecked(), false);
    QCOMPARE(tray.preferencesDialog()->isAutoMountChecked(), false);
    QCOMPARE(tray.preferencesDialog()->isStartAtLoginChecked(), false);
    QVERIFY(updateKeys.contains("mount_point"));
    QVERIFY(updateKeys.contains("auto_mount_on_start"));
    QVERIFY(updateKeys.contains("start_at_login"));
    QVERIFY(!updateKeys.contains("onboardingCompleted"));
    QVERIFY(!updateKeys.contains("schemaVersion"));

    // Advance to Ready step; settings must still be unset until Finish
    dlg->nextButton()->click();
    QCOMPARE(dlg->currentStep(), OnboardingDialog::ReadyStep);
    {
        QSettings checkBeforeFinish(settingsPath, QSettings::IniFormat);
        QVERIFY(!checkBeforeFinish.contains(OnboardingDialog::kCompletedKey));
        QVERIFY(!OnboardingDialog::isOnboardingCompleted(checkBeforeFinish));
    }
    QVERIFY(dlg->readyMountPathText().contains("/tmp/custom-mount"));
    QVERIFY(dlg->readyRecoveryText().contains("Preferences"));
    QVERIFY(dlg->readyRecoveryText().contains("Retry Failed"));
    QVERIFY(dlg->readyRecoveryText().contains("Clear Errors"));
    QVERIFY(!dlg->skipButton()->isVisible());
    QVERIFY(!dlg->nextButton()->isVisible());
    QVERIFY(dlg->finishButton()->isVisible());
    QVERIFY(dlg->finishButton()->isEnabled());

    // Finish onboarding and verify versioned QSettings persistence
    dlg->finishButton()->click();
    QTRY_COMPARE_WITH_TIMEOUT(dlg->outcome(), OnboardingDialog::Outcome::Completed, 2000);
    QCOMPARE(dlg->result(), static_cast<int>(QDialog::Accepted));

    QSettings reloaded(settingsPath, QSettings::IniFormat);
    QCOMPARE(reloaded.value(OnboardingDialog::kSchemaVersionKey).toInt(), OnboardingDialog::kSchemaVersion);
    QCOMPARE(reloaded.value(OnboardingDialog::kCompletedKey).toBool(), true);
    QVERIFY(OnboardingDialog::isOnboardingCompleted(reloaded));
    QVERIFY(!OnboardingDialog::shouldShowOnboarding(reloaded));

    // Subsequent launch skips onboarding, while Preferences remain editable
    TrayCoordinator nextLaunchTray(&client, nullptr, &reloaded);
    QVERIFY(!nextLaunchTray.shouldShowOnboarding());
    QVERIFY(!nextLaunchTray.runOnboardingIfNeeded(false));
    QVERIFY(nextLaunchTray.onboardingDialog() == nullptr);

    nextLaunchTray.preferencesDialog()->setAutoMountOnStart(true, false);
    QTRY_COMPARE_WITH_TIMEOUT(updateConfigCount, 4, 2000);
    QCOMPARE(autoMount, true);
}

void TestOnboarding::testSkipForNowLeavesSettingsUnsetAndReopensNextLaunch() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());

    const QString socketPath = tempDir.filePath("skip.sock");
    const QString settingsPath = tempDir.filePath("gui.conf");

    QLocalServer server;
    QVERIFY(server.listen(socketPath));

    bool authenticated = false;
    int pollCount = 0;

    connect(&server, &QLocalServer::newConnection, [&]() {
        while (QLocalSocket *sock = server.nextPendingConnection()) {
            connect(sock, &QLocalSocket::readyRead, [&, sock]() {
                const QByteArray reqBytes = sock->readAll();
                const QString cmd = QJsonDocument::fromJson(reqBytes).object().value("command").toString();

                QJsonObject resp;
                if (cmd == "get-config") {
                    resp["status"] = "ok";
                    QJsonObject cfg;
                    cfg["mount_point"] = "/tmp/skip-mount";
                    cfg["auto_mount_on_start"] = true;
                    cfg["start_at_login"] = false;
                    resp["config"] = cfg;
                } else if (cmd == "status") {
                    resp["status"] = "ok";
                    resp["authenticated"] = authenticated;
                    resp["auth_message"] = authenticated ? QString("Authenticated") : QString("Not authenticated");
                    resp["sync_status"] = "idle";
                    resp["mount_point"] = "/tmp/skip-mount";
                } else if (cmd == "start-browser-login") {
                    resp["status"] = "ok";
                    resp["login_url"] = "https://account.proton.me/desktop/login?app=drive";
                    resp["user_code"] = "SKIP1234";
                } else if (cmd == "poll-browser-login") {
                    pollCount++;
                    resp["status"] = "pending";
                } else {
                    resp["status"] = "ok";
                }

                sock->write(QJsonDocument(resp).toJson(QJsonDocument::Compact) + "\n");
                sock->flush();
                sock->disconnectFromServer();
            });
            connect(sock, &QLocalSocket::disconnected, sock, &QObject::deleteLater);
        }
    });

    IpcClient client(socketPath);

    // Launch 1: start Browser SSO polling, then click "Skip for now"
    {
        QSettings settings1(settingsPath, QSettings::IniFormat);
        TrayCoordinator tray1(&client, nullptr, &settings1);
        QVERIFY(tray1.runOnboardingIfNeeded(false));
        OnboardingDialog *dlg1 = tray1.onboardingDialog();
        QVERIFY(dlg1 != nullptr);

        dlg1->nextButton()->click();
        QCOMPARE(dlg1->currentStep(), OnboardingDialog::AccountStep);
        QTRY_COMPARE_WITH_TIMEOUT(dlg1->accountStatusText(), QString("Not Authenticated"), 2000);

        dlg1->startBrowserSsoLogin(25);
        QTRY_VERIFY_WITH_TIMEOUT(pollCount >= 1, 2000);

        dlg1->skipButton()->click();
        QTRY_COMPARE_WITH_TIMEOUT(dlg1->outcome(), OnboardingDialog::Outcome::Skipped, 2000);
        QCOMPARE(dlg1->result(), static_cast<int>(QDialog::Rejected));

        QTest::qWait(50);
        const int pollsAfterSkip = pollCount;
        QTest::qWait(120);
        QCOMPARE(pollCount, pollsAfterSkip);
    }

    // Verify QSettings remained unset on disk
    QSettings reloaded1(settingsPath, QSettings::IniFormat);
    QVERIFY(!reloaded1.contains(OnboardingDialog::kCompletedKey));
    QVERIFY(!reloaded1.contains(OnboardingDialog::kSchemaVersionKey));
    QVERIFY(OnboardingDialog::shouldShowOnboarding(reloaded1));

    // Launch 2: onboarding reopens at WelcomeStep; closing via reject() on ReadyStep also leaves unset
    authenticated = true;
    {
        TrayCoordinator tray2(&client, nullptr, &reloaded1);
        QVERIFY(tray2.shouldShowOnboarding());
        QVERIFY(tray2.runOnboardingIfNeeded(false));
        OnboardingDialog *dlg2 = tray2.onboardingDialog();
        QVERIFY(dlg2 != nullptr);
        QCOMPARE(dlg2->currentStep(), OnboardingDialog::WelcomeStep);

        dlg2->nextButton()->click();
        QCOMPARE(dlg2->currentStep(), OnboardingDialog::AccountStep);
        QTRY_VERIFY_WITH_TIMEOUT(dlg2->isAuthenticated(), 2000);
        QVERIFY(dlg2->nextButton()->isEnabled());

        dlg2->nextButton()->click();
        QCOMPARE(dlg2->currentStep(), OnboardingDialog::MountStep);
        dlg2->nextButton()->click();
        QCOMPARE(dlg2->currentStep(), OnboardingDialog::ReadyStep);

        dlg2->reject();
        QCOMPARE(dlg2->outcome(), OnboardingDialog::Outcome::Skipped);
    }

    QSettings reloaded2(settingsPath, QSettings::IniFormat);
    QVERIFY(!reloaded2.contains(OnboardingDialog::kCompletedKey));
    QVERIFY(!reloaded2.contains(OnboardingDialog::kSchemaVersionKey));
    QVERIFY(OnboardingDialog::shouldShowOnboarding(reloaded2));
}

void TestOnboarding::testFailedLoginTwoFactorBrowserSsoAndConfigRollback() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());

    const QString socketPath = tempDir.filePath("failures.sock");
    const QString settingsPath = tempDir.filePath("gui.conf");

    QLocalServer server;
    QVERIFY(server.listen(socketPath));

    bool authenticated = false;
    int pollCount = 0;
    int updateAttempts = 0;

    connect(&server, &QLocalServer::newConnection, [&]() {
        while (QLocalSocket *sock = server.nextPendingConnection()) {
            connect(sock, &QLocalSocket::readyRead, [&, sock]() {
                const QByteArray reqBytes = sock->readAll();
                const QJsonObject req = QJsonDocument::fromJson(reqBytes).object();
                const QString cmd = req.value("command").toString();
                const QJsonObject args = req.value("args").toObject();

                QJsonObject resp;
                if (cmd == "get-config") {
                    resp["status"] = "ok";
                    QJsonObject cfg;
                    cfg["mount_point"] = "/tmp/orig-mount";
                    cfg["auto_mount_on_start"] = true;
                    cfg["start_at_login"] = false;
                    resp["config"] = cfg;
                } else if (cmd == "status") {
                    resp["status"] = "ok";
                    resp["authenticated"] = authenticated;
                    resp["auth_message"] = authenticated
                        ? QString("Authenticated (alice@proton.me)")
                        : QString("Not authenticated");
                    resp["sync_status"] = "idle";
                    resp["mount_point"] = "/tmp/orig-mount";
                } else if (cmd == "login") {
                    const QString user = args.value("username").toString();
                    const QString pass = args.value("password").toString();
                    const QString totp = args.value("totp").toString();
                    if (user == "alice@proton.me" && pass == "secret" && totp.isEmpty()) {
                        resp["status"] = "2fa_required";
                        resp["message"] = "2FA code required";
                    } else {
                        resp["status"] = "error";
                        resp["message"] = "Invalid credentials";
                    }
                } else if (cmd == "start-browser-login") {
                    resp["status"] = "ok";
                    resp["login_url"] = "https://account.proton.me/desktop/login?app=drive";
                    resp["user_code"] = "FAIL9999";
                } else if (cmd == "poll-browser-login") {
                    pollCount++;
                    if (pollCount < 2) {
                        resp["status"] = "pending";
                    } else {
                        authenticated = true;
                        resp["status"] = "ok";
                        resp["message"] = "Authenticated as alice@proton.me";
                    }
                } else if (cmd == "update-config") {
                    updateAttempts++;
                    resp["status"] = "error";
                    resp["message"] = "Simulated config write failure";
                } else {
                    resp["status"] = "ok";
                }

                sock->write(QJsonDocument(resp).toJson(QJsonDocument::Compact) + "\n");
                sock->flush();
                sock->disconnectFromServer();
            });
            connect(sock, &QLocalSocket::disconnected, sock, &QObject::deleteLater);
        }
    });

    QSettings settings(settingsPath, QSettings::IniFormat);
    IpcClient client(socketPath);
    OnboardingDialog dlg(&client, &settings);

    dlg.nextButton()->click();
    QCOMPARE(dlg.currentStep(), OnboardingDialog::AccountStep);
    QTRY_COMPARE_WITH_TIMEOUT(dlg.accountStatusText(), QString("Not Authenticated"), 2000);

    // 1. Failed native login keeps Next disabled and shows inline feedback
    dlg.submitNativeLogin("alice@proton.me", "wrong", QString(), false);
    QTRY_VERIFY_WITH_TIMEOUT(dlg.accountFeedbackText().contains("Invalid credentials"), 2000);
    QVERIFY(!dlg.isAuthenticated());
    QVERIFY(!dlg.nextButton()->isEnabled());

    // 2. 2FA challenge updates status and keeps Next disabled
    dlg.submitNativeLogin("alice@proton.me", "secret", QString(), false);
    QTRY_COMPARE_WITH_TIMEOUT(dlg.accountStatusText(), QString("2FA Required"), 2000);
    QVERIFY(dlg.accountFeedbackText().contains("2FA code required"));
    QVERIFY(!dlg.isAuthenticated());
    QVERIFY(!dlg.nextButton()->isEnabled());

    // 3. Browser SSO pending -> ok authenticates and clears feedback
    dlg.startBrowserSsoLogin(25);
    QTRY_VERIFY_WITH_TIMEOUT(dlg.isAuthenticated(), 3000);
    QVERIFY(pollCount >= 2);
    QVERIFY(dlg.nextButton()->isEnabled());
    QVERIFY(dlg.accountFeedbackText().isEmpty());

    // 4. Advance to Mount step and verify IPC error rollback without signal loops
    dlg.nextButton()->click();
    QCOMPARE(dlg.currentStep(), OnboardingDialog::MountStep);
    QCOMPARE(dlg.mountPoint(), QString("/tmp/orig-mount"));
    QCOMPARE(dlg.isAutoMountChecked(), true);
    QCOMPARE(dlg.isStartAtLoginChecked(), false);

    dlg.applyMountPoint("/tmp/bad-mount", false);
    dlg.autoMountCheckBox()->setChecked(false);
    dlg.startAtLoginCheckBox()->setChecked(true);

    QTRY_COMPARE_WITH_TIMEOUT(updateAttempts, 3, 2000);
    QTRY_COMPARE_WITH_TIMEOUT(dlg.mountPoint(), QString("/tmp/orig-mount"), 2000);
    QTRY_COMPARE_WITH_TIMEOUT(dlg.isAutoMountChecked(), true, 2000);
    QTRY_COMPARE_WITH_TIMEOUT(dlg.isStartAtLoginChecked(), false, 2000);
    QCOMPARE(dlg.preferencesDialog()->mountPoint(), QString("/tmp/orig-mount"));
    QCOMPARE(dlg.preferencesDialog()->isAutoMountChecked(), true);
    QCOMPARE(dlg.preferencesDialog()->isStartAtLoginChecked(), false);
    QVERIFY(dlg.mountFeedbackText().contains("Simulated config write failure"));

    QTest::qWait(50);
    QCOMPARE(updateAttempts, 3);
    QVERIFY(!OnboardingDialog::isOnboardingCompleted(settings));
}

void TestOnboarding::testSchemaVersionMismatchReopensOnboarding() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());

    {
        const QString pathA = tempDir.filePath("v0.conf");
        QSettings sA(pathA, QSettings::IniFormat);
        sA.setValue(OnboardingDialog::kSchemaVersionKey, 0);
        sA.setValue(OnboardingDialog::kCompletedKey, true);
        sA.sync();

        QSettings rA(pathA, QSettings::IniFormat);
        QVERIFY(!OnboardingDialog::isOnboardingCompleted(rA));
        QVERIFY(OnboardingDialog::shouldShowOnboarding(rA));
    }

    {
        const QString pathB = tempDir.filePath("missing_ver.conf");
        QSettings sB(pathB, QSettings::IniFormat);
        sB.setValue(OnboardingDialog::kCompletedKey, true);
        sB.sync();

        QSettings rB(pathB, QSettings::IniFormat);
        QVERIFY(!OnboardingDialog::isOnboardingCompleted(rB));
        QVERIFY(OnboardingDialog::shouldShowOnboarding(rB));
    }

    {
        const QString pathC = tempDir.filePath("future_ver.conf");
        QSettings sC(pathC, QSettings::IniFormat);
        sC.setValue(OnboardingDialog::kSchemaVersionKey, 99);
        sC.setValue(OnboardingDialog::kCompletedKey, true);
        sC.sync();

        QSettings rC(pathC, QSettings::IniFormat);
        QVERIFY(!OnboardingDialog::isOnboardingCompleted(rC));
        QVERIFY(OnboardingDialog::shouldShowOnboarding(rC));
    }

    {
        const QString pathD = tempDir.filePath("current_ver.conf");
        QSettings sD(pathD, QSettings::IniFormat);
        OnboardingDialog::persistOnboardingCompleted(sD);

        QSettings rD(pathD, QSettings::IniFormat);
        QVERIFY(OnboardingDialog::isOnboardingCompleted(rD));
        QVERIFY(!OnboardingDialog::shouldShowOnboarding(rD));
    }
}

int main(int argc, char *argv[]) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);
    TestOnboarding tc;
    return QTest::qExec(&tc, argc, argv);
}

#include "test_onboarding.moc"
