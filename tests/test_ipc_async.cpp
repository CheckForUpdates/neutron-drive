#include <QTest>
#include <QLocalServer>
#include <QLocalSocket>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QTimer>
#include <QApplication>
#include <QThread>

#include "src/gui-cpp/IpcClient.hpp"
#include "src/gui-cpp/PreferencesDialog.hpp"
#include "src/gui-cpp/TrayCoordinator.hpp"

class TestIpcAsync : public QObject {
    Q_OBJECT

private slots:
    void testDelayedDaemonDoesNotBlockEventLoop();
    void testOnlyOneStatusRequestInflight();
    void testTimeoutDisconnectAndMalformedResponses();
    void testPreferencesDialogLoadsConfigAndHandlesRollback();
    void testNativeLoginTwoFactorLogoutAndBrowserSso();
    void testEnsureDaemonRunningStartsProcessWhenOffline();
    void testTrayNotificationsForSyncErrorsAndAuthExpiration();
    void testPreferencesErrorRecoveryRetryAndClear();
};

void TestIpcAsync::testDelayedDaemonDoesNotBlockEventLoop() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());
    QString socketPath = tempDir.filePath("delayed.sock");

    QLocalServer server;
    QVERIFY(server.listen(socketPath));

    // When connection arrives, delay the response by 200ms
    connect(&server, &QLocalServer::newConnection, [&server]() {
        QLocalSocket *sock = server.nextPendingConnection();
        if (!sock) return;

        connect(sock, &QLocalSocket::readyRead, [sock]() {
            QByteArray requestData = sock->readAll();
            Q_UNUSED(requestData);

            // Delay response to simulate slow/delayed daemon subprocess
            QTimer::singleShot(200, sock, [sock]() {
                QJsonObject resp;
                resp["status"] = "ok";
                resp["sync_status"] = "synced";
                resp["is_paused"] = false;
                resp["mount_point"] = "/fake/mount";
                QJsonObject quota;
                quota["used_bytes"] = 1000.0;
                quota["total_bytes"] = 2000.0;
                quota["percent_used"] = 50.0;
                resp["quota"] = quota;

                sock->write(QJsonDocument(resp).toJson(QJsonDocument::Compact));
                sock->flush();
            });
        });
    });

    IpcClient client(socketPath);

    // Track whether the Qt event loop continues processing events during the wait
    int eventLoopTicks = 0;
    QTimer tickTimer;
    tickTimer.setInterval(10);
    connect(&tickTimer, &QTimer::timeout, [&eventLoopTicks]() {
        eventLoopTicks++;
    });
    tickTimer.start();

    bool callbackDelivered = false;
    QJsonObject callbackResult;
    Qt::HANDLE callbackThread = nullptr;

    client.sendCommandAsync("status", [&](const QJsonObject &res) {
        callbackDelivered = true;
        callbackResult = res;
        callbackThread = QThread::currentThreadId();
    });

    // Event loop must remain unblocked while waiting for response
    QTRY_VERIFY_WITH_TIMEOUT(callbackDelivered, 3000);
    tickTimer.stop();

    QCOMPARE(callbackResult.value("status").toString(), QString("ok"));
    QCOMPARE(callbackResult.value("sync_status").toString(), QString("synced"));

    // Verify callback was delivered on the main/calling thread
    QCOMPARE(callbackThread, QThread::currentThreadId());

    // Verify that the event loop actively processed timer ticks during the delay
    QVERIFY2(eventLoopTicks >= 5, "Event loop was blocked during delayed IPC response");
}

void TestIpcAsync::testOnlyOneStatusRequestInflight() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());
    QString socketPath = tempDir.filePath("inflight.sock");

    QLocalServer server;
    QVERIFY(server.listen(socketPath));

    int incomingConnectionCount = 0;
    QLocalSocket *heldSocket = nullptr;

    connect(&server, &QLocalServer::newConnection, [&]() {
        incomingConnectionCount++;
        heldSocket = server.nextPendingConnection();
    });

    IpcClient client(socketPath);
    TrayCoordinator tray(&client);

    QVERIFY(!tray.isStatusInflight());

    // First pollStatus initiates an async request
    tray.pollStatus();

    // The status request should now be marked inflight
    QVERIFY(tray.isStatusInflight());
    QTRY_COMPARE_WITH_TIMEOUT(incomingConnectionCount, 1, 1000);

    // Second pollStatus while inflight must return early without starting a new request
    tray.pollStatus();

    // Verify it is still inflight and no second connection was created
    QVERIFY(tray.isStatusInflight());
    QCOMPARE(incomingConnectionCount, 1);

    // Now daemon server responds to the held request
    QVERIFY(heldSocket != nullptr);
    QJsonObject resp;
    resp["status"] = "ok";
    resp["sync_status"] = "syncing";
    resp["is_paused"] = false;
    heldSocket->write(QJsonDocument(resp).toJson(QJsonDocument::Compact));
    heldSocket->flush();

    // Callback completes and inflight flag resets to false
    QTRY_VERIFY_WITH_TIMEOUT(!tray.isStatusInflight(), 2000);
    QCOMPARE(tray.lastStatus(), QString("syncing"));
}

void TestIpcAsync::testTimeoutDisconnectAndMalformedResponses() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());

    // Subtest A: Malformed JSON response
    {
        QString malformedSocketPath = tempDir.filePath("malformed.sock");
        QLocalServer malformedServer;
        QVERIFY(malformedServer.listen(malformedSocketPath));

        connect(&malformedServer, &QLocalServer::newConnection, [&malformedServer]() {
            QLocalSocket *s = malformedServer.nextPendingConnection();
            if (s) {
                connect(s, &QLocalSocket::readyRead, [s]() {
                    s->readAll();
                    s->write("CORRUPTED_NOT_JSON{{{[");
                    s->flush();
                    s->close();
                });
            }
        });

        IpcClient client(malformedSocketPath);
        TrayCoordinator tray(&client);
        tray.initTray();

        tray.pollStatus();
        QTRY_VERIFY_WITH_TIMEOUT(!tray.isStatusInflight(), 2000);
        QCOMPARE(tray.lastStatus(), QString("offline"));
    }

    // Subtest B: Immediate disconnect from server
    {
        QString disconnectSocketPath = tempDir.filePath("disconnect.sock");
        QLocalServer disconnectServer;
        QVERIFY(disconnectServer.listen(disconnectSocketPath));

        connect(&disconnectServer, &QLocalServer::newConnection, [&disconnectServer]() {
            QLocalSocket *s = disconnectServer.nextPendingConnection();
            if (s) {
                connect(s, &QLocalSocket::readyRead, [s]() {
                    s->readAll();
                    s->abort();
                });
            }
        });

        IpcClient client(disconnectSocketPath);
        TrayCoordinator tray(&client);
        tray.initTray();

        tray.pollStatus();
        QTRY_VERIFY_WITH_TIMEOUT(!tray.isStatusInflight(), 2000);
        QCOMPARE(tray.lastStatus(), QString("offline"));
    }

    // Subtest C: Connection failure / unreachable socket (timeout)
    {
        QString unreachableSocketPath = tempDir.filePath("non_existent_unreachable.sock");
        IpcClient client(unreachableSocketPath);
        TrayCoordinator tray(&client);
        tray.initTray();

        tray.pollStatus();
        QTRY_VERIFY_WITH_TIMEOUT(!tray.isStatusInflight(), 3000);
        QCOMPARE(tray.lastStatus(), QString("offline"));
    }
}

void TestIpcAsync::testPreferencesDialogLoadsConfigAndHandlesRollback() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());
    QString socketPath = tempDir.filePath("prefs.sock");

    QLocalServer server;
    QVERIFY(server.listen(socketPath));

    int updateCalls = 0;
    connect(&server, &QLocalServer::newConnection, [&server, &updateCalls]() {
        while (QLocalSocket *sock = server.nextPendingConnection()) {
            connect(sock, &QLocalSocket::readyRead, [sock, &updateCalls]() {
                QByteArray reqBytes = sock->readAll();
                QJsonDocument doc = QJsonDocument::fromJson(reqBytes);
                QString cmd = doc.object().value("command").toString();

                QJsonObject resp;
                if (cmd == "get-config") {
                    resp["status"] = "ok";
                    QJsonObject cfg;
                    cfg["auto_mount_on_start"] = false;
                    cfg["start_at_login"] = false;
                    cfg["offline_mode"] = true;
                    cfg["event_poll_interval_sec"] = 45;
                    cfg["cache_max_size_mb"] = 2048;
                    cfg["cache_ttl_hours"] = 24;
                    cfg["mount_point"] = "/tmp/test-mount";
                    resp["config"] = cfg;
                } else if (cmd == "status") {
                    resp["status"] = "ok";
                    resp["authenticated"] = true;
                    resp["sync_status"] = "idle";
                    resp["offline_mode"] = true;
                    resp["pending_uploads"] = 2;
                    resp["error_count"] = 1;
                    resp["last_error"] = "/a.txt: upload failed";
                } else if (cmd == "update-config") {
                    updateCalls++;
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

    QTimer modalCloser;
    modalCloser.setInterval(10);
    connect(&modalCloser, &QTimer::timeout, []() {
        if (QWidget *modal = QApplication::activeModalWidget()) {
            modal->close();
        }
    });
    modalCloser.start();

    IpcClient client(socketPath);
    PreferencesDialog prefs(&client);

    QTRY_COMPARE_WITH_TIMEOUT(prefs.authStatusText(), QString("Authenticated"), 2000);
    QCOMPARE(prefs.isOfflineModeChecked(), true);
    QCOMPARE(prefs.pollIntervalSec(), 45);
    QCOMPARE(prefs.cacheMaxSizeMb(), 2048);
    QCOMPARE(prefs.cacheTtlHours(), 24);
    QVERIFY(prefs.syncSummaryText().contains("Pending uploads: 2"));
    QVERIFY(prefs.syncSummaryText().contains("Errors: 1"));
    QVERIFY(prefs.syncSummaryText().contains("/a.txt: upload failed"));

    // Trigger updates that receive IPC error responses and verify rollback
    prefs.offlineModeCheckBox()->setChecked(false);
    prefs.pollIntervalSpinBox()->setValue(120);
    prefs.applySyncButton()->click();
    prefs.cacheMaxMbSpinBox()->setValue(512);
    prefs.cacheTtlHoursSpinBox()->setValue(6);
    prefs.applyCacheButton()->click();

    QTRY_COMPARE_WITH_TIMEOUT(updateCalls, 3, 2000);
    QTRY_COMPARE_WITH_TIMEOUT(prefs.isOfflineModeChecked(), true, 2000);
    QTRY_COMPARE_WITH_TIMEOUT(prefs.pollIntervalSec(), 45, 2000);
    QTRY_COMPARE_WITH_TIMEOUT(prefs.cacheMaxSizeMb(), 2048, 2000);
    QTRY_COMPARE_WITH_TIMEOUT(prefs.cacheTtlHours(), 24, 2000);
}

void TestIpcAsync::testNativeLoginTwoFactorLogoutAndBrowserSso() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());
    QString socketPath = tempDir.filePath("native_login.sock");

    QLocalServer server;
    QVERIFY(server.listen(socketPath));

    bool authenticated = false;
    int pollCount = 0;

    connect(&server, &QLocalServer::newConnection, [&server, &authenticated, &pollCount]() {
        while (QLocalSocket *sock = server.nextPendingConnection()) {
            connect(sock, &QLocalSocket::readyRead, [sock, &authenticated, &pollCount]() {
                QByteArray reqBytes = sock->readAll();
                QJsonDocument doc = QJsonDocument::fromJson(reqBytes);
                QJsonObject obj = doc.object();
                QString cmd = obj.value("command").toString();
                QJsonObject args = obj.value("args").toObject();

                QJsonObject resp;
                if (cmd == "get-config") {
                    resp["status"] = "ok";
                    QJsonObject cfg;
                    cfg["backend"] = "native";
                    cfg["auto_mount_on_start"] = true;
                    cfg["start_at_login"] = false;
                    cfg["offline_mode"] = false;
                    cfg["event_poll_interval_sec"] = 10;
                    cfg["cache_max_size_mb"] = 5120;
                    cfg["cache_ttl_hours"] = 72;
                    cfg["mount_point"] = "/tmp/native-mount";
                    resp["config"] = cfg;
                } else if (cmd == "status") {
                    resp["status"] = "ok";
                    resp["backend"] = "native";
                    resp["authenticated"] = authenticated;
                    resp["auth_message"] = authenticated
                        ? QString("Authenticated (alice@proton.me)")
                        : QString("Not authenticated");
                    resp["sync_status"] = "idle";
                    QJsonObject q;
                    q["used_bytes"] = authenticated ? 512.0 : 0.0;
                    q["total_bytes"] = authenticated ? 1024.0 : 0.0;
                    q["percent_used"] = authenticated ? 50.0 : 0.0;
                    resp["quota"] = q;
                } else if (cmd == "login") {
                    QString user = args.value("username").toString();
                    QString pass = args.value("password").toString();
                    QString totp = args.value("totp").toString();
                    if (user == "alice@proton.me" && pass == "secret" && totp.isEmpty()) {
                        resp["status"] = "2fa_required";
                        resp["message"] = "2FA code required";
                    } else if (user == "alice@proton.me" && pass == "secret" && totp == "654321") {
                        authenticated = true;
                        resp["status"] = "ok";
                        resp["message"] = "Authenticated as alice@proton.me";
                    } else {
                        resp["status"] = "error";
                        resp["message"] = "Invalid credentials";
                    }
                } else if (cmd == "start-browser-login") {
                    resp["status"] = "ok";
                    resp["login_url"] = "https://account.proton.me/desktop/login?app=drive";
                    resp["user_code"] = "ABCD2345";
                } else if (cmd == "poll-browser-login") {
                    pollCount++;
                    if (pollCount < 2) {
                        resp["status"] = "pending";
                    } else {
                        authenticated = true;
                        resp["status"] = "ok";
                        resp["message"] = "Authenticated as alice@proton.me";
                    }
                } else if (cmd == "logout") {
                    authenticated = false;
                    resp["status"] = "ok";
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
    PreferencesDialog prefs(&client);

    QTRY_COMPARE_WITH_TIMEOUT(prefs.authStatusText(), QString("Not Authenticated"), 2000);
    QVERIFY(prefs.loginButton()->isEnabled());
    QVERIFY(!prefs.logoutButton()->isEnabled());

    // 1. Credentials login triggers 2FA challenge first
    prefs.submitNativeLogin("alice@proton.me", "secret", "", false);
    QTRY_COMPARE_WITH_TIMEOUT(prefs.authStatusText(), QString("2FA Required"), 2000);

    // 2. Submitting 2FA TOTP completes authentication and updates status + buttons
    prefs.submitNativeLogin("alice@proton.me", "secret", "654321", false);
    QTRY_COMPARE_WITH_TIMEOUT(prefs.authStatusText(), QString("Authenticated (alice@proton.me)"), 2000);
    QVERIFY(!prefs.loginButton()->isEnabled());
    QVERIFY(prefs.logoutButton()->isEnabled());

    // 3. Logout clears session and restores login button
    prefs.performLogout(true);
    QTRY_COMPARE_WITH_TIMEOUT(prefs.authStatusText(), QString("Not Authenticated"), 2000);
    QVERIFY(prefs.loginButton()->isEnabled());
    QVERIFY(!prefs.logoutButton()->isEnabled());

    // 4. Browser SSO login starts challenge, polls pending -> ok, and authenticates
    prefs.startBrowserSsoLogin(25);
    QTRY_COMPARE_WITH_TIMEOUT(prefs.authStatusText(), QString("Authenticated (alice@proton.me)"), 3000);
    QVERIFY(pollCount >= 2);
}

void TestIpcAsync::testEnsureDaemonRunningStartsProcessWhenOffline() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());

    // 1. Returns true immediately when daemon socket responds to ping
    QString onlineSocketPath = tempDir.filePath("online.sock");
    QLocalServer server;
    QVERIFY(server.listen(onlineSocketPath));

    QThread serverResponder;
    QObject::connect(&server, &QLocalServer::newConnection, [&server]() {
        while (QLocalSocket *sock = server.nextPendingConnection()) {
            QObject::connect(sock, &QLocalSocket::readyRead, [sock]() {
                sock->readAll();
                QJsonObject resp;
                resp["status"] = "ok";
                resp["app"] = "Neutron Drive";
                sock->write(QJsonDocument(resp).toJson(QJsonDocument::Compact));
                sock->flush();
                sock->disconnectFromServer();
            });
            QObject::connect(sock, &QLocalSocket::disconnected, sock, &QObject::deleteLater);
        }
    });

    // Pump server events from a helper thread? No: isDaemonRunning() blocks on waitForReadyRead,
    // so run the server connection handler on a dedicated QThread or verify offline path + ping thread.
    Q_UNUSED(serverResponder);

    QThread clientThread;
    bool onlineResult = false;
    bool offlineResult = true;

    IpcClient onlineClient(onlineSocketPath);
    QObject worker;
    worker.moveToThread(&clientThread);
    QObject::connect(&clientThread, &QThread::started, [&]() {
        onlineResult = onlineClient.ensureDaemonRunning();
        IpcClient offlineClient(tempDir.filePath("offline.sock"));
        offlineResult = offlineClient.ensureDaemonRunning("/nonexistent/daemon", 200);
        clientThread.quit();
    });
    clientThread.start();

    QTRY_VERIFY_WITH_TIMEOUT(clientThread.isFinished(), 5000);
    QVERIFY(onlineResult);
    QVERIFY(!offlineResult);
}

void TestIpcAsync::testTrayNotificationsForSyncErrorsAndAuthExpiration() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());
    QString socketPath = tempDir.filePath("notify.sock");

    QLocalServer server;
    QVERIFY(server.listen(socketPath));

    bool authenticated = true;
    QString authMessage = "Authenticated";
    int errorCount = 0;
    QString lastError;

    connect(&server, &QLocalServer::newConnection, [&]() {
        while (QLocalSocket *sock = server.nextPendingConnection()) {
            connect(sock, &QLocalSocket::readyRead, [&, sock]() {
                sock->readAll();
                QJsonObject resp;
                resp["status"] = "ok";
                resp["authenticated"] = authenticated;
                resp["auth_message"] = authMessage;
                resp["sync_status"] = errorCount > 0 ? "error" : "idle";
                resp["is_paused"] = false;
                resp["offline_mode"] = false;
                resp["pending_uploads"] = 0;
                resp["error_count"] = errorCount;
                if (!lastError.isEmpty()) {
                    resp["last_error"] = lastError;
                }
                sock->write(QJsonDocument(resp).toJson(QJsonDocument::Compact) + "\n");
                sock->flush();
                sock->disconnectFromServer();
            });
            connect(sock, &QLocalSocket::disconnected, sock, &QObject::deleteLater);
        }
    });

    IpcClient client(socketPath);
    TrayCoordinator tray(&client);
    tray.initTray();

    QTRY_VERIFY_WITH_TIMEOUT(!tray.isStatusInflight(), 2000);
    QCOMPARE(tray.notificationCount(), 0);
    QCOMPARE(tray.lastStatus(), QString("idle"));

    // 1. Sync error appears -> notification fires once and tray status becomes "error"
    errorCount = 1;
    lastError = "/docs/report.pdf: Upload command failed";
    tray.pollStatus();
    QTRY_COMPARE_WITH_TIMEOUT(tray.notificationCount(), 1, 2000);
    QCOMPARE(tray.lastStatus(), QString("error"));
    QVERIFY(tray.lastNotificationTitle().contains("Sync Error"));
    QVERIFY(tray.lastNotificationMessage().contains("/docs/report.pdf"));

    // 2. Identical poll does NOT duplicate notification
    tray.pollStatus();
    QTRY_VERIFY_WITH_TIMEOUT(!tray.isStatusInflight(), 2000);
    QCOMPARE(tray.notificationCount(), 1);

    // 3. Additional error triggers new notification
    errorCount = 2;
    lastError = "/docs/budget.xlsx: Upload command failed";
    tray.pollStatus();
    QTRY_COMPARE_WITH_TIMEOUT(tray.notificationCount(), 2, 2000);
    QVERIFY(tray.lastNotificationMessage().contains("/docs/budget.xlsx"));

    // 4. Auth transition true -> false triggers Session Expired notification once
    errorCount = 0;
    lastError.clear();
    authenticated = false;
    authMessage = "Session expired";
    tray.pollStatus();
    QTRY_COMPARE_WITH_TIMEOUT(tray.notificationCount(), 3, 2000);
    QVERIFY(tray.lastNotificationTitle().contains("Session Expired"));
    QVERIFY(tray.lastNotificationMessage().contains("Session expired"));

    // Subsequent unauthenticated poll does NOT spam Session Expired
    tray.pollStatus();
    QTRY_VERIFY_WITH_TIMEOUT(!tray.isStatusInflight(), 2000);
    QCOMPARE(tray.notificationCount(), 3);
}

void TestIpcAsync::testPreferencesErrorRecoveryRetryAndClear() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());
    QString socketPath = tempDir.filePath("recovery.sock");

    QLocalServer server;
    QVERIFY(server.listen(socketPath));

    int errorCount = 2;
    int pendingUploads = 0;
    QString lastError = "/broken.bin: network error";
    int retryCalls = 0;
    int clearCalls = 0;

    connect(&server, &QLocalServer::newConnection, [&]() {
        while (QLocalSocket *sock = server.nextPendingConnection()) {
            connect(sock, &QLocalSocket::readyRead, [&, sock]() {
                QByteArray reqBytes = sock->readAll();
                QString cmd = QJsonDocument::fromJson(reqBytes).object().value("command").toString();

                QJsonObject resp;
                if (cmd == "get-config") {
                    resp["status"] = "ok";
                    QJsonObject cfg;
                    cfg["mount_point"] = "/tmp/mount";
                    resp["config"] = cfg;
                } else if (cmd == "status") {
                    resp["status"] = "ok";
                    resp["authenticated"] = true;
                    resp["sync_status"] = errorCount > 0 ? "error" : "idle";
                    resp["pending_uploads"] = pendingUploads;
                    resp["error_count"] = errorCount;
                    if (!lastError.isEmpty()) {
                        resp["last_error"] = lastError;
                    }
                } else if (cmd == "retry-errors") {
                    retryCalls++;
                    errorCount = 1;
                    pendingUploads = 1;
                    lastError = "/still_failing.bin: 503";
                    resp["status"] = "ok";
                    resp["retried"] = 2;
                } else if (cmd == "clear-errors") {
                    clearCalls++;
                    errorCount = 0;
                    pendingUploads = 0;
                    lastError.clear();
                    resp["status"] = "ok";
                    resp["cleared"] = 1;
                    resp["requeued"] = 0;
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
    PreferencesDialog prefs(&client);

    QTRY_VERIFY_WITH_TIMEOUT(prefs.retryErrorsButton()->isEnabled(), 2000);
    QVERIFY(prefs.clearErrorsButton()->isEnabled());
    QVERIFY(prefs.syncSummaryText().contains("Errors: 2"));

    // Click Retry Failed -> sends retry-errors and refreshes UI
    prefs.retryErrorsButton()->click();
    QTRY_COMPARE_WITH_TIMEOUT(retryCalls, 1, 2000);
    QTRY_VERIFY_WITH_TIMEOUT(prefs.syncSummaryText().contains("Errors: 1"), 2000);
    QVERIFY(prefs.syncSummaryText().contains("/still_failing.bin: 503"));
    QVERIFY(prefs.clearErrorsButton()->isEnabled());

    // Click Clear Errors -> sends clear-errors and disables recovery buttons when 0 errors remain
    prefs.clearErrorsButton()->click();
    QTRY_COMPARE_WITH_TIMEOUT(clearCalls, 1, 2000);
    QTRY_VERIFY_WITH_TIMEOUT(prefs.syncSummaryText().contains("Errors: 0"), 2000);
    QVERIFY(!prefs.retryErrorsButton()->isEnabled());
    QVERIFY(!prefs.clearErrorsButton()->isEnabled());
}

int main(int argc, char *argv[]) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);
    TestIpcAsync tc;
    return QTest::qExec(&tc, argc, argv);
}

#include "test_ipc_async.moc"
