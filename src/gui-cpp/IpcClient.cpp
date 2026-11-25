#include "IpcClient.hpp"
#include <QLocalSocket>
#include <QJsonDocument>
#include <QStandardPaths>
#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include <QElapsedTimer>
#include <QThreadPool>
#include <QCoreApplication>
#include <QPointer>
#include <QThread>

QString IpcClient::defaultSocketPath() {
    QString runtimeDir = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
    if (!runtimeDir.isEmpty() && QDir(runtimeDir).exists()) {
        return runtimeDir + "/neutron-drive.sock";
    }
    QString dataDir = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/neutron-drive";
    return dataDir + "/daemon.sock";
}

IpcClient::IpcClient(const QString &socketPath, QObject *parent)
    : QObject(parent)
    , m_socketPath(socketPath.isEmpty() ? defaultSocketPath() : socketPath)
{
}

QJsonObject IpcClient::performSync(const QString &socketPath, const QString &command, const QJsonObject &args) {
    QLocalSocket socket;
    socket.connectToServer(socketPath);
    if (!socket.waitForConnected(1500)) {
        QJsonObject err;
        err["status"] = "error";
        err["message"] = "Cannot connect to daemon socket";
        return err;
    }

    QJsonObject req;
    req["command"] = command;
    req["args"] = args;

    QByteArray data = QJsonDocument(req).toJson(QJsonDocument::Compact);
    socket.write(data);
    if (!socket.waitForBytesWritten(1500)) {
        QJsonObject err;
        err["status"] = "error";
        err["message"] = "Failed to write to daemon socket";
        return err;
    }

    if (!socket.waitForReadyRead(5000)) {
        QJsonObject err;
        err["status"] = "error";
        err["message"] = "Daemon timed out";
        return err;
    }

    QByteArray respData = socket.readAll();
    QJsonDocument doc = QJsonDocument::fromJson(respData);
    while (!doc.isObject() && socket.waitForReadyRead(500)) {
        respData += socket.readAll();
        doc = QJsonDocument::fromJson(respData);
    }
    if (doc.isObject()) {
        return doc.object();
    }

    QJsonObject err;
    err["status"] = "error";
    err["message"] = "Invalid JSON response from daemon";
    return err;
}

QJsonObject IpcClient::sendCommand(const QString &command, const QJsonObject &args) {
    return performSync(m_socketPath, command, args);
}

void IpcClient::sendCommandAsync(const QString &command, const QJsonObject &args, std::function<void(const QJsonObject &)> callback) {
    if (!callback) {
        return;
    }

    QString socketPath = m_socketPath;
    QPointer<const IpcClient> self(this);
    QThread *callerThread = QThread::currentThread();

    QThreadPool::globalInstance()->start([socketPath, command, args, callback, self, callerThread]() {
        QJsonObject result = performSync(socketPath, command, args);

        auto deliver = [callback, result, self]() {
            if (self) {
                callback(result);
            }
        };

        if (qApp && qApp->thread() == callerThread) {
            QMetaObject::invokeMethod(qApp, deliver, Qt::QueuedConnection);
        } else if (self && self->thread() == callerThread) {
            QMetaObject::invokeMethod(const_cast<IpcClient*>(self.data()), deliver, Qt::QueuedConnection);
        } else if (qApp) {
            QMetaObject::invokeMethod(qApp, deliver, Qt::QueuedConnection);
        } else {
            deliver();
        }
    });
}

void IpcClient::sendCommandAsync(const QString &command, std::function<void(const QJsonObject &)> callback) {
    sendCommandAsync(command, QJsonObject(), std::move(callback));
}

bool IpcClient::isDaemonRunning() {
    QJsonObject res = sendCommand("ping");
    return res.value("status").toString() == "ok";
}

bool IpcClient::ensureDaemonRunning(const QString &daemonExecutable, int timeoutMs) {
    if (isDaemonRunning()) {
        return true;
    }

    QString daemonBin;
    if (!daemonExecutable.isEmpty()) {
        QFileInfo info(daemonExecutable);
        if (info.isFile() && info.isExecutable()) {
            daemonBin = daemonExecutable;
        }
    } else {
        QStringList candidates;
        QString appDir = QCoreApplication::applicationDirPath();
        candidates << appDir + "/neutron-drive-daemon";

        QString pathBin = QStandardPaths::findExecutable("neutron-drive-daemon");
        if (!pathBin.isEmpty()) {
            candidates << pathBin;
        }

        candidates << QDir::homePath() + "/.local/bin/neutron-drive-daemon"
                   << "/usr/local/bin/neutron-drive-daemon"
                   << "/usr/bin/neutron-drive-daemon"
                   << appDir + "/../crates/proton-drive-daemon/target/release/neutron-drive-daemon";

        for (const QString &candidate : candidates) {
            QFileInfo info(candidate);
            if (info.exists() && info.isFile() && info.isExecutable()) {
                daemonBin = candidate;
                break;
            }
        }
    }

    if (daemonBin.isEmpty()) {
        return false;
    }

    if (!QProcess::startDetached(daemonBin, QStringList() << "daemon")) {
        return false;
    }

    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeoutMs) {
        if (isDaemonRunning()) {
            return true;
        }
        QThread::msleep(100);
    }

    return isDaemonRunning();
}
