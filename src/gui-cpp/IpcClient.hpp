#pragma once

#include <QString>
#include <QJsonObject>
#include <QObject>
#include <functional>

class IpcClient : public QObject {
    Q_OBJECT
public:
    explicit IpcClient(const QString &socketPath = QString(), QObject *parent = nullptr);

    static QString defaultSocketPath();

    QJsonObject sendCommand(const QString &command, const QJsonObject &args = QJsonObject());
    void sendCommandAsync(const QString &command, const QJsonObject &args, std::function<void(const QJsonObject &)> callback);
    void sendCommandAsync(const QString &command, std::function<void(const QJsonObject &)> callback);
    bool isDaemonRunning();
    bool ensureDaemonRunning(const QString &daemonExecutable = QString(), int timeoutMs = 3000);

    QString socketPath() const { return m_socketPath; }

private:
    static QJsonObject performSync(const QString &socketPath, const QString &command, const QJsonObject &args);

    QString m_socketPath;
};
