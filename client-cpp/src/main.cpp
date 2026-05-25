/**
 * main.cpp — SecureMsg Qt desktop entry point.
 *
 * 1. Initialise libsodium and Winsock.
 * 2. Launch the Python crypto daemon as a child process if it isn't
 *    already listening on 127.0.0.1:47291.
 * 3. Wait up to 2 seconds for the daemon's TCP socket to accept a
 *    connection; bail out with a dialog if it never comes up.
 * 4. Show LoginWindow; on loginSucceeded swap to MainWindow.
 */

#include <QtCore/QDir>
#include <QtCore/QElapsedTimer>
#include <QtCore/QFileInfo>
#include <QtCore/QProcess>
#include <QtCore/QThread>
#include <QtNetwork/QTcpSocket>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMessageBox>

#include <sodium.h>

#include "Client.hpp"
#include "CryptoDaemonClient.hpp"
#include "LoginWindow.hpp"
#include "MainWindow.hpp"
#include "NetworkUtils.hpp"

namespace {

constexpr quint16 kDaemonPort = 47291;
constexpr int     kDaemonStartupTimeoutMs = 2000;

bool daemonReachable()
{
    QTcpSocket probe;
    probe.connectToHost(QStringLiteral("127.0.0.1"), kDaemonPort);
    const bool up = probe.waitForConnected(150);
    if (up) probe.disconnectFromHost();
    return up;
}

/** Best-effort search for the python interpreter + daemon script. */
bool spawnDaemon(QProcess& proc, QString* error)
{
    // Walk up from the executable directory looking for crypto-daemon/main.py.
    QDir dir(QCoreApplication::applicationDirPath());
    for (int i = 0; i < 6; ++i) {
        const QString candidate = dir.filePath(QStringLiteral("crypto-daemon/main.py"));
        if (QFileInfo::exists(candidate)) {
            const QString python =
#ifdef _WIN32
                QStringLiteral("python");
#else
                QStringLiteral("python3");
#endif
            proc.setProgram(python);
            proc.setArguments(QStringList{} << candidate);
            proc.start();
            if (!proc.waitForStarted(1500)) {
                if (error) *error = QStringLiteral("could not start %1 %2").arg(python, candidate);
                return false;
            }
            return true;
        }
        if (!dir.cdUp()) break;
    }
    if (error) *error = QStringLiteral("could not locate crypto-daemon/main.py");
    return false;
}

bool waitForDaemon(int timeoutMs)
{
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < timeoutMs) {
        if (daemonReachable()) return true;
        QThread::msleep(100);
    }
    return false;
}

} // namespace

int main(int argc, char* argv[])
{
    if (sodium_init() < 0) {
        QApplication app(argc, argv);
        QMessageBox::critical(nullptr, "Fatal",
                              "libsodium failed to initialise. Cannot continue.");
        return 1;
    }
    NetworkUtils::initialize();

    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("SecureMsg"));
    app.setApplicationVersion(QStringLiteral("0.1.0"));

    QProcess daemonProc;
    bool spawnedDaemon = false;
    if (!daemonReachable()) {
        QString err;
        if (!spawnDaemon(daemonProc, &err)) {
            QMessageBox::critical(nullptr, "Crypto daemon",
                                  "Could not start the crypto daemon:\n" + err);
            return 1;
        }
        spawnedDaemon = true;

        if (!waitForDaemon(kDaemonStartupTimeoutMs)) {
            QMessageBox::critical(nullptr, "Crypto daemon",
                                  "Crypto daemon did not become reachable on 127.0.0.1:47291.");
            return 1;
        }
    }

    std::shared_ptr<CryptoDaemonClient> daemon;
    try {
        daemon = std::make_shared<CryptoDaemonClient>();
    } catch (const CryptoDaemonError& e) {
        QMessageBox::critical(nullptr, "Crypto daemon", e.message());
        return 1;
    }

    Client client(daemon);
    client.initialize();

    LoginWindow login(&client);
    MainWindow* mainWindow = nullptr;

    QObject::connect(&login, &LoginWindow::loginSucceeded, [&]() {
        login.hide();
        mainWindow = new MainWindow(&client);
        mainWindow->setAttribute(Qt::WA_DeleteOnClose);
        mainWindow->show();
    });

    login.show();

    const int rc = app.exec();

    if (spawnedDaemon && daemonProc.state() != QProcess::NotRunning) {
        daemonProc.terminate();
        daemonProc.waitForFinished(2000);
    }
    return rc;
}
