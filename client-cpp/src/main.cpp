/**
 * main.cpp — SecureMsg Qt desktop client entry point
 *
 * Creates the QApplication and launches the main window. The Client class
 * owns the application state and orchestrates all networking and UI interactions.
 */

#include <QApplication>
#include <QMessageBox>
#include <sodium.h>

#include "Client.hpp"

int main(int argc, char *argv[])
{
    if (sodium_init() < 0) {
        // libsodium failed to initialise — nothing crypto-related can run safely
        QApplication app(argc, argv);
        QMessageBox::critical(nullptr, "Fatal", "libsodium failed to initialise. Cannot continue.");
        return 1;
    }

    // Log AES-256-GCM hardware support once at startup so it appears in logs
    if (crypto_aead_aes256gcm_is_available()) {
        qInfo("AES-256-GCM: hardware accelerated (AES-NI available)");
    } else {
        qInfo("AES-256-GCM: hardware not available — key files will use ChaCha20-Poly1305-IETF");
    }

    QApplication app(argc, argv);
    app.setApplicationName("SecureMsg");
    app.setApplicationVersion("0.1.0");

    Client client;
    client.show();

    return app.exec();
}
