/**
 * main.cpp — SecureMsg Qt desktop client entry point
 *
 * Initialises libsodium, creates the QApplication, and launches the main
 * window. The Client class owns the application state and orchestrates all
 * networking, crypto, and UI interactions.
 */

#include <QApplication>
#include <QMessageBox>
#include <sodium.h>

#include "Client.hpp"

int main(int argc, char *argv[])
{
    // libsodium must be initialised before any crypto operations.
    // sodium_init() returns -1 on failure, 0 on first init, 1 if already init.
    if (sodium_init() < 0) {
        // Cannot recover — crypto primitives unavailable
        QApplication app(argc, argv);
        QMessageBox::critical(nullptr, "Fatal Error",
                              "Failed to initialise libsodium. Cannot start.");
        return 1;
    }

    QApplication app(argc, argv);
    app.setApplicationName("SecureMsg");
    app.setApplicationVersion("0.1.0");

    Client client;
    client.show();

    return app.exec();
}
