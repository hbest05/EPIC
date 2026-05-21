/**
 * main.cpp — SecureMsg Qt desktop client entry point
 *
 * Creates the QApplication and launches the main window. The Client class
 * owns the application state and orchestrates all networking and UI interactions.
 */

#include <QApplication>

#include "Client.hpp"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("SecureMsg");
    app.setApplicationVersion("0.1.0");

    Client client;
    client.show();

    return app.exec();
}
