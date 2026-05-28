#pragma once

/**
 * LoginWindow.hpp — pre-auth window: log in, or register a new account.
 *
 * Form layout: username, email (register-only), password, two buttons,
 * a status label, and a TLS-padlock indicator that fires once on first
 * paint. On a successful login this widget emits loginSucceeded() and
 * is hidden by main() so MainWindow can take over.
 */

#include <QtWidgets/QWidget>

class Client;
class QLabel;
class QLineEdit;
class QPushButton;

class LoginWindow : public QWidget
{
    Q_OBJECT

public:
    explicit LoginWindow(Client* client, QWidget* parent = nullptr);

signals:
    /** @param freshRegistration true when the account was just created (and a
     *  full prekey batch already uploaded), so MainWindow can skip its
     *  redundant startup OPK replenish. */
    void loginSucceeded(bool freshRegistration);

private slots:
    void onLoginClicked();
    void onRegisterClicked();

private:
    /** Run TLSVerifier against the backend host and paint the padlock label. */
    void updateTlsIndicator();

    Client*      m_client;            // not owned

    QLineEdit*   m_usernameEdit;
    QLineEdit*   m_emailEdit;
    QLineEdit*   m_passwordEdit;
    QPushButton* m_loginButton;
    QPushButton* m_registerButton;
    QLabel*      m_statusLabel;
    QLabel*      m_tlsLabel;
};
