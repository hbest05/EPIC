/**
 * LoginWindow.cpp — Qt Widgets login/register form.
 *
 * Register flow:
 *   1. generateIdentity(password) on the daemon (creates IK + sign key on disk)
 *   2. /auth/register with the IK + Ed25519 publics
 *   3. /auth/login to install the session cookie
 *   4. generatePrekeys() + /auth/prekeys to seed the SPK/OPK pool
 *
 * Login flow:
 *   1. /auth/login
 *   2. loadIdentity(password) on the daemon
 *
 * The TLS check runs once at construction and only paints an indicator —
 * libcurl does its own validation on every call.
 */

#include "LoginWindow.hpp"

#include "Client.hpp"
#include "CryptoDaemonClient.hpp"
#include "TLSVerifier.hpp"

#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>

LoginWindow::LoginWindow(Client* client, QWidget* parent)
    : QWidget(parent)
    , m_client(client)
    , m_usernameEdit(new QLineEdit(this))
    , m_emailEdit(new QLineEdit(this))
    , m_passwordEdit(new QLineEdit(this))
    , m_loginButton(new QPushButton(tr("Log in"), this))
    , m_registerButton(new QPushButton(tr("Register"), this))
    , m_statusLabel(new QLabel(this))
    , m_tlsLabel(new QLabel(this))
{
    setWindowTitle(tr("SecureMsg — Sign in"));

    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_emailEdit->setPlaceholderText(tr("required to register"));
    m_statusLabel->setWordWrap(true);
    m_tlsLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    auto* form = new QFormLayout;
    form->addRow(tr("Username"), m_usernameEdit);
    form->addRow(tr("Email"),    m_emailEdit);
    form->addRow(tr("Password"), m_passwordEdit);

    auto* buttons = new QHBoxLayout;
    buttons->addWidget(m_loginButton);
    buttons->addWidget(m_registerButton);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(m_tlsLabel);
    layout->addLayout(form);
    layout->addLayout(buttons);
    layout->addWidget(m_statusLabel);
    layout->addStretch();

    connect(m_loginButton,    &QPushButton::clicked, this, &LoginWindow::onLoginClicked);
    connect(m_registerButton, &QPushButton::clicked, this, &LoginWindow::onRegisterClicked);

    updateTlsIndicator();
}

void LoginWindow::updateTlsIndicator()
{
    if (!m_client->isTlsEnabled()) {
        m_tlsLabel->setText(tr("\xE2\x9A\xA0  Local dev mode — no TLS"));
        m_tlsLabel->setStyleSheet(QStringLiteral("color: #b45309; font-weight: bold;"));
        return;
    }

    const TLSVerifier::VerifyResult r =
        TLSVerifier::verify(m_client->baseHostname().toStdString(), 443);
    if (r.valid) {
        m_tlsLabel->setText(tr("\xF0\x9F\x94\x92  TLS OK — %1 (expires %2)")
                            .arg(QString::fromStdString(r.commonName),
                                 QString::fromStdString(r.expiryDate)));
        m_tlsLabel->setStyleSheet(QStringLiteral("color: #1a7f37; font-weight: bold;"));
    } else {
        m_tlsLabel->setText(tr("\xE2\x9A\xA0  TLS check failed: %1")
                            .arg(QString::fromStdString(r.error)));
        m_tlsLabel->setStyleSheet(QStringLiteral("color: #b42318; font-weight: bold;"));
    }
}

void LoginWindow::onLoginClicked()
{
    const QString user = m_usernameEdit->text().trimmed();
    const QString pass = m_passwordEdit->text();
    if (user.isEmpty() || pass.isEmpty()) {
        m_statusLabel->setText(tr("Username and password are required."));
        return;
    }
    m_statusLabel->setText(tr("Signing in…"));

    const QString err = m_client->login(user, pass);
    if (!err.isEmpty()) {
        m_statusLabel->setText(tr("Login failed: %1").arg(err));
        return;
    }

    try {
        m_client->daemon()->loadIdentity(pass);
    } catch (const CryptoDaemonError& e) {
        m_statusLabel->setText(tr("Server signed in but local key unlock failed: %1")
                               .arg(e.message()));
        return;
    }

    m_statusLabel->setText(tr("Welcome back, %1.").arg(user));
    emit loginSucceeded(false);
}

void LoginWindow::onRegisterClicked()
{
    const QString user  = m_usernameEdit->text().trimmed();
    const QString email = m_emailEdit->text().trimmed();
    const QString pass  = m_passwordEdit->text();
    if (user.isEmpty() || email.isEmpty() || pass.isEmpty()) {
        m_statusLabel->setText(tr("Username, email, and password are all required."));
        return;
    }
    if (pass.size() < 12) {
        m_statusLabel->setText(tr("Password must be at least 12 characters."));
        return;
    }

    m_statusLabel->setText(tr("Generating identity keys…"));

    CryptoDaemonClient::Identity identity;
    PrekeyBundle prekeys;
    try {
        identity = m_client->daemon()->generateIdentity(pass);
        prekeys  = m_client->daemon()->generatePrekeys(identity.signPub);
    } catch (const CryptoDaemonError& e) {
        m_statusLabel->setText(tr("Identity generation failed: %1").arg(e.message()));
        return;
    }

    m_statusLabel->setText(tr("Registering with the server…"));
    QString err = m_client->registerUser(user, email, pass, identity.ikPub, identity.signPub);
    if (!err.isEmpty()) {
        m_statusLabel->setText(tr("Registration failed: %1").arg(err));
        return;
    }

    // Log in immediately so we have a session for the prekey upload.
    err = m_client->login(user, pass);
    if (!err.isEmpty()) {
        m_statusLabel->setText(tr("Account created, but auto-login failed: %1").arg(err));
        return;
    }

    err = m_client->uploadPrekeys(prekeys.spkPub, prekeys.spkSig, prekeys.opks);
    if (!err.isEmpty()) {
        m_statusLabel->setText(tr("Account created, but prekey upload failed: %1").arg(err));
        return;
    }

    m_statusLabel->setText(tr("Welcome, %1.").arg(user));
    emit loginSucceeded(true);
}
