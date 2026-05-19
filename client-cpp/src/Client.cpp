/**
 * Client.cpp — Application controller implementation.
 */

#include "Client.hpp"
#include <QDebug>
#include <QVBoxLayout>
#include <QLabel>
#include <curl/curl.h>

// libcurl write callback — appends received bytes to a QByteArray
static size_t curlWriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* buffer = static_cast<QByteArray*>(userdata);
    buffer->append(ptr, static_cast<qsizetype>(size * nmemb));
    return size * nmemb;
}

Client::Client(QWidget* parent)
    : QMainWindow(parent)
    , m_store(new MessageStore(this))
    , m_pollTimer(new QTimer(this))
{
    setupUi();
    connect(m_pollTimer, &QTimer::timeout, this, &Client::pollInbox);
    // TODO: Start poll timer after successful login
}

Client::~Client()
{
    // QObjects parented to this are cleaned up by Qt automatically
}

void Client::setupUi()
{
    // TODO: Build Qt widget hierarchy — login view + chat view
    // For now, show a placeholder label
    auto* placeholder = new QLabel("SecureMsg — UI not yet built", this);
    placeholder->setAlignment(Qt::AlignCenter);
    setCentralWidget(placeholder);
    setWindowTitle("SecureMsg");
    resize(900, 600);
}

void Client::showAuthView()
{
    // TODO: Switch central widget to the login/register form
}

void Client::showChatView()
{
    // TODO: Switch central widget to the chat layout
    // TODO: Start inbox poll timer
    m_pollTimer->start(5000);
}

void Client::registerUser(const QString& username, const QString& email, const QString& password)
{
    // TODO: m_localUser = std::make_unique<User>(username)
    // TODO: m_localUser->generateKeyPairs()
    // TODO: Build JSON body with base64-encoded public keys
    // TODO: httpPost("/auth/register", body)
    // TODO: On success → m_localUser->saveKeyFile(keyfilePath, password)
    // TODO: login(username, password)
    qWarning() << "Client::registerUser: not implemented yet";
}

void Client::login(const QString& username, const QString& password)
{
    // TODO: Build JSON body { username, password }
    // TODO: httpPost("/auth/login", body) → parse JWT from response
    // TODO: Store JWT in m_jwtToken
    // TODO: Load keypair from keyfile: m_localUser->loadKeyFile(...)
    // TODO: showChatView()
    Q_UNUSED(username)
    Q_UNUSED(password)
    qWarning() << "Client::login: not implemented yet";
}

void Client::logout()
{
    m_jwtToken.clear();
    m_pollTimer->stop();
    m_store->clearCache();
    showAuthView();
}

void Client::fetchContactKeys(const QString& username)
{
    // TODO: httpGet("/auth/user/" + username + "/pubkeys")
    // TODO: Parse response, create User with public keys, store in m_contacts
    Q_UNUSED(username)
    qWarning() << "Client::fetchContactKeys: not implemented yet";
}

void Client::sendMessage(const QString& recipientUsername, const QString& plaintext)
{
    if (!m_contacts.contains(recipientUsername)) {
        fetchContactKeys(recipientUsername);
        return; // TODO: Queue message and retry after keys arrive
    }

    // TODO: m_store->encryptMessage(plaintext, *m_contacts[recipientUsername], *m_localUser)
    // TODO: Serialise to JSON and httpPost("/messages/send", body)
    Q_UNUSED(plaintext)
    qWarning() << "Client::sendMessage: not implemented yet";
}

void Client::pollInbox()
{
    // TODO: httpGet("/messages/inbox") with Authorization header
    // TODO: For each new message:
    //   1. Ensure sender's pubkeys are in m_contacts
    //   2. m_store->decryptMessage(msg, senderUser, *m_localUser)
    //   3. m_store->addMessage(msg) → triggers newMessageReceived signal → update UI
    qWarning() << "Client::pollInbox: not implemented yet";
}

void Client::onSendClicked()   { /* TODO: Read from UI, call sendMessage() */ }
void Client::onLoginClicked()  { /* TODO: Read from UI, call login() */ }
void Client::onRegisterClicked() { /* TODO: Read from UI, call registerUser() */ }

QByteArray Client::httpPost(const QString& endpoint, const QByteArray& jsonBody)
{
    QByteArray response;
    CURL* curl = curl_easy_init();
    if (!curl) return response;

    const std::string url = std::string(API_BASE) + endpoint.toStdString();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonBody.constData());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, jsonBody.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    // TODO: Add Authorization header when m_jwtToken is set
    // TODO: Add Content-Type: application/json header

    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return response;
}

QByteArray Client::httpGet(const QString& endpoint)
{
    QByteArray response;
    CURL* curl = curl_easy_init();
    if (!curl) return response;

    const std::string url = std::string(API_BASE) + endpoint.toStdString();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    // TODO: Add Authorization: Bearer <m_jwtToken> header

    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return response;
}
