/**
 * Client.cpp — Application controller implementation.
 */

#include "Client.hpp"
#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>
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
    QJsonObject body;
    body["username"] = username;
    body["password"] = password;
    const QByteArray jsonBody = QJsonDocument(body).toJson(QJsonDocument::Compact);

    const QByteArray response = httpPost("/auth/login", jsonBody);
    if (response.isEmpty()) {
        qWarning() << "Client::login: empty response from server";
        return;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(response);
    if (doc.isNull() || !doc.isObject()) {
        qWarning() << "Client::login: invalid JSON response";
        return;
    }

    const QString token = doc.object().value("access_token").toString();
    if (token.isEmpty()) {
        qWarning() << "Client::login: missing access_token in response";
        return;
    }

    m_jwtToken = token;
    m_localUser = std::make_unique<User>(username);
    showChatView();
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
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!m_jwtToken.isEmpty()) {
        const std::string authHeader = "Authorization: Bearer " + m_jwtToken.toStdString();
        headers = curl_slist_append(headers, authHeader.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    const CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        qWarning() << "httpPost" << endpoint << "failed:" << curl_easy_strerror(res);
        response.clear();
    }

    curl_slist_free_all(headers);
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
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    curl_slist* headers = nullptr;
    if (!m_jwtToken.isEmpty()) {
        const std::string authHeader = "Authorization: Bearer " + m_jwtToken.toStdString();
        headers = curl_slist_append(headers, authHeader.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    const CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        qWarning() << "httpGet" << endpoint << "failed:" << curl_easy_strerror(res);
        response.clear();
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}
