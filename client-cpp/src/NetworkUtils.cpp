/**
 * NetworkUtils.cpp — raw BSD-socket implementation.
 *
 * On Windows: Winsock2 (socket, connect, closesocket, WSAStartup).
 * On POSIX:   <sys/socket.h>, <netdb.h>, <arpa/inet.h>, close().
 *
 * Kept deliberately thin so the demonstrative use of getaddrinfo,
 * inet_ntop, socket, and connect remains obvious to a reader.
 */

#include "NetworkUtils.hpp"

#include <cstring>
#include <mutex>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "Ws2_32.lib")
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

socket_t NetworkUtils::invalidSocket()
{
#ifdef _WIN32
    return static_cast<socket_t>(INVALID_SOCKET);
#else
    return -1;
#endif
}

bool NetworkUtils::initialize()
{
#ifdef _WIN32
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        WSADATA wsaData;
        ok = (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
    });
    return ok;
#else
    return true;
#endif
}

std::string NetworkUtils::resolveHost(const std::string& hostname)
{
    initialize();

    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;
    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0 || !result) {
        return {};
    }

    char buf[INET_ADDRSTRLEN] = {0};
    const auto* sa = reinterpret_cast<sockaddr_in*>(result->ai_addr);
    const char* p = inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
    std::string out = p ? std::string(p) : std::string{};

    freeaddrinfo(result);
    return out;
}

socket_t NetworkUtils::tcpConnect(const std::string& hostname, uint16_t port)
{
    initialize();

    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const std::string portStr = std::to_string(port);
    addrinfo* result = nullptr;
    if (getaddrinfo(hostname.c_str(), portStr.c_str(), &hints, &result) != 0 || !result) {
        return invalidSocket();
    }

    socket_t fd = invalidSocket();
    for (addrinfo* ai = result; ai; ai = ai->ai_next) {
#ifdef _WIN32
        const SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
            fd = static_cast<socket_t>(s);
            break;
        }
        closesocket(s);
#else
        const int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
            fd = s;
            break;
        }
        ::close(s);
#endif
    }

    freeaddrinfo(result);
    return fd;
}

void NetworkUtils::closeSocket(socket_t fd)
{
    if (fd == invalidSocket()) return;
#ifdef _WIN32
    closesocket(static_cast<SOCKET>(fd));
#else
    ::close(static_cast<int>(fd));
#endif
}
