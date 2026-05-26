#pragma once

/**
 * NetworkUtils.hpp — raw BSD-socket helpers.
 *
 * Wraps the platform's socket API (Winsock2 on Windows, POSIX sockets
 * everywhere else) behind a tiny portable surface so the rest of the
 * client can demonstrate sockets / getaddrinfo / inet_ntop directly
 * without dragging Winsock2 includes into every translation unit. Used
 * by TLSVerifier to obtain a raw fd that OpenSSL wraps in an SSL*.
 */

#include <cstdint>
#include <string>

#ifdef _WIN32
using socket_t = uintptr_t;     // SOCKET == UINT_PTR on Windows
#else
using socket_t = int;
#endif

class NetworkUtils
{
public:
    /** Sentinel returned by tcpConnect on failure. */
    static socket_t invalidSocket();

    /**
     * One-shot Winsock2 startup. Safe to call repeatedly; only the first
     * call performs the WSAStartup. No-op on POSIX. Returns false if
     * WSAStartup fails.
     */
    static bool initialize();

    /**
     * Resolve `hostname` to a dotted-decimal IPv4 string via getaddrinfo
     * and inet_ntop. Returns an empty string if no A record is found.
     */
    static std::string resolveHost(const std::string& hostname);

    /**
     * Open a connected TCP socket to (`hostname`, `port`). The returned
     * socket is in blocking mode. Returns invalidSocket() on failure.
     * Caller owns the descriptor and must release it via closeSocket().
     */
    static socket_t tcpConnect(const std::string& hostname, uint16_t port);

    /** Cross-platform socket close (closesocket / close). */
    static void closeSocket(socket_t fd);
};
