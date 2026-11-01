// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#ifndef BITCOIN_CONTRIB_RC_PROVER_SOCKET_IO_H
#define BITCOIN_CONTRIB_RC_PROVER_SOCKET_IO_H

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace rc_prover {
#ifdef _WIN32
using Socket = SOCKET;
inline constexpr Socket INVALID_SOCKET_VALUE = INVALID_SOCKET;
inline void Close(Socket s) { closesocket(s); }
#else
using Socket = int;
inline constexpr Socket INVALID_SOCKET_VALUE = -1;
inline void Close(Socket s) { close(s); }
#endif

class Network {
public:
    Network()
    {
#ifdef _WIN32
        WSADATA data{};
        m_ok = WSAStartup(MAKEWORD(2, 2), &data) == 0;
#endif
    }
    ~Network()
    {
#ifdef _WIN32
        if (m_ok) WSACleanup();
#endif
    }
    Network(const Network&) = delete;
    Network& operator=(const Network&) = delete;
    bool Ok() const { return m_ok; }
private:
    bool m_ok{true};
};

class OwnedSocket {
public:
    explicit OwnedSocket(Socket s = INVALID_SOCKET_VALUE) : m_socket(s) {}
    ~OwnedSocket() { if (Valid()) Close(m_socket); }
    OwnedSocket(const OwnedSocket&) = delete;
    OwnedSocket& operator=(const OwnedSocket&) = delete;
    Socket Get() const { return m_socket; }
    bool Valid() const { return m_socket != INVALID_SOCKET_VALUE; }
private:
    Socket m_socket;
};

inline bool NonBlocking(Socket s)
{
#ifdef _WIN32
    u_long enabled{1};
    return ioctlsocket(s, FIONBIO, &enabled) == 0;
#else
    const int flags{fcntl(s, F_GETFL, 0)};
    return flags >= 0 && fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}
inline bool Retryable()
{
#ifdef _WIN32
    const int e{WSAGetLastError()};
    return e == WSAEWOULDBLOCK || e == WSAEINTR;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}
using Deadline = std::chrono::steady_clock::time_point;
inline bool Wait(Socket s, bool write, Deadline deadline)
{
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::microseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) return false;
        timeval tv{static_cast<long>(left.count() / 1000000), static_cast<long>(left.count() % 1000000)};
#ifndef _WIN32
        if (s < 0 || s >= FD_SETSIZE) return false;
#endif
        fd_set set; FD_ZERO(&set); FD_SET(s, &set);
#ifdef _WIN32
        const int nfds{0}; // WinSock ignores this argument; SOCKET need not fit int.
#else
        const int nfds{s + 1};
#endif
        const int n = select(nfds, write ? nullptr : &set, write ? &set : nullptr, nullptr, &tv);
        if (n > 0) return true;
        if (n == 0 || !Retryable()) return false;
    }
}
inline bool ReadLine(Socket s, std::string& line, std::chrono::milliseconds timeout,
                     size_t limit = 65536)
{
    line.clear();
    if (!NonBlocking(s)) return false;
    const Deadline end{std::chrono::steady_clock::now() + timeout};
    char data[4096];
    while (Wait(s, false, end)) {
        const int n = recv(s, data, sizeof(data), 0);
        if (n < 0 && Retryable()) continue;
        if (n <= 0) return false;
        const std::string part(data, n);
        const size_t nl{part.find('\n')};
        const size_t length{nl == std::string::npos ? part.size() : nl};
        if (length > limit - line.size()) return false;
        line.append(part.data(), length);
        if (nl != std::string::npos) return true;
    }
    return false;
}
inline bool WriteAll(Socket s, const std::string& data, std::chrono::milliseconds timeout)
{
    if (!NonBlocking(s)) return false;
    const Deadline end{std::chrono::steady_clock::now() + timeout};
    size_t sent{0};
    while (sent < data.size() && Wait(s, true, end)) {
#ifdef MSG_NOSIGNAL
        constexpr int flags{MSG_NOSIGNAL};
#else
        constexpr int flags{0};
#endif
        const int n = send(s, data.data() + sent, static_cast<int>(std::min<size_t>(4096, data.size() - sent)), flags);
        if (n < 0 && Retryable()) continue;
        if (n <= 0) return false;
        sent += n;
    }
    return sent == data.size();
}
} // namespace rc_prover
#endif
