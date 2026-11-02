// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#ifndef BITCOIN_CONTRIB_RC_PROVER_REQUEST_LISTENER_H
#define BITCOIN_CONTRIB_RC_PROVER_REQUEST_LISTENER_H

#include "socket_io.h"
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

namespace rc_prover {
inline int SocketError()
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}
inline bool RecoverableAcceptError(int error)
{
#ifdef _WIN32
    return error == WSAEWOULDBLOCK || error == WSAEINTR || error == WSAECONNRESET ||
        error == WSAECONNABORTED || error == WSAEMFILE || error == WSAENOBUFS || error == WSAENETDOWN;
#else
    return error == EAGAIN || error == EWOULDBLOCK || error == EINTR || error == ECONNABORTED ||
        error == EMFILE || error == ENFILE || error == ENOBUFS || error == ENOMEM ||
        error == EPROTO || error == ENETDOWN || error == ENETUNREACH || error == EHOSTUNREACH;
#endif
}
inline bool AcceptNeedsBackoff(int error)
{
#ifdef _WIN32
    return error == WSAEMFILE || error == WSAENOBUFS || error == WSAENETDOWN;
#else
    return error == EMFILE || error == ENFILE || error == ENOBUFS || error == ENOMEM ||
        error == ENETDOWN || error == ENETUNREACH || error == EHOSTUNREACH;
#endif
}
inline std::runtime_error SocketFailure(const char* operation)
{
    return std::runtime_error(std::string(operation) + " failed; socket error=" + std::to_string(SocketError()));
}

/** Bounded nonblocking framing; idle peers do not own the serial GPU worker. */
class RequestListener {
    struct Pending {
        std::unique_ptr<OwnedSocket> socket;
        std::string line;
        Deadline deadline;
    };
    OwnedSocket m_listener;
    std::vector<Pending> m_pending;
    Deadline m_dispatch_start{};
    bool m_dispatching{false};
    static constexpr size_t MAX_PENDING{32};
    static constexpr size_t MAX_LINE{65536};
public:
    struct Request { std::unique_ptr<OwnedSocket> socket; std::string line; };
    explicit RequestListener(uint16_t port) : m_listener(socket(AF_INET, SOCK_STREAM, 0))
    {
        if (!m_listener.Valid()) throw SocketFailure("socket");
#ifndef _WIN32
        if (m_listener.Get() >= FD_SETSIZE) throw std::runtime_error("listener exceeds select descriptor limit");
#endif
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        if (bind(m_listener.Get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) throw SocketFailure("bind");
        if (listen(m_listener.Get(), 32) != 0) throw SocketFailure("listen");
        if (!NonBlocking(m_listener.Get())) throw SocketFailure("nonblocking listener");
    }
    uint16_t Port() const
    {
        sockaddr_in address{};
#ifdef _WIN32
        int size{sizeof(address)};
#else
        socklen_t size{sizeof(address)};
#endif
        if (getsockname(m_listener.Get(), reinterpret_cast<sockaddr*>(&address), &size) != 0) throw SocketFailure("getsockname");
        return ntohs(address.sin_port);
    }
    Request Next()
    {
        // Serial GPU execution outside Next must not consume framing deadlines.
        if (m_dispatching) {
            const auto elapsed{std::chrono::steady_clock::now() - m_dispatch_start};
            for (auto& p : m_pending) p.deadline += elapsed;
            m_dispatching = false;
        }
        for (;;) {
            const auto now{std::chrono::steady_clock::now()};
            std::erase_if(m_pending, [&](const Pending& p) { return p.deadline <= now; });
            fd_set reads;
            FD_ZERO(&reads);
            // At capacity, leave new connections in the bounded OS backlog.
            // Never accept-then-reset or evict an admitted partial frame.
            const bool can_accept{m_pending.size() < MAX_PENDING};
            if (can_accept) FD_SET(m_listener.Get(), &reads);
            Socket highest{m_listener.Get()};
            for (const auto& p : m_pending) {
                FD_SET(p.socket->Get(), &reads);
                highest = std::max(highest, p.socket->Get());
            }
            timeval tick{};
            tick.tv_usec = 100000;
#ifdef _WIN32
            const int nfds{0};
#else
            const int nfds{highest + 1};
#endif
            const int count{select(nfds, &reads, nullptr, nullptr, &tick)};
            if (count < 0) {
                if (Retryable()) continue;
                throw SocketFailure("select listener");
            }
            if (!count) continue;
            // Read each ready peer at most once per pass, bounding per-peer work.
            for (size_t i{0}; i < m_pending.size();) {
                auto& p{m_pending[i]};
                if (!FD_ISSET(p.socket->Get(), &reads)) { ++i; continue; }
                char data[4096];
                const auto size{recv(p.socket->Get(), data, sizeof(data), 0)};
                if (size < 0 && Retryable()) { ++i; continue; }
                if (size <= 0 || p.deadline <= std::chrono::steady_clock::now()) {
                    m_pending.erase(m_pending.begin() + i); continue;
                }
                const std::string part(data, size);
                const size_t newline{part.find('\n')};
                const size_t length{newline == std::string::npos ? part.size() : newline};
                if (length > MAX_LINE - p.line.size()) {
                    m_pending.erase(m_pending.begin() + i); continue;
                }
                p.line.append(part.data(), length);
                if (newline != std::string::npos) {
                    Request request{std::move(p.socket), std::move(p.line)};
                    m_pending.erase(m_pending.begin() + i);
                    m_dispatch_start = std::chrono::steady_clock::now();
                    m_dispatching = true;
                    return request;
                }
                ++i;
            }
            if (can_accept && FD_ISSET(m_listener.Get(), &reads)) {
                auto client{std::make_unique<OwnedSocket>(accept(m_listener.Get(), nullptr, nullptr))};
                if (!client->Valid()) {
                    const int error{SocketError()};
                    std::fprintf(stderr, "accept failed; socket error=%d\n", error);
                    if (!RecoverableAcceptError(error)) throw std::runtime_error("fatal listener accept failure");
                    // Avoid spinning on resource exhaustion; the error is visible.
                    if (AcceptNeedsBackoff(error)) std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
#ifndef _WIN32
                if (client->Get() >= FD_SETSIZE) continue;
#endif
                if (!NonBlocking(client->Get())) continue;
                m_pending.push_back({std::move(client), {}, std::chrono::steady_clock::now() + std::chrono::seconds(2)});
            }
        }
    }
};
} // namespace rc_prover
#endif
