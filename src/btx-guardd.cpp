// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/guard_machine.h>

#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace {

/** A request is one short line: PREPARE <effect> <fingerprint> <generation>, EXECUTE <secret>, PAUSE or RESUME. */
constexpr size_t kMaxLineBytes = 4096;
/** One client holds this single-threaded daemon for at most this long per request, well inside the node's 2 s timeout. */
constexpr int64_t kRequestDeadlineMs = 1000;

int64_t NowMs()
{
    using clock = std::chrono::system_clock;
    return std::chrono::duration_cast<std::chrono::milliseconds>(clock::now().time_since_epoch()).count();
}

void CloseSock(int fd)
{
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

void SetTimeouts(int fd, int64_t timeout_ms)
{
#ifdef _WIN32
    const DWORD timeout = static_cast<DWORD>(timeout_ms);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    timeval timeout{};
    timeout.tv_sec = static_cast<time_t>(timeout_ms / 1000);
    timeout.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif
}

bool SendAll(int fd, const std::string& bytes)
{
    size_t sent = 0;
    while (sent < bytes.size()) {
        const auto n = send(fd, bytes.data() + sent, bytes.size() - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

/**
 * Serve one client until it closes, a write fails, a line is longer than kMaxLineBytes,
 * or a request takes longer than kRequestDeadlineMs.
 */
void ServeClient(modelnet::GuardTable& table, int client)
{
    using steady = std::chrono::steady_clock;
    std::string pending;
    char buf[1024];
    auto deadline = steady::now() + std::chrono::milliseconds{kRequestDeadlineMs};
    while (true) {
        const int64_t left_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - steady::now()).count();
        if (left_ms <= 0) return;
        SetTimeouts(client, left_ms);
        const auto n = recv(client, buf, sizeof(buf), 0);
        if (n <= 0) return;
        std::size_t scan = pending.size();
        pending.append(buf, buf + n);
        std::size_t nl;
        while ((nl = pending.find('\n', scan)) != std::string::npos && nl <= kMaxLineBytes) {
            std::string line = pending.substr(0, nl);
            pending.erase(0, nl + 1);
            scan = 0;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!SendAll(client, modelnet::GuardHandleLine(table, line, NowMs()) + "\n")) return;
            deadline = steady::now() + std::chrono::milliseconds{kRequestDeadlineMs};
        }
        if (pending.size() > kMaxLineBytes) {
            SendAll(client, "ERR BTX035_LIMIT_EXCEEDED\n");
            return;
        }
    }
}

} // namespace

int main(int argc, char** argv)
{
    uint16_t port = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        }
    }
    if (port == 0) {
        std::cerr << "btx-guardd --port <1-65535>\n";
        return 1;
    }
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
#else
    // A client that resets the connection while a reply is written must not end the guard.
    std::signal(SIGPIPE, SIG_IGN);
#endif
    const int listen_fd = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
    if (listen_fd < 0) return 1;
    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&yes), sizeof(yes));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) return 1;
    if (listen(listen_fd, 16) != 0) return 1;
    modelnet::GuardTable table;
    while (true) {
        const int client = static_cast<int>(accept(listen_fd, nullptr, nullptr));
        if (client < 0) continue;
        ServeClient(table, client);
        CloseSock(client);
    }
}
