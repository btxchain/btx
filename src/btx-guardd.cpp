// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/guard_machine.h>

#include <chrono>
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
#include <unistd.h>
#endif

namespace {

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
        std::string pending;
        char buf[1024];
        while (true) {
            const auto n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0) break;
            pending.append(buf, buf + n);
            std::size_t nl;
            while ((nl = pending.find('\n')) != std::string::npos) {
                std::string line = pending.substr(0, nl);
                pending.erase(0, nl + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                const std::string reply = modelnet::GuardHandleLine(table, line, NowMs()) + "\n";
                send(client, reply.data(), reply.size(), 0);
            }
        }
        CloseSock(client);
    }
}
