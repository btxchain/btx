// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#include <modelnet/guard_machine.h>
#ifdef BTX_MODEL_SECURITY_V2
#include <modelnet/security_v2/service.h>
#include <memory>
#endif
#include <chrono>
#include <charconv>
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
int64_t NowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
int Stdio(const std::string& security_directory)
{
#ifdef BTX_MODEL_SECURITY_V2
    std::unique_ptr<modelnet::security::Service> service;
    std::unique_ptr<modelnet::security::GuardProtocol> protocol;
    if (!security_directory.empty()) {
        try {
            service = std::make_unique<modelnet::security::Service>(modelnet::security::NativePath(security_directory));
            protocol = std::make_unique<modelnet::security::GuardProtocol>(*service);
        } catch (...) { return 2; }
    }
#else
    if (!security_directory.empty()) return 2;
#endif
    modelnet::GuardTable table;
    std::string line;
    char c;
    while (std::cin.get(c)) {
        if (c == '\n') {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            std::string reply;
#ifdef BTX_MODEL_SECURITY_V2
            if (line.rfind("SEC2 ", 0) == 0) reply = protocol ? protocol->Handle(line) : "ERR SEC_NOT_CONFIGURED";
            else
#endif
                reply = modelnet::GuardHandleLine(table, line, NowMs());
            std::cout << reply << '\n' << std::flush;
            if (!std::cout) return 2;
            line.clear();
        } else {
            if (line.size() >= modelnet::GuardTable::kMaxLine) {
                std::cout << "ERR BTX035_LIMIT\n" << std::flush;
                return 2;
            }
            line.push_back(c);
        }
    }
    // The parent's inherited pipe closes on normal stop or crash.
    return line.empty() ? 0 : 2;
}
#ifdef _WIN32
using Socket = SOCKET;
constexpr Socket INVALID = INVALID_SOCKET;
void Close(Socket fd) { closesocket(fd); }
#else
using Socket = int;
constexpr Socket INVALID = -1;
void Close(Socket fd) { close(fd); }
#endif
int LegacyLoopback(uint16_t port)
{
#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 2;
#endif
    const Socket listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == INVALID) return 2;
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || listen(listener, 16) != 0) {
        Close(listener); return 2;
    }
    modelnet::GuardTable table;
    while (true) {
        const Socket client = accept(listener, nullptr, nullptr);
        if (client == INVALID) continue;
#ifdef _WIN32
        const DWORD timeout = 2000;
#else
        const timeval timeout{2,0};
#endif
        setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));
        setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));
        std::string line;
        bool finished = false;
        char buffer[512];
        while (!finished) {
            const auto n = recv(client, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            for (int i = 0; i < n; ++i) {
                if (buffer[i] == '\n') {
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    const auto reply = modelnet::GuardHandleLine(table,line,NowMs()) + "\n";
                    size_t sent = 0;
                    while (sent < reply.size()) {
#ifdef MSG_NOSIGNAL
                        const int flags = MSG_NOSIGNAL;
#else
                        const int flags = 0;
#endif
                        const auto count = send(client,reply.data()+sent,static_cast<int>(reply.size()-sent),flags);
                        if (count <= 0) break;
                        sent += count;
                    }
                    finished = true; break; // one bounded exchange per connection
                }
                if (line.size() >= modelnet::GuardTable::kMaxLine) { finished = true; break; }
                line.push_back(buffer[i]);
            }
        }
        Close(client);
    }
}
}
int main(int argc, char** argv)
{
    bool stdio = false, legacy = false;
    std::string security_directory;
    uint16_t port = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--stdio") stdio = true;
        else if (arg == "--security-dir" && i + 1 < argc) security_directory = argv[++i];
        else if (arg == "--allow-legacy-loopback") legacy = true;
        else if (arg == "--port" && i + 1 < argc) {
            const std::string value=argv[++i]; unsigned parsed=0;
            const auto r=std::from_chars(value.data(),value.data()+value.size(),parsed);
            if (r.ec!=std::errc{} || r.ptr!=value.data()+value.size() || parsed==0 || parsed>65535) return 1;
            port=static_cast<uint16_t>(parsed);
        } else {
            std::cerr << "usage: btx-guardd --stdio\n"
                         "Legacy diagnostic only: --port N --allow-legacy-loopback\n";
            return 1;
        }
    }
    if (stdio && !legacy && port==0) return Stdio(security_directory);
    if (!stdio && legacy && port!=0 && security_directory.empty()) return LegacyLoopback(port);
    std::cerr << "btx-guardd requires --stdio; TCP is disabled by default\n";
    return 1;
}
