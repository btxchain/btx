// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_guard_client.h>

#include <cstdint>
#include <sstream>
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

namespace modelnet {
namespace {

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

void CloseSock(int fd)
{
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

std::string TrimCr(std::string line)
{
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
    return line;
}

bool ErrorReply(const std::string& reply, std::string& err)
{
    if (reply.rfind("ERR ", 0) != 0) return false;
    err = reply.substr(4);
    if (err.empty()) err = "BTX035_SCHEMA";
    return true;
}

} // namespace

bool GuardClientExchange(const std::string& host, uint16_t port, const std::string& line, std::string& reply, std::string& err)
{
    reply.clear();
    if (host != "127.0.0.1" || port == 0) return Fail(err, "BTX035_SCOPE_DENIED");
    if (line.empty() || line.find('\n') != std::string::npos || line.find('\r') != std::string::npos) {
        return Fail(err, "BTX035_SCHEMA");
    }
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return Fail(err, "BTX035_TRANSPORT");
#endif
    const int fd = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return Fail(err, "BTX035_TRANSPORT");
#ifdef _WIN32
    const DWORD timeout_ms = 2000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    timeval timeout{};
    timeout.tv_sec = 2;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
        CloseSock(fd);
        return Fail(err, "BTX035_SCOPE_DENIED");
    }
    if (connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        CloseSock(fd);
        return Fail(err, "BTX035_TRANSPORT");
    }
    const std::string bytes = line + "\n";
    size_t sent = 0;
    while (sent < bytes.size()) {
        const auto n = send(fd, bytes.data() + sent, bytes.size() - sent, 0);
        if (n <= 0) {
            CloseSock(fd);
            return Fail(err, "BTX035_TRANSPORT");
        }
        sent += static_cast<size_t>(n);
    }
    std::string pending;
    char buf[1024];
    while (pending.find('\n') == std::string::npos) {
        if (pending.size() > 1024 * 1024) {
            CloseSock(fd);
            return Fail(err, "BTX035_TRANSPORT");
        }
        const auto n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            CloseSock(fd);
            return Fail(err, "BTX035_TRANSPORT");
        }
        pending.append(buf, buf + n);
    }
    CloseSock(fd);
    reply = TrimCr(pending.substr(0, pending.find('\n')));
    err.clear();
    return true;
}

bool GuardClientPrepare(const std::string& host, uint16_t port, const std::string& effect, const std::string& fingerprint,
                        uint64_t generation, GuardPermit& out, std::string& err)
{
    if (effect.empty() || fingerprint.empty() || effect.find(' ') != std::string::npos ||
        fingerprint.find(' ') != std::string::npos) {
        return Fail(err, "BTX035_SCHEMA");
    }
    std::string reply;
    const std::string line = "PREPARE " + effect + " " + fingerprint + " " + std::to_string(generation);
    if (!GuardClientExchange(host, port, line, reply, err)) return false;
    if (ErrorReply(reply, err)) return false;
    std::istringstream in(reply);
    std::string verb;
    std::string secret;
    std::string commitment;
    int64_t not_after_ms = 0;
    in >> verb >> secret >> commitment >> not_after_ms;
    if (!in || verb != "PERMIT" || secret.empty() || commitment.empty()) return Fail(err, "BTX035_PERMIT");
    if (commitment != GuardCommitment(secret)) return Fail(err, "BTX035_PERMIT");
    out = GuardPermit{};
    out.secret = secret;
    out.commitment = commitment;
    out.effect = effect;
    out.fingerprint = fingerprint;
    out.generation = generation;
    out.not_after_ms = not_after_ms;
    out.consumed = false;
    err.clear();
    return true;
}

bool GuardClientExecute(const std::string& host, uint16_t port, const std::string& secret, std::string& receipt_id, std::string& err)
{
    if (secret.empty() || secret.find(' ') != std::string::npos) return Fail(err, "BTX035_SCHEMA");
    std::string reply;
    if (!GuardClientExchange(host, port, "EXECUTE " + secret, reply, err)) return false;
    if (ErrorReply(reply, err)) return false;
    std::istringstream in(reply);
    std::string verb;
    std::string receipt;
    std::string executed;
    std::string stopped;
    in >> verb >> receipt >> executed >> stopped;
    if (!in || verb != "RECEIPT" || receipt.empty() || executed != "PERMIT_CONSUMED" || stopped != "NOT_DISPATCHED") {
        return Fail(err, "BTX035_SCHEMA");
    }
    receipt_id = receipt;
    err.clear();
    return true;
}

bool GuardClientPause(const std::string& host, uint16_t port, std::string& err)
{
    std::string reply;
    if (!GuardClientExchange(host, port, "PAUSE", reply, err)) return false;
    if (ErrorReply(reply, err)) return false;
    if (reply != "OK") return Fail(err, "BTX035_SCHEMA");
    err.clear();
    return true;
}

bool GuardClientResume(const std::string& host, uint16_t port, std::string& err)
{
    std::string reply;
    if (!GuardClientExchange(host, port, "RESUME", reply, err)) return false;
    if (ErrorReply(reply, err)) return false;
    if (reply != "OK") return Fail(err, "BTX035_SCHEMA");
    err.clear();
    return true;
}

} // namespace modelnet
