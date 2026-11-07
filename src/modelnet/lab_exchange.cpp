// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_exchange.h>

#include <modelnet/git_snapshot.h>
#include <span.h>
#include <univalue.h>

#include <util/fs.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
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

std::string EnvOrEmpty(const char* key)
{
    const char* value = std::getenv(key);
    if (value == nullptr) return {};
    return std::string(value);
}

std::string TrimSpaces(const std::string& text)
{
    size_t begin = 0;
    while (begin < text.size() && (text[begin] == ' ' || text[begin] == '\t')) ++begin;
    size_t end = text.size();
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t')) --end;
    return text.substr(begin, end - begin);
}

void AppendPeerToken(std::vector<std::string>& tokens, const std::string& raw)
{
    const std::string text = TrimSpaces(raw);
    if (!text.empty()) tokens.push_back(text);
}

void AppendPeerList(std::vector<std::string>& tokens, const std::string& list)
{
    size_t start = 0;
    for (size_t i = 0; i <= list.size(); ++i) {
        if (i == list.size() || list[i] == ',') {
            AppendPeerToken(tokens, list.substr(start, i - start));
            start = i + 1;
        }
    }
}

/** Base64 of `user:password` for an HTTP Basic Authorization header. */
std::string BasicCredential(const std::string& user, const std::string& password)
{
    const std::string raw = user + ":" + password;
    static const char* kB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string auth;
    for (size_t i = 0; i < raw.size(); i += 3) {
        const unsigned int a = static_cast<unsigned char>(raw[i]);
        const unsigned int b = i + 1 < raw.size() ? static_cast<unsigned char>(raw[i + 1]) : 0;
        const unsigned int c = i + 2 < raw.size() ? static_cast<unsigned char>(raw[i + 2]) : 0;
        const unsigned int triple = (a << 16) | (b << 8) | c;
        auth.push_back(kB64[(triple >> 18) & 63]);
        auth.push_back(kB64[(triple >> 12) & 63]);
        auth.push_back(i + 1 < raw.size() ? kB64[(triple >> 6) & 63] : '=');
        auth.push_back(i + 2 < raw.size() ? kB64[triple & 63] : '=');
    }
    return auth;
}

// Loopback only. Does not dial DNS or any host other than 127.0.0.1.
bool ParseLoopbackEndpoint(const std::string& endpoint, std::string& host, uint16_t& port, std::string& err)
{
    const auto colon = endpoint.rfind(':');
    if (colon == std::string::npos || endpoint.substr(0, colon) != "127.0.0.1") {
        return Fail(err, "BTX035_SCOPE_DENIED");
    }
    if (colon + 1 >= endpoint.size()) return Fail(err, "BTX035_SCOPE_DENIED");
    uint64_t parsed = 0;
    for (size_t i = colon + 1; i < endpoint.size(); ++i) {
        const char ch = endpoint[i];
        if (ch < '0' || ch > '9') return Fail(err, "BTX035_SCOPE_DENIED");
        parsed = parsed * 10 + static_cast<unsigned>(ch - '0');
        if (parsed > 65535) return Fail(err, "BTX035_SCOPE_DENIED");
    }
    if (parsed == 0) return Fail(err, "BTX035_SCOPE_DENIED");
    host = "127.0.0.1";
    port = static_cast<uint16_t>(parsed);
    err.clear();
    return true;
}

constexpr int kLoopbackTimeoutMs = 2000;
constexpr size_t kMaxLoopbackBytes = 1024 * 1024;

#ifndef _WIN32

bool ParseHexU(const std::string& text, uint64_t& out)
{
    if (text.empty()) return false;
    uint64_t value = 0;
    for (unsigned char c : text) {
        uint64_t digit = 0;
        if (c >= '0' && c <= '9') digit = static_cast<uint64_t>(c - '0');
        else if (c >= 'a' && c <= 'f') digit = static_cast<uint64_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = static_cast<uint64_t>(c - 'A' + 10);
        else return false;
        if (value > (UINT64_MAX - digit) / 16) return false;
        value = value * 16 + digit;
    }
    out = value;
    return true;
}

bool ParseDecU(const std::string& text, uint64_t& out)
{
    if (text.empty()) return false;
    uint64_t value = 0;
    for (unsigned char c : text) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

bool InodeOwned(uint64_t inode)
{
    const fs::path dir("/proc/self/fd");
    if (!fs::exists(dir)) return false;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (!fs::is_symlink(entry.path())) continue;
        const std::string text = fs::PathToString(fs::read_symlink(entry.path()));
        const std::string prefix = "socket:[";
        if (text.size() < prefix.size() + 2 || text.compare(0, prefix.size(), prefix) != 0 || text.back() != ']') continue;
        uint64_t value = 0;
        if (!ParseDecU(text.substr(prefix.size(), text.size() - prefix.size() - 1), value)) continue;
        if (value == inode) return true;
    }
    return false;
}

bool ScanTcpTable(const char* path, uint16_t port)
{
    FILE* file = std::fopen(path, "r");
    if (!file) return false;
    char line[512];
    if (!std::fgets(line, sizeof(line), file)) {
        std::fclose(file);
        return false;
    }
    bool found = false;
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        std::vector<std::string> fields;
        std::string cur;
        for (char c : std::string(line)) {
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                if (!cur.empty()) {
                    fields.push_back(cur);
                    cur.clear();
                }
            } else {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) fields.push_back(cur);
        if (fields.size() < 10 || fields[3] != "0A") continue;
        const auto colon = fields[1].rfind(':');
        if (colon == std::string::npos) continue;
        uint64_t port_hex = 0;
        uint64_t inode = 0;
        if (!ParseHexU(fields[1].substr(colon + 1), port_hex) || port_hex != port) continue;
        if (!ParseDecU(fields[9], inode)) continue;
        if (InodeOwned(inode)) {
            found = true;
            break;
        }
    }
    std::fclose(file);
    return found;
}

bool OwnListenSocket(uint16_t port)
{
    const long open_max = sysconf(_SC_OPEN_MAX);
    const int limit = open_max > 0 && open_max < 65536 ? static_cast<int>(open_max) : 65536;
    for (int fd = 0; fd < limit; ++fd) {
        sockaddr_storage address{};
        socklen_t length = sizeof(address);
        if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) continue;
        uint16_t local = 0;
        if (address.ss_family == AF_INET) {
            local = ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port);
        } else if (address.ss_family == AF_INET6) {
            local = ntohs(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port);
        }
        if (local != port) continue;
        int type = 0;
        length = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0 || type != SOCK_STREAM) continue;
        // macOS does not report SO_ACCEPTCONN through getsockopt. A stream
        // socket on this port without a peer is our listener.
        sockaddr_storage peer{};
        length = sizeof(peer);
        if (getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &length) != 0 && errno == ENOTCONN) return true;
    }
    return false;
}

bool OwnListenPort(uint16_t port)
{
    // macOS and the BSDs have no /proc/net/tcp: ask each open descriptor
    // whether it is a listening socket on that port.
    if (::access("/proc/net/tcp", R_OK) != 0) return OwnListenSocket(port);
    return ScanTcpTable("/proc/net/tcp", port) || ScanTcpTable("/proc/net/tcp6", port);
}

bool WaitFd(int fd, short events, std::chrono::steady_clock::time_point deadline, std::string& err)
{
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return Fail(err, "BTX035_TRANSPORT");
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        if (left < 1) left = 1;
        if (left > 1000) left = 1000;
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = events;
        const int rc = ::poll(&pfd, 1, static_cast<int>(left));
        if (rc < 0) {
            if (errno == EINTR) continue;
            return Fail(err, "BTX035_TRANSPORT");
        }
        if (rc == 0) continue;
        return true;
    }
}

bool ConnectBounded(int fd, uint16_t port, int timeout_ms, std::string& err)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return Fail(err, "BTX035_TRANSPORT");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) return Fail(err, "BTX035_SCOPE_DENIED");
    const int rc = connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (rc != 0 && errno != EINPROGRESS) return Fail(err, "BTX035_TRANSPORT");
    if (rc != 0) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        if (!WaitFd(fd, POLLOUT, deadline, err)) return false;
        int soerr = 0;
        socklen_t len = sizeof(soerr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0 || soerr != 0) return Fail(err, "BTX035_TRANSPORT");
    }
    err.clear();
    return true;
}

bool SendBounded(int fd, const std::string& bytes, int timeout_ms, std::string& err)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    size_t sent = 0;
    while (sent < bytes.size()) {
        if (!WaitFd(fd, POLLOUT, deadline, err)) return false;
        const auto n = ::send(fd, bytes.data() + sent, bytes.size() - sent, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return Fail(err, "BTX035_TRANSPORT");
        }
        if (n == 0) return Fail(err, "BTX035_TRANSPORT");
        sent += static_cast<size_t>(n);
    }
    err.clear();
    return true;
}

bool ReadBounded(int fd, std::string& out, size_t max_bytes, int timeout_ms, std::string& err)
{
    out.clear();
    if (timeout_ms < 0) return Fail(err, "BTX035_TRANSPORT");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    char buf[4096];
    // Read to end of stream. Stopping at exactly max_bytes would return a
    // response cut at the cap as if it were complete.
    for (;;) {
        if (!WaitFd(fd, POLLIN, deadline, err)) return false;
        const auto n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return Fail(err, "BTX035_TRANSPORT");
        }
        if (n == 0) break;
        if (out.size() + static_cast<size_t>(n) > max_bytes) return Fail(err, "BTX035_LIMIT_EXCEEDED");
        out.append(buf, buf + n);
    }
    err.clear();
    return true;
}

#else

bool OwnListenPort(uint16_t)
{
    return false;
}

bool ReadBounded(int fd, std::string& out, size_t max_bytes, int timeout_ms, std::string& err)
{
    out.clear();
    const DWORD timeout = timeout_ms < 0 ? 0 : static_cast<DWORD>(timeout_ms);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    char buf[4096];
    for (;;) {
        const auto n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) return Fail(err, "BTX035_TRANSPORT");
        if (n == 0) break;
        if (out.size() + static_cast<size_t>(n) > max_bytes) return Fail(err, "BTX035_LIMIT_EXCEEDED");
        out.append(buf, buf + n);
    }
    err.clear();
    return true;
}

#endif

bool ExchangeLoopback(uint16_t port, const std::string& request, std::string& response, std::string& err)
{
    response.clear();
    if (OwnListenPort(port)) return Fail(err, "BTX035_SCOPE_DENIED");
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return Fail(err, "BTX035_TRANSPORT");
    const DWORD timeout = static_cast<DWORD>(kLoopbackTimeoutMs);
#endif
    const int fd = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return Fail(err, "BTX035_TRANSPORT");
#ifndef _WIN32
    if (!ConnectBounded(fd, port, kLoopbackTimeoutMs, err) || !SendBounded(fd, request, kLoopbackTimeoutMs, err) ||
        !ReadBounded(fd, response, kMaxLoopbackBytes, kLoopbackTimeoutMs, err)) {
        CloseSock(fd);
        return false;
    }
#else
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
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
    size_t sent = 0;
    while (sent < request.size()) {
        const auto n = send(fd, request.data() + sent, request.size() - sent, 0);
        if (n <= 0) {
            CloseSock(fd);
            return Fail(err, "BTX035_TRANSPORT");
        }
        sent += static_cast<size_t>(n);
    }
    if (!ReadBounded(fd, response, kMaxLoopbackBytes, kLoopbackTimeoutMs, err)) {
        CloseSock(fd);
        return false;
    }
#endif
    CloseSock(fd);
    err.clear();
    return true;
}

} // namespace

bool ReadLoopbackBounded(int fd, std::string& out, size_t max_bytes, int timeout_ms, std::string& err)
{
    return ReadBounded(fd, out, max_bytes, timeout_ms, err);
}

bool WriteExchangeManifest(const std::vector<ExchangeObject>& objects, std::string& manifest_json, std::string& err)
{
    if (objects.empty()) return Fail(err, "BTX035_NOT_FOUND");
    UniValue arr(UniValue::VARR);
    for (const ExchangeObject& object : objects) {
        const std::vector<unsigned char> bytes(object.content.begin(), object.content.end());
        std::string digest;
        if (!GitObjectDigest(object.kind, Span<const unsigned char>{bytes.data(), bytes.size()}, digest, err)) return false;
        if (digest != object.digest) return Fail(err, "BTX035_ID_MISMATCH");
        UniValue row(UniValue::VOBJ);
        row.pushKV("kind", object.kind);
        row.pushKV("digest", digest);
        row.pushKV("content", object.content);
        arr.push_back(std::move(row));
    }
    UniValue root(UniValue::VOBJ);
    root.pushKV("objects", arr);
    manifest_json = root.write();
    err.clear();
    return true;
}

bool VerifyExchangeManifest(const std::string& manifest_json, std::vector<ExchangeObject>& objects, std::string& err,
                            size_t max_objects, size_t max_object_bytes)
{
    UniValue root;
    if (!root.read(manifest_json) || !root.isObject() || !root.exists("objects") || !root["objects"].isArray() ||
        root["objects"].empty()) {
        return Fail(err, "BTX035_SCHEMA");
    }
    objects.clear();
    if (root["objects"].size() > max_objects) return Fail(err, "BTX035_LIMIT_EXCEEDED");
    for (size_t i = 0; i < root["objects"].size(); ++i) {
        const UniValue& row = root["objects"][i];
        if (!row.isObject() || !row.exists("kind") || !row["kind"].isStr() || !row.exists("digest") ||
            !row["digest"].isStr() || !row.exists("content") || !row["content"].isStr()) {
            return Fail(err, "BTX035_SCHEMA");
        }
        if (row["content"].get_str().size() > max_object_bytes) return Fail(err, "BTX035_LIMIT_EXCEEDED");
        ExchangeObject object;
        object.kind = row["kind"].get_str();
        object.digest = row["digest"].get_str();
        object.content = row["content"].get_str();
        const std::vector<unsigned char> bytes(object.content.begin(), object.content.end());
        std::string digest;
        if (!GitObjectDigest(object.kind, Span<const unsigned char>{bytes.data(), bytes.size()}, digest, err)) return false;
        if (digest != object.digest) return Fail(err, "BTX035_ID_MISMATCH");
        objects.push_back(std::move(object));
    }
    err.clear();
    return true;
}

bool LabCallLoopback(const std::string& host, uint16_t port, const std::string& rpc_user,
                     const std::string& rpc_password, const std::string& method,
                     const std::string& params_json, std::string& result_json, std::string& err)
{
    result_json.clear();
    std::string parsed_host;
    uint16_t parsed_port = 0;
    if (!ParseLoopbackEndpoint(host + ":" + std::to_string(port), parsed_host, parsed_port, err) ||
        parsed_host != host || parsed_port != port || method.empty() || params_json.empty()) {
        return Fail(err, "BTX035_SCOPE_DENIED");
    }
    UniValue params(UniValue::VARR);
    params.push_back(method);
    params.push_back(params_json);
    UniValue rpc_body(UniValue::VOBJ);
    rpc_body.pushKV("jsonrpc", "1.0");
    rpc_body.pushKV("id", "lab");
    rpc_body.pushKV("method", "lab035");
    rpc_body.pushKV("params", params);
    const std::string body = rpc_body.write();
    std::ostringstream request;
    request << "POST / HTTP/1.1\r\nHost: 127.0.0.1:" << port
            << "\r\nAuthorization: Basic " << BasicCredential(rpc_user, rpc_password)
            << "\r\nContent-Type: application/json\r\nContent-Length: " << body.size()
            << "\r\nConnection: close\r\n\r\n"
            << body;

    std::string response;
    if (!ExchangeLoopback(port, request.str(), response, err)) return false;
    const auto split = response.find("\r\n\r\n");
    if (split == std::string::npos) return Fail(err, "BTX035_TRANSPORT");
    const std::string payload = response.substr(split + 4);
    const auto json_at = payload.find('{');
    if (json_at == std::string::npos) return Fail(err, "BTX035_TRANSPORT");
    UniValue rpc;
    if (!rpc.read(payload.substr(json_at)) || !rpc.isObject() || !rpc.exists("result") || !rpc["result"].isObject()) {
        return Fail(err, "BTX035_SCHEMA");
    }
    const UniValue& envelope = rpc["result"];
    if (!envelope.exists("result") || !envelope["result"].isObject()) return Fail(err, "BTX035_SCHEMA");
    if (envelope.exists("automatic_spend_atoms") &&
        (!envelope["automatic_spend_atoms"].isStr() || envelope["automatic_spend_atoms"].get_str() != "0")) {
        return Fail(err, "BTX035_SCOPE_DENIED");
    }
    result_json = envelope["result"].write();
    err.clear();
    return true;
}

bool PeerRouteLoopback(const std::string& host, uint16_t port, const std::string& rpc_user,
                       const std::string& rpc_password, const std::string& route,
                       const std::string& body_json, std::string& result_json, std::string& err)
{
    result_json.clear();
    std::string parsed_host;
    uint16_t parsed_port = 0;
    if (!ParseLoopbackEndpoint(host + ":" + std::to_string(port), parsed_host, parsed_port, err) ||
        parsed_host != host || parsed_port != port || route.empty() || route.find('/') == 0 || body_json.empty()) {
        return Fail(err, "BTX035_SCOPE_DENIED");
    }
    std::ostringstream request;
    request << "POST /btx-model/3/" << route << " HTTP/1.1\r\nHost: 127.0.0.1:" << port
            << "\r\nAuthorization: Basic " << BasicCredential(rpc_user, rpc_password)
            << "\r\nContent-Type: application/json\r\nContent-Length: " << body_json.size()
            << "\r\nConnection: close\r\n\r\n"
            << body_json;
    std::string response;
    if (!ExchangeLoopback(port, request.str(), response, err)) return false;
    const auto split = response.find("\r\n\r\n");
    if (split == std::string::npos || response.size() < 12) return Fail(err, "BTX035_TRANSPORT");
    const bool ok = response.compare(0, 12, "HTTP/1.1 200") == 0 || response.compare(0, 12, "HTTP/1.0 200") == 0;
    const std::string payload = response.substr(split + 4);
    if (!ok) {
        const auto line_end = payload.find_first_of("\r\n");
        err = line_end == std::string::npos ? payload : payload.substr(0, line_end);
        if (err.empty()) err = "BTX035_TRANSPORT";
        return false;
    }
    result_json = payload;
    err.clear();
    return true;
}

bool PullExchangeLoopback(const std::string& host, uint16_t port, const std::string& rpc_user,
                          const std::string& rpc_password, const std::string& repository_id,
                          std::string& manifest_json, std::string& err)
{
    if (repository_id.empty()) return Fail(err, "BTX035_SCOPE_DENIED");
    UniValue inner(UniValue::VOBJ);
    inner.pushKV("repository_id", repository_id);
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    const auto nonce = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    inner.pushKV("idempotency_key", "peer-snapshot-" + std::to_string(nonce));
    inner.pushKV("expected_state", UniValue());
    std::string result_json;
    if (!LabCallLoopback(host, port, rpc_user, rpc_password, "lab.snapshot_export", inner.write(), result_json, err)) {
        return false;
    }
    UniValue result;
    if (!result.read(result_json) || !result.isObject() || !result.exists("manifest") || !result["manifest"].isStr()) {
        return Fail(err, "BTX035_SCHEMA");
    }
    manifest_json = result["manifest"].get_str();
    std::vector<ExchangeObject> objects;
    return VerifyExchangeManifest(manifest_json, objects, err);
}

bool LoopbackPeers(std::vector<LoopbackPeer>& peers, bool& configured, std::string& err)
{
    peers.clear();
    configured = false;
    err.clear();

    std::vector<std::string> tokens;
    AppendPeerToken(tokens, EnvOrEmpty("BTX035_LAB_PEER"));
    AppendPeerList(tokens, EnvOrEmpty("BTX035_LAB_PEERS"));
    if (tokens.empty()) return true;

    std::vector<LoopbackPeer> accepted;
    for (const std::string& token : tokens) {
        std::string host;
        uint16_t port = 0;
        if (!ParseLoopbackEndpoint(token, host, port, err)) {
            peers.clear();
            return false;
        }
        bool seen = false;
        for (const LoopbackPeer& have : accepted) {
            if (have.host == host && have.port == port) {
                seen = true;
                break;
            }
        }
        if (seen) continue;
        LoopbackPeer peer;
        peer.host = std::move(host);
        peer.port = port;
        accepted.push_back(std::move(peer));
    }

    const std::string user = EnvOrEmpty("BTX035_LAB_PEER_USER");
    const std::string password = EnvOrEmpty("BTX035_LAB_PEER_PASSWORD");
    if (user.empty() || password.empty()) {
        peers.clear();
        return Fail(err, "BTX035_PERMIT");
    }
    for (LoopbackPeer& peer : accepted) {
        peer.user = user;
        peer.password = password;
    }
    peers = std::move(accepted);
    configured = true;
    err.clear();
    return true;
}

} // namespace modelnet
