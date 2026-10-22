// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_exchange.h>

#include <modelnet/git_snapshot.h>
#include <span.h>
#include <univalue.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

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

/** Bound each connect, send and recv on a loopback lab socket by `timeout`. */
void SetSocketTimeout(int fd, std::chrono::milliseconds timeout)
{
    if (timeout < std::chrono::milliseconds{1}) timeout = std::chrono::milliseconds{1};
#ifdef _WIN32
    const DWORD ms = static_cast<DWORD>(timeout.count());
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
#else
    timeval tv{};
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

std::chrono::milliseconds Remaining(std::chrono::steady_clock::time_point end)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - std::chrono::steady_clock::now());
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

} // namespace

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
                     const std::string& params_json, std::string& result_json, std::string& err,
                     std::chrono::milliseconds deadline)
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

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return Fail(err, "BTX035_TRANSPORT");
#endif
    const int fd = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return Fail(err, "BTX035_TRANSPORT");
    const auto end = std::chrono::steady_clock::now() + deadline;
    SetSocketTimeout(fd, deadline);
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
    const std::string bytes = request.str();
    size_t sent = 0;
    while (sent < bytes.size()) {
        const auto n = send(fd, bytes.data() + sent, bytes.size() - sent, 0);
        if (n <= 0) {
            CloseSock(fd);
            return Fail(err, "BTX035_TRANSPORT");
        }
        sent += static_cast<size_t>(n);
    }
    std::string response;
    char buf[4096];
    while (true) {
        if (Remaining(end).count() <= 0) {
            CloseSock(fd);
            return Fail(err, "BTX035_TRANSPORT");
        }
        SetSocketTimeout(fd, Remaining(end));
        const auto n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            CloseSock(fd);
            return Fail(err, "BTX035_TRANSPORT");
        }
        if (n == 0) break;
        response.append(buf, buf + n);
    }
    CloseSock(fd);
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
                       const std::string& body_json, std::string& result_json, std::string& err,
                       std::chrono::milliseconds deadline)
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
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return Fail(err, "BTX035_TRANSPORT");
#endif
    const int fd = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return Fail(err, "BTX035_TRANSPORT");
    const auto end = std::chrono::steady_clock::now() + deadline;
    SetSocketTimeout(fd, deadline);
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
    const std::string bytes = request.str();
    size_t sent = 0;
    while (sent < bytes.size()) {
        const auto n = send(fd, bytes.data() + sent, bytes.size() - sent, 0);
        if (n <= 0) {
            CloseSock(fd);
            return Fail(err, "BTX035_TRANSPORT");
        }
        sent += static_cast<size_t>(n);
    }
    std::string response;
    char buf[4096];
    while (true) {
        if (Remaining(end).count() <= 0) {
            CloseSock(fd);
            return Fail(err, "BTX035_TRANSPORT");
        }
        SetSocketTimeout(fd, Remaining(end));
        const auto n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            CloseSock(fd);
            return Fail(err, "BTX035_TRANSPORT");
        }
        if (n == 0) break;
        response.append(buf, buf + n);
    }
    CloseSock(fd);
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
