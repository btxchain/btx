// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/source_registry.h>

#include <crypto/sha384.h>
#include <modelnet/registry_resolver.h>
#include <modelnet/source_local.h>
#include <modelnet/store.h>
#include <modelnet/types.h>
#include <span.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <memory>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <poll.h>
#include <set>
#include <sys/time.h>

namespace modelnet {
namespace {

std::string HeaderLower(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

} // namespace

bool ParseRegistryHttpResponse(const std::string& raw, RegistryHttpResponse& out, std::string& err)
{
    out = {};
    const auto hdr_end = raw.find("\r\n\r\n");
    if (hdr_end == std::string::npos) {
        err = "http headers";
        return false;
    }
    const std::string headers = raw.substr(0, hdr_end);
    out.body = raw.substr(hdr_end + 4);
    {
        const auto sp = headers.find(' ');
        if (sp != std::string::npos) out.status = std::atoi(headers.c_str() + sp + 1);
    }
    const std::string hl = HeaderLower(headers);
    size_t line_start = 0;
    while (line_start < headers.size()) {
        auto line_end = headers.find("\r\n", line_start);
        if (line_end == std::string::npos) line_end = headers.size();
        const std::string line = headers.substr(line_start, line_end - line_start);
        line_start = line_end >= headers.size() ? headers.size() : line_end + 2;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        if (HeaderLower(line.substr(0, colon)) != "location") continue;
        std::string val = line.substr(colon + 1);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r')) val.pop_back();
        out.location = val;
        out.has_location = true;
    }
    const auto te = hl.find("\ntransfer-encoding:");
    if (te != std::string::npos) {
        auto val = hl.substr(te + 19);
        const auto nl = val.find('\n');
        if (nl != std::string::npos) val.resize(nl);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t' || val.front() == '\r')) val.erase(val.begin());
        while (!val.empty() && (val.back() == ' ' || val.back() == '\r' || val.back() == '\t')) val.pop_back();
        if (val != "identity") out.chunked = true;
    }
    const auto cl = hl.find("\ncontent-length:");
    if (cl != std::string::npos) {
        out.has_content_length = true;
        out.content_length = static_cast<uint64_t>(std::strtoull(hl.c_str() + cl + 16, nullptr, 10));
    }
    const auto cr = hl.find("\ncontent-range:");
    if (cr != std::string::npos) {
        auto val = hl.substr(cr + 15);
        const auto nl = val.find('\n');
        if (nl != std::string::npos) val.resize(nl);
        const auto b = val.find("bytes");
        if (b != std::string::npos) val = val.substr(b + 5);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());
        const auto dash = val.find('-');
        const auto slash = val.find('/');
        if (dash != std::string::npos) {
            out.has_content_range = true;
            out.range_start = static_cast<uint64_t>(std::strtoull(val.c_str(), nullptr, 10));
            out.range_end = static_cast<uint64_t>(std::strtoull(val.c_str() + dash + 1, nullptr, 10));
            (void)slash;
        }
    }
    return true;
}

bool RegistryHttpIsRedirect(const RegistryHttpResponse& resp)
{
    return resp.status == 301 || resp.status == 302 || resp.status == 303 || resp.status == 307 ||
           resp.status == 308;
}

bool RegistryHttpBodyAllowed(const RegistryHttpResponse& resp, bool range_requested, uint64_t offset, uint64_t length,
                             std::vector<unsigned char>& out, std::string& err)
{
    out.clear();
    if (resp.status == 301 || resp.status == 302 || resp.status == 303 || resp.status == 307 || resp.status == 308 ||
        resp.has_location) {
        err = "redirects forbidden";
        return false;
    }
    if (resp.chunked) {
        err = "chunked encoding forbidden";
        return false;
    }
    if (!resp.has_content_length) {
        err = "content-length required";
        return false;
    }
    if (range_requested) {
        if (resp.status != 206) {
            err = "range not satisfied";
            return false;
        }
        if (resp.has_content_range && resp.range_start != offset) {
            err = "content-range";
            return false;
        }
    } else if (resp.status != 200) {
        err = "http status";
        return false;
    }
    if (resp.body.size() < resp.content_length) {
        err = "short read";
        return false;
    }
    std::string body = resp.body.substr(0, static_cast<size_t>(resp.content_length));
    if (range_requested && length > 0 && body.size() > length) body.resize(static_cast<size_t>(length));
    out.assign(body.begin(), body.end());
    return true;
}

namespace {

std::mutex g_mu;
RegistryGetFn g_test_get;
std::map<std::string, std::vector<unsigned char>> g_url_bytes;
std::map<std::string, std::vector<unsigned char>> g_type_bytes;
std::set<std::string> g_type_error;
std::map<std::string, std::string> g_redirect_final;

bool EnvLiveWan()
{
    const char* e = std::getenv("BTX_MODELNET_LIVE_WAN");
    return e && e[0] == '1';
}

std::string Sha384Hex(const std::vector<unsigned char>& bytes)
{
    CSHA384 h;
    if (!bytes.empty()) h.Write(bytes.data(), bytes.size());
    unsigned char d[CSHA384::OUTPUT_SIZE];
    h.Finalize(d);
    return HexStr(Span<const unsigned char>{d, CSHA384::OUTPUT_SIZE});
}

/** Piece leaves use ChunkLeaf. Whole-file sha384 only when the extent is the entire file. */
IdentityMatch ExtentMatchesIdentity(const ReadExtent& extent, const std::vector<unsigned char>& got, uint64_t size_bytes,
                                    const std::string& sha384_hex, const std::vector<std::string>& piece_hex,
                                    std::string& why)
{
    if (!piece_hex.empty()) {
        if (extent.offset % PIECE_SIZE != 0) {
            why = "HASH_MISMATCH";
            return IdentityMatch::MISMATCH;
        }
        const size_t idx = static_cast<size_t>(extent.offset / PIECE_SIZE);
        if (idx >= piece_hex.size()) {
            why = "HASH_MISMATCH";
            return IdentityMatch::MISMATCH;
        }
        const uint64_t expect_len =
            size_bytes > extent.offset ? std::min<uint64_t>(PIECE_SIZE, size_bytes - extent.offset) : extent.length;
        if (got.size() != expect_len) {
            why = "HASH_MISMATCH";
            return IdentityMatch::MISMATCH;
        }
        const std::string leaf = ChunkLeaf(idx, Span<const unsigned char>{got.data(), got.size()}).Hex();
        if (leaf != piece_hex[idx]) {
            why = "HASH_MISMATCH";
            return IdentityMatch::MISMATCH;
        }
        return IdentityMatch::LEAF;
    }
    if (!sha384_hex.empty() && size_bytes > 0 && extent.offset == 0 && extent.length == size_bytes &&
        got.size() == size_bytes) {
        if (Sha384Hex(got) != sha384_hex) {
            why = "HASH_MISMATCH";
            return IdentityMatch::MISMATCH;
        }
        return IdentityMatch::WHOLE_FILE;
    }
    why.clear();
    return IdentityMatch::UNCHECKED;
}

bool CopyExtent(const std::vector<unsigned char>& src, const ReadExtent& extent, uint64_t budget,
                std::vector<unsigned char>& out, std::string& err)
{
    out.clear();
    if (extent.length > budget) {
        err = "credit exhausted";
        return false;
    }
    if (extent.offset > src.size() || extent.length > src.size() - extent.offset) {
        err = "extent";
        return false;
    }
    out.assign(src.begin() + static_cast<std::ptrdiff_t>(extent.offset),
               src.begin() + static_cast<std::ptrdiff_t>(extent.offset + extent.length));
    return true;
}

struct ParsedHttps {
    std::string host;
    uint16_t port{443};
    std::string path;
};

bool ParseHttpsUrl(const std::string& url, ParsedHttps& out, std::string& err)
{
    if (url.rfind("https://", 0) != 0) {
        err = "https only";
        return false;
    }
    std::string rest = url.substr(8);
    auto slash = rest.find('/');
    std::string hostport = slash == std::string::npos ? rest : rest.substr(0, slash);
    out.path = slash == std::string::npos ? "/" : rest.substr(slash);
    if (!hostport.empty() && hostport.front() == '[') {
        auto rb = hostport.find(']');
        if (rb == std::string::npos) {
            err = "locator";
            return false;
        }
        out.host = hostport.substr(1, rb - 1);
        if (rb + 1 < hostport.size() && hostport[rb + 1] == ':') {
            out.port = static_cast<uint16_t>(std::atoi(hostport.c_str() + rb + 2));
        }
    } else {
        auto colon = hostport.rfind(':');
        if (colon != std::string::npos && hostport.find(':') == colon) {
            out.host = hostport.substr(0, colon);
            out.port = static_cast<uint16_t>(std::atoi(hostport.c_str() + colon + 1));
        } else {
            out.host = hostport;
        }
    }
    if (out.host.empty() || out.path.empty()) {
        err = "locator";
        return false;
    }
    return true;
}

bool ResolveHttpsRedirectInner(const std::string& current_url, const std::string& location, std::string& out,
                               std::string& err)
{
    std::string loc = location;
    while (!loc.empty() && (loc.front() == ' ' || loc.front() == '\t')) loc.erase(loc.begin());
    while (!loc.empty() && (loc.back() == ' ' || loc.back() == '\t' || loc.back() == '\r')) loc.pop_back();
    if (loc.size() >= 2 && loc.front() == '<' && loc.back() == '>') loc = loc.substr(1, loc.size() - 2);
    auto hash = loc.find('#');
    if (hash != std::string::npos) loc.resize(hash);
    if (loc.empty()) {
        err = "redirect location";
        return false;
    }
    if (loc.rfind("http://", 0) == 0) {
        err = "https only";
        return false;
    }
    if (loc.rfind("https://", 0) == 0) {
        out = loc;
        return true;
    }
    if (loc.rfind("//", 0) == 0) {
        out = "https:" + loc;
        return true;
    }
    ParsedHttps cur;
    if (!ParseHttpsUrl(current_url, cur, err)) return false;
    std::string path;
    if (loc.front() == '/') {
        path = loc;
    } else {
        const auto slash = cur.path.rfind('/');
        const std::string dir = slash == std::string::npos ? "/" : cur.path.substr(0, slash + 1);
        path = dir + loc;
    }
    std::string hostport = cur.host;
    if (cur.port != 443) hostport += ":" + std::to_string(cur.port);
    out = "https://" + hostport + path;
    err.clear();
    return true;
}

constexpr int kRegistryHttpsTimeoutMs = 15000;

void ApplySocketTimeouts(int fd, int timeout_ms)
{
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

bool WaitFd(int fd, short events, int timeout_ms, std::string& err)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            err = "timeout";
            return false;
        }
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = events;
        const int rc = ::poll(&pfd, 1, static_cast<int>(left));
        if (rc == 0) {
            err = "timeout";
            return false;
        }
        if (rc < 0) {
            if (errno == EINTR) continue;
            err = "connect";
            return false;
        }
        return true;
    }
}

int RemainingMs(std::chrono::steady_clock::time_point deadline)
{
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return 0;
    return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
}

bool HttpsExchangeOnce(const std::string& url, uint64_t offset, uint64_t length, RegistryHttpResponse& resp,
                       std::string& err, std::chrono::steady_clock::time_point deadline)
{
    resp = {};
    const int left = RemainingMs(deadline);
    if (left <= 0) {
        err = "timeout";
        return false;
    }
    std::string ssrf;
    if (!HuggingFaceLocatorAllowed(url, ssrf)) {
        err = ssrf;
        return false;
    }
    ParsedHttps u;
    if (!ParseHttpsUrl(url, u, err)) return false;

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* raw = nullptr;
    const std::string port = std::to_string(u.port);
    if (getaddrinfo(u.host.c_str(), port.c_str(), &hints, &raw) != 0 || !raw) {
        err = "dns";
        return false;
    }
    int fd = -1;
    std::string last = "ssrf";
    bool saw_global = false;
    for (addrinfo* ai = raw; ai; ai = ai->ai_next) {
        if (!ai->ai_addr) continue;
        if (!AddressIsGlobalUnicast(ai->ai_addr, ai->ai_addrlen)) {
            last = "ssrf";
            continue;
        }
        saw_global = true;
#ifdef SOCK_CLOEXEC
        fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
#else
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#endif
        if (fd < 0) {
            last = "connect";
            continue;
        }
#ifndef SOCK_CLOEXEC
        fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        const int cr = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (cr != 0 && errno != EINPROGRESS && errno != EINTR) {
            last = "connect";
            ::close(fd);
            fd = -1;
            continue;
        }
        std::string werr;
        if (!WaitFd(fd, POLLOUT, RemainingMs(deadline), werr)) {
            last = werr.empty() ? "timeout" : werr;
            ::close(fd);
            fd = -1;
            continue;
        }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
        if (soerr != 0) {
            last = "connect";
            ::close(fd);
            fd = -1;
            continue;
        }
        if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        ApplySocketTimeouts(fd, RemainingMs(deadline));
        break;
    }
    freeaddrinfo(raw);
    if (fd < 0) {
        err = saw_global ? last : "ssrf";
        return false;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ::close(fd);
        err = "ssl ctx";
        return false;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    (void)SSL_CTX_set_default_verify_paths(ctx);
    SSL* ssl = SSL_new(ctx);
    if (!ssl || SSL_set_fd(ssl, fd) != 1 || SSL_set_tlsext_host_name(ssl, u.host.c_str()) != 1 ||
        SSL_set1_host(ssl, u.host.c_str()) != 1 || SSL_connect(ssl) != 1) {
        if (ssl) SSL_free(ssl);
        SSL_CTX_free(ctx);
        ::close(fd);
        err = "https handshake failed";
        return false;
    }

    const bool range_requested = length > 0;
    std::string req = "GET " + u.path + " HTTP/1.1\r\nHost: " + u.host +
                      "\r\nUser-Agent: BTX-modelnet/0.34.9\r\nAccept: */*\r\nConnection: close\r\n";
    if (range_requested) {
        req += "Range: bytes=" + std::to_string(offset) + "-" + std::to_string(offset + length - 1) + "\r\n";
    }
    req += "\r\n";
    if (SSL_write(ssl, req.data(), static_cast<int>(req.size())) <= 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ::close(fd);
        err = "https write failed";
        return false;
    }

    std::string raw_resp;
    char buf[4096];
    while (true) {
        if (std::chrono::steady_clock::now() >= deadline) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            ::close(fd);
            err = "timeout";
            return false;
        }
        const int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) break;
        raw_resp.append(buf, static_cast<size_t>(n));
        if (raw_resp.size() > (32ull << 20)) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            ::close(fd);
            err = "response too large";
            return false;
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ::close(fd);

    return ParseRegistryHttpResponse(raw_resp, resp, err);
}

bool HttpsGetRange(const std::string& url, uint64_t offset, uint64_t length, std::vector<unsigned char>& out,
                   std::string& err)
{
    out.clear();
    std::string current = url;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_redirect_final.find(url);
        if (it != g_redirect_final.end()) current = it->second;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kRegistryHttpsTimeoutMs);
    for (int hop = 0; hop <= 3; ++hop) {
        RegistryHttpResponse resp;
        if (!HttpsExchangeOnce(current, offset, length, resp, err, deadline)) return false;
        if (RegistryHttpIsRedirect(resp)) {
            if (hop == 3) {
                err = "too many redirects";
                return false;
            }
            if (resp.location.empty()) {
                err = "redirect location";
                return false;
            }
            std::string next;
            if (!ResolveHttpsRedirectInner(current, resp.location, next, err)) return false;
            std::string ssrf;
            if (!HuggingFaceLocatorAllowed(next, ssrf)) {
                err = ssrf;
                return false;
            }
            current = next;
            continue;
        }
        if (current != url) {
            std::lock_guard<std::mutex> lock(g_mu);
            g_redirect_final[url] = current;
        }
        return RegistryHttpBodyAllowed(resp, length > 0, offset, length, out, err);
    }
    err = "too many redirects";
    return false;
}

bool FetchUrl(const std::string& url, uint64_t offset, uint64_t length, std::vector<unsigned char>& out, bool live_wan,
              std::string& err)
{
    RegistryGetFn test_get;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (g_test_get) {
            test_get = g_test_get;
        } else {
            auto it = g_url_bytes.find(url);
            if (it != g_url_bytes.end()) {
                return CopyExtent(it->second, ReadExtent{offset, length}, length + offset, out, err);
            }
        }
    }
    if (test_get) return test_get(url, offset, length, out, err);
    if (!live_wan && !EnvLiveWan()) {
        err = "not wired to live network";
        return false;
    }
    return HttpsGetRange(url, offset, length, out, err);
}

} // namespace

bool ResolveHttpsRedirect(const std::string& current_url, const std::string& location, std::string& out, std::string& err)
{
    return ResolveHttpsRedirectInner(current_url, location, out, err);
}

void SetRegistryGetForTests(RegistryGetFn fn)
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_test_get = std::move(fn);
}

void ClearRegistryGetForTests()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_test_get = nullptr;
}

void InjectRegistryUrlBytes(const std::string& url, std::vector<unsigned char> bytes)
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_url_bytes[url] = std::move(bytes);
}

void InjectRegistryOriginBytes(const std::string& origin_type, std::vector<unsigned char> bytes)
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_type_bytes[origin_type] = std::move(bytes);
}

void ClearRegistryInjections()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_url_bytes.clear();
    g_type_bytes.clear();
    g_type_error.clear();
    g_redirect_final.clear();
    g_test_get = nullptr;
}

bool LiveRegistryWanEnabled()
{
    return EnvLiveWan();
}

void InjectRegistryOriginError(const std::string& origin_type)
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_type_error.insert(origin_type);
}

RegistryByteSource::RegistryByteSource(ImportOrigin origin, bool live_wan)
    : m_origin(std::move(origin)), m_live_wan(live_wan)
{
}

void RegistryByteSource::SelectFile(const std::string& relative, const std::string& sha384_hex)
{
    m_file = relative;
    m_sha384_hex = sha384_hex;
    m_piece_origins.clear();
}

void RegistryByteSource::BindFileIdentity(uint64_t size_bytes, const std::vector<std::string>& piece_sha384_hex)
{
    m_size_bytes = size_bytes;
    m_piece_hex = piece_sha384_hex;
    m_piece_origins.clear();
}

bool RegistryByteSource::Pin(std::string& err)
{
    if (m_origin.snapshot_token.empty()) {
        err = "snapshot_token";
        return false;
    }
    const std::string& loc = m_origin.locator;
    if (loc.rfind("http://", 0) == 0 || loc.rfind("https://", 0) == 0) {
        if (!HuggingFaceLocatorAllowed(loc, err)) return false;
    }
    m_pinned = true;
    err.clear();
    return true;
}

bool RegistryByteSource::Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
                             std::string& err)
{
    out.clear();
    m_origin_errors.clear();
    auto fail = [&](const std::string& why) {
        err = why;
        m_origin_errors.push_back({m_origin.type, err});
        return false;
    };
    if (!m_pinned && !Pin(err)) {
        m_origin_errors.push_back({m_origin.type, err});
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (g_type_error.count(m_origin.type)) {
            return fail("origin unavailable");
        }
        auto it = g_type_bytes.find(m_origin.type);
        if (it != g_type_bytes.end()) {
            if (!CopyExtent(it->second, extent, budget_bytes, out, err)) {
                m_origin_errors.push_back({m_origin.type, err});
                return false;
            }
            if (ExtentMatchesIdentity(extent, out, m_size_bytes, m_sha384_hex, m_piece_hex, err) ==
                IdentityMatch::MISMATCH) {
                out.clear();
                m_origin_errors.push_back({m_origin.type, err});
                return false;
            }
            m_piece_origins.push_back(m_origin.type);
            return true;
        }
    }
    ResolvedRegistryUrl resolved;
    const std::string file = m_file.empty() ? "model.safetensors" : m_file;
    if (!ResolveRegistryFileUrl(m_origin.type, m_origin.locator, m_origin.snapshot_token, file, resolved, err)) {
        m_origin_errors.push_back({m_origin.type, err});
        return false;
    }
    m_last_url = resolved.url;
    if (!HuggingFaceLocatorAllowed(resolved.url, err)) {
        m_origin_errors.push_back({m_origin.type, err});
        return false;
    }
    std::vector<unsigned char> body;
    if (!FetchUrl(resolved.url, extent.offset, extent.length, body, m_live_wan, err)) {
        m_origin_errors.push_back({m_origin.type, err});
        return false;
    }
    if (extent.length > budget_bytes) {
        return fail("credit exhausted");
    }
    out = std::move(body);
    if (ExtentMatchesIdentity(extent, out, m_size_bytes, m_sha384_hex, m_piece_hex, err) == IdentityMatch::MISMATCH) {
        out.clear();
        m_origin_errors.push_back({m_origin.type, err});
        return false;
    }
    m_piece_origins.push_back(m_origin.type);
    return true;
}

std::string RegistryByteSource::Kind() const
{
    std::string k = m_origin.type;
    for (char& c : k) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    return k;
}

MultiOriginByteSource::MultiOriginByteSource(ImportPlan plan) : m_plan(std::move(plan))
{
    SynthesizeOriginsFromV1(m_plan);
}

void MultiOriginByteSource::SelectFile(const std::string& relative, const std::string& sha384_hex)
{
    m_file = relative;
    m_sha384_hex = sha384_hex;
    m_locked_origin.clear();
    m_mixed_without_identity = false;
    m_piece_origins.clear();
    m_bound_piece_origins.clear();
    m_origin_errors.clear();
}

void MultiOriginByteSource::BindFileIdentity(uint64_t size_bytes, const std::vector<std::string>& piece_sha384_hex)
{
    m_size_bytes = size_bytes;
    m_piece_hex = piece_sha384_hex;
    m_piece_origins.clear();
    m_bound_piece_origins.clear();
    m_origin_errors.clear();
    m_locked_origin.clear();
    m_mixed_without_identity = false;
}

bool MultiOriginByteSource::Pin(std::string& err)
{
    if (m_plan.origins.empty()) {
        err = "origins";
        return false;
    }
    std::string last = "origins";
    for (const auto& o : m_plan.origins) {
        if (o.type == "local" || o.type == "torrent" || o.type == "magnet" || o.type == "s3" || o.type == "btx") {
            last.clear();
            continue;
        }
        RegistryByteSource src(o, m_plan.live_wan);
        std::string perr;
        if (src.Pin(perr)) {
            err.clear();
            return true;
        }
        last = perr;
    }
    err = last.empty() ? "ok" : last;
    return last.empty() || last == "ok";
}

bool MultiOriginByteSource::Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
                                std::string& err)
{
    out.clear();
    m_conflicts.clear();
    m_origin_errors.clear();
    std::string last = "origin unavailable";
    for (const auto& o : m_plan.origins) {
        if (!m_locked_origin.empty() && o.type != m_locked_origin) continue;
        std::unique_ptr<ByteSource> src;
        if (o.type == "local") {
            src = std::make_unique<LocalFileByteSource>(fs::PathFromString(o.locator));
        } else if (o.type == "s3") {
            src = std::make_unique<S3OriginByteSource>(o);
        } else if (o.type == "btx") {
            src = std::make_unique<BtxOriginByteSource>(o);
        } else if (o.type == "torrent" || o.type == "magnet") {
            last = "torrent origin uses TorrentByteSource";
            m_origin_errors.push_back({o.type, last});
            continue;
        } else {
            auto reg = std::make_unique<RegistryByteSource>(o, m_plan.live_wan);
            reg->SelectFile(m_file, m_sha384_hex);
            reg->BindFileIdentity(m_size_bytes, m_piece_hex);
            src = std::move(reg);
        }
        std::string perr;
        if (!src->Pin(perr)) {
            last = perr;
            m_origin_errors.push_back({o.type, perr});
            continue;
        }
        std::vector<unsigned char> got;
        if (!src->Read(extent, got, budget_bytes, perr)) {
            if (perr == "HASH_MISMATCH") {
                m_conflicts.push_back(o.type + ":HASH_MISMATCH");
                last = "ORIGIN_CONFLICT";
            } else {
                last = perr;
            }
            m_origin_errors.push_back({o.type, perr.empty() ? last : perr});
            continue;
        }
        std::string why;
        const IdentityMatch match = ExtentMatchesIdentity(extent, got, m_size_bytes, m_sha384_hex, m_piece_hex, why);
        if (match == IdentityMatch::MISMATCH) {
            m_conflicts.push_back(o.type + ":" + why);
            last = "ORIGIN_CONFLICT";
            m_origin_errors.push_back({o.type, why.empty() ? last : why});
            continue;
        }
        const bool identity_bound = match == IdentityMatch::LEAF || match == IdentityMatch::WHOLE_FILE;
        if (!identity_bound) {
            if (m_locked_origin.empty()) {
                m_locked_origin = o.type;
            } else if (m_locked_origin != o.type) {
                m_mixed_without_identity = true;
                last = "UNBOUND_ORIGIN_MIX";
                m_origin_errors.push_back({o.type, last});
                continue;
            }
        }
        m_last_origin = o.type;
        m_piece_origins.push_back(o.type);
        if (identity_bound) m_bound_piece_origins.push_back(o.type);
        out = std::move(got);
        err.clear();
        return true;
    }
    err = last;
    return false;
}

std::string MultiOriginByteSource::Locator() const
{
    if (m_plan.origins.empty()) return m_plan.locator;
    return m_plan.origins.front().locator;
}

std::string MultiOriginByteSource::SourceIntegrity() const
{
    if (m_plan.origins.empty()) return m_plan.snapshot_token;
    return m_plan.origins.front().snapshot_token;
}

int MultiOriginByteSource::IndependentOriginCount() const
{
    if (m_mixed_without_identity) {
        std::set<std::string> unique(m_bound_piece_origins.begin(), m_bound_piece_origins.end());
        return static_cast<int>(unique.size());
    }
    const auto& src = !m_bound_piece_origins.empty() ? m_bound_piece_origins : m_piece_origins;
    std::set<std::string> unique(src.begin(), src.end());
    return static_cast<int>(unique.size());
}

S3OriginByteSource::S3OriginByteSource(ImportOrigin origin) : m_origin(std::move(origin)) {}

void S3OriginByteSource::InjectTestBytes(std::vector<unsigned char> bytes)
{
    m_injected = std::move(bytes);
    m_has_injected = true;
}

bool S3OriginByteSource::Pin(std::string& err)
{
    const std::string& loc = m_origin.locator;
    if (loc.rfind("s3://", 0) != 0 && loc.rfind("https://", 0) != 0) {
        err = "locator";
        return false;
    }
    if (loc.rfind("https://", 0) == 0 && !HuggingFaceLocatorAllowed(loc, err)) return false;
    m_pinned = true;
    return true;
}

bool S3OriginByteSource::Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
                             std::string& err)
{
    if (!m_pinned && !Pin(err)) return false;
    if (m_has_injected) return CopyExtent(m_injected, extent, budget_bytes, out, err);
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_type_bytes.find("s3");
    if (it != g_type_bytes.end()) return CopyExtent(it->second, extent, budget_bytes, out, err);
    err = "s3 origin has no bytes (inject, setcloudstorage, or live_wan object GET)";
    return false;
}

BtxOriginByteSource::BtxOriginByteSource(ImportOrigin origin) : m_origin(std::move(origin)) {}

void BtxOriginByteSource::InjectTestBytes(std::vector<unsigned char> bytes)
{
    m_injected = std::move(bytes);
    m_has_injected = true;
}

bool BtxOriginByteSource::Pin(std::string& err)
{
    if (m_origin.locator.rfind("btx://", 0) != 0) {
        err = "locator";
        return false;
    }
    m_pinned = true;
    return true;
}

bool BtxOriginByteSource::Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
                              std::string& err)
{
    if (!m_pinned && !Pin(err)) return false;
    if (m_has_injected) return CopyExtent(m_injected, extent, budget_bytes, out, err);
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_type_bytes.find("btx");
    if (it != g_type_bytes.end()) return CopyExtent(it->second, extent, budget_bytes, out, err);
    err = "btx origin has no local pieces";
    return false;
}

} // namespace modelnet
