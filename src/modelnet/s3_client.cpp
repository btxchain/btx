// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/s3_client.h>

#include <modelnet/supervisor.h>
#include <compat/compat.h>
#include <crypto/hmac_sha256.h>
#include <crypto/sha256.h>
#include <support/cleanse.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/time.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <sstream>
#include <utility>

namespace modelnet {
namespace {

constexpr char EMPTY_SHA256[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

void WipeString(std::string& s)
{
    if (!s.empty()) {
        memory_cleanse(s.data(), s.size());
        s.clear();
        s.shrink_to_fit();
    }
}

std::string UriEncode(std::string_view in, bool encode_slash)
{
    std::string out;
    out.reserve(in.size() * 3);
    for (unsigned char c : in) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || (c == '/' && !encode_slash)) {
            out.push_back(static_cast<char>(c));
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", c);
            out.append(buf);
        }
    }
    return out;
}

bool ParseIPv4(std::string_view host, uint32_t& ip)
{
    ip = 0;
    int dots = 0;
    uint32_t acc = 0;
    int digits = 0;
    for (size_t i = 0; i <= host.size(); ++i) {
        const char c = i < host.size() ? host[i] : '.';
        if (c == '.') {
            if (digits == 0 || acc > 255 || dots > 3) return false;
            ip = (ip << 8) | acc;
            acc = 0;
            digits = 0;
            if (i < host.size()) ++dots;
            continue;
        }
        if (i == host.size()) break;
        if (!IsDigit(c)) return false;
        acc = acc * 10 + static_cast<uint32_t>(c - '0');
        ++digits;
        if (digits > 3) return false;
    }
    return dots == 3;
}

bool IsLoopbackHost(const std::string& host)
{
    if (host == "localhost" || host == "localhost.") return true;
    if (host == "::1" || host == "0:0:0:0:0:0:0:1") return true;
    uint32_t ip = 0;
    if (ParseIPv4(host, ip)) return (ip >> 24) == 127;
    if (host.starts_with("::ffff:")) {
        uint32_t mapped = 0;
        if (ParseIPv4(host.substr(7), mapped)) return (mapped >> 24) == 127;
    }
    return false;
}

bool IsLinkLocalIPv4(uint32_t ip)
{
    return (ip & 0xffff0000u) == 0xa9fe0000u;
}

void RedactFrom(std::string& s, size_t start, size_t n)
{
    const size_t end = std::min(s.size(), start + n);
    for (size_t i = start; i < end; ++i) s[i] = '*';
}

/**
 * Mask the value introduced by `needle`. With require_separator, a hit is only
 * masked when `=` or `:` follows, so a needle that is a prefix of a longer field
 * name ("access_key" in "aws_access_key_id") leaves that name intact.
 */
void RedactValueAfterNeedle(std::string& s, std::string_view needle, bool require_separator = false)
{
    const std::string lower = ToLower(s);
    const std::string n = ToLower(needle);
    size_t pos = 0;
    while (pos < lower.size()) {
        const size_t found = lower.find(n, pos);
        if (found == std::string::npos) break;
        size_t i = found + n.size();
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '"' || s[i] == '\'')) ++i;
        if (i < s.size() && (s[i] == '=' || s[i] == ':')) {
            ++i;
            while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '"')) ++i;
        } else if (require_separator) {
            pos = found + n.size();
            continue;
        }
        const size_t begin = i;
        while (i < s.size() && s[i] != '&' && s[i] != ' ' && s[i] != '\n' && s[i] != '\r' && s[i] != '"' &&
               s[i] != '\'' && s[i] != ',' && s[i] != ';') {
            ++i;
        }
        if (i > begin) RedactFrom(s, begin, i - begin);
        pos = found + n.size();
    }
}

bool ParseCredBody(const std::string& body, std::string& access, std::string& secret, std::string& err)
{
    access.clear();
    secret.clear();
    std::vector<std::string> plain;
    std::istringstream in(body);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const std::string t = std::string(util::TrimStringView(line));
        if (t.empty() || t[0] == '#' || t[0] == ';') continue;
        const auto eq = t.find('=');
        if (eq != std::string::npos) {
            const std::string key = ToLower(std::string(util::TrimStringView(t.substr(0, eq))));
            const std::string val = std::string(util::TrimStringView(t.substr(eq + 1)));
            if (key == "aws_access_key_id" || key == "access_key_id" || key == "access_key") access = val;
            else if (key == "aws_secret_access_key" || key == "secret_access_key" || key == "secret") secret = val;
            continue;
        }
        plain.push_back(t);
    }
    if (access.empty() && secret.empty() && plain.size() >= 2) {
        access = plain[0];
        secret = plain[1];
    }
    if (access.empty() || secret.empty()) {
        err = "credential body missing access_key_id or secret_access_key";
        WipeString(access);
        WipeString(secret);
        return false;
    }
    return true;
}

bool EnvNameOk(const std::string& name)
{
    if (name.empty() || name.size() > 128) return false;
    if (!(std::isalpha(static_cast<unsigned char>(name[0])) || name[0] == '_')) return false;
    for (unsigned char c : name) {
        if (!(std::isalnum(c) || c == '_')) return false;
    }
    return true;
}

std::array<unsigned char, 32> HmacSha256(Span<const unsigned char> key, Span<const unsigned char> data)
{
    std::array<unsigned char, 32> out{};
    CHMAC_SHA256 hasher(key.data(), key.size());
    if (!data.empty()) hasher.Write(data.data(), data.size());
    hasher.Finalize(out.data());
    return out;
}

std::array<unsigned char, 32> HmacSha256Msg(Span<const unsigned char> key, std::string_view msg)
{
    return HmacSha256(key, Span<const unsigned char>{reinterpret_cast<const unsigned char*>(msg.data()), msg.size()});
}

std::string HexLower(Span<const unsigned char> b)
{
    return HexStr(b);
}

std::map<std::string, std::string> CanonicalHeaderMap(const SigV4Request& req)
{
    std::map<std::string, std::string> hdrs;
    for (const auto& kv : req.headers) {
        hdrs[ToLower(kv.first)] = std::string(util::TrimStringView(kv.second));
    }
    hdrs.erase("authorization");
    return hdrs;
}

std::string CanonicalQuery(const std::map<std::string, std::string>& query)
{
    std::string out;
    bool first = true;
    for (const auto& kv : query) {
        if (!first) out += '&';
        first = false;
        out += UriEncode(kv.first, true);
        out += '=';
        out += UriEncode(kv.second, true);
    }
    return out;
}

bool VerifyAgainstFake(const std::string& access,
                       const std::string& secret,
                       const std::string& region,
                       const SigV4Request& signed_req,
                       const std::string& signature,
                       Span<const unsigned char> body,
                       std::string& err)
{
    if (access.empty() || secret.empty()) {
        err = "fake s3 has no signing context";
        return false;
    }
    if (signed_req.access_key_id != access) {
        err = "sigv4 access key mismatch";
        return false;
    }
    const std::string payload = signed_req.payload_sha256_hex == "UNSIGNED-PAYLOAD"
                                    ? std::string{"UNSIGNED-PAYLOAD"}
                                    : Sha256Hex(body);
    if (ToLower(payload) != ToLower(signed_req.payload_sha256_hex) &&
        signed_req.payload_sha256_hex != "UNSIGNED-PAYLOAD") {
        err = "sigv4 payload hash mismatch";
        return false;
    }
    SigV4Request v = signed_req;
    v.secret_access_key = secret;
    v.access_key_id = access;
    v.region = region;
    const std::string want = SigV4SignatureHex(v);
    WipeString(v.secret_access_key);
    if (ToLower(want) != ToLower(signature)) {
        err = "sigv4 signature mismatch";
        return false;
    }
    return true;
}

std::string QueryParam(const std::string& url, const std::string& key)
{
    const auto q = url.find('?');
    if (q == std::string::npos) return {};
    const std::string qs = url.substr(q + 1);
    size_t start = 0;
    const std::string want = ToLower(key);
    while (start < qs.size()) {
        const size_t amp = qs.find('&', start);
        const std::string pair = qs.substr(start, amp == std::string::npos ? std::string::npos : amp - start);
        const auto eq = pair.find('=');
        const std::string k = ToLower(eq == std::string::npos ? pair : pair.substr(0, eq));
        const std::string v = eq == std::string::npos ? std::string{} : pair.substr(eq + 1);
        if (k == want) return v;
        if (amp == std::string::npos) break;
        start = amp + 1;
    }
    return {};
}

constexpr int kS3HttpsTimeoutMs = 5000;
constexpr size_t kS3HttpsMaxHeaderBytes = size_t{64} << 10;
constexpr size_t kS3HttpsReadBuf = size_t{64} << 10;
constexpr uint64_t kS3HttpsMaxGetBytes = uint64_t{1} << 30;
constexpr uint64_t kS3HttpsMaxControlBytes = uint64_t{1} << 20;
constexpr uint64_t kS3HttpsForbidObjectBytes = uint64_t{400} << 30;
constexpr int kS3HttpsMaxParts = 10000;

struct SslCtxFree {
    void operator()(SSL_CTX* c) const
    {
        if (c) SSL_CTX_free(c);
    }
};
struct SslFree {
    void operator()(SSL* s) const
    {
        if (s) SSL_free(s);
    }
};

std::string FailCloud(std::string_view msg, std::string_view extra_secret = {})
{
    return RedactCloudSecrets(msg, extra_secret);
}

bool HostLooksLikeIp(const std::string& host)
{
    uint32_t ip = 0;
    if (ParseIPv4(host, ip)) return true;
    return host.find(':') != std::string::npos;
}

std::string NumericHostFromAddr(const sockaddr* sa, socklen_t len)
{
    char buf[NI_MAXHOST]{};
    if (!sa || getnameinfo(sa, len, buf, sizeof(buf), nullptr, 0, NI_NUMERICHOST) != 0) return {};
    std::string h = buf;
    const auto pct = h.find('%');
    if (pct != std::string::npos) h.resize(pct);
    return ToLower(h);
}

bool ResolvedAddrBlocked(const sockaddr* sa, socklen_t len, bool allow_link_local)
{
    const std::string h = NumericHostFromAddr(sa, len);
    if (h.empty()) return true;
    if (S3HostBlockedAsMetadata(h) && !allow_link_local) return true;
    uint32_t ip = 0;
    if (ParseIPv4(h, ip) && IsLinkLocalIPv4(ip) && !allow_link_local) return true;
    return false;
}

bool WaitFd(int fd, short events, int timeout_ms, std::string& err)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            err = FailCloud("s3 https timeout");
            return false;
        }
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = events;
        const int rc = ::poll(&pfd, 1, static_cast<int>(left));
        if (rc == 0) {
            err = FailCloud("s3 https timeout");
            return false;
        }
        if (rc < 0) {
            if (errno == EINTR) continue;
            err = FailCloud("s3 https poll failed");
            return false;
        }
        return true;
    }
}

void ApplySocketTimeouts(int fd, int timeout_ms)
{
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

bool ConnectTcp(const ParsedS3Endpoint& ep, bool allow_http_loopback, bool allow_link_local, int& fd_out, std::string& err)
{
    fd_out = -1;
    const uint16_t port = ep.port != 0 ? ep.port : (ep.scheme == "http" ? 80 : 443);
    if (port == 0) {
        err = FailCloud("s3 https bad port");
        return false;
    }
    if (ep.scheme == "http") {
        if (!allow_http_loopback || !IsLoopbackHost(ep.host)) {
            err = FailCloud("http cloud endpoint is only allowed for loopback MinIO / tests");
            return false;
        }
    }

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (HostLooksLikeIp(ep.host)) hints.ai_flags |= AI_NUMERICHOST;

    addrinfo* raw = nullptr;
    const int ga = ::getaddrinfo(ep.host.c_str(), std::to_string(port).c_str(), &hints, &raw);
    if (ga != 0 || raw == nullptr) {
        err = FailCloud("https resolve failed");
        if (raw) freeaddrinfo(raw);
        return false;
    }

    std::string last = "https connect failed";
    for (addrinfo* ai = raw; ai != nullptr; ai = ai->ai_next) {
        if (!ai->ai_addr) continue;
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) continue;
        if (ai->ai_addrlen == 0 || ai->ai_addrlen > sizeof(sockaddr_storage)) continue;
        if (ResolvedAddrBlocked(ai->ai_addr, ai->ai_addrlen, allow_link_local)) {
            last = "cloud endpoint host is a metadata/link-local address";
            continue;
        }
        const std::string nh = NumericHostFromAddr(ai->ai_addr, ai->ai_addrlen);
        if (ep.scheme == "http" && !IsLoopbackHost(nh)) {
            last = "http cloud endpoint is only allowed for loopback MinIO / tests";
            continue;
        }
#ifdef SOCK_CLOEXEC
        const int fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
#else
        const int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#endif
        if (fd < 0) {
            last = "https connect failed";
            continue;
        }
#ifndef SOCK_CLOEXEC
        fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        const int cr = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (cr != 0 && errno != EINPROGRESS && errno != EINTR) {
            last = "https connect failed";
            ::close(fd);
            continue;
        }
        std::string werr;
        if (!WaitFd(fd, POLLOUT, kS3HttpsTimeoutMs, werr)) {
            last = werr.empty() ? "https connect failed" : werr;
            ::close(fd);
            continue;
        }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
        if (soerr != 0) {
            last = "https connect failed";
            ::close(fd);
            continue;
        }
        if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        ApplySocketTimeouts(fd, kS3HttpsTimeoutMs);
        int nodelay = 1;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        freeaddrinfo(raw);
        fd_out = fd;
        return true;
    }
    freeaddrinfo(raw);
    err = FailCloud(last);
    return false;
}

bool OpensslHandshake(int fd, const std::string& host, std::unique_ptr<SSL_CTX, SslCtxFree>& ctx,
                      std::unique_ptr<SSL, SslFree>& ssl, std::string& err)
{
    ctx.reset(SSL_CTX_new(TLS_client_method()));
    if (!ctx) {
        err = FailCloud("s3 https SSL_CTX_new failed");
        return false;
    }
    // Classical TLS to object storage (R2 / S3 / MinIO). Do not reuse the swarm
    // PQ1 SSL_CTX (MLKEM768 / mldsa44 / AES-256-GCM-SHA384 pin).
    if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION) != 1) {
        err = FailCloud("https handshake failed");
        return false;
    }
    (void)SSL_CTX_set1_groups_list(ctx.get(), "X25519:secp256r1:secp384r1");
    SSL_CTX_set_options(ctx.get(), SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_default_verify_paths(ctx.get()) != 1) {
        err = FailCloud("s3 https CA path failed");
        return false;
    }
    ssl.reset(SSL_new(ctx.get()));
    if (!ssl) {
        err = FailCloud("s3 https SSL_new failed");
        return false;
    }
    if (SSL_set_fd(ssl.get(), fd) != 1) {
        err = FailCloud("s3 https SSL_set_fd failed");
        return false;
    }
    if (HostLooksLikeIp(host)) {
        if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl.get()), host.c_str()) != 1) {
            err = FailCloud("s3 https TLS IP verify param failed");
            return false;
        }
    } else {
        if (SSL_set_tlsext_host_name(ssl.get(), host.c_str()) != 1) {
            err = FailCloud("s3 https SNI failed");
            return false;
        }
        if (SSL_set1_host(ssl.get(), host.c_str()) != 1) {
            err = FailCloud("s3 https hostname verify failed");
            return false;
        }
    }
    const int rc = SSL_connect(ssl.get());
    if (rc != 1) {
        err = FailCloud("https handshake failed");
        return false;
    }
    return true;
}

bool SendAll(int fd, SSL* ssl, const unsigned char* data, size_t n, std::string& err)
{
    size_t off = 0;
    while (off < n) {
        const size_t chunk = std::min(n - off, kS3HttpsReadBuf);
        if (ssl) {
            const int w = SSL_write(ssl, data + off, static_cast<int>(chunk));
            if (w <= 0) {
                const int e = SSL_get_error(ssl, w);
                if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) continue;
                err = FailCloud("s3 https write failed");
                return false;
            }
            off += static_cast<size_t>(w);
        } else {
            const ssize_t w = ::send(fd, data + off, chunk, MSG_NOSIGNAL);
            if (w < 0) {
                if (errno == EINTR) continue;
                err = FailCloud("s3 https write failed");
                return false;
            }
            if (w == 0) {
                err = FailCloud("s3 https write failed");
                return false;
            }
            off += static_cast<size_t>(w);
        }
    }
    return true;
}

bool RecvSome(int fd, SSL* ssl, unsigned char* data, size_t n, size_t& got, std::string& err)
{
    got = 0;
    if (n == 0) return true;
    if (ssl) {
        const int r = SSL_read(ssl, data, static_cast<int>(std::min(n, kS3HttpsReadBuf)));
        if (r == 0) return true;
        if (r < 0) {
            const int e = SSL_get_error(ssl, r);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return true;
            if (e == SSL_ERROR_ZERO_RETURN) return true;
            err = FailCloud("s3 https read failed");
            return false;
        }
        got = static_cast<size_t>(r);
        return true;
    }
    const ssize_t r = ::recv(fd, data, n, 0);
    if (r < 0) {
        if (errno == EINTR) return true;
        err = FailCloud("s3 https read failed");
        return false;
    }
    got = static_cast<size_t>(r);
    return true;
}

int ParseHttpStatus(std::string_view headers)
{
    if (headers.size() < 12 || headers.substr(0, 5) != "HTTP/") return 0;
    const auto sp = headers.find(' ');
    if (sp == std::string::npos) return 0;
    int code = 0;
    size_t i = sp + 1;
    int digits = 0;
    while (i < headers.size() && headers[i] >= '0' && headers[i] <= '9' && digits < 3) {
        code = code * 10 + (headers[i] - '0');
        ++i;
        ++digits;
    }
    return digits == 3 ? code : 0;
}

std::string HttpHeaderValue(std::string_view headers, std::string_view name)
{
    const std::string want = ToLower(std::string(name));
    size_t i = 0;
    const size_t first_nl = headers.find('\n');
    if (first_nl == std::string::npos) return {};
    i = first_nl + 1;
    while (i < headers.size()) {
        size_t line_end = headers.find('\n', i);
        if (line_end == std::string::npos) line_end = headers.size();
        std::string_view line = headers.substr(i, line_end - i);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) break;
        const auto colon = line.find(':');
        if (colon != std::string::npos) {
            const std::string hname = ToLower(std::string(line.substr(0, colon)));
            if (hname == want) return std::string(util::TrimStringView(line.substr(colon + 1)));
        }
        i = line_end + 1;
    }
    return {};
}

bool XmlTagValue(std::string_view xml, std::string_view tag, std::string& out)
{
    const std::string open = "<" + std::string(tag) + ">";
    const std::string close = "</" + std::string(tag) + ">";
    const auto a = xml.find(open);
    if (a == std::string::npos) return false;
    const auto b = xml.find(close, a + open.size());
    if (b == std::string::npos) return false;
    std::string v{xml.substr(a + open.size(), b - (a + open.size()))};
    if (v.find('<') != std::string::npos) return false;
    out = std::string(util::TrimStringView(v));
    return !out.empty();
}

struct S3HttpResult {
    int status{0};
    std::string location;
    uint64_t content_length{0};
    bool has_content_length{false};
    std::string etag;
    std::vector<unsigned char> body;
};

std::string HttpRequestTarget(const SigV4Request& req, const std::string& raw_target)
{
    if (!raw_target.empty()) return raw_target;
    std::string path = req.canonical_uri.empty() ? std::string{"/"} : req.canonical_uri;
    const std::string qs = CanonicalQuery(req.query);
    if (!qs.empty()) path += "?" + qs;
    return path;
}

std::string BuildHttpHead(const SigV4Request& req, size_t body_len, bool sign, const std::string& raw_target)
{
    std::string out;
    out += req.method.empty() ? "GET" : req.method;
    out += ' ';
    out += HttpRequestTarget(req, raw_target);
    out += " HTTP/1.1\r\n";
    bool have_cl = false;
    for (const auto& kv : req.headers) {
        const std::string lname = ToLower(kv.first);
        if (lname == "authorization") continue;
        if (lname == "content-length") have_cl = true;
        out += kv.first;
        out += ": ";
        out += kv.second;
        out += "\r\n";
    }
    if (sign) {
        out += "Authorization: ";
        out += SigV4AuthorizationHeader(req);
        out += "\r\n";
    }
    if (!have_cl) {
        out += "Content-Length: ";
        out += std::to_string(body_len);
        out += "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

bool PerformS3Http(const S3ClientConfig& cfg, SigV4Request req, Span<const unsigned char> body, bool sign,
                   bool read_body, uint64_t max_body, const std::string& raw_target, S3HttpResult& res,
                   std::string& err)
{
    res = {};
    ParsedS3Endpoint ep;
    if (!ParseS3Endpoint(cfg.endpoint, ep, err)) {
        err = FailCloud(err, req.secret_access_key);
        WipeString(req.secret_access_key);
        return false;
    }
    if (!ValidateS3Endpoint(cfg.endpoint, cfg.allow_http_loopback, cfg.allow_link_local, err)) {
        err = FailCloud(err, req.secret_access_key);
        WipeString(req.secret_access_key);
        return false;
    }
    if (ep.scheme != "https" && ep.scheme != "http") {
        err = FailCloud("cloud endpoint scheme not allowed", req.secret_access_key);
        WipeString(req.secret_access_key);
        return false;
    }

    const std::string head = BuildHttpHead(req, body.size(), sign, raw_target);
    WipeString(req.secret_access_key);

    int fd = -1;
    if (!ConnectTcp(ep, cfg.allow_http_loopback, cfg.allow_link_local, fd, err)) {
        return false;
    }

    std::unique_ptr<SSL_CTX, SslCtxFree> ctx;
    std::unique_ptr<SSL, SslFree> ssl;
    if (ep.scheme == "https") {
        if (!OpensslHandshake(fd, ep.host, ctx, ssl, err)) {
            ssl.reset();
            ctx.reset();
            ::close(fd);
            return false;
        }
    }

    auto cleanup = [&]() {
        ssl.reset();
        ctx.reset();
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    };

    SSL* s = ssl.get();
    if (!SendAll(fd, s, reinterpret_cast<const unsigned char*>(head.data()), head.size(), err)) {
        cleanup();
        return false;
    }
    size_t body_off = 0;
    while (body_off < body.size()) {
        const size_t n = std::min(body.size() - body_off, kS3HttpsReadBuf);
        if (!SendAll(fd, s, body.data() + body_off, n, err)) {
            cleanup();
            return false;
        }
        body_off += n;
    }

    std::string header_buf;
    std::vector<unsigned char> leftover;
    unsigned char rbuf[kS3HttpsReadBuf];
    size_t header_end = std::string::npos;
    while (header_end == std::string::npos) {
        size_t got = 0;
        if (!RecvSome(fd, s, rbuf, sizeof(rbuf), got, err)) {
            cleanup();
            return false;
        }
        if (got == 0) {
            err = FailCloud("s3 https read failed");
            cleanup();
            return false;
        }
        header_buf.append(reinterpret_cast<char*>(rbuf), got);
        if (header_buf.size() > kS3HttpsMaxHeaderBytes) {
            err = FailCloud("s3 https headers too large");
            cleanup();
            return false;
        }
        header_end = header_buf.find("\r\n\r\n");
        if (header_end == std::string::npos) header_end = header_buf.find("\n\n");
    }
    const size_t sep_len = header_buf.compare(header_end, 4, "\r\n\r\n") == 0 ? 4 : 2;
    leftover.assign(header_buf.begin() + static_cast<std::ptrdiff_t>(header_end + sep_len), header_buf.end());
    header_buf.resize(header_end);

    res.status = ParseHttpStatus(header_buf);
    res.location = HttpHeaderValue(header_buf, "location");
    res.etag = HttpHeaderValue(header_buf, "etag");
    const std::string cl = HttpHeaderValue(header_buf, "content-length");
    if (!cl.empty()) {
        int64_t n = 0;
        if (!ParseInt64(cl, &n) || n < 0) {
            err = FailCloud("s3 https bad content-length");
            cleanup();
            return false;
        }
        res.has_content_length = true;
        res.content_length = static_cast<uint64_t>(n);
    }
    const std::string te = ToLower(HttpHeaderValue(header_buf, "transfer-encoding"));
    if (te.find("chunked") != std::string::npos) {
        err = FailCloud("s3 https chunked transfer unsupported");
        cleanup();
        return false;
    }

    if (S3HttpResponseForbiddenRedirect(res.status, res.location)) {
        err = FailCloud("http redirect refused");
        cleanup();
        return false;
    }

    if (!read_body) {
        cleanup();
        return true;
    }

    if (res.has_content_length && res.content_length >= kS3HttpsForbidObjectBytes) {
        err = FailCloud("s3 https object too large");
        cleanup();
        return false;
    }
    if (res.has_content_length && res.content_length > max_body) {
        err = FailCloud("s3 https object too large for unchunked GET");
        cleanup();
        return false;
    }

    uint64_t remaining = res.has_content_length ? res.content_length : max_body;
    if (!leftover.empty()) {
        if (leftover.size() > remaining) {
            err = FailCloud("s3 https object too large for unchunked GET");
            cleanup();
            return false;
        }
        res.body.insert(res.body.end(), leftover.begin(), leftover.end());
        remaining -= leftover.size();
    }
    while (remaining > 0) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(remaining, sizeof(rbuf)));
        size_t got = 0;
        if (!RecvSome(fd, s, rbuf, want, got, err)) {
            cleanup();
            return false;
        }
        if (got == 0) {
            if (res.has_content_length && remaining > 0) {
                err = FailCloud("s3 https short body");
                cleanup();
                return false;
            }
            break;
        }
        res.body.insert(res.body.end(), rbuf, rbuf + got);
        remaining -= got;
        if (!res.has_content_length && res.body.size() > max_body) {
            err = FailCloud("s3 https object too large for unchunked GET");
            cleanup();
            return false;
        }
    }
    cleanup();
    return true;
}

bool FinishS3Http(const S3HttpResult& res, std::string& err)
{
    if (S3HttpResponseForbiddenRedirect(res.status, res.location)) {
        err = FailCloud("http redirect refused");
        return false;
    }
    if (res.status < 200 || res.status >= 300) {
        if (res.status == 404) {
            err = FailCloud("missing object");
            return false;
        }
        err = FailCloud("s3 https status " + std::to_string(res.status));
        return false;
    }
    return true;
}

std::string UrlPathAndQuery(std::string_view url)
{
    const auto se = url.find("://");
    if (se == std::string::npos) return "/";
    const size_t start = se + 3;
    const size_t path = url.find_first_of("/?#", start);
    if (path == std::string::npos) return "/";
    if (url[path] == '#') return "/";
    if (url[path] == '?') return "/" + std::string(url.substr(path));
    std::string pq{url.substr(path)};
    const auto hash = pq.find('#');
    if (hash != std::string::npos) pq.resize(hash);
    return pq.empty() ? "/" : pq;
}

std::string HostPortKey(const ParsedS3Endpoint& p)
{
    const uint16_t def = p.scheme == "http" ? 80 : 443;
    std::string h = p.host;
    if (h.find(':') != std::string::npos && (h.empty() || h.front() != '[')) h = "[" + h + "]";
    if (p.port != 0 && p.port != def) return h + ":" + std::to_string(p.port);
    return h;
}

} // namespace

bool S3HttpRedirectRefused(int status)
{
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

bool S3HttpResponseForbiddenRedirect(int status, std::string_view location)
{
    if (S3HttpRedirectRefused(status)) return true;
    return !util::TrimStringView(location).empty();
}

std::string Sha256Hex(Span<const unsigned char> data)
{
    unsigned char h[CSHA256::OUTPUT_SIZE];
    CSHA256 hasher;
    if (!data.empty()) hasher.Write(data.data(), data.size());
    hasher.Finalize(h);
    return HexStr(Span<const unsigned char>{h, sizeof(h)});
}

std::string SigV4SignedHeaders(const SigV4Request& req)
{
    const auto hdrs = CanonicalHeaderMap(req);
    std::string signed_headers;
    bool first = true;
    for (const auto& kv : hdrs) {
        if (!first) signed_headers += ';';
        first = false;
        signed_headers += kv.first;
    }
    return signed_headers;
}

std::string SigV4CanonicalRequest(const SigV4Request& req)
{
    const auto hdrs = CanonicalHeaderMap(req);
    std::string canonical_headers;
    std::string signed_headers;
    bool first = true;
    for (const auto& kv : hdrs) {
        canonical_headers += kv.first;
        canonical_headers += ':';
        canonical_headers += kv.second;
        canonical_headers += '\n';
        if (!first) signed_headers += ';';
        first = false;
        signed_headers += kv.first;
    }
    std::string payload = req.payload_sha256_hex.empty() ? std::string(EMPTY_SHA256) : req.payload_sha256_hex;
    if (payload != "UNSIGNED-PAYLOAD") payload = ToLower(payload);
    std::string cr;
    cr += req.method;
    cr += '\n';
    cr += req.canonical_uri;
    cr += '\n';
    cr += CanonicalQuery(req.query);
    cr += '\n';
    cr += canonical_headers;
    cr += '\n';
    cr += signed_headers;
    cr += '\n';
    cr += payload;
    return cr;
}

std::string SigV4SignatureHex(const SigV4Request& req)
{
    const std::string cr = SigV4CanonicalRequest(req);
    const std::string hashed_cr = Sha256Hex(Span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(cr.data()), cr.size()});
    std::string amz = req.amz_date;
    if (amz.empty()) {
        const auto it = req.headers.find("x-amz-date");
        if (it != req.headers.end()) amz = it->second;
        else {
            auto hdrs = CanonicalHeaderMap(req);
            amz = hdrs["x-amz-date"];
        }
    }
    const std::string date = amz.size() >= 8 ? amz.substr(0, 8) : amz;
    const std::string scope = date + "/" + req.region + "/" + req.service + "/aws4_request";
    const std::string sts = std::string("AWS4-HMAC-SHA256\n") + amz + "\n" + scope + "\n" + hashed_cr;

    std::string k0 = "AWS4" + req.secret_access_key;
    auto kDate = HmacSha256Msg(Span<const unsigned char>{reinterpret_cast<const unsigned char*>(k0.data()), k0.size()}, date);
    WipeString(k0);
    auto kRegion = HmacSha256Msg(Span<const unsigned char>{kDate.data(), kDate.size()}, req.region);
    memory_cleanse(kDate.data(), kDate.size());
    auto kService = HmacSha256Msg(Span<const unsigned char>{kRegion.data(), kRegion.size()}, req.service);
    memory_cleanse(kRegion.data(), kRegion.size());
    auto kSigning = HmacSha256Msg(Span<const unsigned char>{kService.data(), kService.size()}, "aws4_request");
    memory_cleanse(kService.data(), kService.size());
    auto sig = HmacSha256Msg(Span<const unsigned char>{kSigning.data(), kSigning.size()}, sts);
    memory_cleanse(kSigning.data(), kSigning.size());
    const std::string hex = HexLower(Span<const unsigned char>{sig.data(), sig.size()});
    memory_cleanse(sig.data(), sig.size());
    return hex;
}

std::string SigV4AuthorizationHeader(const SigV4Request& req)
{
    const std::string amz = req.amz_date.empty() ? CanonicalHeaderMap(req)["x-amz-date"] : req.amz_date;
    const std::string date = amz.size() >= 8 ? amz.substr(0, 8) : amz;
    const std::string scope = date + "/" + req.region + "/" + req.service + "/aws4_request";
    const std::string sig = SigV4SignatureHex(req);
    return "AWS4-HMAC-SHA256 Credential=" + req.access_key_id + "/" + scope + ", SignedHeaders=" +
           SigV4SignedHeaders(req) + ", Signature=" + sig;
}

std::string RedactCloudSecrets(std::string_view text, std::string_view extra_secret)
{
    std::string s{text};
    RedactValueAfterNeedle(s, "aws_secret_access_key");
    RedactValueAfterNeedle(s, "secret_access_key");
    RedactValueAfterNeedle(s, "AWS_SECRET_ACCESS_KEY");
    RedactValueAfterNeedle(s, "x-amz-signature");
    RedactValueAfterNeedle(s, "X-Amz-Signature");
    RedactValueAfterNeedle(s, "x-amz-credential");
    RedactValueAfterNeedle(s, "X-Amz-Credential");
    RedactValueAfterNeedle(s, "x-amz-security-token");
    // Only AWS access key ids have a recognisable shape (the AKIA scan below).
    // Cloudflare R2 ids are 32 hex characters and MinIO ids are arbitrary, so
    // they can only be masked by the field name that introduces them.
    RedactValueAfterNeedle(s, "aws_access_key_id", /*require_separator=*/true);
    RedactValueAfterNeedle(s, "access_key_id", /*require_separator=*/true);
    RedactValueAfterNeedle(s, "access_key", /*require_separator=*/true);
    const std::string lower = ToLower(s);
    size_t i = 0;
    while (i + 4 < s.size()) {
        if (lower.compare(i, 4, "akia") == 0) {
            size_t n = 4;
            while (i + n < s.size() && n < 20 && std::isalnum(static_cast<unsigned char>(s[i + n]))) ++n;
            if (n == 20) {
                for (size_t k = 4; k < 20; ++k) s[i + k] = '*';
                i += 20;
                continue;
            }
        }
        ++i;
    }
    if (extra_secret.size() >= 4) {
        size_t pos = 0;
        while ((pos = s.find(extra_secret, pos)) != std::string::npos) {
            s.replace(pos, extra_secret.size(), "***REDACTED***");
            pos += 12;
        }
    }
    return s;
}

bool ParseS3Endpoint(std::string_view endpoint, ParsedS3Endpoint& out, std::string& err)
{
    out = {};
    const std::string raw = std::string(util::TrimStringView(endpoint));
    if (raw.empty()) {
        err = "empty cloud endpoint";
        return false;
    }
    if (raw.find('\n') != std::string::npos || raw.find('\r') != std::string::npos ||
        raw.find(' ') != std::string::npos) {
        err = "cloud endpoint contains illegal characters";
        return false;
    }
    const auto scheme_end = raw.find("://");
    if (scheme_end == std::string::npos || scheme_end == 0) {
        err = "cloud endpoint must include a URI scheme";
        return false;
    }
    out.scheme = ToLower(raw.substr(0, scheme_end));
    size_t host_begin = scheme_end + 3;
    const size_t host_end = raw.find_first_of("/?#", host_begin);
    std::string auth = raw.substr(host_begin, (host_end == std::string::npos ? raw.size() : host_end) - host_begin);
    if (auth.find('@') != std::string::npos) {
        out.has_userinfo = true;
        err = "cloud endpoint must not contain userinfo (credentials in URL)";
        return false;
    }
    if (!auth.empty() && auth.front() == '[') {
        const auto br = auth.find(']');
        if (br == std::string::npos) {
            err = "bad ipv6 cloud endpoint host";
            return false;
        }
        out.host = ToLower(auth.substr(1, br - 1));
        if (br + 1 < auth.size() && auth[br + 1] == ':') {
            int32_t port = 0;
            if (!ParseInt32(auth.substr(br + 2), &port) || port <= 0 || port > 65535) {
                err = "bad cloud endpoint port";
                return false;
            }
            out.port = static_cast<uint16_t>(port);
        }
    } else {
        const auto colon = auth.rfind(':');
        if (colon != std::string::npos && auth.find(':') == colon) {
            out.host = ToLower(auth.substr(0, colon));
            int32_t port = 0;
            if (!ParseInt32(auth.substr(colon + 1), &port) || port <= 0 || port > 65535) {
                err = "bad cloud endpoint port";
                return false;
            }
            out.port = static_cast<uint16_t>(port);
        } else {
            out.host = ToLower(auth);
        }
    }
    while (!out.host.empty() && out.host.back() == '.') out.host.pop_back();
    if (out.host.empty()) {
        err = "cloud endpoint missing host";
        return false;
    }
    return true;
}

bool S3HostBlockedAsMetadata(std::string_view host)
{
    std::string h = ToLower(std::string(util::TrimStringView(host)));
    while (!h.empty() && h.back() == '.') h.pop_back();
    if (h == "169.254.169.254" || h == "fd00:ec2::254") return true;
    if (h.starts_with("::ffff:")) {
        const std::string mapped = h.substr(7);
        if (mapped == "169.254.169.254") return true;
        uint32_t ip = 0;
        if (ParseIPv4(mapped, ip) && IsLinkLocalIPv4(ip)) return true;
    }
    uint32_t ip = 0;
    if (ParseIPv4(h, ip) && IsLinkLocalIPv4(ip)) return true;
    if (h == "metadata" || h == "metadata.google.internal" || h == "metadata.goog") return true;
    if (h.ends_with(".metadata.google.internal")) return true;
    if (h == "instance-data" || h == "instance-data.ec2.internal") return true;
    if (h.ends_with(".instance-data.ec2.internal")) return true;
    if (h == "100.100.100.200") return true;
    return false;
}

bool ValidateS3Endpoint(std::string_view endpoint, bool allow_http_loopback, bool allow_link_local, std::string& err)
{
    const std::string raw = ToLower(std::string(util::TrimStringView(endpoint)));
    if (raw.starts_with("file:") || raw.starts_with("unix:") || raw.starts_with("gopher:") ||
        raw.starts_with("ftp:") || raw.starts_with("data:") || raw.starts_with("javascript:") ||
        raw.starts_with("s3:")) {
        err = "cloud endpoint scheme not allowed";
        return false;
    }
    ParsedS3Endpoint p;
    if (!ParseS3Endpoint(endpoint, p, err)) return false;
    if (p.scheme != "https" && p.scheme != "http") {
        err = "cloud endpoint must be https (http only for local MinIO / loopback tests)";
        return false;
    }
    if (p.scheme == "http") {
        if (!allow_http_loopback || !IsLoopbackHost(p.host)) {
            err = "http cloud endpoint is only allowed for loopback MinIO / tests";
            return false;
        }
    }
    if (S3HostBlockedAsMetadata(p.host) && !allow_link_local) {
        err = "cloud endpoint host is a metadata/link-local address";
        return false;
    }
    uint32_t ip = 0;
    if (ParseIPv4(p.host, ip) && IsLinkLocalIPv4(ip) && !allow_link_local) {
        err = "cloud endpoint host is a metadata/link-local address";
        return false;
    }
    return true;
}

bool LoadS3Secrets(const CredentialRef& ref, std::string& access_key_id, std::string& secret_access_key,
                   std::string& err)
{
    access_key_id.clear();
    secret_access_key.clear();
    std::string body;
    if (ref.kind == CredentialRefKind::PATH) {
        if (ref.value.empty()) {
            err = "credential path is empty";
            return false;
        }
        const fs::path path = fs::PathFromString(ref.value);
        std::error_code ec;
        const auto st = fs::status(path, ec);
        if (ec || st.type() != fs::file_type::regular) {
            err = "credential path is not a regular file";
            return false;
        }
        const auto leaked = fs::perms::group_read | fs::perms::group_write | fs::perms::group_exec |
                            fs::perms::others_read | fs::perms::others_write | fs::perms::others_exec;
        if ((st.permissions() & leaked) != fs::perms::none) {
            err = "credential file must be mode 0600";
            return false;
        }
        const auto sz = fs::file_size(path, ec);
        if (ec || sz == 0 || sz > 4096) {
            err = "credential file size is invalid";
            return false;
        }
        std::ifstream in{path};
        if (!in) {
            err = "failed to read credential file";
            return false;
        }
        body.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    } else {
        if (!EnvNameOk(ref.value)) {
            err = "credential env name is invalid";
            return false;
        }
        if (EnvLooksLikeWalletSecret(ref.value)) {
            err = "credential env name looks like a wallet secret";
            return false;
        }
        const char* v = std::getenv(ref.value.c_str());
        if (v == nullptr || v[0] == '\0') {
            err = "credential env is empty";
            return false;
        }
        body = v;
    }
    const bool ok = ParseCredBody(body, access_key_id, secret_access_key, err);
    WipeString(body);
    return ok;
}

bool S3HttpsTransportAvailable()
{
    return true;
}

FakeS3::FakeS3() = default;

FakeS3::~FakeS3()
{
    WipeString(m_access_key_id);
    WipeString(m_secret_access_key);
}

void FakeS3::SetSigningContext(std::string access_key_id, std::string secret_access_key, std::string region,
                               std::string bucket)
{
    std::lock_guard<std::mutex> lock(m_mu);
    WipeString(m_access_key_id);
    WipeString(m_secret_access_key);
    m_access_key_id = std::move(access_key_id);
    m_secret_access_key = std::move(secret_access_key);
    m_region = std::move(region);
    m_bucket = std::move(bucket);
}

uint64_t FakeS3::GetCount() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_get;
}
uint64_t FakeS3::PutCount() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_put;
}
uint64_t FakeS3::HeadCount() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_head;
}
uint64_t FakeS3::RangeCount() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_range;
}
uint64_t FakeS3::MultipartCount() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_multipart;
}
uint64_t FakeS3::PresignCount() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_presign;
}
size_t FakeS3::ObjectCount() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_objects.size();
}
bool FakeS3::Contains(const std::string& key) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_objects.find(key) != m_objects.end();
}
uint64_t FakeS3::ObjectBytes(const std::string& key) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    const auto it = m_objects.find(key);
    if (it == m_objects.end()) return 0;
    return it->second.size();
}
std::vector<std::string> FakeS3::Keys() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    std::vector<std::string> keys;
    keys.reserve(m_objects.size());
    for (const auto& kv : m_objects) keys.push_back(kv.first);
    return keys;
}
std::string FakeS3::Meta(const std::string& key, const std::string& name) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    const auto it = m_meta.find(key);
    if (it == m_meta.end()) return {};
    const auto m = it->second.find(name);
    if (m == it->second.end()) return {};
    return m->second;
}
void FakeS3::SetMeta(const std::string& key, const std::string& name, const std::string& value)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_meta[key][name] = value;
}

bool FakeS3::Put(const std::string& key, Span<const unsigned char> body, const SigV4Request& signed_req,
                 const std::string& signature, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (!VerifyAgainstFake(m_access_key_id, m_secret_access_key, m_region, signed_req, signature, body, err)) {
        return false;
    }
    m_objects[key] = std::vector<unsigned char>(body.begin(), body.end());
    ++m_put;
    return true;
}

bool FakeS3::Get(const std::string& key, const SigV4Request& signed_req, const std::string& signature,
                 std::vector<unsigned char>& out, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (!VerifyAgainstFake(m_access_key_id, m_secret_access_key, m_region, signed_req, signature, {}, err)) {
        return false;
    }
    const auto it = m_objects.find(key);
    if (it == m_objects.end()) {
        err = "missing object";
        return false;
    }
    out = it->second;
    ++m_get;
    return true;
}

bool FakeS3::Head(const std::string& key, const SigV4Request& signed_req, const std::string& signature, uint64_t& size,
                  std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (!VerifyAgainstFake(m_access_key_id, m_secret_access_key, m_region, signed_req, signature, {}, err)) {
        return false;
    }
    const auto it = m_objects.find(key);
    if (it == m_objects.end()) {
        err = "missing object";
        return false;
    }
    size = it->second.size();
    ++m_head;
    return true;
}

bool FakeS3::RangeGet(const std::string& key, uint64_t offset, uint64_t length, const SigV4Request& signed_req,
                      const std::string& signature, std::vector<unsigned char>& out, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (!VerifyAgainstFake(m_access_key_id, m_secret_access_key, m_region, signed_req, signature, {}, err)) {
        return false;
    }
    const auto it = m_objects.find(key);
    if (it == m_objects.end()) {
        err = "missing object";
        return false;
    }
    if (offset > it->second.size()) {
        err = "range offset past end";
        return false;
    }
    const uint64_t avail = it->second.size() - offset;
    const uint64_t n = length == 0 ? avail : std::min(length, avail);
    out.assign(it->second.begin() + static_cast<std::ptrdiff_t>(offset),
               it->second.begin() + static_cast<std::ptrdiff_t>(offset + n));
    ++m_range;
    return true;
}

bool FakeS3::Delete(const std::string& key, const SigV4Request& signed_req, const std::string& signature,
                    std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (!VerifyAgainstFake(m_access_key_id, m_secret_access_key, m_region, signed_req, signature, {}, err)) {
        return false;
    }
    m_objects.erase(key);
    m_meta.erase(key);
    return true;
}

bool FakeS3::BeginMultipart(const std::string& key, std::string& upload_id, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_secret_access_key.empty()) {
        err = "fake s3 has no signing context";
        return false;
    }
    ++m_upload_seq;
    upload_id = "upload-" + std::to_string(m_upload_seq);
    Multipart mp;
    mp.key = key;
    m_uploads[upload_id] = std::move(mp);
    ++m_multipart;
    return true;
}

bool FakeS3::UploadPart(const std::string& upload_id, int part, Span<const unsigned char> body, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    const auto it = m_uploads.find(upload_id);
    if (it == m_uploads.end() || part < 1) {
        err = "bad multipart upload";
        return false;
    }
    it->second.parts[part] = std::vector<unsigned char>(body.begin(), body.end());
    ++m_multipart;
    return true;
}

bool FakeS3::CompleteMultipart(const std::string& upload_id, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    const auto it = m_uploads.find(upload_id);
    if (it == m_uploads.end() || it->second.parts.empty()) {
        err = "bad multipart complete";
        return false;
    }
    std::vector<unsigned char> assembled;
    for (const auto& part : it->second.parts) {
        assembled.insert(assembled.end(), part.second.begin(), part.second.end());
    }
    m_objects[it->second.key] = std::move(assembled);
    m_uploads.erase(it);
    ++m_multipart;
    ++m_put;
    return true;
}

bool FakeS3::AbortMultipart(const std::string& upload_id, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    const auto it = m_uploads.find(upload_id);
    if (it == m_uploads.end()) {
        err = "bad multipart abort";
        return false;
    }
    m_uploads.erase(it);
    ++m_multipart;
    return true;
}

void FakeS3::NotePresign(const std::string& key, int64_t expires_unix, const std::string& signature)
{
    std::lock_guard<std::mutex> lock(m_mu);
    Presign p;
    p.key = key;
    p.expires_unix = expires_unix;
    p.signature = ToLower(signature);
    m_presigns.push_back(std::move(p));
    ++m_presign;
}

bool FakeS3::GetPresigned(const std::string& url, std::vector<unsigned char>& out, std::string& err)
{
    if (ToLower(QueryParam(url, "X-Amz-Algorithm")) != ToLower("AWS4-HMAC-SHA256")) {
        err = "presign missing algorithm";
        return false;
    }
    if (!QueryParam(url, "list-type").empty() || url.find("list-type=") != std::string::npos) {
        err = "presign must not list a bucket";
        return false;
    }
    const std::string sig = ToLower(QueryParam(url, "X-Amz-Signature"));
    std::lock_guard<std::mutex> lock(m_mu);
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    std::string key;
    for (const auto& p : m_presigns) {
        if (p.signature == sig) {
            if (now > p.expires_unix) {
                err = "presign expired";
                return false;
            }
            key = p.key;
            break;
        }
    }
    if (key.empty()) {
        err = "unknown presign";
        return false;
    }
    const auto it = m_objects.find(key);
    if (it == m_objects.end()) {
        err = "missing object";
        return false;
    }
    out = it->second;
    ++m_get;
    return true;
}

S3Client::S3Client() = default;

S3Client::~S3Client()
{
    WipeSecrets();
}

void S3Client::WipeSecrets()
{
    WipeString(m_access);
    WipeString(m_secret);
    WipeString(m_write_access);
    WipeString(m_write_secret);
}

bool S3Client::EnsureReady(std::string& err) const
{
    if (!m_ready) {
        err = "s3 client not initialized";
        return false;
    }
    return true;
}

std::string S3Client::AmzDateNow() const
{
    const std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
    gmtime_r(&t, &tm);
    char ts[32];
    std::strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tm);
    return ts;
}

std::string S3Client::HostHeader() const
{
    ParsedS3Endpoint p;
    std::string err;
    if (!ParseS3Endpoint(m_cfg.endpoint, p, err)) return {};
    return HostPortKey(p);
}

std::string S3Client::CanonicalUriFor(const std::string& key) const
{
    std::string k = key;
    while (!k.empty() && k.front() == '/') k.erase(k.begin());
    std::string path = "/" + m_cfg.bucket;
    if (!k.empty()) path += "/" + k;
    return UriEncode(path, false);
}

SigV4Request S3Client::BaseSigned(const std::string& method, const std::string& key, Span<const unsigned char> body,
                                  const std::string& extra_header_name, const std::string& extra_header_value,
                                  bool write) const
{
    SigV4Request req;
    req.method = method;
    req.canonical_uri = CanonicalUriFor(key);
    req.payload_sha256_hex = Sha256Hex(body);
    req.access_key_id = write && !m_write_access.empty() ? m_write_access : m_access;
    req.secret_access_key = write && !m_write_secret.empty() ? m_write_secret : m_secret;
    req.region = m_cfg.region;
    req.service = "s3";
    req.amz_date = AmzDateNow();
    req.headers["host"] = HostHeader();
    req.headers["x-amz-date"] = req.amz_date;
    req.headers["x-amz-content-sha256"] = req.payload_sha256_hex;
    if (!extra_header_name.empty()) req.headers[ToLower(extra_header_name)] = extra_header_value;
    return req;
}

bool S3Client::Init(const S3ClientConfig& cfg, std::string& err)
{
    WipeSecrets();
    m_fake.reset();
    m_ready = false;
    m_cfg = cfg;
    if (m_cfg.bucket.empty()) {
        err = "cloud bucket is required";
        return false;
    }
    for (unsigned char c : m_cfg.bucket) {
        if (!(std::islower(c) || std::isdigit(c) || c == '-' || c == '.')) {
            err = "cloud bucket name is invalid";
            return false;
        }
    }
    if (!ValidateS3Endpoint(m_cfg.endpoint, m_cfg.allow_http_loopback, m_cfg.allow_link_local, err)) {
        return false;
    }
    if (!LoadS3Secrets(m_cfg.creds, m_access, m_secret, err)) return false;
    if (m_cfg.write_creds) {
        if (!LoadS3Secrets(*m_cfg.write_creds, m_write_access, m_write_secret, err)) return false;
    }
    if (m_cfg.region.empty()) m_cfg.region = "us-east-1";
    if (m_cfg.use_fake) {
        m_fake = std::make_unique<FakeS3>();
        m_fake->SetSigningContext(m_access, m_secret, m_cfg.region, m_cfg.bucket);
    }
    m_ready = true;
    return true;
}

bool S3Client::Put(const std::string& key, Span<const unsigned char> body, std::string& err)
{
    if (!EnsureReady(err)) return false;
    SigV4Request req = BaseSigned("PUT", key, body, {}, {}, /*write=*/true);
    if (!m_fake) {
        S3HttpResult res;
        const bool sent = PerformS3Http(m_cfg, req, body, /*sign=*/true, /*read_body=*/true,
                                        kS3HttpsMaxControlBytes, {}, res, err);
        WipeString(req.secret_access_key);
        if (!sent || !FinishS3Http(res, err)) {
            err = FailCloud(err, m_write_secret.empty() ? m_secret : m_write_secret);
            ++m_errors;
            return false;
        }
        m_saw_put = true;
        m_last_put_max_buffer = std::max(m_last_put_max_buffer, body.size());
        return true;
    }
    const std::string sig = SigV4SignatureHex(req);
    WipeString(req.secret_access_key);
    const bool ok = m_fake->Put(key, body, req, sig, err);
    WipeString(req.secret_access_key);
    if (!ok) {
        ++m_errors;
        return false;
    }
    m_saw_put = true;
    m_last_put_max_buffer = std::max(m_last_put_max_buffer, body.size());
    return true;
}

bool S3Client::PutStream(const std::string& key, std::istream& body, uint64_t content_length, std::string& err)
{
    if (!EnsureReady(err)) return false;
    m_last_put_max_buffer = 0;
    const size_t chunk = kCloudStreamChunkBytes;
    auto read_n = [&](std::vector<unsigned char>& buf, size_t n) -> bool {
        buf.resize(n);
        if (n == 0) return true;
        body.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(n));
        const auto got = static_cast<size_t>(body.gcount());
        buf.resize(got);
        m_last_put_max_buffer = std::max(m_last_put_max_buffer, got);
        return got == n || body.eof();
    };

    auto live_abort = [&](const std::string& upload_id) {
        if (upload_id.empty() || m_fake) return;
        SigV4Request abort = BaseSigned("DELETE", key, {}, {}, {}, /*write=*/true);
        abort.query["uploadId"] = upload_id;
        S3HttpResult ignored;
        std::string aerr;
        (void)PerformS3Http(m_cfg, abort, {}, /*sign=*/true, /*read_body=*/true, kS3HttpsMaxControlBytes, {}, ignored,
                            aerr);
    };

    auto live_begin = [&](std::string& upload_id) -> bool {
        SigV4Request req = BaseSigned("POST", key, {}, {}, {}, /*write=*/true);
        req.query["uploads"] = "";
        S3HttpResult res;
        if (!PerformS3Http(m_cfg, req, {}, /*sign=*/true, /*read_body=*/true, kS3HttpsMaxControlBytes, {}, res, err) ||
            !FinishS3Http(res, err)) {
            err = FailCloud(err, m_write_secret.empty() ? m_secret : m_write_secret);
            return false;
        }
        const std::string xml(res.body.begin(), res.body.end());
        if (!XmlTagValue(xml, "UploadId", upload_id)) {
            err = FailCloud("s3 https multipart missing upload id");
            return false;
        }
        return true;
    };

    auto live_part = [&](const std::string& upload_id, int part, Span<const unsigned char> buf, std::string& etag) -> bool {
        SigV4Request req = BaseSigned("PUT", key, buf, {}, {}, /*write=*/true);
        req.query["partNumber"] = std::to_string(part);
        req.query["uploadId"] = upload_id;
        S3HttpResult res;
        if (!PerformS3Http(m_cfg, req, buf, /*sign=*/true, /*read_body=*/true, kS3HttpsMaxControlBytes, {}, res, err) ||
            !FinishS3Http(res, err)) {
            err = FailCloud(err, m_write_secret.empty() ? m_secret : m_write_secret);
            return false;
        }
        etag = res.etag;
        if (etag.empty()) {
            err = FailCloud("s3 https multipart missing etag");
            return false;
        }
        return true;
    };

    auto live_complete = [&](const std::string& upload_id, const std::vector<std::pair<int, std::string>>& parts) -> bool {
        std::string xml = "<CompleteMultipartUpload>";
        for (const auto& p : parts) {
            xml += "<Part><PartNumber>";
            xml += std::to_string(p.first);
            xml += "</PartNumber><ETag>";
            xml += p.second;
            xml += "</ETag></Part>";
        }
        xml += "</CompleteMultipartUpload>";
        const Span<const unsigned char> body_span{reinterpret_cast<const unsigned char*>(xml.data()), xml.size()};
        SigV4Request req = BaseSigned("POST", key, body_span, {}, {}, /*write=*/true);
        req.query["uploadId"] = upload_id;
        S3HttpResult res;
        if (!PerformS3Http(m_cfg, req, body_span, /*sign=*/true, /*read_body=*/true, kS3HttpsMaxControlBytes, {}, res,
                           err) ||
            !FinishS3Http(res, err)) {
            err = FailCloud(err, m_write_secret.empty() ? m_secret : m_write_secret);
            return false;
        }
        return true;
    };

    if (content_length > 0 && content_length <= chunk) {
        std::vector<unsigned char> buf;
        if (!read_n(buf, static_cast<size_t>(content_length)) || buf.size() != content_length) {
            err = "short cloud put";
            return false;
        }
        return Put(key, buf, err);
    }

    if (m_fake) {
        if (content_length == 0) {
            std::vector<unsigned char> first;
            if (!read_n(first, chunk)) {
                err = "cloud put read failed";
                return false;
            }
            if (body.eof() || first.size() < chunk) {
                return Put(key, first, err);
            }
            std::string upload_id;
            if (!m_fake->BeginMultipart(key, upload_id, err)) return false;
            int part = 1;
            if (!m_fake->UploadPart(upload_id, part++, first, err)) return false;
            while (body) {
                std::vector<unsigned char> buf;
                if (!read_n(buf, chunk)) {
                    err = "cloud put chunk read failed";
                    return false;
                }
                if (buf.empty()) break;
                if (!m_fake->UploadPart(upload_id, part++, buf, err)) return false;
                if (buf.size() < chunk) break;
            }
            const bool ok = m_fake->CompleteMultipart(upload_id, err);
            if (ok) m_saw_put = true;
            return ok;
        }

        std::string upload_id;
        if (!m_fake->BeginMultipart(key, upload_id, err)) return false;
        int part = 1;
        uint64_t remaining = content_length;
        while (remaining > 0) {
            const size_t n = static_cast<size_t>(std::min<uint64_t>(remaining, chunk));
            std::vector<unsigned char> buf;
            if (!read_n(buf, n) || buf.size() != n) {
                err = "cloud put chunk read failed";
                return false;
            }
            if (!m_fake->UploadPart(upload_id, part++, buf, err)) return false;
            remaining -= n;
        }
        const bool ok = m_fake->CompleteMultipart(upload_id, err);
        if (ok) m_saw_put = true;
        return ok;
    }

    std::vector<std::pair<int, std::string>> parts;
    std::string upload_id;
    int part = 1;

    if (content_length == 0) {
        std::vector<unsigned char> first;
        if (!read_n(first, chunk)) {
            err = "cloud put read failed";
            ++m_errors;
            return false;
        }
        if (body.eof() || first.size() < chunk) {
            return Put(key, first, err);
        }
        if (!live_begin(upload_id)) {
            ++m_errors;
            return false;
        }
        std::string etag;
        if (!live_part(upload_id, part, first, etag)) {
            live_abort(upload_id);
            ++m_errors;
            return false;
        }
        parts.emplace_back(part, std::move(etag));
        ++part;
        while (body) {
            if (part > kS3HttpsMaxParts) {
                live_abort(upload_id);
                err = FailCloud("s3 https too many multipart parts");
                ++m_errors;
                return false;
            }
            std::vector<unsigned char> buf;
            if (!read_n(buf, chunk)) {
                live_abort(upload_id);
                err = "cloud put chunk read failed";
                ++m_errors;
                return false;
            }
            if (buf.empty()) break;
            if (!live_part(upload_id, part, buf, etag)) {
                live_abort(upload_id);
                ++m_errors;
                return false;
            }
            parts.emplace_back(part, std::move(etag));
            ++part;
            if (buf.size() < chunk) break;
        }
        if (!live_complete(upload_id, parts)) {
            live_abort(upload_id);
            ++m_errors;
            return false;
        }
        m_saw_put = true;
        return true;
    }

    if (!live_begin(upload_id)) {
        ++m_errors;
        return false;
    }
    uint64_t remaining = content_length;
    while (remaining > 0) {
        if (part > kS3HttpsMaxParts) {
            live_abort(upload_id);
            err = FailCloud("s3 https too many multipart parts");
            ++m_errors;
            return false;
        }
        const size_t n = static_cast<size_t>(std::min<uint64_t>(remaining, chunk));
        std::vector<unsigned char> buf;
        if (!read_n(buf, n) || buf.size() != n) {
            live_abort(upload_id);
            err = "cloud put chunk read failed";
            ++m_errors;
            return false;
        }
        std::string etag;
        if (!live_part(upload_id, part, buf, etag)) {
            live_abort(upload_id);
            ++m_errors;
            return false;
        }
        parts.emplace_back(part, std::move(etag));
        ++part;
        remaining -= n;
    }
    if (!live_complete(upload_id, parts)) {
        live_abort(upload_id);
        ++m_errors;
        return false;
    }
    m_saw_put = true;
    return true;
}

bool S3Client::Get(const std::string& key, std::vector<unsigned char>& out, std::string& err)
{
    if (!EnsureReady(err)) return false;
    SigV4Request req = BaseSigned("GET", key, {});
    if (!m_fake) {
        S3HttpResult res;
        const bool sent = PerformS3Http(m_cfg, req, {}, /*sign=*/true, /*read_body=*/true, kS3HttpsMaxGetBytes, {}, res,
                                        err);
        WipeString(req.secret_access_key);
        if (!sent || !FinishS3Http(res, err)) {
            err = FailCloud(err, m_secret);
            ++m_errors;
            return false;
        }
        out = std::move(res.body);
        m_saw_get = true;
        return true;
    }
    const std::string sig = SigV4SignatureHex(req);
    WipeString(req.secret_access_key);
    const bool ok = m_fake->Get(key, req, sig, out, err);
    if (!ok) {
        ++m_errors;
        return false;
    }
    m_saw_get = true;
    return true;
}

bool S3Client::Head(const std::string& key, uint64_t& size, std::string& err) const
{
    if (!EnsureReady(err)) return false;
    SigV4Request req = BaseSigned("HEAD", key, {});
    if (!m_fake) {
        S3HttpResult res;
        const bool sent = PerformS3Http(m_cfg, req, {}, /*sign=*/true, /*read_body=*/false, 0, {}, res, err);
        WipeString(req.secret_access_key);
        if (!sent || !FinishS3Http(res, err)) {
            err = FailCloud(err, m_secret);
            return false;
        }
        size = res.has_content_length ? res.content_length : 0;
        return true;
    }
    const std::string sig = SigV4SignatureHex(req);
    WipeString(req.secret_access_key);
    if (!m_fake->Head(key, req, sig, size, err)) return false;
    return true;
}

bool S3Client::RangeGet(const std::string& key, uint64_t offset, uint64_t length, std::vector<unsigned char>& out,
                        std::string& err)
{
    if (!EnsureReady(err)) return false;
    const uint64_t end = length == 0 ? 0 : (offset + length - 1);
    const std::string range = length == 0 ? ("bytes=" + std::to_string(offset) + "-")
                                          : ("bytes=" + std::to_string(offset) + "-" + std::to_string(end));
    SigV4Request req = BaseSigned("GET", key, {}, "range", range);
    if (!m_fake) {
        if (length > kS3HttpsMaxGetBytes) {
            err = FailCloud("s3 https object too large for unchunked GET");
            ++m_errors;
            return false;
        }
        const uint64_t max_body = length == 0 ? kS3HttpsMaxGetBytes : length;
        S3HttpResult res;
        const bool sent = PerformS3Http(m_cfg, req, {}, /*sign=*/true, /*read_body=*/true, max_body, {}, res, err);
        WipeString(req.secret_access_key);
        if (!sent || !FinishS3Http(res, err)) {
            err = FailCloud(err, m_secret);
            ++m_errors;
            return false;
        }
        out = std::move(res.body);
        m_saw_get = true;
        return true;
    }
    const std::string sig = SigV4SignatureHex(req);
    WipeString(req.secret_access_key);
    const bool ok = m_fake->RangeGet(key, offset, length, req, sig, out, err);
    if (!ok) {
        ++m_errors;
        return false;
    }
    m_saw_get = true;
    return true;
}

bool S3Client::Delete(const std::string& key, std::string& err)
{
    if (!EnsureReady(err)) return false;
    SigV4Request req = BaseSigned("DELETE", key, {});
    if (!m_fake) {
        S3HttpResult res;
        const bool sent = PerformS3Http(m_cfg, req, {}, /*sign=*/true, /*read_body=*/true, kS3HttpsMaxControlBytes, {},
                                        res, err);
        WipeString(req.secret_access_key);
        if (!sent || !FinishS3Http(res, err)) {
            err = FailCloud(err, m_secret);
            ++m_errors;
            return false;
        }
        return true;
    }
    const std::string sig = SigV4SignatureHex(req);
    WipeString(req.secret_access_key);
    return m_fake->Delete(key, req, sig, err);
}

bool S3Client::PresignGet(const std::string& key, int ttl_seconds, std::string& url, std::string& err)
{
    if (!EnsureReady(err)) return false;
    if (ttl_seconds <= 0 || ttl_seconds > kS3PresignTtlMaxSeconds) {
        err = "presign TTL must be 1..3600 seconds";
        return false;
    }
    if (key.empty() || key.back() == '/' || key.find("..") != std::string::npos ||
        key.find('?') != std::string::npos || ToLower(key).find("list-type") != std::string::npos) {
        err = "presign requires an exact object key";
        return false;
    }
    ParsedS3Endpoint p;
    if (!ParseS3Endpoint(m_cfg.endpoint, p, err)) return false;
    SigV4Request req;
    req.method = "GET";
    req.canonical_uri = CanonicalUriFor(key);
    req.payload_sha256_hex = "UNSIGNED-PAYLOAD";
    req.access_key_id = m_access;
    req.secret_access_key = m_secret;
    req.region = m_cfg.region;
    req.service = "s3";
    req.amz_date = AmzDateNow();
    req.headers["host"] = HostHeader();
    const std::string date = req.amz_date.substr(0, 8);
    const std::string cred = m_access + "/" + date + "/" + m_cfg.region + "/s3/aws4_request";
    req.query["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256";
    req.query["X-Amz-Credential"] = cred;
    req.query["X-Amz-Date"] = req.amz_date;
    req.query["X-Amz-Expires"] = std::to_string(ttl_seconds);
    req.query["X-Amz-SignedHeaders"] = "host";
    req.query["X-Amz-Content-Sha256"] = "UNSIGNED-PAYLOAD";
    const std::string sig = SigV4SignatureHex(req);
    WipeString(req.secret_access_key);
    std::string q = CanonicalQuery(req.query);
    q += "&X-Amz-Signature=" + sig;
    url = p.scheme + "://" + HostPortKey(p) + CanonicalUriFor(key) + "?" + q;
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    if (m_fake) m_fake->NotePresign(key, now + ttl_seconds, sig);
    return true;
}

bool S3Client::FetchPresignedGet(const std::string& url, std::vector<unsigned char>& out, std::string& err)
{
    if (!EnsureReady(err)) return false;
    const std::string low = ToLower(url);
    if (low.find("file:") != std::string::npos || low.find("unix:") != std::string::npos ||
        low.find("gopher:") != std::string::npos) {
        err = "presign scheme not allowed";
        return false;
    }
    if (m_fake) return m_fake->GetPresigned(url, out, err);

    ParsedS3Endpoint url_ep;
    if (!ParseS3Endpoint(url, url_ep, err)) {
        err = FailCloud(err);
        return false;
    }
    ParsedS3Endpoint cfg_ep;
    if (!ParseS3Endpoint(m_cfg.endpoint, cfg_ep, err)) {
        err = FailCloud(err);
        return false;
    }
    if (url_ep.scheme != cfg_ep.scheme || HostPortKey(url_ep) != HostPortKey(cfg_ep)) {
        err = FailCloud("presign host mismatch");
        return false;
    }
    if (!ValidateS3Endpoint(url, m_cfg.allow_http_loopback, m_cfg.allow_link_local, err)) {
        err = FailCloud(err);
        return false;
    }
    SigV4Request req;
    req.method = "GET";
    req.canonical_uri = "/";
    req.headers["host"] = HostHeader();
    S3HttpResult res;
    S3ClientConfig call_cfg = m_cfg;
    call_cfg.endpoint = url_ep.scheme + "://" + HostPortKey(url_ep);
    if (!PerformS3Http(call_cfg, req, {}, /*sign=*/false, /*read_body=*/true, kS3HttpsMaxGetBytes,
                       UrlPathAndQuery(url), res, err) ||
        !FinishS3Http(res, err)) {
        err = FailCloud(err);
        return false;
    }
    out = std::move(res.body);
    m_saw_get = true;
    return true;
}

UniValue S3Client::HealthJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("reachable", m_ready);
    o.pushKV("auth", m_ready);
    o.pushKV("read", m_saw_get || (m_fake && m_fake->GetCount() > 0));
    o.pushKV("write", m_saw_put || (m_fake && m_fake->PutCount() > 0));
    o.pushKV("latency_ms", m_latency_ms);
    o.pushKV("errors", static_cast<uint64_t>(m_errors));
    o.pushKV("https_enabled", S3HttpsTransportAvailable());
    o.pushKV("fake", m_fake != nullptr);
    if (m_fake) {
        o.pushKV("get_count", m_fake->GetCount());
        o.pushKV("put_count", m_fake->PutCount());
        o.pushKV("head_count", m_fake->HeadCount());
        o.pushKV("range_count", m_fake->RangeCount());
        o.pushKV("multipart_count", m_fake->MultipartCount());
        o.pushKV("presign_count", m_fake->PresignCount());
        uint64_t bytes = 0;
        for (const auto& k : m_fake->Keys()) bytes += m_fake->ObjectBytes(k);
        o.pushKV("stored_bytes", bytes);
        o.pushKV("object_count", static_cast<uint64_t>(m_fake->ObjectCount()));
    } else {
        o.pushKV("get_count", 0);
        o.pushKV("put_count", 0);
        o.pushKV("head_count", 0);
        o.pushKV("range_count", 0);
        o.pushKV("multipart_count", 0);
        o.pushKV("presign_count", 0);
        o.pushKV("stored_bytes", 0);
        o.pushKV("object_count", 0);
    }
    return o;
}

UniValue S3Client::ConfigJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("endpoint", m_cfg.endpoint);
    o.pushKV("region", m_cfg.region);
    o.pushKV("bucket", m_cfg.bucket);
    o.pushKV("prefix", m_cfg.prefix);
    o.pushKV("credential_ref_kind", m_cfg.creds.kind == CredentialRefKind::ENV ? "env" : "path");
    o.pushKV("credential_configured", m_ready);
    o.pushKV("fake", m_fake != nullptr);
    o.pushKV("https_enabled", S3HttpsTransportAvailable());
    o.pushKV("write_creds_distinct", m_cfg.write_creds.has_value());
    return o;
}

size_t S3Client::LastPutMaxBufferBytes() const
{
    return m_last_put_max_buffer;
}

} // namespace modelnet
