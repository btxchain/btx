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
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>

namespace modelnet {
namespace {

std::mutex g_mu;
RegistryGetFn g_test_get;
std::map<std::string, std::vector<unsigned char>> g_url_bytes;
std::map<std::string, std::vector<unsigned char>> g_type_bytes;
std::set<std::string> g_type_error;

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
bool ExtentMatchesIdentity(const ReadExtent& extent, const std::vector<unsigned char>& got, uint64_t size_bytes,
                           const std::string& sha384_hex, const std::vector<std::string>& piece_hex, std::string& why)
{
    if (!piece_hex.empty() && extent.offset % PIECE_SIZE == 0) {
        const size_t idx = static_cast<size_t>(extent.offset / PIECE_SIZE);
        if (idx < piece_hex.size()) {
            const uint64_t expect_len =
                size_bytes > extent.offset ? std::min<uint64_t>(PIECE_SIZE, size_bytes - extent.offset) : extent.length;
            if (got.size() != expect_len) {
                why = "HASH_MISMATCH";
                return false;
            }
            const std::string leaf = ChunkLeaf(idx, Span<const unsigned char>{got.data(), got.size()}).Hex();
            if (leaf != piece_hex[idx]) {
                why = "HASH_MISMATCH";
                return false;
            }
            return true;
        }
    }
    if (!sha384_hex.empty() && size_bytes > 0 && extent.offset == 0 && extent.length == size_bytes &&
        got.size() == size_bytes) {
        if (Sha384Hex(got) != sha384_hex) {
            why = "HASH_MISMATCH";
            return false;
        }
    }
    return true;
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

bool HttpsGetRange(const std::string& url, uint64_t offset, uint64_t length, std::vector<unsigned char>& out,
                   std::string& err)
{
    out.clear();
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
    for (addrinfo* ai = raw; ai; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(raw);
    if (fd < 0) {
        err = "connect";
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

    std::string req = "GET " + u.path + " HTTP/1.1\r\nHost: " + u.host + "\r\nConnection: close\r\n";
    if (length > 0) {
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

    const auto hdr_end = raw_resp.find("\r\n\r\n");
    if (hdr_end == std::string::npos) {
        err = "http headers";
        return false;
    }
    const std::string headers = raw_resp.substr(0, hdr_end);
    int status = 0;
    {
        const auto sp = headers.find(' ');
        if (sp != std::string::npos) status = std::atoi(headers.c_str() + sp + 1);
    }
    if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308 ||
        headers.find("\nLocation:") != std::string::npos || headers.find("\nlocation:") != std::string::npos) {
        err = "redirects forbidden";
        return false;
    }
    if (status != 200 && status != 206) {
        err = "http status";
        return false;
    }
    const std::string body = raw_resp.substr(hdr_end + 4);
    out.assign(body.begin(), body.end());
    if (length > 0 && out.size() > length) out.resize(static_cast<size_t>(length));
    return true;
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
}

void RegistryByteSource::BindFileIdentity(uint64_t size_bytes, const std::vector<std::string>& piece_sha384_hex)
{
    m_size_bytes = size_bytes;
    m_piece_hex = piece_sha384_hex;
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
    if (!m_pinned && !Pin(err)) return false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (g_type_error.count(m_origin.type)) {
            err = "origin unavailable";
            return false;
        }
        auto it = g_type_bytes.find(m_origin.type);
        if (it != g_type_bytes.end()) {
            if (!CopyExtent(it->second, extent, budget_bytes, out, err)) return false;
            if (!ExtentMatchesIdentity(extent, out, m_size_bytes, m_sha384_hex, m_piece_hex, err)) {
                out.clear();
                return false;
            }
            return true;
        }
    }
    ResolvedRegistryUrl resolved;
    const std::string file = m_file.empty() ? "model.safetensors" : m_file;
    if (!ResolveRegistryFileUrl(m_origin.type, m_origin.locator, m_origin.snapshot_token, file, resolved, err)) {
        return false;
    }
    m_last_url = resolved.url;
    if (!HuggingFaceLocatorAllowed(resolved.url, err)) return false;
    std::vector<unsigned char> body;
    if (!FetchUrl(resolved.url, extent.offset, extent.length, body, m_live_wan, err)) return false;
    if (extent.length > budget_bytes) {
        err = "credit exhausted";
        return false;
    }
    out = std::move(body);
    if (!ExtentMatchesIdentity(extent, out, m_size_bytes, m_sha384_hex, m_piece_hex, err)) {
        out.clear();
        return false;
    }
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
}

void MultiOriginByteSource::BindFileIdentity(uint64_t size_bytes, const std::vector<std::string>& piece_sha384_hex)
{
    m_size_bytes = size_bytes;
    m_piece_hex = piece_sha384_hex;
    m_piece_origins.clear();
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
    std::string last = "origin unavailable";
    for (const auto& o : m_plan.origins) {
        std::unique_ptr<ByteSource> src;
        if (o.type == "local") {
            src = std::make_unique<LocalFileByteSource>(fs::PathFromString(o.locator));
        } else if (o.type == "s3") {
            src = std::make_unique<S3OriginByteSource>(o);
        } else if (o.type == "btx") {
            src = std::make_unique<BtxOriginByteSource>(o);
        } else if (o.type == "torrent" || o.type == "magnet") {
            last = "torrent origin uses TorrentByteSource";
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
            continue;
        }
        std::string why;
        if (!ExtentMatchesIdentity(extent, got, m_size_bytes, m_sha384_hex, m_piece_hex, why)) {
            m_conflicts.push_back(o.type + ":" + why);
            last = "ORIGIN_CONFLICT";
            continue;
        }
        m_last_origin = o.type;
        m_piece_origins.push_back(o.type);
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
