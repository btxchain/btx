// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/source_local.h>

#include <util/strencodings.h>

#include <arpa/inet.h>
#include <cctype>
#include <cstring>
#include <fstream>
#include <netinet/in.h>
#include <sys/socket.h>

namespace modelnet {
namespace {

std::string ExtractLocatorHost(const std::string& lower)
{
    std::string rest = lower;
    const auto scheme = rest.find("://");
    if (scheme != std::string::npos) rest = rest.substr(scheme + 3);
    const auto slash = rest.find('/');
    if (slash != std::string::npos) rest = rest.substr(0, slash);
    const auto at = rest.rfind('@');
    if (at != std::string::npos) rest = rest.substr(at + 1);
    if (!rest.empty() && rest.front() == '[') {
        const auto rb = rest.find(']');
        if (rb == std::string::npos) return rest;
        return rest.substr(1, rb - 1);
    }
    const auto colon = rest.find(':');
    if (colon != std::string::npos) rest = rest.substr(0, colon);
    return rest;
}

bool HostIsRfc1918OrLinkLocalOrMetadata(const std::string& host)
{
    if (host.empty()) return true;
    if (host == "localhost" || host == "metadata" || host == "metadata.google.internal") return true;
    if (host == "127.0.0.1" || host == "0.0.0.0" || host == "::1") return true;
    if (host.rfind("127.", 0) == 0) return true;
    if (host.rfind("10.", 0) == 0) return true;
    if (host.rfind("192.168.", 0) == 0) return true;
    if (host.rfind("169.254.", 0) == 0) return true;
    if (host.rfind("fe80:", 0) == 0) return true;
    if (host.rfind("::ffff:127.", 0) == 0 || host.rfind("::ffff:10.", 0) == 0 ||
        host.rfind("::ffff:192.168.", 0) == 0 || host.rfind("::ffff:169.254.", 0) == 0) {
        return true;
    }
    if (host.rfind("172.", 0) == 0) {
        size_t i = 4;
        int oct = 0;
        bool any = false;
        while (i < host.size() && std::isdigit(static_cast<unsigned char>(host[i]))) {
            oct = oct * 10 + (host[i] - '0');
            if (oct > 255) return false;
            ++i;
            any = true;
        }
        if (!any) return false;
        if (i < host.size() && host[i] != '.') return false;
        return oct >= 16 && oct <= 31;
    }
    return false;
}

} // namespace

LocalFileByteSource::LocalFileByteSource(fs::path path) : m_path(std::move(path)) {}

bool LocalFileByteSource::Pin(std::string& err)
{
    if (!fs::exists(m_path) || !fs::is_regular_file(m_path)) {
        err = "local source missing";
        return false;
    }
    m_size = fs::file_size(m_path);
    m_pinned = true;
    return true;
}

bool LocalFileByteSource::Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
                               std::string& err)
{
    out.clear();
    if (!m_pinned && !Pin(err)) return false;
    if (extent.length > budget_bytes) {
        err = "credit exhausted";
        return false;
    }
    if (extent.offset > m_size || extent.offset + extent.length > m_size) {
        err = "extent";
        return false;
    }
    std::ifstream in(m_path, std::ios::binary);
    if (!in) {
        err = "open";
        return false;
    }
    in.seekg(static_cast<std::streamoff>(extent.offset));
    out.resize(extent.length);
    in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(extent.length));
    if (static_cast<uint64_t>(in.gcount()) != extent.length) {
        err = "short read";
        return false;
    }
    m_piece_origins.push_back("local");
    return true;
}

std::string LocalFileByteSource::Locator() const
{
    return fs::PathToString(m_path);
}

bool HuggingFaceLocatorAllowed(const std::string& locator, std::string& err)
{
    std::string lower = locator;
    for (char& c : lower) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    if (lower.find("file:") != std::string::npos || lower.find("unix:") != std::string::npos ||
        lower.find("gopher:") != std::string::npos) {
        err = "scheme";
        return false;
    }
    const std::string host = ExtractLocatorHost(lower);
    if (HostIsRfc1918OrLinkLocalOrMetadata(host)) {
        err = "ssrf";
        return false;
    }
    if (lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("hf://") ||
        lower.find("huggingface.co/") != std::string::npos) {
        return true;
    }
    err = "locator";
    return false;
}

bool AddressIsGlobalUnicast(const sockaddr* sa, socklen_t len)
{
    if (!sa) return false;
    if (sa->sa_family == AF_INET) {
        if (len < static_cast<socklen_t>(sizeof(sockaddr_in))) return false;
        const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
        const uint32_t ip = ntohl(in->sin_addr.s_addr);
        const uint8_t a = static_cast<uint8_t>((ip >> 24) & 0xff);
        const uint8_t b = static_cast<uint8_t>((ip >> 16) & 0xff);
        if (a == 0 || a == 127 || a == 10) return false;
        if (a == 169 && b == 254) return false;
        if (a == 192 && b == 168) return false;
        if (a == 172 && b >= 16 && b <= 31) return false;
        if (a == 100 && b >= 64 && b <= 127) return false;
        if (a >= 224) return false;
        return true;
    }
    if (sa->sa_family == AF_INET6) {
        if (len < static_cast<socklen_t>(sizeof(sockaddr_in6))) return false;
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
        if (IN6_IS_ADDR_UNSPECIFIED(&in6->sin6_addr) || IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr) ||
            IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr) || IN6_IS_ADDR_SITELOCAL(&in6->sin6_addr) ||
            IN6_IS_ADDR_MULTICAST(&in6->sin6_addr)) {
            return false;
        }
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            sockaddr_in v4{};
            v4.sin_family = AF_INET;
            std::memcpy(&v4.sin_addr, in6->sin6_addr.s6_addr + 12, 4);
            return AddressIsGlobalUnicast(reinterpret_cast<const sockaddr*>(&v4), sizeof(v4));
        }
        if ((in6->sin6_addr.s6_addr[0] & 0xfe) == 0xfc) return false;
        return true;
    }
    return false;
}

} // namespace modelnet
