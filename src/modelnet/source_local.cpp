// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/source_local.h>

#include <util/strencodings.h>

#include <cctype>
#include <fstream>

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

} // namespace modelnet
