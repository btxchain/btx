// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/direct_seed.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <mutex>

namespace modelnet {
namespace {

std::string Lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

bool HostFromUrl(const std::string& url, std::string& scheme, std::string& host, std::string& err)
{
    const auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos || scheme_end == 0) {
        err = "url missing scheme";
        return false;
    }
    scheme = Lower(url.substr(0, scheme_end));
    size_t host_begin = scheme_end + 3;
    size_t host_end = url.find_first_of("/?#", host_begin);
    if (host_end == std::string::npos) host_end = url.size();
    std::string auth = url.substr(host_begin, host_end - host_begin);
    const auto at = auth.rfind('@');
    if (at != std::string::npos) auth = auth.substr(at + 1);
    const auto colon = auth.rfind(':');
    const auto bracket = auth.find(']');
    if (!auth.empty() && auth.front() == '[') {
        if (bracket == std::string::npos) {
            err = "bad ipv6 host";
            return false;
        }
        host = Lower(auth.substr(1, bracket - 1));
    } else if (colon != std::string::npos) {
        host = Lower(auth.substr(0, colon));
    } else {
        host = Lower(auth);
    }
    if (host.empty()) {
        err = "url missing host";
        return false;
    }
    return true;
}

} // namespace

bool LooksLikeMetadataServiceHost(const std::string& host)
{
    const std::string h = Lower(host);
    if (h == "169.254.169.254" || h == "fd00:ec2::254") return true;
    if (h == "metadata.google.internal") return true;
    if (h == "metadata" || h == "metadata.google.internal.") return true;
    if (h == "localhost" || h == "127.0.0.1" || h == "::1") return true;
    return false;
}

bool DirectSeedUrlAllowed(const std::string& url, const DirectSeedPolicy& pol, std::string& err)
{
    if (!pol.enabled) {
        err = "direct seed disabled";
        return false;
    }
    std::string scheme, host;
    if (!HostFromUrl(url, scheme, host, err)) return false;
    if (scheme != "https" && scheme != "http") {
        err = "direct seed scheme not allowed";
        return false;
    }
    if (scheme == "http" && host != "127.0.0.1" && host != "localhost") {
        err = "direct seed http only allowed for local test origin";
        return false;
    }
    if (LooksLikeMetadataServiceHost(host)) {
        err = "direct seed host blocked";
        return false;
    }
    if (url.find("file:") != std::string::npos || url.find("unix:") != std::string::npos ||
        url.find("gopher:") != std::string::npos) {
        err = "direct seed scheme not allowed";
        return false;
    }
    if (!pol.allowed_https_host.empty() && host != Lower(pol.allowed_https_host)) {
        err = "direct seed host not in operator allowlist";
        return false;
    }
    return true;
}

std::string RedactPresignedUrl(const std::string& url)
{
    const auto q = url.find('?');
    if (q == std::string::npos) return url;
    return url.substr(0, q) + "?[redacted]";
}

bool DirectSeedExpired(int64_t now_ms, const DirectSeedOffer& offer)
{
    return now_ms >= offer.expires_at_ms;
}

UniValue DirectSeedOfferPublicJson(const DirectSeedOffer& o)
{
    UniValue v(UniValue::VOBJ);
    v.pushKV("capability_id", o.capability_id);
    v.pushKV("object_key", o.object_key);
    v.pushKV("expires_at_ms", o.expires_at_ms);
    v.pushKV("size", static_cast<int64_t>(o.size));
    v.pushKV("resume_offset", static_cast<int64_t>(o.resume_offset));
    v.pushKV("full_file", o.full_file);
    v.pushKV("method", "GET");
    v.pushKV("presigned_get", RedactPresignedUrl(o.presigned_get));
    return v;
}

std::string DirectSeedNetgroup(const std::string& peer)
{
    std::string host = peer;
    if (!host.empty() && host.front() == '[') {
        const auto rb = host.find(']');
        if (rb != std::string::npos) host = host.substr(1, rb - 1);
    } else {
        const auto colon = host.rfind(':');
        if (colon != std::string::npos && host.find(':') == colon) host = host.substr(0, colon);
    }
    int a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(host.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        return std::to_string(a) + "." + std::to_string(b) + "." + std::to_string(c) + ".0";
    }
    return host.empty() ? "unknown" : host;
}

bool DirectSeedAllowIssue(DirectSeedAdmissionState& st, const DirectSeedLimits& lim, const std::string& peer,
                          const std::string& netgroup, int64_t now_ms, std::string& err)
{
    if (now_ms < 0) now_ms = 0;
    const int64_t rate_window = 60 * 1000;
    const int64_t ttl = lim.ttl_ms > 0 ? lim.ttl_ms : rate_window;
    std::lock_guard<std::mutex> lock(st.mu);
    st.issued.erase(std::remove_if(st.issued.begin(), st.issued.end(),
                                     [&](const DirectSeedIssue& e) {
                                         return now_ms - e.ms > std::max(rate_window, ttl);
                                     }),
                    st.issued.end());
    int concurrent = 0;
    int peer_n = 0;
    int ng_n = 0;
    for (const auto& e : st.issued) {
        if (now_ms - e.ms <= ttl) ++concurrent;
        if (now_ms - e.ms <= rate_window && e.peer == peer) ++peer_n;
        if (now_ms - e.ms <= rate_window && e.netgroup == netgroup) ++ng_n;
    }
    if (lim.max_concurrent > 0 && concurrent >= lim.max_concurrent) {
        err = "direct seed concurrent limit";
        return false;
    }
    if (lim.max_per_peer_per_minute > 0 && peer_n >= lim.max_per_peer_per_minute) {
        err = "direct seed peer rate limit";
        return false;
    }
    if (lim.max_per_netgroup_per_minute > 0 && ng_n >= lim.max_per_netgroup_per_minute) {
        err = "direct seed netgroup rate limit";
        return false;
    }
    st.issued.push_back(DirectSeedIssue{now_ms, peer, netgroup});
    return true;
}

} // namespace modelnet
