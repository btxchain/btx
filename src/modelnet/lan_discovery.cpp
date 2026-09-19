// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lan_discovery.h>

#include <cctype>

namespace modelnet {

namespace {

std::string Lower(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

bool StartsWith(const std::string& s, const char* p)
{
    const size_t n = std::char_traits<char>::length(p);
    return s.size() >= n && s.compare(0, n, p) == 0;
}

} // namespace

bool EndpointLooksLan(const std::string& endpoint)
{
    const std::string e = Lower(endpoint);
    if (e.find(".local") != std::string::npos) return true;
    if (e.find("fe80:") != std::string::npos) return true;
    if (StartsWith(e, "10.")) return true;
    if (StartsWith(e, "192.168.")) return true;
    if (StartsWith(e, "169.254.")) return true;
    if (StartsWith(e, "127.")) return true;
    if (StartsWith(e, "[::1]")) return true;
    if (StartsWith(e, "172.")) {
        const auto second = e.find('.', 4);
        if (second == std::string::npos) return false;
        int oct = 0;
        for (size_t i = 4; i < second; ++i) {
            if (!std::isdigit(static_cast<unsigned char>(e[i]))) return false;
            oct = oct * 10 + (e[i] - '0');
        }
        return oct >= 16 && oct <= 31;
    }
    return false;
}

bool PreferLanPeer(const std::string& candidate, const std::string& other)
{
    const bool a = EndpointLooksLan(candidate);
    const bool b = EndpointLooksLan(other);
    return a && !b;
}

bool DelegatedRoutingMutatesConsensus()
{
    return false;
}

bool LanDiscoveryRequiresPublicAddress()
{
    return false;
}

} // namespace modelnet
