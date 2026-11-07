// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_codec.h>

#include <crypto/sha384.h>
#include <util/strencodings.h>

namespace modelnet {

std::string SwarmCanonical(const std::map<std::string, std::string>& fields)
{
    std::string out = "{";
    bool first = true;
    for (const auto& [key, value] : fields) {
        for (unsigned char c : key) {
            if (c < 0x20 || c == '"' || c == '\\') return {};
        }
        for (unsigned char c : value) {
            if (c < 0x20 || c == '"' || c == '\\') return {};
        }
        if (!first) out += ',';
        first = false;
        out += '"';
        out += key;
        out += "\":\"";
        out += value;
        out += '"';
    }
    out += '}';
    return out;
}

std::string SwarmDigest(std::string_view domain, std::string_view canonical)
{
    if (domain.empty() || canonical.empty()) return {};
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(domain.data()), domain.size());
    const unsigned char sep = 0;
    hasher.Write(&sep, 1);
    hasher.Write(reinterpret_cast<const unsigned char*>(canonical.data()), canonical.size());
    unsigned char hash[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(hash);
    return HexStr(Span<const unsigned char>(hash, CSHA384::OUTPUT_SIZE));
}

bool SwarmFixedId(std::string_view id)
{
    if (id.size() != 96) return false;
    for (unsigned char c : id) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

} // namespace modelnet
