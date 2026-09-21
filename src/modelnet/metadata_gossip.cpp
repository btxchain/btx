// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/metadata_gossip.h>

#include <crypto/sha384.h>

#include <algorithm>

namespace modelnet {

bool GossipMessageAllowed(const GossipMessage& msg, std::string& err)
{
    if (msg.secret_bearing) {
        err = "secret-bearing gossip forbidden";
        return false;
    }
    // Must stay equal to RECONCILE_WANT_MAX (index_reconcile.h), which bounds
    // the producer side. It is a literal here only to keep this file below
    // index_reconcile in the include order. Raising one without the other
    // makes IndexReconciler emit want lists its own AdmitInbound rejects.
    if (msg.want_ids.size() > 256) {
        err = "want cap";
        return false;
    }
    return true;
}

std::string CatalogDigestHex(const std::vector<std::string>& sorted_ids)
{
    CSHA384 hasher;
    for (const auto& id : sorted_ids) {
        hasher.Write(reinterpret_cast<const unsigned char*>(id.data()), id.size());
        hasher.Write(reinterpret_cast<const unsigned char*>("\n"), 1);
    }
    unsigned char d[48];
    hasher.Finalize(d);
    static const char* hex = "0123456789abcdef";
    std::string out(96, '0');
    for (int i = 0; i < 48; ++i) {
        out[2 * i] = hex[d[i] >> 4];
        out[2 * i + 1] = hex[d[i] & 0xf];
    }
    return out;
}

QuerySummary SummarizeQueryHits(const std::vector<std::string>& ids, size_t max_sample)
{
    QuerySummary s;
    s.hit_count = static_cast<uint32_t>(ids.size());
    const size_t n = std::min(max_sample, ids.size());
    s.sample_ids.assign(ids.begin(), ids.begin() + n);
    s.truncated = ids.size() > n ? static_cast<uint32_t>(ids.size() - n) : 0;
    return s;
}

} // namespace modelnet
