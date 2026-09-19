// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_METADATA_GOSSIP_H
#define BITCOIN_MODELNET_METADATA_GOSSIP_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

struct GossipDigest {
    std::string catalog_digest_hex;
    uint32_t entry_count{0};
};

struct GossipMessage {
    GossipDigest digest;
    std::vector<std::string> want_ids;
    bool secret_bearing{false};
};

bool GossipMessageAllowed(const GossipMessage& msg, std::string& err);
std::string CatalogDigestHex(const std::vector<std::string>& sorted_ids);

struct QuerySummary {
    uint32_t hit_count{0};
    uint32_t truncated{0};
    std::vector<std::string> sample_ids;
    uint64_t snapshot_generation{0};
    uint64_t tombstone_floor{0};
};

QuerySummary SummarizeQueryHits(const std::vector<std::string>& ids, size_t max_sample);

} // namespace modelnet

#endif // BITCOIN_MODELNET_METADATA_GOSSIP_H
