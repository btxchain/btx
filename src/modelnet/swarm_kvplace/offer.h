// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVPLACE_OFFER_H
#define BITCOIN_MODELNET_SWARM_KVPLACE_OFFER_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * One offered fingerprint and, once accepted, its prefix.
 * family is true for every stored offer. kv and cohort are true only for a
 * "full" profile that carried a non-empty checkpoint and recipe.
 */
struct SwarmKvPlaceRecord {
    std::string fingerprint;
    std::string quantization;
    std::string checkpoint;
    std::string recipe;
    bool family{false};
    bool kv{false};
    bool cohort{false};
    bool has_prefix{false};
    std::int64_t prefix_length{0};
    std::string parent;
    bool parent_known{false};
};

/**
 * Offer book keyed by fingerprint.
 * An empty fingerprint is FINGERPRINT.
 * A fingerprint already stored is REPLAY and the first record stays,
 * including when the new quantization would have been refused or would
 * have changed membership.
 * Any profile other than "4bit", or "full" with both checkpoint and recipe
 * non-empty, is QUANTIZATION and stores nothing.
 */
class SwarmKvPlaceBook {
public:
    bool Offer(const std::string& fingerprint, const std::string& quantization, const std::string& checkpoint,
               const std::string& recipe, std::string& err);

    bool Has(const std::string& fingerprint) const;
    bool in_family(const std::string& fingerprint) const;
    bool in_kv(const std::string& fingerprint) const;
    bool in_cohort(const std::string& fingerprint) const;

    const SwarmKvPlaceRecord* Find(const std::string& fingerprint) const;
    SwarmKvPlaceRecord* Find(const std::string& fingerprint);

private:
    std::map<std::string, SwarmKvPlaceRecord> m_records;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVPLACE_OFFER_H
