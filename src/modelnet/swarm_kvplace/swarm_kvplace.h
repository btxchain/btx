// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVPLACE_H
#define BITCOIN_MODELNET_SWARM_KVPLACE_H

#include <modelnet/swarm_kvplace/offer.h>
#include <modelnet/swarm_kvplace/share.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process KV placement plane.
 *
 * This plane decides where a KV page would be served. It does not move
 * bytes, open a socket, or start an engine. bytes_moved() stays 0.
 * launched() stays false. gpu() stays false. measured_benchmark() stays
 * false. No method sets bytes_moved() above 0. A transfer is not marked
 * as a measured benchmark.
 *
 * Offer stores a fingerprint. An empty fingerprint is FINGERPRINT.
 * "4bit" is family-only: in_family true, in_kv false, in_cohort false.
 * "full" with a non-empty checkpoint and a non-empty recipe is in_family,
 * in_kv, and in_cohort. Any other quantization profile is QUANTIZATION
 * and stores nothing. A second offer of a stored fingerprint is REPLAY
 * and keeps the first.
 *
 * Prefix length below 1 is PREFIX. A fingerprint that is not a stored
 * offer is PREFIX_MISMATCH and is not ENGINE_ABSENT. A non-empty parent
 * with parent_known false is CAUSAL_GAP. Otherwise the prefix is stored.
 *
 * Choose costs are int64. A negative recompute, idle, route, transfer,
 * missing_ppm, memory_pressure, or copies is PRESSURE and stores nothing.
 * Each option is base + missing_ppm/1000 + memory_pressure + copies.
 * Continuation subtracts from the idle cost only, and that cost is floored
 * at 0. The minimum wins. Ties prefer recompute, then idle, then route,
 * then transfer. The stored name is "recompute", "idle", "route", or
 * "transfer". Transfer without an engine returns false with ENGINE_ABSENT.
 * Transfer with an engine returns true with err LOCAL. Other winners
 * return true and clear err. bytes_moved() stays 0 either way.
 *
 * Share of different fingerprints, or of a fingerprint that is not in KV,
 * is NOT_COMPAT and does not share. The same fingerprint in KV returns true.
 *
 * Prefetch of an unknown fingerprint, or one not in KV, is NOT_COMPAT.
 * Prefetch of a KV fingerprint returns false with ENGINE_ABSENT.
 * Prefetch does not report a never-offered fingerprint as ENGINE_ABSENT.
 */
class SwarmKvPlace {
public:
    bool Offer(const std::string& fingerprint, const std::string& quantization, const std::string& checkpoint,
               const std::string& recipe, std::string& err);
    bool Prefix(const std::string& fingerprint, std::int64_t length, const std::string& parent, bool parent_known,
                std::string& err);
    bool Choose(std::int64_t recompute, std::int64_t idle, std::int64_t route, std::int64_t transfer,
                std::int64_t missing_ppm, std::int64_t memory_pressure, std::int64_t copies, std::int64_t continuation,
                bool engine_present, std::string& err);
    bool Share(const std::string& left_fingerprint, const std::string& right_fingerprint, std::string& err);
    bool Prefetch(const std::string& fingerprint, std::string& err);

    bool in_family(const std::string& fingerprint) const;
    bool in_kv(const std::string& fingerprint) const;
    bool in_cohort(const std::string& fingerprint) const;
    const std::string& winner() const;
    std::int64_t bytes_moved() const;
    bool launched() const;
    bool gpu() const;
    bool measured_benchmark() const;

private:
    SwarmKvPlaceBook m_book;
    SwarmKvPlaceShares m_shares;
    std::string m_winner;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVPLACE_H
