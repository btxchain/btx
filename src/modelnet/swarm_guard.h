// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_GUARD_H
#define BTX_MODELNET_SWARM_GUARD_H

#include <cstdint>
#include <set>
#include <string>

namespace modelnet {

/** A quarantined digest is not offered. An empty digest is QUARANTINE. */
bool SwarmOfferWork(const std::set<std::string>& quarantined, const std::string& digest, std::string& err);

struct SwarmRecompute {
    bool recompute{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * A fingerprint mismatch, a gap, an expiry, or a non-finite page is RECOMPUTE.
 * bytes_moved stays false. This function does not copy a tensor.
 */
SwarmRecompute SwarmRecomputeAfter(bool mismatch, bool gap, bool expired, bool nonfinite, std::string& err);

/**
 * Conventional attention bytes: 2 * layers * kv_heads * head_dim * prefix_tokens * bytes_per_element.
 * A non-positive factor or an overflow is KV_GEOMETRY.
 */
bool SwarmKvBytes(int64_t layers, int64_t kv_heads, int64_t head_dim, int64_t prefix_tokens, int64_t bytes_per_element,
                  int64_t& out, std::string& err);

/**
 * A cache does not replace replay, admission, work evidence, an execution grant,
 * or an independent evaluation. Any of those claims is CACHE_ASSURANCE.
 */
bool SwarmCacheStandsAlone(bool replaces_replay, bool replaces_admission, bool replaces_work_evidence,
                           bool replaces_execution_grant, bool replaces_independent_evaluation, std::string& err);

/** A peer path is not a storage key. '/', '\\', '..', and an empty string are PEER_PATH. */
bool SwarmAcceptStorageKey(const std::string& key, std::string& err);

/** A flat manifest above 16384 pieces is MANIFEST_CAP. A non-positive count is MANIFEST_CAP. */
bool SwarmManifestPieceCount(int64_t pieces, std::string& err);

/**
 * measured_benchmark is true only when the caller supplied a finite local measurement.
 * A missing or non-finite measurement leaves the flag false.
 */
bool SwarmRecordMeasurement(bool supplied, bool finite, bool& measured_benchmark, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_GUARD_H
