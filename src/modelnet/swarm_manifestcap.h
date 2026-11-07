// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MANIFESTCAP_H
#define BTX_MODELNET_SWARM_MANIFESTCAP_H

#include <cstdint>
#include <string>

namespace modelnet {

/** A flat manifest is capped at 16384 pieces. */
static constexpr int64_t SWARM_MANIFEST_COUNT_CAP = 16384;

/**
 * A local note about one flat manifest. manifest_id names the manifest.
 * piece_count is the claimed piece count. want_accept asks this note to
 * accept the manifest.
 *
 * This note does not accept a manifest and does not store one. accepted
 * stays false on every path. No hostnames or IPs are used.
 */
struct SwarmManifestCap {
    std::string manifest_id;
    int64_t piece_count{0};
    bool want_accept{false};
};

/**
 * Outcome of noting a flat manifest. accepted stays false: this note
 * does not accept a manifest.
 */
struct SwarmManifestCapResult {
    bool accepted{false};
    std::string code;
};

/**
 * Note a flat manifest without accepting or storing it.
 * Order, first match wins:
 * an empty manifest_id or piece_count < 0 is MANIFEST.
 * piece_count above 16384 is MANIFEST_CAP, including when want_accept
 * is true.
 * want_accept is HELD and err is cleared. This note does not accept a
 * manifest.
 * Otherwise the note is NOTED and err is cleared. piece_count == 16384
 * with want_accept false is NOTED.
 * accepted stays false. Nothing is stored.
 */
SwarmManifestCapResult SwarmNoteManifestCap(const SwarmManifestCap& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MANIFESTCAP_H
