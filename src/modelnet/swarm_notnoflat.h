// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFLAT_H
#define BTX_MODELNET_SWARM_NOTNOFLAT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one flat manifest. want_store asks this note to store
 * the manifest.
 *
 * A flat manifest other than 16384 bytes is not stored. stored and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoFlat {
    std::string manifest_id;
    int64_t size_bytes{0};
    bool want_store{false};
};

/**
 * Outcome of noting a flat manifest. stored and bytes_moved stay false on
 * every path. A flat manifest other than 16384 bytes is not stored.
 */
struct SwarmNotNoFlatResult {
    std::string code;
    bool stored{false};
    bool bytes_moved{false};
};

/**
 * Note a flat manifest without storing it. Order, first match wins: an
 * empty manifest_id is MANIFEST. size_bytes that is not exactly 16384 is
 * CAPPED even when want_store is false. want_store is CAPPED. Otherwise
 * the note is NOTED and err is cleared. stored and bytes_moved stay false
 * on every path. A flat manifest other than 16384 bytes is not stored.
 */
SwarmNotNoFlatResult SwarmNoteNotNoFlat(const SwarmNotNoFlat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFLAT_H
