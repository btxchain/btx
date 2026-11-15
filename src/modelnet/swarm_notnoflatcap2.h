// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFLATCAP2_H
#define BTX_MODELNET_SWARM_NOTNOFLATCAP2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one flat manifest. want_store asks this note to
 * store the manifest.
 *
 * A flat manifest stays capped at 16384 entries and this note stores
 * nothing. stored stays false on every path.
 */
struct SwarmNotNoFlatCap2 {
    std::string manifest_id;
    uint32_t entries{0};
    bool want_store{false};
};

/**
 * Outcome of noting a flat manifest. stored stays false on every path.
 * A flat manifest stays capped at 16384 entries and this note stores
 * nothing.
 */
struct SwarmNotNoFlatCap2Result {
    std::string code;
    bool stored{false};
};

/**
 * Note a flat manifest without storing it. Order, first match wins: an
 * empty manifest_id is MANIFEST. entries greater than 16384 is CAPPED
 * even when want_store is false. want_store is CAPPED. Otherwise the
 * note is NOTED and err is cleared. stored stays false on every path.
 * A flat manifest stays capped at 16384 entries and this note stores
 * nothing.
 */
SwarmNotNoFlatCap2Result SwarmNoteNotNoFlatCap2(const SwarmNotNoFlatCap2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFLATCAP2_H
