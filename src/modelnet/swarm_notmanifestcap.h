// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMANIFESTCAP_H
#define BTX_MODELNET_SWARM_NOTMANIFESTCAP_H

#include <string>

namespace modelnet {

/**
 * A local note about one flat manifest. want_store asks this note to store
 * the manifest.
 *
 * The flat manifest cap is 16384 bytes and this note stores nothing.
 * stored and bytes_moved stay false on every path.
 */
struct SwarmNotManifestCap {
    std::string manifest_id;
    int size_bytes{0};
    bool want_store{false};
};

/**
 * Outcome of noting a flat manifest. stored and bytes_moved stay false on
 * every path: this note stores nothing.
 */
struct SwarmNotManifestCapResult {
    std::string code;
    bool stored{false};
    bool bytes_moved{false};
};

/**
 * Note a flat manifest without storing it. Order, first match wins: an
 * empty manifest_id is MANIFEST. size_bytes that is not exactly 16384 is
 * CAPPED even when want_store is false. want_store is CAPPED. Otherwise
 * the note is NOTED and err is cleared. stored and bytes_moved stay false
 * on every path. The flat manifest cap is 16384 bytes and this note stores
 * nothing.
 */
SwarmNotManifestCapResult SwarmNoteNotManifestCap(const SwarmNotManifestCap& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMANIFESTCAP_H
