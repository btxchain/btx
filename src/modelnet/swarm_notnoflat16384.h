// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFLAT16384_H
#define BTX_MODELNET_SWARM_NOTNOFLAT16384_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one flat manifest. want_raise asks this note to
 * raise the manifest.
 *
 * The flat manifest cap stays 16384 bytes. raised stays false on every
 * path.
 */
struct SwarmNotNoFlat16384 {
    std::string manifest_id;
    bool want_raise{false};
};

/**
 * Outcome of noting a flat manifest. raised stays false and bytes stays
 * 16384 on every path.
 */
struct SwarmNotNoFlat16384Result {
    std::string code;
    bool raised{false};
    int64_t bytes{0};
};

/**
 * Note a flat manifest without raising it. Order, first match wins: an
 * empty manifest_id is MANIFEST. want_raise is HELD. Otherwise the note
 * is NOTED and err is cleared. raised stays false and bytes stays 16384
 * on every path. The flat manifest cap stays 16384 bytes.
 */
SwarmNotNoFlat16384Result SwarmNoteNotNoFlat16384(const SwarmNotNoFlat16384& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFLAT16384_H
