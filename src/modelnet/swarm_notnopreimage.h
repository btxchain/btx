// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPREIMAGE_H
#define BTX_MODELNET_SWARM_NOTNOPREIMAGE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one preimage. length is the preimage length in
 * bytes. want_claim asks this note to claim it.
 *
 * A preimage of the wrong length claims nothing. claimed stays false
 * and atoms stays 0 on every path.
 */
struct SwarmNotNoPreimage {
    std::string preimage_id;
    int64_t length{0};
    bool want_claim{false};
};

/**
 * Outcome of noting a preimage. claimed stays false and atoms stays 0
 * on every path. A preimage of the wrong length claims nothing.
 */
struct SwarmNotNoPreimageResult {
    std::string code;
    bool claimed{false};
    int64_t atoms{0};
};

/**
 * Note a preimage without claiming it. Order, first match wins: an
 * empty preimage_id is PREIMAGE. length that is not exactly 32 is
 * REFUSED even when want_claim is false. want_claim is REFUSED.
 * Otherwise the note is NOTED and err is cleared. claimed stays false
 * and atoms stays 0 on every path. A preimage of the wrong length
 * claims nothing.
 */
SwarmNotNoPreimageResult SwarmNoteNotNoPreimage(const SwarmNotNoPreimage& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPREIMAGE_H
