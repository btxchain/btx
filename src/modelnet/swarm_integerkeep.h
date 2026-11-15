// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_INTEGERKEEP_H
#define BTX_MODELNET_SWARM_INTEGERKEEP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * An integer-pair record. pair_id names the record. pairs is the count
 * the record was asked to keep. want_add asks this record to add a pair.
 *
 * INTEGER_LINEAR stays eight frozen pairs. A ninth pair is held.
 * added stays false and pairs stays 8 on every path.
 */
struct SwarmIntegerKeep {
    std::string pair_id;
    int64_t pairs{0};
    bool want_add{false};
};

/**
 * Outcome of keeping integer pairs. added stays false and pairs stays 8
 * on every path. INTEGER_LINEAR stays eight frozen pairs.
 */
struct SwarmIntegerKeepResult {
    std::string code;
    bool added{false};
    int64_t pairs{8};
};

/**
 * Keep integer pairs. Order, first match wins: an empty pair_id is PAIR.
 * pairs other than 8 is RANGE. want_add is HELD. Otherwise the note is
 * NOTED and err is cleared. added stays false and pairs stays 8 on every
 * path. INTEGER_LINEAR stays eight frozen pairs. A ninth pair is held.
 */
SwarmIntegerKeepResult SwarmKeepIntegerPairs(const SwarmIntegerKeep& pair, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_INTEGERKEEP_H
