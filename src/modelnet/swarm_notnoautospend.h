// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOAUTOSPEND_H
#define BTX_MODELNET_SWARM_NOTNOAUTOSPEND_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one mandate. want_arm asks this note to arm.
 *
 * automatic_spend_atoms stays zero until an operator wallet signs a
 * bounded mandate. This note arms nothing. armed stays false and atoms
 * stays 0 on every path.
 */
struct SwarmNotNoAutoSpend {
    std::string mandate_id;
    bool want_arm{false};
};

/**
 * Outcome of noting an automatic spend. armed stays false and atoms
 * stays 0 on every path. automatic_spend_atoms stays zero until an
 * operator wallet signs a bounded mandate. This note arms nothing.
 */
struct SwarmNotNoAutoSpendResult {
    std::string code;
    bool armed{false};
    int64_t atoms{0};
};

/**
 * Note an automatic spend without arming. Order, first match wins: an
 * empty mandate_id is MANDATE. want_arm is ZERO. Otherwise the note is
 * NOTED and err is cleared. armed stays false and atoms stays 0 on
 * every path. automatic_spend_atoms stays zero until an operator wallet
 * signs a bounded mandate. This note arms nothing.
 */
SwarmNotNoAutoSpendResult SwarmNoteNotNoAutoSpend(const SwarmNotNoAutoSpend& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOAUTOSPEND_H
