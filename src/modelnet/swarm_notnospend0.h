// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSPEND0_H
#define BTX_MODELNET_SWARM_NOTNOSPEND0_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one mandate. spend_atoms is the spend amount this
 * note would claim. want_spend asks this note to spend.
 *
 * automatic_spend_atoms stays 0 until a wallet signs a bounded mandate,
 * and this note spends nothing. spent stays false and atoms stays 0 on
 * every path.
 */
struct SwarmNotNoSpend0 {
    std::string mandate_id;
    int64_t spend_atoms{0};
    bool want_spend{false};
};

/**
 * Outcome of noting a mandate. spent stays false and atoms stays 0 on
 * every path. automatic_spend_atoms stays 0 until a wallet signs a
 * bounded mandate, and this note spends nothing.
 */
struct SwarmNotNoSpend0Result {
    std::string code;
    bool spent{false};
    int64_t atoms{0};
};

/**
 * Note a mandate without spending. Order, first match wins: an empty
 * mandate_id is MANDATE. spend_atoms not 0 is HELD even when want_spend
 * is false. want_spend is HELD. Otherwise the note is NOTED and err is
 * cleared. spent stays false and atoms stays 0 on every path.
 * automatic_spend_atoms stays 0 until a wallet signs a bounded mandate,
 * and this note spends nothing.
 */
SwarmNotNoSpend0Result SwarmNoteNotNoSpend0(const SwarmNotNoSpend0& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSPEND0_H
