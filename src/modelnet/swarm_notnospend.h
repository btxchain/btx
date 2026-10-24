// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSPEND_H
#define BTX_MODELNET_SWARM_NOTNOSPEND_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one mandate. signed_by_wallet records whether a
 * wallet signed a bounded mandate. want_spend asks this note to spend.
 *
 * automatic_spend_atoms stays 0 until a wallet signs a bounded mandate,
 * and this note spends nothing. spent stays false and atoms stays 0 on
 * every path.
 */
struct SwarmNotNoSpend {
    std::string mandate_id;
    bool signed_by_wallet{false};
    bool want_spend{false};
};

/**
 * Outcome of noting a mandate. spent stays false and atoms stays 0 on
 * every path. automatic_spend_atoms stays 0 until a wallet signs a
 * bounded mandate, and this note spends nothing.
 */
struct SwarmNotNoSpendResult {
    std::string code;
    bool spent{false};
    int64_t atoms{0};
};

/**
 * Note a mandate without spending. Order, first match wins: an empty
 * mandate_id is MANDATE. signed_by_wallet false is UNSIGNED even when
 * want_spend is false. want_spend is HELD. Otherwise the note is NOTED
 * and err is cleared. spent stays false and atoms stays 0 on every
 * path. automatic_spend_atoms stays 0 until a wallet signs a bounded
 * mandate, and this note spends nothing.
 */
SwarmNotNoSpendResult SwarmNoteNotNoSpend(const SwarmNotNoSpend& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSPEND_H
