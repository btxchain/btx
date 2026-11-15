// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOIMMATURE_H
#define BTX_MODELNET_SWARM_NOTNOIMMATURE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one refund. immature says the refund is immature.
 * want_pay asks this note to pay.
 *
 * An immature refund pays nothing.
 * paid stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoImmature {
    std::string refund_id;
    bool immature{false};
    bool want_pay{false};
};

/**
 * Outcome of noting a refund. paid stays false and atoms stays 0 on
 * every path: an immature refund pays nothing.
 */
struct SwarmNotNoImmatureResult {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
};

/**
 * Note a refund without paying it.
 * Order, first match wins: an empty refund_id is REFUND.
 * immature true is NOT_PAID even when want_pay is false.
 * want_pay is HELD. Otherwise the note is NOTED and err is cleared.
 * paid stays false and atoms stays 0 on every path. An immature
 * refund pays nothing.
 */
SwarmNotNoImmatureResult SwarmNoteNotNoImmature(const SwarmNotNoImmature& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOIMMATURE_H
