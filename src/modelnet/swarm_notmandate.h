// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMANDATE_H
#define BTX_MODELNET_SWARM_NOTMANDATE_H

#include <string>

namespace modelnet {

/**
 * A local note about one mandate. operator_signed records whether an
 * operator wallet signed a bounded mandate. want_spend asks this note
 * to spend.
 *
 * automatic_spend_atoms stays 0 until an operator wallet signs a bounded
 * mandate. This note does not spend or broadcast. spent and broadcast
 * stay false on every path.
 */
struct SwarmNotMandate {
    std::string mandate_id;
    bool operator_signed{false};
    bool want_spend{false};
};

/**
 * Outcome of noting a mandate. spent and broadcast stay false on every
 * path. automatic_spend_atoms stays 0 until an operator wallet signs a
 * bounded mandate. This note does not spend or broadcast.
 */
struct SwarmNotMandateResult {
    std::string code;
    bool spent{false};
    bool broadcast{false};
};

/**
 * Note a mandate without spending or broadcasting. Order, first match
 * wins: an empty mandate_id is MANDATE. operator_signed false is
 * UNSIGNED even when want_spend is false. want_spend is HELD. Otherwise
 * the note is NOTED and err is clear. spent and broadcast stay false on
 * every path. automatic_spend_atoms stays 0 until an operator wallet
 * signs a bounded mandate. This note does not spend or broadcast.
 */
SwarmNotMandateResult SwarmNoteNotMandate(const SwarmNotMandate& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMANDATE_H
