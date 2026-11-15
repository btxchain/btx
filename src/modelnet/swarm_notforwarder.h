// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFORWARDER_H
#define BTX_MODELNET_SWARM_NOTFORWARDER_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one invoice. want_charge asks this note to charge
 * a computed forwarder fee.
 *
 * A computed forwarder fee is not charged by this note. charged stays
 * false and fee_atoms stays 0 on every path.
 */
struct SwarmNotForwarder {
    std::string invoice_id;
    bool want_charge{false};
};

/**
 * Outcome of noting a forwarder charge. charged stays false and
 * fee_atoms stays 0: a computed forwarder fee is not charged by this note.
 */
struct SwarmNotForwarderResult {
    std::string code;
    bool charged{false};
    int64_t fee_atoms{0};
};

/**
 * Note a forwarder charge without charging a computed forwarder fee.
 * Order, first match wins: an empty invoice_id is INVOICE. want_charge
 * is NOT_CHARGED. Otherwise the note is NOTED and err is clear.
 * charged stays false and fee_atoms stays 0 on every path.
 */
SwarmNotForwarderResult SwarmNoteNotForwarder(const SwarmNotForwarder& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFORWARDER_H
