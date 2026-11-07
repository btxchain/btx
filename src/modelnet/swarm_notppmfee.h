// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPPMFEE_H
#define BTX_MODELNET_SWARM_NOTPPMFEE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one invoice. want_charge asks this note to charge
 * the forwarder formula base + (amount * ppm + 999999) / 1000000.
 *
 * That formula is not charged by this note. charged stays false and
 * fee_atoms stays 0 on every path.
 */
struct SwarmNotPpmFee {
    std::string invoice_id;
    int64_t base{0};
    int64_t amount{0};
    int64_t ppm{0};
    bool want_charge{false};
};

/**
 * Outcome of noting a ppm charge. charged stays false and fee_atoms stays
 * 0: the forwarder formula is not charged by this note.
 */
struct SwarmNotPpmFeeResult {
    std::string code;
    bool charged{false};
    int64_t fee_atoms{0};
};

/**
 * Note a ppm charge without charging the forwarder formula.
 * Order, first match wins: an empty invoice_id is INVOICE. want_charge
 * is NOT_CHARGED. Otherwise the note is NOTED and err is clear.
 * charged stays false and fee_atoms stays 0 on every path. The forwarder
 * formula base + (amount * ppm + 999999) / 1000000 is not charged by
 * this note.
 */
SwarmNotPpmFeeResult SwarmNoteNotPpmFee(const SwarmNotPpmFee& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPPMFEE_H
