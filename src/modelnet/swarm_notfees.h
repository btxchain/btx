// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFEES_H
#define BTX_MODELNET_SWARM_NOTFEES_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one invoice. want_publish asks this note to publish
 * a measured fee.
 *
 * Fees are unmeasured. Nothing is published, settled, or broadcast.
 * published, settled, and broadcast stay false on every path. fee_atoms
 * and latency_us stay 0 on every path.
 */
struct SwarmNotFees {
    std::string invoice_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a fee request. published, settled, and broadcast stay
 * false on every path. fee_atoms and latency_us stay 0: fees are
 * unmeasured, and nothing is published, settled, or broadcast.
 */
struct SwarmNotFeesResult {
    std::string code;
    bool published{false};
    bool settled{false};
    bool broadcast{false};
    int64_t fee_atoms{0};
    int64_t latency_us{0};
};

/**
 * Note a fee request without measuring, publishing, settling, or
 * broadcasting.
 * Order, first match wins: an empty invoice_id is INVOICE. want_publish
 * is UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published, settled, and broadcast stay false on every path. fee_atoms
 * and latency_us stay 0 on every path.
 */
SwarmNotFeesResult SwarmNoteNotFees(const SwarmNotFees& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFEES_H
