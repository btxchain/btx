// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT12_H
#define BTX_MODELNET_SWARM_FAULT12_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Live fault 12: evaluators submit conflicting reports.
 * Local note only. settled and broadcast stay false.
 * atoms_moved stays zero.
 */
struct SwarmFault12 {
    std::string report_id;
    bool conflict{false};
    bool distinct_evaluators{false};
    bool distinct_domains{false};
    bool want_settle{false};
};

/**
 * Outcome of a conflicting-evaluator note.
 * settled and broadcast stay false. atoms_moved stays zero.
 */
struct SwarmFault12Result {
    std::string code;
    bool settled{false};
    int64_t atoms_moved{0};
    bool broadcast{false};
};

/**
 * Note conflicting evaluator reports without settling or moving atoms.
 * Order, first match wins:
 * 1. An empty report_id is REPORT. settled stays false, atoms_moved
 *    stays zero, and err is REPORT.
 * 2. conflict, or not distinct_evaluators, or not distinct_domains,
 *    is QUORUM, even if want_settle. settled stays false, atoms_moved
 *    stays zero, and err is QUORUM.
 * 3. want_settle is HELD. settled stays false, atoms_moved stays zero,
 *    and err is cleared.
 * 4. Otherwise NOTED. settled stays false, atoms_moved stays zero,
 *    and err is cleared.
 * settled, atoms_moved, and broadcast stay false on every path.
 * This does not settle, move atoms, or broadcast.
 */
SwarmFault12Result SwarmRecoverFault12(const SwarmFault12& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT12_H
