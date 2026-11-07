// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG10_H
#define BTX_MODELNET_SWARM_FLAG10_H

#include <string>

namespace modelnet {

/**
 * Flagship stage 10 adopt: a subscribed second node verifies, stages,
 * and keeps rollback. node_id names that second node. descendant_id
 * names the descendant under note. previous_id is the rollback point
 * that stays. want_adopt asks to adopt. want_pass asks to treat the
 * note as passed.
 *
 * adopted, passed, and bytes_moved stay false on every path. No bytes
 * move. rollback_kept is true only after a previous id is present.
 */
struct SwarmFlag10 {
    std::string node_id;
    std::string descendant_id;
    std::string previous_id;
    bool want_adopt{false};
    bool want_pass{false};
};

/**
 * Outcome of noting flagship stage 10 adopt. adopted, passed, and
 * bytes_moved stay false. rollback_kept is true only when a previous
 * id was present and the note reached the keep-rollback paths.
 */
struct SwarmFlag10Result {
    std::string code;
    bool adopted{false};
    bool rollback_kept{false};
    bool passed{false};
    bool bytes_moved{false};
};

/**
 * Note flagship stage 10 adopt. A subscribed second node verifies and
 * stages, and the previous id stays. Adoption is not performed.
 * Order, first match wins:
 * 1. An empty node_id or descendant_id is NODE. Every result bool stays
 *    false and err is NODE.
 * 2. An empty previous_id is NO_ROLLBACK. adopted and rollback_kept stay
 *    false and err is NO_ROLLBACK.
 * 3. want_adopt is NOT_ADOPTED. adopted stays false, rollback_kept is
 *    true, and err is NOT_ADOPTED. The previous id stays.
 * 4. want_pass is UNQUALIFIED. adopted and passed stay false,
 *    rollback_kept is true, and err is UNQUALIFIED.
 * 5. Otherwise the note is NOTED. adopted and passed stay false,
 *    rollback_kept is true, and err is cleared.
 * adopted, passed, and bytes_moved stay false on every path.
 */
SwarmFlag10Result SwarmStageAdopt(const SwarmFlag10& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG10_H
