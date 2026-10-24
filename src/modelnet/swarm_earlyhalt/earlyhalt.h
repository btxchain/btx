// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_H

#include <modelnet/swarm_earlyhalt/mark.h>
#include <modelnet/swarm_earlyhalt/realm.h>
#include <modelnet/swarm_earlyhalt/remain.h>
#include <modelnet/swarm_earlyhalt/score.h>
#include <modelnet/swarm_earlyhalt/seat.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Early-stop plane for one run.
 *
 * A lower score stops the run. The stopped row stays. This plane does
 * not graduate and does not mine.
 *
 * Open stores a budget of at least 1 as the remainder. budget < 1 is
 * BUDGET and stores nothing. A second Open is REPLAY and leaves the
 * first budget.
 *
 * Step before Open is STEP and stores nothing. Each successful step
 * decrements the remainder by 1 and stores the score. A score lower
 * than the previous stored score sets early_stop and the remainder to
 * 0. That step still returns true. Later steps are STOPPED and store
 * nothing.
 *
 * Promote of an early-stopped run is STOPPED and does not remove the
 * row. Promote before any step is STEP. Promote of a non-decreasing
 * run returns true even when the remainder is 0. graduated() stays
 * false.
 *
 * PromoteRealm returns REALM. bytes_moved() is 0. gpu() is false.
 */
class SwarmEarlyHalt {
public:
    bool Open(int64_t budget, std::string& err);
    bool Step(int64_t score, std::string& err);
    bool Promote(std::string& err) const;
    bool PromoteRealm(std::string& err) const;

    bool opened() const { return m_seat.opened(); }
    int64_t budget() const { return m_seat.budget(); }
    int64_t remaining() const { return m_remain.left(); }
    bool has_score() const { return m_score.held(); }
    int64_t score() const { return m_score.value(); }
    bool early_stop() const { return m_mark.set(); }

    int64_t bytes_moved() const { return m_realm.bytes_moved(); }
    bool gpu() const { return m_realm.gpu(); }
    bool graduated() const { return m_realm.graduated(); }
    bool mined() const { return m_realm.mined(); }

private:
    SwarmEarlyHaltSeat m_seat;
    SwarmEarlyHaltRemain m_remain;
    SwarmEarlyHaltScore m_score;
    SwarmEarlyHaltMark m_mark;
    SwarmEarlyHaltRealm m_realm;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_H
