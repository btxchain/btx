// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_H

#include <modelnet/swarm_canaryback/active.h>
#include <modelnet/swarm_canaryback/candidate.h>
#include <modelnet/swarm_canaryback/prior.h>
#include <modelnet/swarm_canaryback/quiet.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Canary-rollback plane.
 * The active id starts as "base". A regression after a successful
 * adopt restores the previous id once. This plane does not graduate
 * and does not mine.
 *
 * Stage stores a candidate and does not change the active id.
 * An empty id is ID and stores nothing.
 *
 * Adopt with nothing staged is STAGE. Otherwise Adopt sets the
 * active id to the staged id and remembers the previous id. The
 * staged id stays. A second Adopt without a new Stage is REPLAY
 * and leaves the active id.
 *
 * Regress after a successful Adopt restores the previous id and
 * clears the staged id. A second Regress, with no newer successful
 * Adopt, is ROLLBACK and leaves the active id. Regress before any
 * Adopt is STAGE and changes nothing.
 *
 * A newer successful Adopt remembers one new previous id and arms
 * one more restore. Regress does not walk further back than that.
 *
 * Graduate always returns REALM. graduated() stays false. The
 * active id is unchanged by Graduate.
 *
 * Mine returns HELD. mined() stays false. blocks() stays 0.
 * bytes_moved() stays 0. gpu() stays false.
 */
class SwarmCanaryBack {
public:
    bool Stage(const std::string& id, std::string& err);
    bool Adopt(std::string& err);
    bool Regress(std::string& err);
    bool Graduate(std::string& err) const;
    bool Mine(std::string& err) const;

    const std::string& active() const { return m_active.get(); }
    const std::string& staged() const { return m_candidate.id(); }
    bool graduated() const { return m_quiet.graduated(); }
    bool mined() const { return m_quiet.mined(); }
    int64_t blocks() const { return m_quiet.blocks(); }
    int64_t bytes_moved() const { return m_quiet.bytes_moved(); }
    bool gpu() const { return m_quiet.gpu(); }

private:
    SwarmCanaryBackActive m_active;
    SwarmCanaryBackCandidate m_candidate;
    SwarmCanaryBackPrior m_prior;
    SwarmCanaryBackQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_H
