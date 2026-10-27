// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_H

#include <modelnet/swarm_promotegate/active.h>
#include <modelnet/swarm_promotegate/candidate.h>
#include <modelnet/swarm_promotegate/flag.h>
#include <modelnet/swarm_promotegate/memory.h>
#include <modelnet/swarm_promotegate/realm.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Promotion-interrupt plane for one active id.
 *
 * The active id starts as "base". An interrupted promotion does not
 * change it. This plane does not mine or broadcast.
 *
 * Begin stores a non-empty candidate and does not change the active id.
 * An empty candidate is HEAD and stores nothing. A second Begin replaces
 * the staged candidate only. The interrupt flag is left as it was.
 * staged() returns that candidate, or empty when nothing is staged.
 *
 * Interrupt with no staged candidate is STEP and stores nothing. The
 * active id stays "base" when it was base. A staged candidate is marked
 * interrupted and the active id stays.
 *
 * Finish while interrupted is INTERRUPTED. The active id stays and the
 * staged id is not cleared. Finish with no staged candidate is STEP.
 * Finish with a staged candidate that was not interrupted adopts it,
 * remembers the previous active id, clears the staged slot, and clears
 * the interrupt flag.
 *
 * Resume does not adopt. After an interrupt it is INTERRUPTED. With no
 * interrupt mark it is STEP.
 *
 * Clear drops the staged candidate and the interrupt flag and leaves the
 * active id unchanged. A later Begin can stage a new candidate.
 *
 * Rollback after a successful Finish restores the previous id once.
 * A second rollback is ROLLBACK. Rollback does not mine.
 *
 * bytes_moved() is 0. mined() is false. graduated() stays false.
 * PromoteRealm returns REALM and does not change the active id.
 */
class SwarmPromoteGate {
public:
    bool Begin(const std::string& candidate, std::string& err);
    bool Interrupt(std::string& err);
    bool Finish(std::string& err);
    bool Resume(std::string& err) const;
    bool Clear(std::string& err);
    bool Rollback(std::string& err);
    bool PromoteRealm(std::string& err) const;

    const std::string& active() const { return m_active.id(); }
    const std::string& staged() const { return m_staged.id(); }
    const std::string& previous() const { return m_memory.previous(); }
    bool interrupted() const { return m_flag.marked(); }

    int64_t bytes_moved() const { return m_realm.bytes_moved(); }
    bool mined() const { return m_realm.mined(); }
    bool graduated() const { return m_realm.graduated(); }
    bool broadcast() const { return m_realm.broadcast(); }
    bool spent() const { return m_realm.spent(); }

private:
    SwarmPromoteActive m_active;
    SwarmPromoteCandidate m_staged;
    SwarmPromoteMemory m_memory;
    SwarmPromoteFlag m_flag;
    SwarmPromoteRealm m_realm;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_H
