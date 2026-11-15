// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STAGEHEAD_H
#define BITCOIN_MODELNET_SWARM_STAGEHEAD_H

#include <modelnet/swarm_stagehead/active.h>
#include <modelnet/swarm_stagehead/candidate.h>
#include <modelnet/swarm_stagehead/memory.h>
#include <modelnet/swarm_stagehead/realm.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Stage, adopt, and rollback plane for one active id.
 *
 * The active id starts as "base". This plane does not mine, broadcast,
 * or spend.
 *
 * Stage stores a non-empty candidate and does not change the active id.
 * An empty candidate is HEAD and stores nothing. A second stage replaces
 * the staged candidate only. staged() returns that candidate, or empty
 * when nothing is staged.
 *
 * Adopt with no staged candidate is ADOPT and the active id stays.
 * local_compatible false is LOCAL_INCOMPATIBLE and the candidate stays
 * unadopted. local_compatible true remembers the previous active id,
 * adopts the staged id, clears staged, and returns true. A later adopt
 * remembers the id it replaced.
 *
 * Rollback restores the remembered previous id once and clears that
 * memory. A second rollback with nothing remembered is ROLLBACK and
 * leaves the active id. Rollback does not mine.
 *
 * Pin clears the staged candidate and leaves the active id unchanged.
 *
 * Regress after an adopt restores the previous id once, the same way
 * rollback does. Rollback and regress share one remembered id. A second
 * regress is ROLLBACK.
 *
 * bytes_moved() is 0. mined() is false. graduated() stays false.
 * PromoteRealm returns REALM and does not change the active id.
 */
class SwarmStageHead {
public:
    bool Stage(const std::string& candidate, std::string& err);
    bool Adopt(bool local_compatible, std::string& err);
    bool Rollback(std::string& err);
    bool Pin(std::string& err);
    bool Regress(std::string& err);
    bool PromoteRealm(std::string& err) const;

    const std::string& active() const { return m_active.id(); }
    const std::string& staged() const { return m_staged.id(); }
    const std::string& previous() const { return m_memory.previous(); }

    int64_t bytes_moved() const { return m_realm.bytes_moved(); }
    bool mined() const { return m_realm.mined(); }
    bool graduated() const { return m_realm.graduated(); }
    bool broadcast() const { return m_realm.broadcast(); }
    bool spent() const { return m_realm.spent(); }

private:
    SwarmStageActive m_active;
    SwarmStageCandidate m_staged;
    SwarmStageMemory m_memory;
    SwarmStageRealm m_realm;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STAGEHEAD_H
