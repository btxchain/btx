// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ROLLBACK_H
#define BTX_MODELNET_SWARM_ROLLBACK_H

#include <string>

namespace modelnet {

/**
 * In-memory active id with one staged candidate and one previous id.
 * The active id starts as "base". Stage stores a candidate and leaves
 * the active id unchanged. Adopt sets the active id to the staged id
 * and remembers the previous active id. Rollback restores that previous
 * id. It does not mine and does not promote a realm. A second rollback
 * with no newer adopt is refused.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or IP.
 */
class SwarmRollback {
public:
    /**
     * An empty candidate is MODEL and stores nothing. Otherwise the
     * candidate is stored as the staged id and err is cleared. The
     * active id is left unchanged.
     */
    bool Stage(const std::string& candidate, std::string& err);

    /**
     * No staged id is STAGE and leaves the active id. Otherwise the
     * active id becomes the staged id, the previous active id is
     * remembered, the staged id is cleared, and err is cleared.
     */
    bool Adopt(std::string& err);

    /**
     * No previous adopt is ROLLBACK and leaves the active id. Otherwise
     * the active id is restored to the previous id, that previous adopt
     * is consumed, and err is cleared.
     */
    bool Rollback(std::string& err);

    /** Current active id. Starts as "base". */
    const std::string& active() const;

private:
    std::string m_active{"base"};
    std::string m_staged;
    std::string m_previous;
    bool m_has_previous{false};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ROLLBACK_H
