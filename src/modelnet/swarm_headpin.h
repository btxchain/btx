// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_HEADPIN_H
#define BTX_MODELNET_SWARM_HEADPIN_H

#include <string>

namespace modelnet {

/**
 * In-memory head pin. The active id starts as "base". Stage stores a
 * candidate and leaves the active id. Follow adopts that staged id only
 * when local_compatible is true. Pin drops the staged id and keeps the
 * previous head.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or IP.
 */
class SwarmHeadPin {
public:
    /**
     * An empty candidate is MODEL and stores nothing. Otherwise the
     * candidate is stored as the staged id and err is cleared. The
     * active id is left unchanged.
     */
    bool Stage(const std::string& candidate, std::string& err);

    /**
     * No staged id is STAGE and leaves the active id. A staged id that
     * is not local_compatible is LOCAL_INCOMPATIBLE: the active id and
     * the staged id both stay. Otherwise the active id becomes the
     * staged id, the staged id is cleared, and err is cleared.
     */
    bool Follow(bool local_compatible, std::string& err);

    /**
     * No staged id is STAGE and leaves the active id. Otherwise the
     * staged id is cleared, the active id is left unchanged, and err
     * is cleared.
     */
    bool Pin(std::string& err);

    /** Current active id. Starts as "base". */
    const std::string& active() const;

private:
    std::string m_active{"base"};
    std::string m_staged;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_HEADPIN_H
