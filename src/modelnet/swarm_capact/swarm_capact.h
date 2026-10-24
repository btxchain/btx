// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_H
#define BITCOIN_MODELNET_SWARM_CAPACT_H

#include <modelnet/swarm_capact/actions.h>
#include <modelnet/swarm_capact/grants.h>
#include <modelnet/swarm_capact/quiet.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Capability-action plane.
 * An action runs only when that capability was granted. Nothing is
 * launched.
 *
 * Grant stores a non-empty name. An empty name is CAPABILITY and stores
 * nothing. A duplicate name is REPLAY and keeps the first grant.
 *
 * Act before that name was granted is NOT_ACTED and records nothing.
 * Act of an empty name is CAPABILITY. Act of a granted name records the
 * action once and returns true. A second Act of the same name is REPLAY
 * and does not add a second record.
 *
 * launched() stays false. bytes_moved() stays 0. gpu() stays false.
 * automatic_spend() stays "0".
 */
class SwarmCapAct {
public:
    bool Grant(const std::string& name, std::string& err);
    bool Act(const std::string& name, std::string& err);

    bool granted(const std::string& name) const;
    bool acted(const std::string& name) const;
    std::size_t grant_count() const;
    std::size_t action_count() const;

    bool launched() const;
    int64_t bytes_moved() const;
    bool gpu() const;
    std::string automatic_spend() const;

private:
    SwarmCapActGrants m_grants;
    SwarmCapActActions m_actions;
    SwarmCapActQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_H
