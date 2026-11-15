// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_SPEND_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_SPEND_H

#include <modelnet/swarm_nodedefault/bound.h>
#include <modelnet/swarm_nodedefault/limits.h>
#include <modelnet/swarm_nodedefault/sign.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Operator-signed spend bound for the default node.
 * automatic_spend() is "0" and armed() is false until one arm is recorded.
 * atoms_moved() stays 0. This does not spend.
 *
 * ArmSpend checks, first match: an already armed record is REPLAY and the
 * stored decimal stays; a research key or scheduler is NOT_SIGNED;
 * operator_signed false is NOT_SIGNED; atoms below 1 is BOUND. A signed
 * bound of at least 1 stores that decimal and armed() becomes true.
 */
class SwarmNodeDefaultSpend {
public:
    bool ArmSpend(int64_t atoms, bool operator_signed, bool research_key, bool scheduler, std::string& err);
    const std::string& automatic_spend() const;
    bool armed() const;
    int64_t atoms_moved() const;

private:
    SwarmNodeDefaultSign m_sign;
    SwarmNodeDefaultBound m_bound;
    bool m_armed{false};
    std::string m_automatic_spend{kSwarmNodeDefaultSpendZero};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_SPEND_H
