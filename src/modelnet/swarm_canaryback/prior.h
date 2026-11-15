// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_PRIOR_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_PRIOR_H

#include <string>

namespace modelnet {

/**
 * Whether a Regress can restore a previous id.
 * Unadopted: no Adopt has succeeded. Regress is STAGE.
 * Armed: the last Adopt stored one previous id. Regress restores it.
 * Spent: that restore already ran and no newer Adopt has armed another.
 * Regress is ROLLBACK.
 */
enum class SwarmCanaryBackPriorKind {
    Unadopted,
    Armed,
    Spent,
};

/**
 * The one previous id remembered by the latest Adopt.
 * arm replaces it. disarm drops it and leaves the slot spent until
 * a newer arm. This is one level, not a stack.
 */
class SwarmCanaryBackPrior {
public:
    SwarmCanaryBackPriorKind kind() const;
    const std::string& id() const;

    void arm(const std::string& id);
    void disarm();

private:
    std::string m_id;
    bool m_armed{false};
    bool m_ever{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_PRIOR_H
