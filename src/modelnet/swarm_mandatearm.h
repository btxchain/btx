// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MANDATEARM_H
#define BTX_MODELNET_SWARM_MANDATEARM_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Records an operator-signed bounded mandate.
 * automatic_spend stays the string "0" until that mandate is recorded.
 * Recording a mandate does not move atoms and does not hand a spend key
 * to a research key or a scheduler.
 */
class SwarmMandateArm {
public:
    bool Arm(int64_t bound_atoms, bool operator_signed, bool research_key, bool scheduler, std::string& err);
    std::string automatic_spend() const;
    bool armed() const;
    int64_t atoms_moved() const;

private:
    bool m_armed{false};
    int64_t m_bound_atoms{0};
    std::string m_automatic_spend{"0"};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MANDATEARM_H
