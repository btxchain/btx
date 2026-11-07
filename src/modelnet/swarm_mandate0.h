// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MANDATE0_H
#define BTX_MODELNET_SWARM_MANDATE0_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of a requested mandate spend.
 * A signed bounded mandate in this note does not arm spending.
 * automatic_spend stays 0 on every path. Nothing is signed and nothing
 * is broadcast. No hostnames, IPs, or key material are used.
 */
struct SwarmMandateSpend {
    std::string mandate_id;
    bool operator_signed{false};
    int64_t bound_atoms{0};
    int64_t requested_atoms{0};
};

/**
 * Outcome of noting a mandate spend. automatic_spend stays 0: a signed
 * bounded mandate in this note does not arm spending, nothing is signed,
 * and nothing is broadcast.
 */
struct SwarmMandateSpendResult {
    int64_t automatic_spend{0};
    std::string code;
};

/**
 * Note a mandate spend without arming it.
 * Order, first match wins: an empty mandate_id, bound_atoms < 1, or
 * requested_atoms <= 0 is MANDATE. An unsigned request is UNSIGNED.
 * requested_atoms above bound_atoms is BOUND. Otherwise the note is
 * HELD and err is cleared. automatic_spend stays 0 on every path.
 * A signed bounded mandate in this note does not arm spending. Nothing
 * is signed and nothing is broadcast.
 */
SwarmMandateSpendResult SwarmNoteMandateSpend(const SwarmMandateSpend& spend, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MANDATE0_H
