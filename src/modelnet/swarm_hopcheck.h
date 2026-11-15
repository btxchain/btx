// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_HOPCHECK_H
#define BTX_MODELNET_SWARM_HOPCHECK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Caller description of a script route. route_id names the description.
 * preimage_len is the claimed preimage byte length. covers_outputs,
 * overlapping_timeout, and signer are caller claims. hops is the claimed
 * hop count.
 *
 * This is a precondition check for a script route. It does not build a
 * transaction, broadcast, spend, mine, or set multi-hop settlement qualified.
 */
struct SwarmHopCheck {
    std::string route_id;
    int64_t preimage_len{0};
    bool covers_outputs{false};
    bool overlapping_timeout{false};
    bool signer{false};
    int64_t hops{0};
};

/**
 * Outcome of a hop-script precondition check. qualified and secp_penalty
 * stay false on every path. hops is copied from the description. A
 * well-formed description is still not a script-enforced settlement.
 */
struct SwarmHopCheckResult {
    std::string code;
    bool qualified{false};
    bool secp_penalty{false};
    int64_t hops{0};
};

/**
 * Check a script-route description.
 * Order, first match wins: an empty route_id is ROUTE. preimage_len other
 * than 32 is PREIMAGE. covers_outputs false is OUTPUTS. overlapping_timeout
 * true is TIMEOUT. signer false is SIGNER. hops below 2 is HOPS. Otherwise
 * the code is UNQUALIFIED and err is UNQUALIFIED.
 * qualified and secp_penalty stay false on every path. hops is copied into
 * the result. A hop check can reject a bad description and still leaves
 * settlement unqualified. This check does not build a transaction,
 * broadcast, spend, or mine.
 */
SwarmHopCheckResult SwarmCheckHopScript(const SwarmHopCheck& check, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_HOPCHECK_H
