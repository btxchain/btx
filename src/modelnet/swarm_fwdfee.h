// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FWDFEE_H
#define BTX_MODELNET_SWARM_FWDFEE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of a forward fee on one hop. hop_id names the hop.
 * amount is the forwarded atoms. base is the fixed part. ppm is parts
 * per million of amount. sender_first_edge says this hop is the
 * sender's own first edge.
 *
 * The integer is a note, not a charge and not a broadcast. charged
 * stays false on every path. No hostnames or IPs are used.
 */
struct SwarmForwardFee {
    std::string hop_id;
    int64_t amount{0};
    int64_t base{0};
    int64_t ppm{0};
    bool sender_first_edge{false};
};

/**
 * Outcome of noting a forward fee. fee_atoms is the noted integer when
 * the note is NOTED, and 0 otherwise. charged stays false: the integer
 * is a note, not a charge and not a broadcast.
 */
struct SwarmForwardFeeResult {
    int64_t fee_atoms{0};
    bool charged{false};
    std::string code;
};

/**
 * Note a forward fee without charging or broadcasting.
 * Order, first match wins: an empty hop_id, amount below 1, base below
 * 0, or ppm below 0 is FEE, with fee_atoms 0. When ppm is above 0 and
 * amount is above INT64_MAX / ppm, the note is FEE, with fee_atoms 0,
 * so the multiply cannot overflow. sender_first_edge is NO_FEE. The
 * sender's own first edge adds no fee. Otherwise the note is NOTED and
 * err is cleared. fee_atoms is base plus (amount * ppm + 999999) /
 * 1000000. If that addition would overflow int64, the note is FEE, with
 * fee_atoms 0, and err is cleared. charged stays false on every path.
 * The integer is a note, not a charge and not a broadcast.
 */
SwarmForwardFeeResult SwarmNoteForwardFee(const SwarmForwardFee& fee, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FWDFEE_H
