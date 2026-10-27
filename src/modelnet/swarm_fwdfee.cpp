// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fwdfee.h>

#include <cstdint>

namespace modelnet {

SwarmForwardFeeResult SwarmNoteForwardFee(const SwarmForwardFee& fee, std::string& err)
{
    SwarmForwardFeeResult result;
    result.fee_atoms = 0;
    result.charged = false;
    if (fee.hop_id.empty() || fee.amount < 1 || fee.base < 0 || fee.ppm < 0) {
        result.code = "FEE";
        result.fee_atoms = 0;
        result.charged = false;
        err = "FEE";
        return result;
    }
    // amount * ppm must fit in int64. Do not overflow.
    if (fee.ppm > 0 && fee.amount > INT64_MAX / fee.ppm) {
        result.code = "FEE";
        result.fee_atoms = 0;
        result.charged = false;
        err = "FEE";
        return result;
    }
    // The sender's own first edge adds no fee. Nothing is charged and
    // nothing is broadcast.
    if (fee.sender_first_edge) {
        result.code = "NO_FEE";
        result.fee_atoms = 0;
        result.charged = false;
        err = "NO_FEE";
        return result;
    }
    const int64_t product = fee.amount * fee.ppm;
    // The rounding addend and the base addition must both fit. An
    // overflowing note is FEE with fee_atoms 0, and err is cleared.
    if (product > INT64_MAX - 999999 || fee.base > INT64_MAX - ((product + 999999) / 1000000)) {
        result.code = "FEE";
        result.fee_atoms = 0;
        result.charged = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.fee_atoms = fee.base + (product + 999999) / 1000000;
    result.charged = false;
    err.clear();
    return result;
}

} // namespace modelnet
