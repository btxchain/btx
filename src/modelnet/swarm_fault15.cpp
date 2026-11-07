// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault15.h>

namespace modelnet {
namespace {

SwarmFault15Result Code(const char* code, bool clear_err, std::string& err)
{
    SwarmFault15Result out;
    out.code = code;
    out.measured = false;
    out.broadcast = false;
    out.committed = false;
    // 8000 bytes is not a measurement.
    out.assumed_bytes = 0;
    if (clear_err) {
        err.clear();
    } else {
        err = code;
    }
    return out;
}

} // namespace

SwarmFault15Result SwarmRecoverFault15(const SwarmFault15& in, std::string& err)
{
    // Multiple channels exiting during a reorganization. Nothing is measured,
    // broadcast, or committed.
    if (in.batch_id.empty() || in.channel_count < 2) {
        return Code("BATCH", false, err);
    }
    if (in.want_measure) {
        // Refused even when want_broadcast is also set.
        return Code("MEASURE_REFUSED", false, err);
    }
    if (in.want_broadcast) {
        return Code("HELD", true, err);
    }
    return Code("NOTED", true, err);
}

} // namespace modelnet
