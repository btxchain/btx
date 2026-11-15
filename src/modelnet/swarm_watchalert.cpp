// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchalert.h>

#include <string>

namespace modelnet {

SwarmWatchAlertResult SwarmNoteWatchAlert(const SwarmWatchAlert& alert, std::string& err)
{
    SwarmWatchAlertResult result;
    result.secp_penalty = false;
    result.broadcast = false;
    if (alert.channel_id.empty()) {
        result.code = "WATCH";
        result.secp_penalty = false;
        result.broadcast = false;
        err = "WATCH";
        return result;
    }
    // A prior secret release is a hashlock remedy. This wins even when
    // draining or stale_state is true. Nothing is broadcast.
    if (alert.prior_secret_released) {
        result.code = "HASHLOCK_REMEDY";
        result.secp_penalty = false;
        result.broadcast = false;
        err.clear();
        return result;
    }
    // Draining is a local drain-and-notify note. This wins even when
    // stale_state is true. Nothing is broadcast.
    if (alert.draining) {
        result.code = "DRAIN_AND_NOTIFY";
        result.secp_penalty = false;
        result.broadcast = false;
        err.clear();
        return result;
    }
    if (alert.stale_state) {
        result.code = "STALE_STATE_ALERT";
        result.secp_penalty = false;
        result.broadcast = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.secp_penalty = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
