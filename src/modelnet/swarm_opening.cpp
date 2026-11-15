// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_opening.h>

namespace modelnet {

bool SwarmBindRefund(SwarmOpening& opening, bool outpoint_matches, std::string& err)
{
    opening.automatic_spend_atoms = "0";
    if (!outpoint_matches) {
        err = "REFUND_UNBOUND";
        return false;
    }
    opening.refund_bound = true;
    opening.state = SwarmOpenState::RefundBound;
    err.clear();
    return true;
}

bool SwarmBroadcastFunding(SwarmOpening& opening, const std::string& txid, std::string& err)
{
    opening.automatic_spend_atoms = "0";
    // txid is not stored and is not broadcast. Bound or not, this process
    // must not enter FundingBroadcast.
    (void)txid;
    if (!opening.refund_bound) {
        opening.broadcast = false;
        err = "BROADCAST_FORBIDDEN";
        return false;
    }
    opening.broadcast = false;
    err = "BROADCAST_FORBIDDEN";
    return false;
}

bool SwarmNoteConfirmations(SwarmOpening& opening, int confirmations, std::string& err)
{
    opening.automatic_spend_atoms = "0";
    (void)confirmations;
    if (opening.state != SwarmOpenState::FundingConfirmed && !opening.broadcast) {
        err = "CONFIRMED_WITHOUT_BROADCAST";
        opening.confirmations = 0;
        return false;
    }
    // Do not invent FundingConfirmed from a confirmation count.
    err = "CONFIRMED_WITHOUT_BROADCAST";
    opening.confirmations = 0;
    return false;
}

} // namespace modelnet
