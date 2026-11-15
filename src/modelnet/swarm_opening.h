// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_OPENING_H
#define BTX_MODELNET_SWARM_OPENING_H

#include <string>

namespace modelnet {

/** Local opening record. This process never broadcasts and holds no spend key. */
enum class SwarmOpenState {
    Proposed,
    RefundBound,
    FundingBroadcast,
    FundingConfirmed,
};

/**
 * Refund binding is a boolean the caller asserts. FundingBroadcast and
 * FundingConfirmed are named so a later transition cannot be invented here.
 * automatic_spend_atoms stays "0". There is no spend key.
 */
struct SwarmOpening {
    SwarmOpenState state{SwarmOpenState::Proposed};
    bool refund_bound{false};
    bool broadcast{false};
    std::string funding_txid;
    int confirmations{0};
    std::string automatic_spend_atoms{"0"};
};

/** Mismatched outpoint is REFUND_UNBOUND and leaves state Proposed. */
bool SwarmBindRefund(SwarmOpening& opening, bool outpoint_matches, std::string& err);

/**
 * Always BROADCAST_FORBIDDEN. broadcast stays false. State does not become
 * FundingBroadcast. A non-empty txid does not change that. Nothing is sent.
 */
bool SwarmBroadcastFunding(SwarmOpening& opening, const std::string& txid, std::string& err);

/**
 * Without a broadcast, CONFIRMED_WITHOUT_BROADCAST and confirmations stay 0.
 * Does not assign FundingConfirmed.
 */
bool SwarmNoteConfirmations(SwarmOpening& opening, int confirmations, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_OPENING_H
