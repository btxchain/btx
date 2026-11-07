// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CLEARNOTE_H
#define BTX_MODELNET_SWARM_CLEARNOTE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one clearing batch. payments is the number of
 * payments in the note. want_l1_per_payment asks this note to emit one
 * L1 transaction per payment.
 *
 * This note does not emit one L1 transaction per payment and does not
 * broadcast. l1_transactions stays 0 on every path. No hostnames or IPs
 * are used.
 */
struct SwarmClearingNote {
    int64_t payments{0};
    bool want_l1_per_payment{false};
};

/**
 * Outcome of noting a clearing batch. l1_transactions stays 0 on every
 * path: this note does not emit one L1 transaction per payment and does
 * not broadcast.
 */
struct SwarmClearingNoteResult {
    int64_t l1_transactions{0};
    std::string code;
};

/**
 * Note a clearing batch without emitting L1 transactions.
 * Order, first match wins: payments below 1 is CLEAR. want_l1_per_payment
 * is L1_REFUSED. Otherwise the note is NETTED and err is clear.
 * l1_transactions stays 0 on every path. One clearing note does not emit
 * one L1 transaction per payment and does not broadcast.
 */
SwarmClearingNoteResult SwarmNoteClearing(const SwarmClearingNote& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CLEARNOTE_H
