// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REVSPLIT_H
#define BTX_MODELNET_SWARM_REVSPLIT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of a revenue split for one pool. pool_id names the pool.
 * gross is the atom count being split. sponsor_ppm, worker_ppm, and
 * reserve_ppm are parts per million. Together they must sum to 1000000.
 * want_pay asks this note to pay.
 *
 * The known illustration is gross 10000 with sponsor_ppm 700000,
 * worker_ppm 200000, and reserve_ppm 100000, which records 7000, 2000,
 * and 1000. This note does not invent a general split. paid stays false
 * on every path. Nothing is signed and nothing is broadcast. No
 * hostnames or IPs are used.
 */
struct SwarmRevenueSplitRequest {
    std::string pool_id;
    int64_t gross{0};
    int64_t sponsor_ppm{0};
    int64_t worker_ppm{0};
    int64_t reserve_ppm{0};
    bool want_pay{false};
};

/**
 * Outcome of noting a revenue split. sponsor_atoms, worker_atoms, and
 * reserve_atoms are the recorded illustration counts, or zero when the
 * input is refused. paid stays false: this note does not pay, nothing
 * is signed, and nothing is broadcast.
 */
struct SwarmRevenueSplitResult {
    int64_t sponsor_atoms{0};
    int64_t worker_atoms{0};
    int64_t reserve_atoms{0};
    bool paid{false};
    std::string code;
};

/**
 * Note a revenue split without paying, signing, or broadcasting.
 * Order, first match wins:
 * an empty pool_id, a gross below 0, or any ppm below 0 is SPLIT.
 * Adding the three ppm values in a way that would overflow int64 is
 * SPLIT. sponsor_atoms, worker_atoms, and reserve_atoms are 0 and err
 * is SPLIT.
 * A sum other than 1000000 is SUM. The atom counts stay 0 and err is
 * SUM. This wins even when want_pay is true.
 * An input that is not exactly gross 10000, sponsor_ppm 700000,
 * worker_ppm 200000, and reserve_ppm 100000 is ILLUSTRATION. The atom
 * counts stay 0 and err is ILLUSTRATION. This wins even when want_pay
 * is true. This note does not invent a general split.
 * want_pay is HELD. sponsor_atoms is 7000, worker_atoms is 2000,
 * reserve_atoms is 1000, and err is cleared. This note does not pay.
 * Otherwise the note is NOTED with the same atom counts and err is
 * cleared. paid stays false. Nothing is signed and nothing is
 * broadcast. No hostnames or IPs are used.
 */
SwarmRevenueSplitResult SwarmNoteRevenueSplit(const SwarmRevenueSplitRequest& split, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REVSPLIT_H
