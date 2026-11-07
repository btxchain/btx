// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_CODES_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_CODES_H

namespace modelnet {

/** The receipt is empty, or Pay names a receipt that was never bound. */
inline constexpr char kSwarmDupReceipt[] = "RECEIPT";

/** atoms is below 1, or the earned sum would pass int64 max. Nothing is added. */
inline constexpr char kSwarmDupAtoms[] = "ATOMS";

/**
 * A second Bind of a stored receipt, or a second Pay of a paid receipt.
 * The first bind stays. Earned does not change.
 */
inline constexpr char kSwarmDupReplay[] = "REPLAY";

/**
 * The caller is a research key or the scheduler.
 * The receipt stays unpaid and earned does not change.
 */
inline constexpr char kSwarmDupNotSigned[] = "NOT_SIGNED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_CODES_H
