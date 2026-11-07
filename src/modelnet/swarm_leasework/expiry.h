// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_EXPIRY_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_EXPIRY_H

#include <cstdint>

namespace modelnet {

/** now_ms < 0 or until_ms < 0. */
bool LeaseWorkTimeOutOfRange(int64_t now_ms, int64_t until_ms);

/**
 * until_ms < now_ms.
 * until_ms == now_ms is not expired. The bound is inclusive.
 */
bool LeaseWorkGrantExpired(int64_t now_ms, int64_t until_ms);

/**
 * A stored grant is still live at observed now when until_ms >= now_ms.
 * Equality is live.
 */
bool LeaseWorkGrantLive(int64_t until_ms, int64_t now_ms);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_EXPIRY_H
