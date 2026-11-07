// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_CODES_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_CODES_H

namespace modelnet {

/** Empty usd. The quote is not stored. */
inline constexpr char kSwarmQuoteFiatQuote[] = "QUOTE";

/**
 * A non-empty usd was stored. The quote is kept and is not a BTX balance.
 * atoms stay 0.
 */
inline constexpr char kSwarmQuoteFiatNotBalance[] = "NOT_BALANCE";

/** The same usd was quoted again. The first quote stays. */
inline constexpr char kSwarmQuoteFiatReplay[] = "REPLAY";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_CODES_H
