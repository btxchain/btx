// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WORKPAY_FIAT_QUOTE_H
#define BITCOIN_MODELNET_SWARM_WORKPAY_FIAT_QUOTE_H

#include <string>

namespace modelnet {

/**
 * A fiat quote is not a balance. Returns false, sets err to NOT_BALANCE,
 * and stores nothing. fiat is not retained.
 */
bool SwarmWorkFiatQuote(const std::string& fiat, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WORKPAY_FIAT_QUOTE_H
