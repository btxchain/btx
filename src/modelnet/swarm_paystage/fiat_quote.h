// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PAYSTAGE_FIAT_QUOTE_H
#define BTX_MODELNET_SWARM_PAYSTAGE_FIAT_QUOTE_H

#include <string>

namespace modelnet {

/**
 * A fiat quote is not a balance. Returns false, sets err to NOT_BALANCE,
 * and stores nothing.
 */
bool SwarmPayFiatQuote(std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PAYSTAGE_FIAT_QUOTE_H
