// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FIATKEEP_H
#define BITCOIN_MODELNET_SWARM_FIATKEEP_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmFiatKeep {
    std::string quote_id;
    bool fiat{false};
    bool want_book{false};
};

struct SwarmFiatKeepResult {
    std::string code;
    bool booked{false};
    int64_t atoms{0};
};

SwarmFiatKeepResult SwarmNoteFiatQuote(const SwarmFiatKeep& quote, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FIATKEEP_H
