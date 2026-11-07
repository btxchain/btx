// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FUNDING_CLASS_H
#define BTX_MODELNET_SWARM_FUNDING_CLASS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One position in the funding ladder. A certificate is not a balance.
 * Escrow atoms and channel capacity are not the same atoms twice.
 */
struct SwarmMoneyPosition {
    std::string kind;
    int64_t atoms{0};
    bool counts_as_balance{false};
    bool confirmed_backing{false};
    bool immediately_payable{false};
    bool earned{false};
    std::string code;
};

bool SwarmClassifyMoney(const std::string& kind, int64_t atoms, SwarmMoneyPosition& out, std::string& err);

/** The same outpoint cannot be both an escrow lot and channel collateral. */
bool SwarmAcceptCollateralUse(bool already_escrow, bool as_channel, std::string& err);

} // namespace modelnet

#endif
