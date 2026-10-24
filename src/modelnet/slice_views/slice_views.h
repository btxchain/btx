// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SLICE_VIEWS_SLICE_VIEWS_H
#define BITCOIN_MODELNET_SLICE_VIEWS_SLICE_VIEWS_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/research_index.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One local pass over the research index views.
 *
 * Pass announces one measured contribution and reads LEADING, CONTESTED,
 * NEGLECTED, RECENT, REPRODUCED, and an unknown view name. An unknown name
 * leaves err as VIEW. Results stay on that local index.
 *
 * hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * passed(), launched(), gpu(), broadcast(), qualified(), and
 * release_qualified() stay false.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * This class opens no file and no socket.
 */
class SliceViews {
public:
    bool Pass(std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);

    bool passed() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }

};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SLICE_VIEWS_SLICE_VIEWS_H
