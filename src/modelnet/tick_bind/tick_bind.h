// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_TICK_BIND_TICK_BIND_H
#define BITCOIN_MODELNET_TICK_BIND_TICK_BIND_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One latched pass of the native binders from the btxd observer.
 * The first Pass calls bnd01 through bnd11, cyc01, and ext01.
 * A later Pass does not call them again.
 * passed(), gpu_passed(), and windows_passed() stay false.
 * Release stays unqualified. Spend stays "0". Hosts stay 1.
 * No child process is started.
 */
class TickBind {
public:
    bool Pass(std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);

    bool passed() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool release_qualified() const { return false; }
    bool launched() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_done{false};
};

} // namespace modelnet

#endif
