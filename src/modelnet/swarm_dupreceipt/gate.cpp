// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/gate.h>

#include <modelnet/swarm_dupreceipt/atoms.h>
#include <modelnet/swarm_dupreceipt/blank.h>
#include <modelnet/swarm_dupreceipt/caller.h>
#include <modelnet/swarm_dupreceipt/codes.h>
#include <modelnet/swarm_dupreceipt/replay.h>

namespace modelnet {

std::string SwarmDupBindRefusal(const SwarmDupReceiptBook& book, const std::string& receipt)
{
    std::string err;
    if (!SwarmDupBlank{}.accept(receipt, err)) {
        return err;
    }
    if (SwarmDupBindIsReplay(book, receipt)) {
        return std::string{kSwarmDupReplay};
    }
    return {};
}

std::string SwarmDupPayRefusal(const SwarmDupReceiptBook& book,
                               const std::string& receipt,
                               int64_t atoms,
                               bool research_key,
                               bool scheduler)
{
    if (!book.contains(receipt)) {
        return std::string{kSwarmDupReceipt};
    }
    std::string err;
    if (!SwarmDupAtoms{}.accept(atoms, err)) {
        return err;
    }
    if (SwarmDupPayIsReplay(book, receipt)) {
        return std::string{kSwarmDupReplay};
    }
    if (!SwarmDupCaller{}.accept(research_key, scheduler, err)) {
        return err;
    }
    if (!SwarmDupAtoms{}.fits(book.earned(), atoms)) {
        return std::string{kSwarmDupAtoms};
    }
    return {};
}

} // namespace modelnet
