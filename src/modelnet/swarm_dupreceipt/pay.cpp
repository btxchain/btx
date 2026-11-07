// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/pay.h>

#include <modelnet/swarm_dupreceipt/codes.h>
#include <modelnet/swarm_dupreceipt/gate.h>
#include <modelnet/swarm_dupreceipt/limits.h>

namespace modelnet {

bool SwarmDupPay::Apply(SwarmDupReceiptBook& book,
                        const std::string& receipt,
                        int64_t atoms,
                        bool research_key,
                        bool scheduler,
                        std::string& err) const
{
    const std::string refusal = SwarmDupPayRefusal(book, receipt, atoms, research_key, scheduler);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!book.credit(receipt, atoms, research_key, scheduler)) {
        if (!book.contains(receipt)) {
            err = kSwarmDupReceipt;
        } else if (atoms < kSwarmDupMinAtoms) {
            err = kSwarmDupAtoms;
        } else if (book.paid(receipt)) {
            err = kSwarmDupReplay;
        } else if (research_key || scheduler) {
            err = kSwarmDupNotSigned;
        } else {
            err = kSwarmDupAtoms;
        }
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
