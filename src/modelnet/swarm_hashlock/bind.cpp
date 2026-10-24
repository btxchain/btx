// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashlock/bind.h>

#include <modelnet/swarm_paymesh.h>

#include <util/strencodings.h>

namespace modelnet {

bool SwarmHashlockBindAgrees(const std::string& id,
                             const std::vector<unsigned char>& payment_hash,
                             const std::vector<unsigned char>& preimage)
{
    SwarmInvoice invoice;
    invoice.id = id;
    invoice.preimage_hash = HexStr(payment_hash);
    std::string bind_err;
    if (SwarmBindPreimage(invoice, preimage, bind_err)) {
        return true;
    }
    // PREIMAGE means the digest did not match. A later refusal means the
    // digest matched and this plane simply has no amount or route.
    return bind_err != "PREIMAGE";
}

} // namespace modelnet
