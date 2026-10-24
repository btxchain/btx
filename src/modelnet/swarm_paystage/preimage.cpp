// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/preimage.h>

#include <crypto/sha256.h>

namespace modelnet {

uint256 SwarmPayPreimageHash(const std::vector<unsigned char>& preimage)
{
    uint256 hash;
    // Same single SHA-256 SwarmInvoiceBook::Reveal compares.
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash.begin());
    return hash;
}

} // namespace modelnet
