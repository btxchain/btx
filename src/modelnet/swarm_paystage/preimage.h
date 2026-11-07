// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PAYSTAGE_PREIMAGE_H
#define BTX_MODELNET_SWARM_PAYSTAGE_PREIMAGE_H

#include <uint256.h>

#include <vector>

namespace modelnet {

/**
 * Single SHA-256 of the preimage, in the byte order CSHA256 writes.
 * SwarmInvoiceBook::Reveal compares this digest. Hash() in hash.h is a
 * double SHA-256 and does not match that reveal.
 */
uint256 SwarmPayPreimageHash(const std::vector<unsigned char>& preimage);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PAYSTAGE_PREIMAGE_H
