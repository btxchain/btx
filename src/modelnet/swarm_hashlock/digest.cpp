// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashlock/digest.h>

#include <modelnet/swarm_hashlock/types.h>
#include <hash.h>

#include <algorithm>

namespace modelnet {

uint256 SwarmHashlockSha256(const std::vector<unsigned char>& bytes)
{
    // GetSHA256() is one CSHA256 round. Hash() would hash that digest again.
    HashWriter writer;
    if (!bytes.empty()) {
        writer.write(MakeByteSpan(bytes));
    }
    return writer.GetSHA256();
}

bool SwarmHashlockDigestEquals(const std::vector<unsigned char>& payment_hash,
                               const std::vector<unsigned char>& preimage)
{
    if (payment_hash.size() != kSwarmHashlockDigestSize || preimage.size() != kSwarmHashlockDigestSize) {
        return false;
    }
    const uint256 digest = SwarmHashlockSha256(preimage);
    return std::equal(digest.begin(), digest.end(), payment_hash.begin());
}

} // namespace modelnet
