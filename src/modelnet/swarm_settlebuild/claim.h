// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SETTLEBUILD_CLAIM_H
#define BITCOIN_MODELNET_SWARM_SETTLEBUILD_CLAIM_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * Build one SHA-256 HTLC claim leaf and parse it back.
 * A payment hash whose size is not 32 is PREIMAGE and leaves script empty.
 * An empty pubkey, or a pubkey whose size is not the chosen PQAlgorithm size,
 * is KEY. The leaf builder is not called in either case.
 * Otherwise BuildP2MRHTLCSha256Leaf runs. The leaf is kept only when
 * ParseP2MRHTLCSha256Leaf returns the same hash and pubkey and
 * P2MRClaimLeafPinsPreimageLength is true. A miss is SCRIPT and script is cleared.
 */
bool SwarmSettleBuildMakeClaim(const std::vector<unsigned char>& payment_hash,
                               const std::vector<unsigned char>& pubkey,
                               std::vector<unsigned char>& script,
                               std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SETTLEBUILD_CLAIM_H
