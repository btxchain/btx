// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_settlebuild/algo.h>

#include <modelnet/swarm_settlebuild/codes.h>
#include <pqkey.h>

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

static_assert(static_cast<unsigned>(PQAlgorithm::ML_DSA_44) !=
                  static_cast<unsigned>(PQAlgorithm::SLH_DSA_128S),
              "ML-DSA-44 and SLH-DSA-128s are distinct algorithms");
static_assert(MLDSA44_PUBKEY_SIZE != SLHDSA128S_PUBKEY_SIZE,
              "the two algorithms publish different pubkey sizes");

PQAlgorithm SwarmSettleBuildAlgorithm()
{
    return PQAlgorithm::ML_DSA_44;
}

std::size_t SwarmSettleBuildPubkeySize()
{
    const PQAlgorithm algo = SwarmSettleBuildAlgorithm();
    const std::size_t from_enum = GetPQPubKeySize(algo);
    const std::size_t from_params = GetPQAlgorithmParams(algo).pubkey_size;
    if (from_enum == 0 || from_enum != from_params) {
        return 0;
    }
    if (algo == PQAlgorithm::ML_DSA_44) {
        return from_enum == MLDSA44_PUBKEY_SIZE ? from_enum : 0;
    }
    if (algo == PQAlgorithm::SLH_DSA_128S) {
        return from_enum == SLHDSA128S_PUBKEY_SIZE ? from_enum : 0;
    }
    return 0;
}

bool SwarmSettleBuildPubkeyAccepted(const std::vector<unsigned char>& pubkey, std::string& err)
{
    const std::size_t need = SwarmSettleBuildPubkeySize();
    if (pubkey.empty() || need == 0 || pubkey.size() != need) {
        err = kSwarmSettleBuildKey;
        return false;
    }
    return true;
}

} // namespace modelnet
