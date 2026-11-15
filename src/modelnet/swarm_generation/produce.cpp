// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/produce.h>

#include <modelnet/swarm_generation/codes.h>

#include <hash.h>
#include <span.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {
namespace {

std::string CandidateDigest(const std::string& parent, const std::string& recipe, const std::string& weights, const std::string& nonce)
{
    // Hash(parent, recipe, weights, nonce): the two-argument Hash concatenates,
    // so the four fields are hashed in order as one byte string.
    const uint256 digest = Hash(parent + recipe, weights + nonce);
    return HexStr(Span<const uint8_t>(digest.data(), static_cast<std::size_t>(digest.size())));
}

} // namespace

bool SwarmGenerationProduce::Apply(SwarmGenerationPopulation& population, SwarmGenerationChallengers& challengers,
                                   const std::string& parent, const std::string& recipe, const std::string& weights,
                                   const std::string& nonce, std::string& err) const
{
    if (parent.empty() || recipe.empty() || weights.empty() || nonce.empty()) {
        return SwarmGenerationFail(err, kSwarmGenerationCandidate);
    }
    SwarmGenerationCandidate row;
    row.id = CandidateDigest(parent, recipe, weights, nonce);
    const bool known = population.find(row.id) != nullptr;
    row.parent = parent;
    row.recipe = recipe;
    row.weights = weights;
    row.nonce = nonce;
    row.verified = false;
    population.store(std::move(row));
    if (!known) {
        challengers.add(population.last_id(), parent);
    }
    return SwarmGenerationOk(err);
}

} // namespace modelnet
