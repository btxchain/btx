// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ACCESS_H
#define BTX_MODELNET_SWARM_ACCESS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Future access stops. Previously delivered plaintext is not erased.
 * A shared realm key is not per-recipient revocation.
 */
struct SwarmMembershipRevocation {
    bool future_access{true};
    bool plaintext_erased{false};
    bool per_recipient{false};
};

bool SwarmRevokeMembership(SwarmMembershipRevocation& row, bool shared_realm_key, std::string& err);

/**
 * An exact cache requires a trusted producer. A model-author signature does
 * not authorize a compiler cache or runtime software.
 */
bool SwarmAcceptProducer(bool trusted_producer, bool author_signature_as_compiler, std::string& err);

/**
 * Equality of plaintext across two realms is not revealed. reveal_equality
 * stays false in that case.
 */
bool SwarmDedupAcrossRealms(const std::string& realm_a, const std::string& realm_b, bool same_plaintext, bool& reveal_equality, std::string& err);

/**
 * The same family is not checkpoint, recipe, or quantization compatibility.
 */
bool SwarmFamilyIsCompatible(bool same_family, bool same_checkpoint, bool same_recipe, bool same_quantization, std::string& err);

/** A batch above 128 tasks is BATCH_CAP. A non-positive count is BATCH_CAP. */
bool SwarmBatchWithinCap(int64_t tasks, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ACCESS_H
