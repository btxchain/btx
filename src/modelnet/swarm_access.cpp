// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_access.h>

namespace modelnet {

bool SwarmRevokeMembership(SwarmMembershipRevocation& row, bool shared_realm_key, std::string& err)
{
    row.future_access = false;
    row.plaintext_erased = false;
    row.per_recipient = false;
    if (shared_realm_key) {
        err = "SHARED_REALM_KEY";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmAcceptProducer(bool trusted_producer, bool author_signature_as_compiler, std::string& err)
{
    if (author_signature_as_compiler) {
        err = "COMPILER_CACHE";
        return false;
    }
    if (!trusted_producer) {
        err = "PRODUCER";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmDedupAcrossRealms(const std::string& realm_a, const std::string& realm_b, bool same_plaintext, bool& reveal_equality, std::string& err)
{
    if (realm_a.empty() || realm_b.empty()) {
        reveal_equality = false;
        err = "REALM";
        return false;
    }
    if (realm_a != realm_b) {
        reveal_equality = false;
        if (same_plaintext) {
            err = "DEDUP_PRIVATE";
            return false;
        }
        err.clear();
        return true;
    }
    reveal_equality = same_plaintext;
    err.clear();
    return true;
}

bool SwarmFamilyIsCompatible(bool same_family, bool same_checkpoint, bool same_recipe, bool same_quantization, std::string& err)
{
    (void)same_family;
    if (!same_checkpoint || !same_recipe || !same_quantization) {
        err = "FAMILY_NOT_COMPAT";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmBatchWithinCap(int64_t tasks, std::string& err)
{
    if (tasks <= 0 || tasks > 128) {
        err = "BATCH_CAP";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
