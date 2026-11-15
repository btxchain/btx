// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fabric.h>

#include <modelnet/swarm_codec.h>
#include <crypto/sha256.h>
#include <pqkey.h>
#include <util/strencodings.h>

namespace modelnet {

bool SwarmPrefixCompatible(const SwarmPrefix& held, const SwarmPrefix& wanted, std::string& err)
{
    if (held.fingerprint.empty() || wanted.fingerprint.empty() || held.length <= 0 || wanted.length <= 0) {
        err = "FINGERPRINT";
        return false;
    }
    if (held.fingerprint != wanted.fingerprint) {
        err = "PREFIX_MISMATCH";
        return false;
    }
    if (!held.causal || !wanted.causal) {
        err = "CAUSAL_GAP";
        return false;
    }
    if (!held.parent_fingerprint.empty() && !wanted.parent_fingerprint.empty() &&
        held.parent_fingerprint != wanted.parent_fingerprint) {
        err = "CAUSAL_GAP";
        return false;
    }
    err.clear();
    return true;
}

SwarmPrefetch SwarmPrefetchPages(bool engine_present, const SwarmPrefix& held, const SwarmPrefix& wanted, std::string& err)
{
    SwarmPrefetch result;
    if (!SwarmPrefixCompatible(held, wanted, err)) {
        result.bytes_moved = false;
        result.code.clear();
        return result;
    }
    result.bytes_moved = false;
    result.code = engine_present ? "LOCAL" : "ENGINE_ABSENT";
    err.clear();
    return result;
}

uint256 SwarmLanCardHash(const SwarmLanCard& card)
{
    const std::string body = card.artifact_id + "\n" + card.lineage_id + "\n" + (card.public_mapping ? "1" : "0");
    CSHA256 sha;
    sha.Write(reinterpret_cast<const unsigned char*>(body.data()), body.size());
    uint256 hash;
    sha.Finalize(hash.begin());
    return hash;
}

bool SwarmAcceptLanCard(const SwarmLanCard& card, std::string& err)
{
    if (!SwarmFixedId(card.artifact_id) || !SwarmFixedId(card.lineage_id)) {
        err = "CARD";
        return false;
    }
    if (!card.public_mapping) {
        err = "PRIVATE_MEMBERSHIP";
        return false;
    }
    const std::vector<unsigned char> sig = ParseHex(card.signature_hex);
    if (card.pubkey.size() != MLDSA44_PUBKEY_SIZE || sig.size() != MLDSA44_SIGNATURE_SIZE) {
        err = "CARD_SIGNATURE";
        return false;
    }
    const CPQPubKey pubkey(PQAlgorithm::ML_DSA_44, card.pubkey);
    if (!pubkey.Verify(SwarmLanCardHash(card), sig)) {
        err = "CARD_SIGNATURE";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
