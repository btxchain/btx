// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_TOKFP_H
#define BTX_MODELNET_SWARM_TOKFP_H

#include <string>

namespace modelnet {

/**
 * Two model identities to compare. The concrete ids are tokenizer,
 * architecture, and quantization on each side. family_id is carried and
 * is not compared. It is not turned into a fingerprint. family_member
 * does not imply compatibility.
 */
struct SwarmMatchFingerprintRequest {
    std::string family_id;
    std::string tokenizer_id;
    std::string architecture_id;
    std::string quantization;
    std::string other_tokenizer_id;
    std::string other_architecture_id;
    std::string other_quantization;
    bool family_member{false};
};

/**
 * An id-compare answer. compatible stays false unless every concrete id
 * matches and is non-empty. This result has no benchmark flag.
 */
struct SwarmMatchFingerprintResult {
    bool compatible{false};
    std::string code;
};

/**
 * Compares tokenizer, architecture, and quantization ids. This is an id
 * compare, not a loaded-model measurement. family_id is ignored.
 * Family membership does not imply compatibility. No benchmark flag is set.
 *
 * Order: any empty tokenizer, architecture, or quantization on either
 * side is FINGERPRINT and compatible stays false. family_member true
 * while the concrete ids are not an exact match is FAMILY_NOT_COMPAT
 * and compatible stays false. A tokenizer mismatch is TOKENIZER. An
 * architecture mismatch is ARCHITECTURE. A quantization mismatch is
 * QUANTIZATION. All three pairs equal and non-empty is MATCH and
 * compatible is true, including when family_member is true. On MATCH,
 * err is cleared. Otherwise err is the code.
 */
SwarmMatchFingerprintResult SwarmMatchFingerprint(const SwarmMatchFingerprintRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_TOKFP_H
