// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokfp.h>

namespace modelnet {

SwarmMatchFingerprintResult SwarmMatchFingerprint(const SwarmMatchFingerprintRequest& request, std::string& err)
{
    SwarmMatchFingerprintResult result;
    result.compatible = false;

    const bool missing = request.tokenizer_id.empty() || request.architecture_id.empty() ||
                         request.quantization.empty() || request.other_tokenizer_id.empty() ||
                         request.other_architecture_id.empty() || request.other_quantization.empty();
    if (missing) {
        result.code = "FINGERPRINT";
        err = "FINGERPRINT";
        return result;
    }

    const bool exact = request.tokenizer_id == request.other_tokenizer_id &&
                       request.architecture_id == request.other_architecture_id &&
                       request.quantization == request.other_quantization;
    if (request.family_member && !exact) {
        result.code = "FAMILY_NOT_COMPAT";
        err = "FAMILY_NOT_COMPAT";
        return result;
    }
    if (request.tokenizer_id != request.other_tokenizer_id) {
        result.code = "TOKENIZER";
        err = "TOKENIZER";
        return result;
    }
    if (request.architecture_id != request.other_architecture_id) {
        result.code = "ARCHITECTURE";
        err = "ARCHITECTURE";
        return result;
    }
    if (request.quantization != request.other_quantization) {
        result.code = "QUANTIZATION";
        err = "QUANTIZATION";
        return result;
    }

    result.compatible = true;
    result.code = "MATCH";
    err.clear();
    return result;
}

} // namespace modelnet
