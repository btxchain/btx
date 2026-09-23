// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROVENANCE_H
#define BITCOIN_MODELNET_PROVENANCE_H

#include <modelnet/import_plan.h>
#include <span.h>

#include <string>
#include <vector>

namespace modelnet {

struct ProvenanceVerifyResult {
    bool parsed{false};
    bool verified_here{false};
    std::string algorithm;
    std::string error;
};

/** DSSEv1 PAE: "DSSEv1 " || len(type) || " " || type || " " || len(body) || " " || body */
void DssePae(const std::string& payload_type, Span<const unsigned char> payload, std::vector<unsigned char>& out);

/**
 * Local verification only. Never talks to Rekor, Fulcio, or a registry.
 * Native BTX publisher signatures use ML-DSA-44. OMS/Sigstore/Cosign accept
 * ML-DSA-44, ED25519, or ECDSA-P256-SHA256 over the payload (or DSSE PAE when
 * payload_type is set). Missing key material stays parsed and unverified.
 */
bool VerifyProvenanceEvidence(const ProvenanceEvidence& pe, ProvenanceVerifyResult& out);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PROVENANCE_H
