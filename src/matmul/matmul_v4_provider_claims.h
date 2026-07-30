// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MATMUL_V4_PROVIDER_CLAIMS_H
#define BTX_MATMUL_V4_PROVIDER_CLAIMS_H

#include <string>
#include <vector>

// ENC_RC / ENC-DR-LT provider honesty claim matrix (Workstream E).
//
// Four distinct axes — never conflate:
//   compiled  — vendor TU / SDK ABI linked into this binary
//   attempted — self-qual invoked a real vendor surface (not arch/getenv alone)
//   qualified — oracle byte-match on that surface; native_* latch may flip
//   deficit   — HARD BLOCKER string when not qualified
//
// Rules (fail-closed):
//   qualified ⇒ attempted ∧ compiled
//   Never qualify from arch name, getenv, simulated output, or host recomputation
//   Never label Apple INT8 / Metal ALU as OCP MXFP4
//   Scalar-decode / host-pack exactness probes may set backend="…scalar-decode"
//     but must leave qualified=false
//
// Main-machine compile-only coverage:
//   test suite matmul_v4_provider_contract_tests
// Future physical qualification commands are documented there.

namespace matmul::v4 {

struct ProviderClaim {
    const char* provider{nullptr}; // "hip_rc_mxfp4" | "metal_rc_exact" | …
    const char* format{nullptr};   // "OCP_MXFP4_E2M1_VEC32" | "INT8_ExactGemm" | …
    bool compiled{false};
    bool attempted{false};
    bool qualified{false};
    std::string backend; // execution path label (empty when none)
    std::string deficit; // HARD BLOCKER when !qualified
};

/** Snapshot every RC/LT vendor claim surface for honesty audits / gates. */
[[nodiscard]] std::vector<ProviderClaim> ProbeAllProviderClaims();

/** True iff claim obeys qualified ⇒ attempted ∧ compiled and no OCP MXFP4
 *  masquerade on Metal INT8. */
[[nodiscard]] bool ProviderClaimIsInternallyConsistent(const ProviderClaim& c);

} // namespace matmul::v4

#endif // BTX_MATMUL_V4_PROVIDER_CLAIMS_H
