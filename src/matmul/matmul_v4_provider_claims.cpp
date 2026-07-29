// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/matmul_v4_provider_claims.h>

#include <ascend/matmul_v4_rc_accel.h>
#include <hip/matmul_v4_lt_mx_native.h>
#include <hip/matmul_v4_rc_mx_ozaki_native.h>
#include <metal/matmul_v4_rc_ozaki_accel.h>
#include <tpu/matmul_v4_rc_accel.h>
#include <trainium/matmul_v4_rc_accel.h>

#include <cstring>
#include <string>

namespace matmul::v4 {
namespace {

[[nodiscard]] bool LooksLikeOcpMxfp4Label(const std::string& s)
{
    return s.find("OCP") != std::string::npos &&
           (s.find("MXFP4") != std::string::npos || s.find("mxfp4") != std::string::npos);
}

} // namespace

bool ProviderClaimIsInternallyConsistent(const ProviderClaim& c)
{
    if (c.provider == nullptr || c.format == nullptr) return false;
    if (c.qualified && !(c.attempted && c.compiled)) return false;
    // Metal INT8 ExactGemm must never be labeled OCP MXFP4.
    if (std::strcmp(c.provider, "metal_rc_exact") == 0 ||
        std::strcmp(c.provider, "metal_rc_mxfp4") == 0 ||
        std::strcmp(c.provider, "metal_lt_mx") == 0) {
        if (LooksLikeOcpMxfp4Label(c.format) && c.qualified) return false;
        if (c.backend.find("OCP") != std::string::npos &&
            c.backend.find("MXFP4") != std::string::npos && c.qualified) {
            return false;
        }
    }
    // Scalar-decode backends must never qualify.
    if (c.backend.find("scalar-decode") != std::string::npos && c.qualified) return false;
    return true;
}

std::vector<ProviderClaim> ProbeAllProviderClaims()
{
    std::vector<ProviderClaim> out;
    out.reserve(10);

    // --- HIP RC Ozaki MXFP4 (gfx950 / MI350X / MI355X) ---
    {
        ProviderClaim c;
        c.provider = "hip_rc_mxfp4";
        c.format = "OCP_MXFP4_E2M1_VEC32";
        c.compiled = matmul_v4::hip::IsRcOzakiHipCompiled();
        (void)matmul_v4::hip::SelfQualifyRcOzakiHipMxfp4Once();
        c.attempted = matmul_v4::hip::IsRcOzakiHipMxfp4Attempted();
        c.qualified = matmul_v4::hip::IsRcOzakiHipMxfp4Qualified();
        c.backend = matmul_v4::hip::RcOzakiHipMxfp4Backend();
        c.deficit = c.qualified ? std::string{} : matmul_v4::hip::RcOzakiHipMxfp4Deficit();
        out.push_back(std::move(c));
    }

    // --- HIP RC ExactPanels (INT8 MFMA) — not native MX ---
    {
        ProviderClaim c;
        c.provider = "hip_rc_exact_panels";
        c.format = "INT8_ExactGemm_MFMA";
        c.compiled = matmul_v4::hip::IsRcOzakiHipCompiled();
        (void)matmul_v4::hip::SelfQualifyRcOzakiHipExactPanelsOnce();
        c.attempted = c.compiled; // self-qual runs when compiled
        c.qualified = matmul_v4::hip::IsRcOzakiHipExactPanelsQualified();
        c.backend = c.qualified ? "hip_exactgemm_mfma_int8" : "";
        c.deficit = c.qualified ? std::string{} : matmul_v4::hip::RcOzakiHipDeficit();
        out.push_back(std::move(c));
    }

    // --- HIP LT native MXFP4/FP8 ---
    {
        const auto prov = matmul_v4::hip::ProbeLtHipMxNativeProvenance();
        ProviderClaim c4;
        c4.provider = "hip_lt_mxfp4";
        c4.format = "OCP_MXFP4_E2M1_VEC32";
        c4.compiled = matmul_v4::hip::IsRcOzakiHipCompiled(); // same HIP TU gate
        c4.attempted = prov.native_mxfp4_attempted;
        c4.qualified = prov.native_mxfp4_qualified;
        c4.backend = c4.qualified ? "hipblaslt_blockscale_mxfp4_gfx950" : "";
        c4.deficit = c4.qualified ? std::string{} : "requires gfx950 silicon";
        out.push_back(std::move(c4));

        ProviderClaim c8;
        c8.provider = "hip_lt_mxfp8";
        c8.format = "OCP_MXFP8_E4M3_VEC32";
        c8.compiled = matmul_v4::hip::IsRcOzakiHipCompiled();
        c8.attempted = prov.native_fp8_attempted;
        c8.qualified = prov.native_fp8_qualified;
        c8.backend = c8.qualified ? "hipblaslt_blockscale_mxfp8_gfx950" : "";
        c8.deficit = c8.qualified ? std::string{} : "requires gfx950 silicon";
        out.push_back(std::move(c8));
    }

    // --- Metal RC ExactPanels (best available native exact INT8) ---
    {
        ProviderClaim c;
        c.provider = "metal_rc_exact";
        c.format = "INT8_ExactGemm"; // NEVER OCP MXFP4
        c.compiled = matmul_v4::metal::IsRcOzakiMetalCompiled();
        (void)matmul_v4::metal::SelfQualifyRcOzakiMetalExactPanelsOnce();
        c.attempted = matmul_v4::metal::IsRcOzakiMetalExactPanelsAttempted();
        c.qualified = matmul_v4::metal::IsRcOzakiMetalExactPanelsQualified();
        c.backend = matmul_v4::metal::RcOzakiMetalExactPanelsBackend();
        c.deficit = c.qualified ? std::string{} : matmul_v4::metal::RcOzakiMetalDeficit();
        out.push_back(std::move(c));
    }

    // --- Metal RC MXFP4 — always fail-closed ---
    {
        ProviderClaim c;
        c.provider = "metal_rc_mxfp4";
        c.format = "unavailable_OCP_MXFP4"; // honest: not admitted
        c.compiled = matmul_v4::metal::IsRcOzakiMetalCompiled();
        (void)matmul_v4::metal::SelfQualifyRcOzakiMetalMxfp4Once();
        c.attempted = false; // no OCP surface to attempt
        c.qualified = matmul_v4::metal::IsRcOzakiMetalMxfp4Qualified();
        c.backend = matmul_v4::metal::RcOzakiMetalMxfp4Backend();
        c.deficit = "no OCP MXFP4 RC tensor path on Metal (INT8 ≠ native MX)";
        out.push_back(std::move(c));
    }

    // --- TPU PJRT RC episode ---
    {
        ProviderClaim c;
        c.provider = "tpu_rc_episode";
        c.format = "TPU_MXU_ExactGemm";
        c.compiled = matmul_v4::tpu::IsRcTpuCompiled();
        c.qualified = matmul_v4::tpu::IsTpuPjrtRcEpisodeAvailable();
        c.attempted = matmul_v4::tpu::IsRcTpuAttempted();
        c.backend = c.qualified ? "pjrt_tpu_rc_episode" : "";
        c.deficit = c.qualified ? std::string{} : matmul_v4::tpu::RcTpuDeficit();
        out.push_back(std::move(c));
    }

    // --- Trainium Neuron RC episode ---
    {
        ProviderClaim c;
        c.provider = "trainium_rc_episode";
        c.format = "Trainium_BF16_tensor_engine";
        c.compiled = matmul_v4::trainium::IsRcTrainiumCompiled();
        c.qualified = matmul_v4::trainium::IsTrainiumNeuronRcEpisodeAvailable();
        c.attempted = matmul_v4::trainium::IsRcTrainiumAttempted();
        c.backend = c.qualified ? "neuron_nrt_rc_episode" : "";
        c.deficit = c.qualified ? std::string{} : matmul_v4::trainium::RcTrainiumDeficit();
        out.push_back(std::move(c));
    }

    // --- Ascend CANN RC episode (Cube INT8 — not native MX float) ---
    {
        ProviderClaim c;
        c.provider = "ascend_rc_episode";
        c.format = "Ascend_Cube_INT8_ExactGemm";
        c.compiled = matmul_v4::ascend::IsRcAscendCompiled();
        c.qualified = matmul_v4::ascend::IsAscendRcEpisodeAvailable();
        c.attempted = matmul_v4::ascend::IsRcAscendAttempted();
        c.backend = c.qualified ? "cann_cube_int8_rc_episode" : "";
        c.deficit = c.qualified ? std::string{} : matmul_v4::ascend::RcAscendDeficit();
        out.push_back(std::move(c));
    }

    return out;
}

} // namespace matmul::v4
