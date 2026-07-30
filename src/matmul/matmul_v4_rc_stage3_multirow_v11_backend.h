// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_BACKEND_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_BACKEND_H

#include <matmul/matmul_v4_rc_stage3_multirow_p2_transcript.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_proof_abi.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_backend {

namespace p2 = stage3_multirow_p2_transcript;
namespace abi = stage3_multirow_v11_proof_abi;
namespace gf = gkr_field;

/**
 * Additive V11 wire envelope. The nested Split-RAP object is only a convenient
 * in-memory schema: it retains outer version 1 / FMR2 version 2 so none of the
 * frozen V2 codec or verifier selectors change. V11 has its own mandatory
 * wrapper magic, protocol version, domain, Fiat-Shamir schedule and verifier.
 */
inline constexpr uint32_t kWireMagicV1 = 0x31423156U; // "V1B1"
inline constexpr uint16_t kWireFormatVersionV1 = 1;
inline constexpr uint32_t kProtocolVersionV11 = p2::kProtocolVersionV1;
inline constexpr uint64_t kProtocolDomainV11 = p2::kProtocolDomainV1;
inline constexpr size_t kMaxProofBytesV1 =
    air_quotient::kAirQuotientSplitRapRowsMaxProofBytesHard + 64;

struct ProofV1 {
    abi::EnvelopeV1 envelope{};
};

/**
 * Result of the mandatory pre-quotient phase. The two trace roots and all
 * statement dimensions are fixed before air_constraint_lambda is returned.
 * Prover caches are checked hints and are never serialized.
 */
struct TracePrecommitV1 {
    uint256 public_fs_seed{};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t quotient_len{0};
    uint32_t n_coeffs{0};
    std::vector<uint32_t> base_column_indices;
    std::vector<std::vector<gf::Fp3>> r0;
    std::vector<std::vector<gf::Fp3>> rdep;
    std::shared_ptr<Fri3AlgRowTreeCache> r0_cache;
    std::shared_ptr<Fri3AlgRowTreeCache> rdep_cache;
    gf::Fp3 air_constraint_lambda{};
    bool transcript_derived_before_quotient{false};
    bool valid{false};
    std::string note;
};

struct ProveResultV1 {
    ProofV1 proof{};
    p2::ReceiptV1 transcript{};
    std::vector<std::shared_ptr<Fri3AlgRowTreeCache>> group_caches;
    size_t proof_bytes{0};
    bool q192_with_replacement{false};
    bool self_verified{false};
    bool ok{false};
    std::string note;
};

struct AirProveResultV1 {
    ProveResultV1 proximity{};
    std::vector<gf::Fp3> remainder;
    bool division_exact{false};
    bool quotient_built_after_v11_lambda{false};
    bool ok{false};
    std::string note;
};

/**
 * Commit R0/Rdep and derive V11 air_constraint_lambda before Rq exists.
 * Inputs are already coset-shifted coefficient vectors, matching the existing
 * Split-RAP backend boundary.
 */
[[nodiscard]] TracePrecommitV1 PrecommitTraceV1(
    const std::vector<std::vector<gf::Fp3>>& r0,
    const std::vector<std::vector<gf::Fp3>>& rdep,
    uint32_t trace_rows,
    uint32_t trace_columns,
    uint32_t quotient_len,
    uint32_t n_coeffs,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed);

/**
 * Supply the quotient polynomial only after PrecommitTraceV1 returned its
 * transcript-derived lambda. Produces the complete Q192/K2 V11 FRI proof and
 * the two authenticated next-row openings needed by Split-RAP transition AIR.
 */
[[nodiscard]] ProveResultV1 CompleteWithQuotientV1(
    const TracePrecommitV1& precommit,
    const std::vector<gf::Fp3>& quotient);

/**
 * Complete additive Split-RAP authority primitive. It interpolates the raw AIR
 * trace, commits R0/Rdep, derives V11 air_lambda, constructs C(X)/Z_H(X), then
 * enters CompleteWithQuotientV1. No sampled/exact replay path is used.
 */
[[nodiscard]] AirProveResultV1 ProveAirQuotientV1(
    const air_quotient::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed);

/** Complete native verifier for the V11 FRI/DEEP/current+next-opening layer. */
[[nodiscard]] bool VerifyV1(
    const ProofV1& proof,
    p2::ReceiptV1* transcript = nullptr,
    std::string* why = nullptr);

/** Verify FRI plus C(y)=Z_H(y)Q(y) at every authenticated Q192 site. */
[[nodiscard]] bool VerifyAirQuotientV1(
    const air_quotient::AirConstraintSystem<gf::Fp3>& cs,
    const ProofV1& proof,
    const std::vector<uint32_t>& expected_base_column_indices,
    const uint256& expected_public_fs_seed,
    std::string* why = nullptr);

/** New wrapper codec; never emits or accepts bare ASR1/FMR2 bytes. */
[[nodiscard]] size_t SerializeV1(
    const ProofV1& proof,
    std::vector<unsigned char>& out);
[[nodiscard]] std::optional<ProofV1> DeserializeV1(
    const std::vector<unsigned char>& in,
    std::string* why = nullptr);

struct ReadinessV1 {
    bool two_phase_air_lambda_executable{true};
    bool poseidon_transcript_executable{true};
    bool sequential_fold_challenges_executable{true};
    bool q192_k2_with_replacement_executable{true};
    bool current_and_next_openings_executable{true};
    bool canonical_versioned_codec_executable{true};
    bool split_rap_air_quotient_dispatch_executable{true};
    bool same_parent_transcript_aliases_executable{false};
    bool recursive_authority_ready{false};
};

[[nodiscard]] constexpr ReadinessV1 CurrentReadinessV1()
{
    return {};
}

} // namespace matmul::v4::rc::stage3_multirow_v11_backend

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_BACKEND_H
