// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_DOMAIN_REGISTRY_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_DOMAIN_REGISTRY_H

#include <matmul/matmul_v4_rc_stage3_safe_v12_fs_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_safe_v12_domain_registry {

namespace aq = air_quotient;
namespace aht = alg_hash_typed;
namespace fsair = stage3_safe_v12_fs_air;
namespace gf = gkr_field;
namespace safe = safe_v12;

inline constexpr uint16_t kDomainRegistryVersionV12 = 1;
inline constexpr uint32_t kTranscriptChannelsV12 = 5;
inline constexpr uint32_t kGoldilocksTagLanesV12 = 4;
inline constexpr uint32_t kSafeNominalSecurityBitsV12 = 128;
inline constexpr uint32_t kSafeV1SecurityTargetBitsV12 = 64;

struct DomainRegistryEntryV12 {
    fsair::ChannelV12 channel{fsair::ChannelV12::AirQuotient};
    uint32_t lane{0};
    aht::RoleV12 capacity_role{
        aht::RoleV12::TranscriptAirLambda};
    std::vector<uint8_t> application_domain;
    std::vector<uint8_t> typed_domain;
    std::vector<uint32_t> canonical_io_words;
    std::vector<fsair::CallSpecV12> calls;
    std::array<gf::Fp, safe::kSafeCapacityV12> tag{};
    alg_hash::Digest entry_commitment{};

    bool operator==(const DomainRegistryEntryV12&) const = default;
};

/**
 * Shape-derived registry for all five SAFE transcript oracles in the V12
 * proof: AIR, two FRI lanes, and two shared-tax query lanes.
 *
 * This is recomputed by the verifier; no network registry hash is invented
 * here. The root is a typed Poseidon2 field digest over injectively framed
 * u32/byte data and all four canonical tag lanes.
 */
struct TranscriptDomainRegistryV12 {
    uint16_t version{kDomainRegistryVersionV12};
    fsair::ShapeV12 shape{};
    std::array<DomainRegistryEntryV12, kTranscriptChannelsV12> entries{};
    alg_hash::Digest root{};
    uint32_t exact_call_count{0};
    bool manifest_rebuilt_from_shape{false};
    bool exact_five_channel_inventory{false};
    bool io_patterns_fixed{false};
    bool pairwise_domains_distinct{false};
    bool pairwise_tags_distinct{false};
    bool all_tags_fill_capacity{false};
    bool root_field_native{false};
    bool valid{false};
    std::string note;

    bool operator==(const TranscriptDomainRegistryV12&) const = default;
};

struct SafeCrossOracleAuditV12 {
    uint32_t field_element_bits{0};
    uint32_t arithmetic_capacity_elements{0};
    uint32_t tag_elements{0};
    uint32_t registry_oracles{0};
    double ideal_permutation_capacity_bits{0.0};
    bool fixed_io_patterns{false};
    bool pairwise_domain_separators{false};
    bool full_capacity_tags{false};
    bool safe_cross_oracle_parameter_target_met{false};
    /** Explicit cryptographic assumption, not something an AIR can prove. */
    bool concrete_poseidon2_permutation_assumption_registered{false};
    /** Becomes true only when the normalized parent consumes the root pin. */
    bool registry_root_recursively_consumed{false};
    bool conditional_cross_oracle_reduction_complete{false};
    std::string note;
};

/**
 * Four direct equality constraints:
 *
 *   proof_owned_registry_root[i] == verifier_rebuilt_registry_root[i].
 *
 * Only the rebuilt root is preprocessed. The proof copy is ordinary witness.
 */
struct DomainRegistryRootPinAirV12 {
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    alg_hash::Digest expected_root{};
    alg_hash::Digest proof_root{};
    uint32_t verifier_owned_preprocessed_columns{0};
    uint32_t proof_owned_preprocessed_columns{0};
    uint32_t equality_constraints{0};
    uint32_t violations{0};
    bool valid{false};
    bool recursively_consumed{false};
    std::string note;
};

[[nodiscard]] bool BuildTranscriptDomainRegistryV12(
    const fsair::ManifestV12& manifest,
    TranscriptDomainRegistryV12& out,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateTranscriptDomainRegistryV12(
    const fsair::ManifestV12& manifest,
    const TranscriptDomainRegistryV12& registry,
    std::string* why = nullptr);

[[nodiscard]] SafeCrossOracleAuditV12
AssessSafeCrossOracleParametersV12(
    const TranscriptDomainRegistryV12& registry);

[[nodiscard]] bool BuildDomainRegistryRootPinAirV12(
    const TranscriptDomainRegistryV12& registry,
    const alg_hash::Digest& proof_root,
    DomainRegistryRootPinAirV12& out,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateDomainRegistryRootPinAirV12(
    const TranscriptDomainRegistryV12& registry,
    const alg_hash::Digest& proof_root,
    const DomainRegistryRootPinAirV12& air,
    std::string* why = nullptr);

inline constexpr bool kDomainRegistryExecutableV12 = true;
inline constexpr bool kDomainRegistryRootPinAirExecutableV12 = true;
inline constexpr bool kDomainRegistryRootRecursivelyConsumedV12 = false;
inline constexpr bool kSafeCrossOracleReductionCertifiedV12 = false;

static_assert(!kDomainRegistryRootRecursivelyConsumedV12);
static_assert(!kSafeCrossOracleReductionCertifiedV12);

} // namespace matmul::v4::rc::stage3_safe_v12_domain_registry

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_DOMAIN_REGISTRY_H
