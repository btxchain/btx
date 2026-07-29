// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_DERIVED_HASH_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_DERIVED_HASH_AIR_H

#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_derived_hash_air {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace gf = gkr_field;
namespace pa = stage3_poseidon_air;
namespace tape = stage3_multirow_v13_proof_tape_air;

inline constexpr uint16_t kDerivedHashAirVersionV1 = 1;
inline constexpr uint32_t kRateV1 = alg_hash::kAlgHashRate;
inline constexpr uint32_t kDigestLanesV1 =
    alg_hash::kAlgHashDigestLen;

struct SelectedPointsV1 {
    gf::Fp3 z1{};
    gf::Fp3 z2{};

    friend bool operator==(
        const SelectedPointsV1& a,
        const SelectedPointsV1& b)
    {
        return gf::Eq(a.z1, b.z1) &&
            gf::Eq(a.z2, b.z2);
    }
};

struct BindingV1 {
    Fri3AlgDigest shape_commit{};
    Fri3AlgDigest ood_evaluation_commit{};

    friend bool operator==(
        const BindingV1&,
        const BindingV1&) = default;
};

struct LayoutV1 {
    pa::Layout poseidon{};
    uint32_t message_base{0};
    uint32_t state_base{0};
    uint32_t active{0};
    uint32_t first{0};
    uint32_t terminal{0};
    uint32_t shape{0};
    uint32_t ood{0};
    uint32_t source_active_base{0};
    uint32_t fp_source_base{0};
    uint32_t selected_source_base{0};
    uint32_t fixed_active_base{0};
    uint32_t fixed_value_base{0};
    uint32_t low_base{0};
    uint32_t high_base{0};
    uint32_t bit_base{0};
    uint32_t high_is_max_base{0};
    uint32_t high_delta_inverse_base{0};
    uint32_t selected_value_base{0};
    uint32_t digest_byte_base{0};
    uint32_t digest_bit_base{0};
    uint32_t digest_high_is_max_base{0};
    uint32_t digest_high_delta_inverse_base{0};

    [[nodiscard]] uint32_t Message(uint32_t lane) const;
    [[nodiscard]] uint32_t State(uint32_t lane) const;
    [[nodiscard]] uint32_t SourceActive(uint32_t lane) const;
    [[nodiscard]] uint32_t FpSource(uint32_t lane) const;
    [[nodiscard]] uint32_t SelectedSource(uint32_t lane) const;
    [[nodiscard]] uint32_t FixedActive(uint32_t lane) const;
    [[nodiscard]] uint32_t FixedValue(uint32_t lane) const;
    [[nodiscard]] uint32_t Low(uint32_t lane) const;
    [[nodiscard]] uint32_t High(uint32_t lane) const;
    [[nodiscard]] uint32_t Bit(
        uint32_t lane, uint32_t bit) const;
    [[nodiscard]] uint32_t HighIsMax(uint32_t lane) const;
    [[nodiscard]] uint32_t HighDeltaInverse(
        uint32_t lane) const;
    [[nodiscard]] uint32_t SelectedValue(uint32_t lane) const;
    [[nodiscard]] uint32_t DigestByte(
        uint32_t lane, uint32_t byte) const;
    [[nodiscard]] uint32_t DigestBit(
        uint32_t lane, uint32_t byte,
        uint32_t bit) const;
    [[nodiscard]] uint32_t DigestHighIsMax(
        uint32_t lane) const;
    [[nodiscard]] uint32_t DigestHighDeltaInverse(
        uint32_t lane) const;
    [[nodiscard]] uint32_t End() const;
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1();

enum class PayloadFamilyV1 : uint8_t {
    ShapeCommit = 1,
    OodEvaluationCommit = 2,
};

struct SourceExportV1 {
    abi::SourceKeyV1 key{};
    abi::SourceKeyV1 high_key{};
    uint32_t source_address{UINT32_MAX};
    uint32_t high_source_address{UINT32_MAX};
    uint32_t row{0};
    uint32_t lane{0};
    uint32_t low_column{0};
    uint32_t high_column{0};
    uint32_t value_column{0};
    bool u32_source{false};
    bool has_high_source{false};
    bool selected_point_source{false};

    friend bool operator==(
        const SourceExportV1&,
        const SourceExportV1&) = default;
};

struct DigestExportV1 {
    PayloadFamilyV1 family{PayloadFamilyV1::ShapeCommit};
    uint32_t terminal_row{0};
    uint32_t permutation_base{0};
    std::array<std::array<uint32_t, 8>,
               kDigestLanesV1> byte_column{};
    bool value_is_virtual_poseidon2_output{false};
};

struct ScheduleV1 {
    tape::PublicShapeV1 shape{};
    uint32_t active_rows{0};
    uint32_t trace_rows{0};
    uint32_t shape_terminal_row{0};
    uint32_t ood_terminal_row{0};
    std::vector<SourceExportV1> source_exports;
    std::array<DigestExportV1, 2> digest_exports{};
    bool exact_native_domains{false};
    bool exact_native_lane_order{false};
    bool exact_10star_padding{false};
    bool proof_tape_addresses_resolved{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildScheduleV1(
    const tape::PublicShapeV1& shape,
    ScheduleV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildConstraintSystemV1(
    const tape::PublicShapeV1& shape,
    const BindingV1& binding,
    aq::AirConstraintSystem<gf::Fp3>& out,
    LayoutV1* layout = nullptr,
    ScheduleV1* schedule = nullptr,
    std::string* why = nullptr);

struct ProductV1 {
    LayoutV1 layout{};
    ScheduleV1 schedule{};
    BindingV1 binding{};
    SelectedPointsV1 selected_points{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t violations{0};
    bool canonical_safe_v13_tape_decoded{false};
    bool source_values_ordinary_columns{false};
    bool no_preprocessed_proof_values{false};
    bool canonical_two_u32_goldilocks_air{false};
    bool selected_points_equal_tape_z_air{false};
    bool exact_poseidon2_relations{false};
    bool proof_tape_same_parent_equality_executed{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ProductV1 BuildProductV1(
    const tape::PublicShapeV1& shape,
    const std::vector<uint32_t>& canonical_safe_v13_words,
    const SelectedPointsV1& selected_points);

struct ProofV1 {
    uint16_t version{kDerivedHashAirVersionV1};
    BindingV1 binding{};
    aq::AirQuotientRowsProof proof{};
    bool proof_tape_same_parent_equality_executed{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] bool ProveV1(
    const ProductV1& product,
    const uint256& fs_seed,
    ProofV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyV1(
    const tape::PublicShapeV1& shape,
    const BindingV1& expected_binding,
    const ProofV1& proof,
    const uint256& fs_seed,
    std::string* why = nullptr);

[[nodiscard]] uint32_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

inline constexpr bool kDerivedHashAirExecutableV1 = true;
inline constexpr bool kProofTapeSameParentEqualityExecutedV1 = false;
inline constexpr bool kDerivedHashRecursiveAuthorityReadyV1 = false;

static_assert(!kProofTapeSameParentEqualityExecutedV1);
static_assert(!kDerivedHashRecursiveAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_derived_hash_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_DERIVED_HASH_AIR_H
