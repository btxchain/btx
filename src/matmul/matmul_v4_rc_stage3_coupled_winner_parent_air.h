// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_WINNER_PARENT_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_WINNER_PARENT_AIR_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_coupled_winner_child_binding.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class CBlockHeader;

namespace matmul::v4::rc::coupled_winner_parent_air {

namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kRootLimbsV1 = 8;
inline constexpr uint32_t kMaxTerminalCellsV1 = 1U << 22;

/**
 * Canonical source family for one proof-owned parent cell.
 *
 * Values are format ABI: the parent row schedule and its R0 commitment use
 * these exact numeric tags.
 */
enum class TerminalFamilyV1 : uint16_t {
    Binding = 1,
    Product = 2,
    BankHash = 3,
    BankDequant = 4,
    InitialHash = 5,
    InitialDequant = 6,
    Gemm = 7,
    SignedRange = 8,
    ExchangeHash = 9,
    Exchange = 10,
    Permutation = 11,
    MixHash = 12,
    Mix = 13,
    ExtractHash = 14,
    Extract = 15,
    BankRootHash = 16,
    BarrierHash = 17,
    DigestHash = 18,
    RootVector = 19,
    SemanticShard = 20,
};

enum class TerminalKindV1 : uint16_t {
    StatementRoot = 1,
    ShapeRoot = 2,
    PinRoot = 3,
    TraceRoot = 4,
    R0GroupRoot = 5,
    DependentGroupRoot = 6,
    QuotientGroupRoot = 7,
    TerminalRoot = 8,
    ProductRoot = 9,
    ManifestRoot = 10,
    Count = 11,
};

/**
 * One exact verifier-derived cell. `instance` and `subordinal` make repeated
 * proof families unambiguous without relying on vector position alone.
 */
struct TerminalCellV1 {
    TerminalFamilyV1 family{TerminalFamilyV1::Binding};
    TerminalKindV1 kind{TerminalKindV1::StatementRoot};
    uint64_t instance{0};
    uint32_t subordinal{0};
    uint256 value{};

    bool operator==(const TerminalCellV1&) const = default;
};

struct LayoutV1 {
    uint32_t active{0};
    uint32_t ordinal{0};
    uint32_t family{0};
    uint32_t kind{0};
    uint32_t instance_lo{0};
    uint32_t instance_hi{0};
    uint32_t subordinal{0};
    uint32_t claimed_root_base{0};
    uint32_t verified_root_base{0};
    uint32_t phase0_end{0};
    uint32_t difference_base{0};
    uint32_t n_columns{0};
};

struct ParentProofV1 {
    uint16_t version{kVersionV1};
    uint32_t terminal_cells{0};
    uint32_t trace_rows{0};
    uint256 terminal_table_commitment{};
    uint256 r0_row_group_root{};
    aq::AirQuotientSplitRapRowsProof proof;
};

/**
 * Strict canonical codec for the proof-owned parent itself.
 *
 * This deliberately serializes no child-verification receipt or readiness
 * value.  A consumer must still reconstruct the complete terminal table from
 * the durable child-proof inventory and call VerifyV1.  The codec exists so
 * that a later consensus envelope cannot silently substitute a host boolean
 * or an unauthenticated commitment for the native SAFE proof.
 */
[[nodiscard]] size_t SerializeParentProofV1(
    const ParentProofV1& proof,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

[[nodiscard]] std::optional<ParentProofV1>
DeserializeParentProofV1(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);

/**
 * Enumerate the binding fields and every proof-object root consumed by the
 * bounded coupled verifier. No caller-supplied completion bit participates.
 */
[[nodiscard]] bool CollectTerminalCellsV1(
    const RCStage3CoupledWinnerChildBindingV1& binding,
    const RCStage3BoundedCoupledSemanticComposition& children,
    std::vector<TerminalCellV1>& out,
    std::string* why = nullptr);

[[nodiscard]] uint256 CommitTerminalCellsV1(
    const std::vector<TerminalCellV1>& cells);

/**
 * Build the constant-width parent equality AIR.
 *
 * R0 contains the complete row schedule plus both the claimed and
 * verifier-derived root limbs. Rdep contains their eight differences.
 * The SAFE FixedTrace V3 verifier pins the exact R0 root reconstructed from
 * public inputs and already-verified child proof objects.
 */
[[nodiscard]] bool BuildConstraintSystemV1(
    uint32_t terminal_cells,
    aq::AirConstraintSystem<gf::Fp3>& out,
    LayoutV1* layout = nullptr,
    std::string* why = nullptr);

[[nodiscard]] bool BuildWitnessV1(
    const std::vector<TerminalCellV1>& cells,
    const LayoutV1& layout,
    uint32_t trace_rows,
    std::vector<std::vector<gf::Fp3>>& out,
    std::string* why = nullptr);

/**
 * Native-v1 attachment path.
 *
 * This first executes the complete bounded child verifier and recomputes the
 * winner binding. It then proves the canonical terminal cells in one SAFE
 * parent. It is a sound end-to-end attachment, but native child verification
 * is not yet sublinear recursive verification.
 */
[[nodiscard]] bool ProveV1(
    const CBlockHeader& finalized_header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options,
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledWinnerReceiptV1& winner,
    const RCStage3BoundedCoupledSemanticComposition& children,
    const RCStage3CoupledWinnerChildBindingV1& expected_binding,
    ParentProofV1& out,
    const aq::AirProveOptions& prove_options = {},
    std::string* why = nullptr);

/** Re-execute the same child proofs, rebuild R0, and verify the SAFE parent. */
[[nodiscard]] bool VerifyV1(
    const CBlockHeader& finalized_header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options,
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledWinnerReceiptV1& winner,
    const RCStage3BoundedCoupledSemanticComposition& children,
    const RCStage3CoupledWinnerChildBindingV1& expected_binding,
    const ParentProofV1& proof,
    std::string* why = nullptr);

inline constexpr bool kNativeChildProofVerificationExecutableV1 = true;
inline constexpr bool kAllTerminalCellsMappedV1 = true;
inline constexpr bool kCompleteChildVerifierSameParentV1 = false;
inline constexpr bool kRecursivelyConsumedV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;

static_assert(kNativeChildProofVerificationExecutableV1);
static_assert(kAllTerminalCellsMappedV1);
static_assert(!kCompleteChildVerifierSameParentV1);
static_assert(!kRecursivelyConsumedV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::coupled_winner_parent_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_WINNER_PARENT_AIR_H
