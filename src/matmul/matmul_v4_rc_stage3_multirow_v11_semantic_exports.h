// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_EXPORTS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_EXPORTS_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_ctl.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_stream_endpoint.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::multirow_v11_semantic_exports {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace semantic_ctl = multirow_v11_semantic_ctl;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kEndpointCountV1 = 52;
inline constexpr uint32_t kRoleCountV1 = 14;
inline constexpr uint32_t kRootWordsV1 = 8;
inline constexpr uint32_t kWordBitsV1 = 32;
inline constexpr uint32_t kNoColumnV1 = UINT32_MAX;

/**
 * The proof artifact that owns an endpoint root.
 *
 * `DirectRelationCell` classifies a canonical source column; it is not proof
 * ownership by itself. Every kind below must be backed by a supplied,
 * verifier-rebuilt role artifact before this bridge credits an endpoint:
 *
 *  - VectorOpening: an AlgHash Merkle opening executed inside C_rho;
 *  - WiredLedger: the full Poseidon ledger/sumcheck closer executed in C_rho;
 *  - StreamChild: a separate SHA/XOF/ChaCha child plus C_rho's root pin.
 *
 * A route or metadata record without that executable evidence remains a
 * residual. In particular, `preexisting_literal` is inventory metadata and
 * never authorizes a semantic export.
 */
enum class ProducerKindV1 : uint8_t {
    Absent = 0,
    DirectRelationCell = 1,
    VectorOpening = 2,
    WiredLedger = 3,
    StreamChild = 4,
};

struct CanonicalExportRouteV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint32_t ordinal{0};
    ProducerKindV1 kind{ProducerKindV1::Absent};
    uint32_t relation_column{kNoColumnV1};
    const char* producer_module{nullptr};
    const char* producer_function{nullptr};
    bool preexisting_literal{false};
    bool requires_stream_child{false};
};

/** A heavy §4 child supplied by the role-proof producer. */
struct StreamChildArtifactV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3StreamEndpointClosure closure;
};

/**
 * One endpoint exported from an actually executed role AIR.
 *
 * The eight u32 words are the canonical two-limb representation of the four
 * Goldilocks lanes in `committed_root`. They are not arbitrary semantic
 * fixtures. `role_air_witness_executed` means the witness satisfies a
 * verifier-rebuilt C_rho whose root constants are exactly `committed_root`.
 */
struct ProofOwnedExportV1 {
    CanonicalExportRouteV1 route;
    alg_hash::Digest committed_root{};
    std::array<uint32_t, kRootWordsV1> root_words{};
    uint32_t export_tag_base{kNoColumnV1};
    uint32_t export_word_base{kNoColumnV1};
    uint32_t export_bits_base{kNoColumnV1};
    bool role_air_witness_executed{false};
    bool stream_child_witness_executed{false};
    bool same_trace_root_equality{false};
    bool canonical_u32_limbs{false};
    bool recursively_consumed{false};
    std::string residual;
};

/** One rebuilt role AIR plus its canonical root-export columns. */
struct RoleExportProofV1 {
    RCStage3RelationRole role{};
    uint32_t source_columns{0};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<ProofOwnedExportV1> exports;
    uint32_t violations{UINT32_MAX};
    bool source_shape_canonical{false};
    bool exact_endpoint_order{false};
    bool exact_root_count{false};
    bool valid{false};
    std::string note;
};

struct InventoryEntryV1 {
    CanonicalExportRouteV1 route;
    bool supplied_role_artifact{false};
    bool executed_role_artifact{false};
    bool executed_stream_child{false};
    bool literal_proof_owned_export{false};
    bool recursively_consumed{false};
    std::string residual;
};

/**
 * Consolidated local export result. This is deliberately not recursive
 * authority: it proves which role roots are available as canonical V11
 * semantic words, but the normalized parent must still consume every role
 * proof and every heavy stream child.
 */
struct ProductV1 {
    uint16_t version{kVersionV1};
    std::vector<RoleExportProofV1> role_proofs;
    std::vector<InventoryEntryV1> endpoints;
    std::vector<semantic_ctl::EndpointCellsV1> semantic_ctl_cells;
    /** Canonical routes with a direct source column; inventory, not credit. */
    uint32_t preexisting_literal_endpoints{0};
    /** Endpoints backed by an executed, verifier-rebuilt role export. */
    uint32_t newly_executed_export_endpoints{0};
    uint32_t literal_proof_owned_endpoints{0};
    uint32_t residual_endpoints{0};
    uint32_t complete_roles{0};
    bool exact_inventory{false};
    bool no_duplicate_roles{false};
    bool no_duplicate_stream_children{false};
    bool all_supplied_artifacts_valid{false};
    bool recursive_consumption_complete{false};
    bool production_authority{false};
    std::string note;
};

/** Exact immutable route table for all 52 semantic endpoints. */
[[nodiscard]] std::array<CanonicalExportRouteV1, kEndpointCountV1>
CanonicalExportRoutesV1();

/**
 * Consume already-built role products. No role witness is synthesized here.
 * The verifier rebuilds each role CS from the artifact's committed roots,
 * executes the supplied witness, and only then adds its root export columns.
 * Stream endpoints additionally require the matching heavy child artifact.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const std::vector<RCStage3RoleAirProduct>& role_artifacts,
    const std::vector<StreamChildArtifactV1>& stream_children);

[[nodiscard]] bool ValidateRoleExportProofV1(
    const RoleExportProofV1& proof,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateProductV1(
    const ProductV1& product,
    std::string* why = nullptr);

/**
 * Emit the exact 52 V11 semantic-CTL cells only after every endpoint has an
 * executed proof-owned export. Partial products return an empty vector rather
 * than filling residual rows with deterministic or zero fixtures. This is an
 * adapter only: V11 semantic CTL still has to be proven and recursively
 * consumed by the parent.
 */
[[nodiscard]] std::vector<semantic_ctl::EndpointCellsV1>
BuildSemanticCtlCellsV1(const ProductV1& product);

inline constexpr bool kRecursiveConsumptionReadyV1 = false;
inline constexpr bool kProductionAuthorityV1 = false;
static_assert(!kRecursiveConsumptionReadyV1);
static_assert(!kProductionAuthorityV1);

} // namespace matmul::v4::rc::multirow_v11_semantic_exports

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_EXPORTS_H
