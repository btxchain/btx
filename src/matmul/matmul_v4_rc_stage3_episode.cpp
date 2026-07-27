// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode.h>

#include <crypto/sha256.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc {
namespace {

constexpr std::array<RCStage3RelationRole, 6> EPISODE_ROLES{
    RCStage3RelationRole::EpisodeDeterministicBuilder,
    RCStage3RelationRole::EpisodeGemm,
    RCStage3RelationRole::EpisodeExtract,
    RCStage3RelationRole::EpisodeWiring,
    RCStage3RelationRole::EpisodeTileTree,
    RCStage3RelationRole::EpisodeDigest,
};

constexpr uint64_t Bit(RCStage3EpisodeObligation obligation)
{
    return static_cast<uint64_t>(obligation);
}

constexpr uint64_t BUILDER_COVERAGE =
    Bit(RCStage3EpisodeObligation::BuilderParamsFromHeader) |
    Bit(RCStage3EpisodeObligation::BuilderSeedChain) |
    Bit(RCStage3EpisodeObligation::BuilderOperandExpansion) |
    Bit(RCStage3EpisodeObligation::BuilderTraceBinding);
constexpr uint64_t GEMM_COVERAGE =
    Bit(RCStage3EpisodeObligation::GemmEveryLayer) |
    Bit(RCStage3EpisodeObligation::GemmSumcheck) |
    Bit(RCStage3EpisodeObligation::GemmOperandOpenings) |
    Bit(RCStage3EpisodeObligation::GemmSignedAccumulatorRange);
constexpr uint64_t EXTRACT_COVERAGE =
    Bit(RCStage3EpisodeObligation::ExtractEveryTile) |
    Bit(RCStage3EpisodeObligation::ExtractSamplerWalk) |
    Bit(RCStage3EpisodeObligation::ExtractChaChaBinding) |
    Bit(RCStage3EpisodeObligation::ExtractScaleBinding) |
    Bit(RCStage3EpisodeObligation::ExtractDequantAndRange) |
    Bit(RCStage3EpisodeObligation::ExtractOutputBinding);
constexpr uint64_t WIRING_COVERAGE =
    Bit(RCStage3EpisodeObligation::WiringCopies) |
    Bit(RCStage3EpisodeObligation::WiringTransposes) |
    Bit(RCStage3EpisodeObligation::WiringResiduals) |
    Bit(RCStage3EpisodeObligation::WiringRoundOrder);
constexpr uint64_t TILETREE_COVERAGE =
    Bit(RCStage3EpisodeObligation::TileTreeCompleteStream) |
    Bit(RCStage3EpisodeObligation::TileTreeLeafHash) |
    Bit(RCStage3EpisodeObligation::TileTreeInternalHash) |
    Bit(RCStage3EpisodeObligation::TileTreeRootBinding);
constexpr uint64_t DIGEST_COVERAGE =
    Bit(RCStage3EpisodeObligation::DigestRoundRoots) |
    Bit(RCStage3EpisodeObligation::DigestEpisode) |
    Bit(RCStage3EpisodeObligation::DigestHeaderAndTarget) |
    Bit(RCStage3EpisodeObligation::DigestPowBinding);
bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:episode:" + message;
    return false;
}

void WriteU8(std::vector<unsigned char>& out, uint8_t v) { out.push_back(v); }

void WriteU16(std::vector<unsigned char>& out, uint16_t v)
{
    out.push_back(static_cast<unsigned char>(v));
    out.push_back(static_cast<unsigned char>(v >> 8));
}

void WriteU32(std::vector<unsigned char>& out, uint32_t v)
{
    for (unsigned i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(v >> (8 * i)));
    }
}

void WriteU64(std::vector<unsigned char>& out, uint64_t v)
{
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>(v >> (8 * i)));
    }
}

void WriteUint256(std::vector<unsigned char>& out, const uint256& v)
{
    out.insert(out.end(), v.data(), v.data() + v.size());
}

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes) : m_bytes(bytes) {}

    bool ReadU8(uint8_t& out)
    {
        if (Remaining() < 1) return false;
        out = m_bytes[m_pos++];
        return true;
    }

    bool ReadU16(uint16_t& out)
    {
        if (Remaining() < 2) return false;
        out = static_cast<uint16_t>(m_bytes[m_pos]) |
              (static_cast<uint16_t>(m_bytes[m_pos + 1]) << 8);
        m_pos += 2;
        return true;
    }

    bool ReadU32(uint32_t& out)
    {
        if (Remaining() < 4) return false;
        out = 0;
        for (unsigned i = 0; i < 4; ++i) {
            out |= static_cast<uint32_t>(m_bytes[m_pos + i]) << (8 * i);
        }
        m_pos += 4;
        return true;
    }

    bool ReadU64(uint64_t& out)
    {
        if (Remaining() < 8) return false;
        out = 0;
        for (unsigned i = 0; i < 8; ++i) {
            out |= static_cast<uint64_t>(m_bytes[m_pos + i]) << (8 * i);
        }
        m_pos += 8;
        return true;
    }

    bool ReadUint256(uint256& out)
    {
        if (Remaining() < out.size()) return false;
        std::copy_n(m_bytes.data() + m_pos, out.size(), out.data());
        m_pos += out.size();
        return true;
    }

    bool ReadBytes(size_t count, std::vector<unsigned char>& out)
    {
        if (count > Remaining()) return false;
        out.assign(m_bytes.begin() + m_pos, m_bytes.begin() + m_pos + count);
        m_pos += count;
        return true;
    }

    [[nodiscard]] size_t Remaining() const { return m_bytes.size() - m_pos; }

private:
    const std::vector<unsigned char>& m_bytes;
    size_t m_pos{0};
};

bool KnownEngine(RCStage3EpisodeEngine engine)
{
    return engine == RCStage3EpisodeEngine::EpisodeAirV1 ||
           engine == RCStage3EpisodeEngine::WinnerGkrV7NativeV1 ||
           engine == RCStage3EpisodeEngine::DirectNativeV1 ||
           engine == RCStage3EpisodeEngine::RecursionPrototypeV1;
}

uint256 Sha256d(const std::vector<unsigned char>& bytes)
{
    unsigned char first[CSHA256::OUTPUT_SIZE];
    uint256 out;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(first);
    CSHA256().Write(first, sizeof(first)).Finalize(out.data());
    return out;
}

std::vector<RCStage3EpisodeRelationGap> Gaps()
{
    // Per-role missing masks are COMPUTED from the measured
    // kRCStage3Episode*RecursionEnginesExecuted flags (matmul_v4_rc_stage3_
    // episode.h). Each true flag is backed by the matching case in
    // matmul_v4_rc_stage3_episode_recursion_prototype_tests.cpp driving that
    // role's real C_rho through AirQuotientProve/Verify +
    // air_recurse::ProveAggregate/VerifyAggregate to
    // constraints_resolved && backend_shape_supported. Shared cross-lane
    // recursive authority gates remain tracked independently by the ledger.
    const uint64_t builder_missing =
        kRCStage3EpisodeBuilderRecursionEnginesExecuted ? 0 : BUILDER_COVERAGE;
    const uint64_t gemm_missing =
        kRCStage3EpisodeGemmRecursionEnginesExecuted
            ? 0
            : (Bit(RCStage3EpisodeObligation::GemmEveryLayer) |
               Bit(RCStage3EpisodeObligation::GemmOperandOpenings) |
               Bit(RCStage3EpisodeObligation::GemmSignedAccumulatorRange));
    const uint64_t extract_missing =
        kRCStage3EpisodeExtractRecursionEnginesExecuted ? 0 : EXTRACT_COVERAGE;
    const uint64_t wiring_missing =
        kRCStage3EpisodeWiringRecursionEnginesExecuted ? 0 : WIRING_COVERAGE;
    const uint64_t tiletree_missing =
        kRCStage3EpisodeTileTreeRecursionEnginesExecuted ? 0 : TILETREE_COVERAGE;
    const uint64_t digest_missing =
        kRCStage3EpisodeDigestRecursionEnginesExecuted ? 0 : DIGEST_COVERAGE;

    const std::string builder_reason =
        kRCStage3EpisodeBuilderRecursionEnginesExecuted
            ? "BuildRCStage3NoKernelRoleAir (Params opening + SeedChain/"
              "OperandXof stream + BuilderTrace wired) now executes through "
              "AirQuotientProve/Verify + ProveAggregate/VerifyAggregate to "
              "constraints_resolved && backend_shape_supported; authority "
              "remains blocked ONLY by shared cross-lane recursive gates"
            : "no proof-only header/params/seed/XOF builder; V7 and episode AIR "
              "regenerate or trust SHA-derived preprocessing natively";
    const std::string gemm_reason =
        kRCStage3EpisodeGemmRecursionEnginesExecuted
            ? "sumcheck endpoint support plus an exact Λ manifest, range AIR, "
              "A/B/Y proof obligations, and range-to-Extract CTL pins exist, "
              "and matmul_v4_rc_stage3_episode_recursion_prototype_tests.cpp "
              "now drives the real recursive child proof engine "
              "(BuildRCStage3EpisodeGemmRoleAir -> AirQuotientProve/Verify -> "
              "air_recurse::ProveAggregate/VerifyAggregate) to "
              "constraints_resolved && backend_shape_supported for a genuine "
              "relation instance; the role's authority remains blocked ONLY "
              "by the shared cross-lane recursive gates in "
              "matmul_v4_rc_stage3_recursive.h, tracked independently"
            : "sumcheck endpoint support plus an exact Λ manifest, range AIR, "
              "A/B/Y proof obligations, and range-to-Extract CTL pins exist, "
              "but the recursive child proof engines are not executed";
    const std::string extract_reason =
        kRCStage3EpisodeExtractRecursionEnginesExecuted
            ? "BuildRCStage3NoKernelRoleAir (Input/Sampler/Scale/Output "
              "openings + ChaCha stream) now executes through "
              "AirQuotientProve/Verify + ProveAggregate/VerifyAggregate to "
              "constraints_resolved && backend_shape_supported; authority "
              "remains blocked ONLY by shared cross-lane recursive gates"
            : "episode AIR covers accepted-slot low-degree rules and the sibling "
              "manifest exactly partitions every tile with CTL/scale obligations, "
              "but its recursive roots, SHA scale proof, and ChaCha proof are not "
              "executed";
    const std::string wiring_reason =
        kRCStage3EpisodeWiringRecursionEnginesExecuted
            ? "BuildRCStage3EpisodeWiringRoleAir (Copy opening + Transpose/"
              "Residual/RoundOrder wired ledger folds) now executes through "
              "AirQuotientProve/Verify + ProveAggregate/VerifyAggregate to "
              "constraints_resolved && backend_shape_supported; authority "
              "remains blocked ONLY by shared cross-lane recursive gates"
            : "copy/transpose/residual/round-order checks still scan carried native "
              "wires and are not bound by a durable proof-only permutation argument";
    const std::string tiletree_reason =
        kRCStage3EpisodeTileTreeRecursionEnginesExecuted
            ? "BuildRCStage3PureStreamRoleAir(EpisodeTileTree) now executes "
              "through AirQuotientProve/Verify + ProveAggregate/VerifyAggregate "
              "to constraints_resolved && backend_shape_supported; authority "
              "remains blocked ONLY by shared cross-lane recursive gates"
            : "tile-tree closure still hashes the full native stream directly; no "
              "complete recursive hash/stream proof is serialized";
    const std::string digest_reason =
        kRCStage3EpisodeDigestRecursionEnginesExecuted
            ? "BuildRCStage3PureStreamRoleAir(EpisodeDigest) now executes "
              "through AirQuotientProve/Verify + ProveAggregate/VerifyAggregate "
              "to constraints_resolved && backend_shape_supported; authority "
              "remains blocked ONLY by shared cross-lane recursive gates"
            : "episode digest and PoW bindings are native gates over roots that are "
              "not yet supplied by complete proof-only builder/tile-tree relations";

    std::vector<RCStage3EpisodeRelationGap> gaps{
        {RCStage3RelationRole::EpisodeDeterministicBuilder, builder_missing,
         builder_reason},
        {RCStage3RelationRole::EpisodeGemm, gemm_missing, gemm_reason},
        {RCStage3RelationRole::EpisodeExtract, extract_missing, extract_reason},
        {RCStage3RelationRole::EpisodeWiring, wiring_missing, wiring_reason},
        {RCStage3RelationRole::EpisodeTileTree, tiletree_missing, tiletree_reason},
        {RCStage3RelationRole::EpisodeDigest, digest_missing, digest_reason},
    };
    // A role with no missing obligations is not a gap: drop it so
    // Gaps().empty() is exactly true only when every role is genuinely
    // clear, matching the invariant matmul_v4_rc_stage3_global_soundness_
    // ledger.cpp's g1 evidence relies on.
    gaps.erase(std::remove_if(gaps.begin(), gaps.end(),
                              [](const RCStage3EpisodeRelationGap& gap) {
                                  return gap.missing_obligations == 0;
                              }),
              gaps.end());
    return gaps;
}

bool VerifyCompleteEngine(const RCStage3SuccinctProof& statement,
                          const RCStage3EpisodeRelationProof& relation,
                          std::string* why)
{
    // All known engines have an explicitly documented completeness residual.
    // This switch is exhaustive so a future enum addition cannot silently pass.
    switch (relation.engine) {
    case RCStage3EpisodeEngine::EpisodeAirV1:
        return Fail(why, std::string(RCStage3RelationRoleName(relation.role)) +
                             ":episode_air_has_unproved_residuals");
    case RCStage3EpisodeEngine::WinnerGkrV7NativeV1:
        return Fail(why, std::string(RCStage3RelationRoleName(relation.role)) +
                             ":native_witness_engine_forbidden");
    case RCStage3EpisodeEngine::DirectNativeV1:
        return Fail(why, std::string(RCStage3RelationRoleName(relation.role)) +
                             ":direct_native_engine_forbidden");
    case RCStage3EpisodeEngine::RecursionPrototypeV1: {
        std::string recursive_why;
        const auto recursive =
            DeserializeRCStage3RecursiveProof(relation.payload, &recursive_why);
        if (!recursive.has_value()) {
            return Fail(why, std::string(RCStage3RelationRoleName(relation.role)) +
                                 ":recursive_decode:" + recursive_why);
        }
        if (recursive->role != relation.role) {
            return Fail(why, std::string(RCStage3RelationRoleName(relation.role)) +
                                 ":recursive_role");
        }
        if (!VerifyRCStage3RecursiveProof(statement, *recursive, &recursive_why)) {
            return Fail(why, std::string(RCStage3RelationRoleName(relation.role)) +
                                 ":recursive_verify:" + recursive_why);
        }
        return true;
    }
    }
    return Fail(why, "unknown_engine");
}

} // namespace

bool IsRCStage3EpisodeRole(RCStage3RelationRole role)
{
    return std::find(EPISODE_ROLES.begin(), EPISODE_ROLES.end(), role) !=
           EPISODE_ROLES.end();
}

uint64_t RequiredRCStage3EpisodeCoverage(RCStage3RelationRole role)
{
    switch (role) {
    case RCStage3RelationRole::EpisodeDeterministicBuilder: return BUILDER_COVERAGE;
    case RCStage3RelationRole::EpisodeGemm: return GEMM_COVERAGE;
    case RCStage3RelationRole::EpisodeExtract: return EXTRACT_COVERAGE;
    case RCStage3RelationRole::EpisodeWiring: return WIRING_COVERAGE;
    case RCStage3RelationRole::EpisodeTileTree: return TILETREE_COVERAGE;
    case RCStage3RelationRole::EpisodeDigest: return DIGEST_COVERAGE;
    default: return 0;
    }
}

const char* RCStage3EpisodeEngineName(RCStage3EpisodeEngine engine)
{
    switch (engine) {
    case RCStage3EpisodeEngine::EpisodeAirV1: return "episode_air_v1_partial";
    case RCStage3EpisodeEngine::WinnerGkrV7NativeV1: return "winner_gkr_v7_native";
    case RCStage3EpisodeEngine::DirectNativeV1: return "direct_native";
    case RCStage3EpisodeEngine::RecursionPrototypeV1: return "recursion_prototype";
    }
    return "unknown";
}

uint256 RCStage3EpisodeStatementCommitment(const RCStage3SuccinctProof& statement)
{
    static constexpr std::array<unsigned char, 30> DOMAIN_BYTES{
        'B', 'T', 'X', '_', 'R', 'C', '_', 'S', 'T', 'A', 'G', 'E', '3', '_', 'E',
        'P', '_', 'S', 'T', 'A', 'T', 'E', 'M', 'E', 'N', 'T', '_', 'V', '2', 0,
    };
    std::vector<unsigned char> bytes(DOMAIN_BYTES.begin(), DOMAIN_BYTES.end());
    WriteU8(bytes, static_cast<uint8_t>(statement.statement));
    const auto& p = statement.public_inputs;
    WriteU32(bytes, static_cast<uint32_t>(p.height));
    WriteU32(bytes, p.n_bits);
    WriteU32(bytes, p.episode_profile);
    WriteU32(bytes, p.coupled_profile);
    WriteU32(bytes, p.transcript_version);
    WriteU16(bytes, p.program_consensus_pin.version);
    WriteUint256(bytes, p.program_consensus_pin.recursive_alg_hash_root);
    WriteUint256(bytes, p.program_consensus_pin.external_sha256d_audit_root);
    WriteUint256(bytes, p.program_consensus_pin.registry_binding);
    WriteUint256(bytes, p.header_commitment);
    WriteUint256(bytes, p.params_commitment);
    WriteUint256(bytes, p.target);
    WriteUint256(bytes, p.sigma);
    WriteUint256(bytes, p.episode_digest);
    WriteUint256(bytes, p.coupled_digest);
    WriteUint256(bytes, p.final_digest);
    return Sha256d(bytes);
}

uint256 RCStage3EpisodeSectionCommitment(
    const std::vector<unsigned char>& canonical_section)
{
    static constexpr std::array<unsigned char, 28> DOMAIN_BYTES{
        'B', 'T', 'X', '_', 'R', 'C', '_', 'S', 'T', 'A', 'G', 'E', '3', '_',
        'E', 'P', '_', 'S', 'E', 'C', 'T', 'I', 'O', 'N', '_', 'V', '1', 0,
    };
    std::vector<unsigned char> bytes(DOMAIN_BYTES.begin(), DOMAIN_BYTES.end());
    WriteU32(bytes, static_cast<uint32_t>(canonical_section.size()));
    bytes.insert(bytes.end(), canonical_section.begin(), canonical_section.end());
    return Sha256d(bytes);
}

bool EncodeRCStage3EpisodeRelationProof(const RCStage3EpisodeRelationProof& proof,
                                        std::vector<unsigned char>& out,
                                        std::string* why)
{
    out.clear();
    if (proof.magic != kRCStage3EpisodeSectionMagic) return Fail(why, "bad_inner_magic");
    if (proof.version != kRCStage3EpisodeSectionVersion) return Fail(why, "bad_inner_version");
    if (!IsRCStage3EpisodeRole(proof.role)) return Fail(why, "non_episode_inner_role");
    if (!KnownEngine(proof.engine)) return Fail(why, "unknown_inner_engine");
    const uint64_t required = RequiredRCStage3EpisodeCoverage(proof.role);
    if (proof.covered_obligations == 0 || (proof.covered_obligations & ~required) != 0) {
        return Fail(why, "noncanonical_obligation_mask");
    }
    if (proof.statement_commitment.IsNull()) return Fail(why, "null_statement_binding");
    if (proof.payload.empty()) return Fail(why, "empty_engine_proof");
    if (proof.payload.size() > kRCStage3EpisodeMaxSectionPayload) {
        return Fail(why, "engine_proof_oversize");
    }

    WriteU32(out, proof.magic);
    WriteU16(out, proof.version);
    WriteU16(out, static_cast<uint16_t>(proof.role));
    WriteU8(out, static_cast<uint8_t>(proof.engine));
    WriteU8(out, 0); // reserved, must remain zero
    WriteU64(out, proof.covered_obligations);
    WriteUint256(out, proof.statement_commitment);
    WriteU32(out, static_cast<uint32_t>(proof.payload.size()));
    out.insert(out.end(), proof.payload.begin(), proof.payload.end());
    return true;
}

bool DecodeRCStage3EpisodeRelationProof(const std::vector<unsigned char>& bytes,
                                        RCStage3EpisodeRelationProof& out,
                                        std::string* why)
{
    out = RCStage3EpisodeRelationProof{};
    if (bytes.empty()) return Fail(why, "empty_inner_section");
    if (bytes.size() > kRCStage3EpisodeMaxSectionPayload + 54U) {
        return Fail(why, "inner_section_oversize");
    }

    Reader reader(bytes);
    uint16_t role{0};
    uint8_t engine{0};
    uint8_t reserved{0};
    uint32_t payload_size{0};
    if (!reader.ReadU32(out.magic) || !reader.ReadU16(out.version) ||
        !reader.ReadU16(role) || !reader.ReadU8(engine) ||
        !reader.ReadU8(reserved) || !reader.ReadU64(out.covered_obligations) ||
        !reader.ReadUint256(out.statement_commitment) ||
        !reader.ReadU32(payload_size)) {
        return Fail(why, "truncated_inner_header");
    }
    out.role = static_cast<RCStage3RelationRole>(role);
    out.engine = static_cast<RCStage3EpisodeEngine>(engine);
    if (reserved != 0) return Fail(why, "nonzero_reserved");
    if (payload_size == 0 || payload_size > kRCStage3EpisodeMaxSectionPayload) {
        return Fail(why, "bad_engine_proof_size");
    }
    if (payload_size != reader.Remaining() ||
        !reader.ReadBytes(payload_size, out.payload) || reader.Remaining() != 0) {
        return Fail(why, "noncanonical_engine_proof_length");
    }

    std::vector<unsigned char> canonical;
    if (!EncodeRCStage3EpisodeRelationProof(out, canonical, why)) return false;
    if (canonical != bytes) return Fail(why, "noncanonical_inner_encoding");
    return true;
}

bool ValidateRCStage3EpisodeRelationBindings(
    const RCStage3SuccinctProof& proof,
    std::vector<RCStage3EpisodeRelationProof>* decoded,
    std::string* why)
{
    if (proof.statement == RCStage3StatementKind::Coupled) {
        return Fail(why, "coupled_only_statement");
    }
    if (proof.statement != RCStage3StatementKind::Episode &&
        proof.statement != RCStage3StatementKind::Composed) {
        return Fail(why, "bad_statement_kind");
    }
    std::string structure_why;
    if (!ValidateRCStage3ProofStructure(proof, &structure_why)) {
        return Fail(why, "outer_structure:" + structure_why);
    }

    const uint256 statement_commitment = RCStage3EpisodeStatementCommitment(proof);
    std::vector<RCStage3EpisodeRelationProof> parsed;
    parsed.reserve(EPISODE_ROLES.size());
    for (size_t i = 0; i < EPISODE_ROLES.size(); ++i) {
        if (proof.sections[i].role != EPISODE_ROLES[i] ||
            proof.commitments[i].role != EPISODE_ROLES[i]) {
            return Fail(why, "outer_episode_role_order");
        }
        RCStage3EpisodeRelationProof relation;
        if (!DecodeRCStage3EpisodeRelationProof(proof.sections[i].proof, relation, why)) {
            return false;
        }
        if (relation.role != EPISODE_ROLES[i]) return Fail(why, "inner_outer_role_mismatch");
        if (relation.statement_commitment != statement_commitment) {
            return Fail(why, std::string(RCStage3RelationRoleName(relation.role)) +
                                 ":statement_binding");
        }
        if (RCStage3EpisodeSectionCommitment(proof.sections[i].proof) !=
            proof.commitments[i].root) {
            return Fail(why, std::string(RCStage3RelationRoleName(relation.role)) +
                                 ":section_commitment");
        }
        parsed.push_back(std::move(relation));
    }
    if (decoded != nullptr) *decoded = std::move(parsed);
    return true;
}

RCStage3EpisodeProveResult ProveRCStage3EpisodeRelations(
    const RCStage3SuccinctProof& statement,
    const std::vector<RCStage3EpisodeRelationProof>& relation_proofs)
{
    RCStage3EpisodeProveResult out;
    out.gaps = Gaps();
    if (statement.statement == RCStage3StatementKind::Coupled) {
        out.note = "stage3:episode:coupled_only_statement";
        return out;
    }
    if (relation_proofs.size() != EPISODE_ROLES.size()) {
        out.note = "stage3:episode:prover_relation_count";
        return out;
    }
    for (size_t i = 0; i < EPISODE_ROLES.size(); ++i) {
        if (relation_proofs[i].role != EPISODE_ROLES[i]) {
            out.note = "stage3:episode:prover_relation_order";
            return out;
        }
    }

    // Do not emit apparently authoritative sections from partial/native
    // artifacts.  Keeping both vectors empty prevents accidental attachment.
    out.note = "stage3:episode:no_complete_proof_only_engine";
    return out;
}

bool VerifyRCStage3EpisodeRelations(const RCStage3SuccinctProof& proof,
                                    std::string* why)
{
    std::vector<RCStage3EpisodeRelationProof> relations;
    if (!ValidateRCStage3EpisodeRelationBindings(proof, &relations, why)) return false;
    if (relations.size() != EPISODE_ROLES.size()) return Fail(why, "internal_relation_count");

    for (const auto& relation : relations) {
        const uint64_t required = RequiredRCStage3EpisodeCoverage(relation.role);
        if (relation.covered_obligations != required) {
            return Fail(why, std::string(RCStage3RelationRoleName(relation.role)) +
                                 ":incomplete_obligation_mask");
        }
        if (!VerifyCompleteEngine(proof, relation, why)) return false;
    }

    // Unreachable while the known-engine switch is exhaustive and readiness is
    // false.  Keep the independent gate so a future engine cannot activate
    // consensus merely by being added to the switch.
    if (!RCStage3EpisodeRelationsReady()) return Fail(why, "authority_not_ready");
    return true;
}

std::vector<RCStage3EpisodeRelationGap> CurrentRCStage3EpisodeRelationGaps()
{
    return Gaps();
}

} // namespace matmul::v4::rc
