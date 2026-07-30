// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_role_sections.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <hash.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <primitives/block.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>

namespace matmul::v4::rc {
namespace {

using AlgB3 = air_quotient::AirFriBackendAlg<gkr_field::Fp3>;
using AirProof = air_quotient::AirQuotientProof<gkr_field::Fp3, AlgB3>;
using gkr_field::Fp3;

constexpr char SECTION_COMMIT_DOMAIN[] = "BTX_RC_STAGE3_ROLE_SECTION_COMMIT_V1";
constexpr char SECTION_SEED_DOMAIN[] = "BTX_RC_STAGE3_ROLE_SECTION_SEED_V1";

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:section:" + message;
    return false;
}

template <typename T>
std::optional<T> FailOptional(std::string* why, const std::string& message)
{
    Fail(why, message);
    return std::nullopt;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

bool KnownSectionRole(RCStage3RelationRole role)
{
    const auto roles =
        RequiredRCStage3RelationRoles(RCStage3StatementKind::Composed);
    return std::find(roles.begin(), roles.end(), role) != roles.end();
}

void PutU16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void PutU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void PutU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

class Cursor
{
public:
    explicit Cursor(const std::vector<unsigned char>& bytes)
        : m_pos(bytes.data()), m_end(bytes.data() + bytes.size())
    {
    }
    size_t Remaining() const { return static_cast<size_t>(m_end - m_pos); }
    bool U16(uint16_t& value)
    {
        if (Remaining() < 2) return false;
        value = static_cast<uint16_t>(m_pos[0]) |
                static_cast<uint16_t>(static_cast<uint16_t>(m_pos[1]) << 8);
        m_pos += 2;
        return true;
    }
    bool U32(uint32_t& value)
    {
        if (Remaining() < 4) return false;
        value = 0;
        for (unsigned i = 0; i < 4; ++i) {
            value |= static_cast<uint32_t>(m_pos[i]) << (8 * i);
        }
        m_pos += 4;
        return true;
    }
    bool U64(uint64_t& value)
    {
        if (Remaining() < 8) return false;
        value = 0;
        for (unsigned i = 0; i < 8; ++i) {
            value |= static_cast<uint64_t>(m_pos[i]) << (8 * i);
        }
        m_pos += 8;
        return true;
    }
    bool Take(size_t count, std::vector<unsigned char>& out)
    {
        if (count > Remaining()) return false;
        out.assign(m_pos, m_pos + count);
        m_pos += count;
        return true;
    }

private:
    const unsigned char* m_pos;
    const unsigned char* m_end;
};

} // namespace

bool SerializeRCStage3RoleAirSection(const RCStage3RoleAirSection& section,
                                     std::vector<unsigned char>& out,
                                     std::string* why)
{
    out.clear();
    if (section.magic != kRCStage3RoleSectionMagic) {
        return Fail(why, "bad_magic");
    }
    if (section.version != kRCStage3RoleSectionVersion) {
        return Fail(why, "bad_version");
    }
    if (section.registry_version != kRCStage3ConstraintRegistryVersion) {
        return Fail(why, "bad_registry_version");
    }
    if (!KnownSectionRole(section.role)) return Fail(why, "unknown_role");
    if (!IsPowerOfTwo(section.n_rows) || section.n_rows < 2) {
        return Fail(why, "bad_rows");
    }
    if (section.n_columns == 0 ||
        section.n_columns + 1 > kRCFri3AlgBatchMaxColumns) {
        return Fail(why, "bad_columns");
    }
    if (section.endpoint_authority_roots.size() >
        kRCStage3RelationClosureEndpointCount) {
        return Fail(why, "too_many_endpoint_roots");
    }
    for (const auto& root : section.endpoint_authority_roots) {
        for (const gkr_field::Fp limb : root) {
            if (limb >= gkr_field::kP) return Fail(why, "noncanonical_root");
        }
    }

    std::vector<unsigned char> air_bytes;
    std::string air_why;
    if (!SerializeRCStage3RoleAirProof(section.air, air_bytes, &air_why)) {
        return Fail(why, "air:" + air_why);
    }

    PutU32(out, section.magic);
    PutU16(out, section.version);
    PutU16(out, section.registry_version);
    PutU16(out, static_cast<uint16_t>(section.role));
    PutU16(out, 0); // reserved, must remain zero
    PutU32(out, section.n_rows);
    PutU32(out, section.n_columns);
    PutU32(out, static_cast<uint32_t>(section.endpoint_authority_roots.size()));
    for (const auto& root : section.endpoint_authority_roots) {
        for (const gkr_field::Fp limb : root) PutU64(out, limb);
    }
    PutU32(out, static_cast<uint32_t>(air_bytes.size()));
    out.insert(out.end(), air_bytes.begin(), air_bytes.end());
    if (out.size() > kRCStage3MaxProofBytes) {
        out.clear();
        return Fail(why, "oversize");
    }
    return true;
}

std::optional<RCStage3RoleAirSection>
DeserializeRCStage3RoleAirSection(const std::vector<unsigned char>& bytes,
                                  std::string* why)
{
    if (bytes.empty()) {
        return FailOptional<RCStage3RoleAirSection>(why, "empty");
    }
    if (bytes.size() > kRCStage3MaxProofBytes) {
        return FailOptional<RCStage3RoleAirSection>(why, "oversize");
    }
    Cursor cursor(bytes);
    RCStage3RoleAirSection section;
    uint16_t role{0};
    uint16_t reserved{0};
    uint32_t root_count{0};
    if (!cursor.U32(section.magic) || !cursor.U16(section.version) ||
        !cursor.U16(section.registry_version) || !cursor.U16(role) ||
        !cursor.U16(reserved) || reserved != 0 ||
        !cursor.U32(section.n_rows) || !cursor.U32(section.n_columns) ||
        !cursor.U32(root_count)) {
        return FailOptional<RCStage3RoleAirSection>(why, "truncated_header");
    }
    section.role = static_cast<RCStage3RelationRole>(role);
    if (root_count > kRCStage3RelationClosureEndpointCount ||
        static_cast<size_t>(root_count) * 32 > cursor.Remaining()) {
        return FailOptional<RCStage3RoleAirSection>(why, "bad_root_count");
    }
    section.endpoint_authority_roots.resize(root_count);
    for (auto& root : section.endpoint_authority_roots) {
        for (gkr_field::Fp& limb : root) {
            if (!cursor.U64(limb) || limb >= gkr_field::kP) {
                return FailOptional<RCStage3RoleAirSection>(
                    why, "noncanonical_root");
            }
        }
    }
    uint32_t air_len{0};
    std::vector<unsigned char> air_bytes;
    if (!cursor.U32(air_len) || !cursor.Take(air_len, air_bytes) ||
        cursor.Remaining() != 0) {
        return FailOptional<RCStage3RoleAirSection>(why, "truncated_air");
    }
    std::string air_why;
    auto air = DeserializeRCStage3RoleAirProof(air_bytes, &air_why);
    if (!air.has_value()) {
        return FailOptional<RCStage3RoleAirSection>(why, "air:" + air_why);
    }
    section.air = std::move(*air);

    std::vector<unsigned char> canonical;
    if (!SerializeRCStage3RoleAirSection(section, canonical, why)) {
        return std::nullopt;
    }
    if (canonical != bytes) {
        return FailOptional<RCStage3RoleAirSection>(why, "noncanonical");
    }
    return section;
}

uint256 ComputeRCStage3RoleAirSectionCommitment(
    const RCStage3RoleAirSection& section)
{
    HashWriter hash;
    hash << SECTION_COMMIT_DOMAIN;
    hash << section.version;
    hash << section.registry_version;
    hash << static_cast<uint16_t>(section.role);
    hash << section.n_rows;
    hash << section.n_columns;
    hash << static_cast<uint32_t>(section.endpoint_authority_roots.size());
    for (const auto& root : section.endpoint_authority_roots) {
        for (const gkr_field::Fp limb : root) hash << limb;
    }
    // The proof's own committed roots. These are what FRI binds; hashing the
    // whole encoded section instead would be a self-referential envelope hash.
    hash << section.air.trace_commit;
    for (const gkr_field::Fp limb : section.air.batch.row_commit.root) {
        hash << limb;
    }
    hash << static_cast<uint32_t>(section.air.batch.fold_layers.size());
    for (const auto& layer : section.air.batch.fold_layers) {
        for (const gkr_field::Fp limb : layer.root) hash << limb;
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3RoleAirSectionSeed(const RCStage3SuccinctProof& statement,
                                          RCStage3RelationRole role)
{
    HashWriter hash;
    hash << SECTION_SEED_DOMAIN;
    hash << ComputeRCStage3AggregationSeed(statement);
    hash << kRCStage3ConstraintRegistryVersion;
    hash << static_cast<uint16_t>(role);
    return hash.GetHash();
}

bool RebuildRCStage3RoleAirConstraintSystem(
    const RCStage3RoleAirSection& section,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (!KnownSectionRole(section.role)) return Fail(why, "unknown_role");
    if (!RCStage3RoleIsInCsClosable(section.role)) {
        return Fail(why, std::string("no_role_air:") +
                             RCStage3RelationRoleName(section.role));
    }
    if (!IsPowerOfTwo(section.n_rows) || section.n_rows < 2) {
        return Fail(why, "bad_rows");
    }

    // The immutable registry is the SAME one the recursive verifier resolves
    // child AIRs from. The pin carries only public data taken off the wire.
    air_recurse::ChildPublicInputs pin;
    pin.child_n_rows = section.n_rows;
    pin.child_w = section.n_columns;
    pin.endpoint_authority_roots = section.endpoint_authority_roots;

    air_quotient::AirConstraintSystem<Fp3> cs;
    std::string registry_why;
    if (!ResolveCurrentRCStage3RelationConstraintSystem(section.role, pin, cs,
                                                        &registry_why)) {
        return Fail(why, "registry:" + registry_why);
    }
    if (cs.constraints.empty()) return Fail(why, "empty_registry_air");
    if (cs.n_rows != section.n_rows || cs.n_columns != section.n_columns) {
        return Fail(why, "registry_shape_mismatch:rows=" +
                             std::to_string(cs.n_rows) + ",cols=" +
                             std::to_string(cs.n_columns) + " pinned=" +
                             std::to_string(section.n_rows) + "," +
                             std::to_string(section.n_columns));
    }
    // Completeness: a role whose endpoints are opened in-trace must resolve to
    // an AIR carrying one opening block per required endpoint. Identical to the
    // recursive readiness gate; a shape-only AIR is not acceptable.
    const uint32_t required_openings =
        RCStage3RequiredInCsOpeningBlocks(section.role);
    if (required_openings != 0 &&
        RCStage3CountInCsClosers(cs) != required_openings) {
        return Fail(why, "registry_missing_endpoint_openings");
    }
    if (required_openings != 0 &&
        section.endpoint_authority_roots.size() != required_openings) {
        return Fail(why, "endpoint_root_count");
    }
    out = std::move(cs);
    return true;
}

RCStage3RoleSectionProveResult ProveRCStage3RoleAirSection(
    const RCStage3SuccinctProof& statement,
    const RCStage3RoleAirProduct& product)
{
    RCStage3RoleSectionProveResult out;
    if (!product.ok) {
        out.note = "stage3:section:product_not_ok:" + product.note;
        return out;
    }
    if (!KnownSectionRole(product.role)) {
        out.note = "stage3:section:unknown_role";
        return out;
    }
    if (product.cs.constraints.empty() || product.cs.n_rows == 0 ||
        product.cs.n_columns == 0 ||
        product.witness.size() != product.cs.n_columns) {
        out.note = "stage3:section:malformed_product";
        return out;
    }
    // A satisfying witness is a precondition, not a substitute for the proof.
    if (air_recurse::CountWitnessViolationsOnH(product.cs, product.witness) !=
        0) {
        out.note = "stage3:section:witness_violates_cs";
        return out;
    }

    RCStage3RoleAirSection section;
    section.role = product.role;
    section.n_rows = product.cs.n_rows;
    section.n_columns = product.cs.n_columns;
    section.endpoint_authority_roots = product.endpoint_committed_roots;

    // Refuse to emit a section the immutable registry cannot rebuild: such a
    // section could never verify, and shipping it would look like progress.
    air_quotient::AirConstraintSystem<Fp3> rebuilt;
    std::string rebuild_why;
    if (!RebuildRCStage3RoleAirConstraintSystem(section, rebuilt,
                                                &rebuild_why)) {
        out.note = "stage3:section:rebuild:" + rebuild_why;
        return out;
    }

    const uint256 seed =
        ComputeRCStage3RoleAirSectionSeed(statement, product.role);
    const auto t0 = std::chrono::steady_clock::now();
    const auto proved = air_quotient::AirQuotientProve<Fp3, AlgB3>(
        product.cs, product.witness, seed, {});
    out.prove_seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t0)
            .count();
    if (!proved.ok) {
        out.note = "stage3:section:prove:" + proved.note;
        return out;
    }
    section.air = proved.proof;

    // Self-check against the REBUILT registry AIR (not the product's own), so
    // the emitted section is known to be verifiable by a witness-free verifier.
    std::string verify_why;
    if (!air_quotient::AirQuotientVerify<Fp3, AlgB3>(rebuilt, section.air, seed,
                                                     &verify_why)) {
        out.note = "stage3:section:self_verify:" + verify_why;
        return out;
    }
    std::vector<unsigned char> encoded;
    std::string codec_why;
    if (!SerializeRCStage3RoleAirSection(section, encoded, &codec_why)) {
        out.note = "stage3:section:encode:" + codec_why;
        return out;
    }
    if (!DeserializeRCStage3RoleAirSection(encoded, &codec_why).has_value()) {
        out.note = "stage3:section:codec_roundtrip:" + codec_why;
        return out;
    }
    out.section = std::move(section);
    out.ok = true;
    out.note = "stage3:section:proved_authority_off";
    return out;
}

bool AssembleRCStage3SuccinctProofSections(
    RCStage3SuccinctProof& proof,
    const std::vector<RCStage3RoleAirSection>& sections,
    std::string* why)
{
    const auto required = RequiredRCStage3RelationRoles(proof.statement);
    if (required.empty()) return Fail(why, "unknown_statement");
    if (sections.size() != required.size()) {
        return Fail(why, "section_count:" + std::to_string(sections.size()) +
                             " required=" + std::to_string(required.size()));
    }

    proof.commitments.clear();
    proof.sections.clear();
    proof.commitments.reserve(required.size());
    proof.sections.reserve(required.size());

    for (const RCStage3RelationRole role : required) {
        const auto it = std::find_if(
            sections.begin(), sections.end(),
            [&](const RCStage3RoleAirSection& s) { return s.role == role; });
        if (it == sections.end()) {
            return Fail(why, std::string("missing_role:") +
                                 RCStage3RelationRoleName(role));
        }
        if (std::count_if(sections.begin(), sections.end(),
                          [&](const RCStage3RoleAirSection& s) {
                              return s.role == role;
                          }) != 1) {
            return Fail(why, std::string("duplicate_role:") +
                                 RCStage3RelationRoleName(role));
        }
        std::vector<unsigned char> encoded;
        std::string codec_why;
        if (!SerializeRCStage3RoleAirSection(*it, encoded, &codec_why)) {
            return Fail(why, std::string("encode:") +
                                 RCStage3RelationRoleName(role) + ":" +
                                 codec_why);
        }
        proof.commitments.push_back(
            {role, ComputeRCStage3RoleAirSectionCommitment(*it)});
        proof.sections.push_back({role, std::move(encoded)});
    }

    // The transcript commitment binds the assembled envelope, so it can only be
    // computed once every section is in place.
    proof.public_inputs.transcript_commitment = {};
    proof.public_inputs.transcript_commitment =
        ComputeRCStage3TranscriptCommitment(proof);
    if (proof.public_inputs.transcript_commitment.IsNull()) {
        return Fail(why, "null_transcript_commitment");
    }
    return ValidateRCStage3ProofStructure(proof, why);
}

bool VerifyRCStage3RoleAirSection(const RCStage3SuccinctProof& statement,
                                  const RCStage3RoleAirSection& section,
                                  std::string* why)
{
    air_quotient::AirConstraintSystem<Fp3> cs;
    std::string rebuild_why;
    if (!RebuildRCStage3RoleAirConstraintSystem(section, cs, &rebuild_why)) {
        return Fail(why, rebuild_why);
    }
    const uint256 seed =
        ComputeRCStage3RoleAirSectionSeed(statement, section.role);
    std::string air_why;
    if (!air_quotient::AirQuotientVerify<Fp3, AlgB3>(cs, section.air, seed,
                                                      &air_why)) {
        return Fail(why, "air_verify:" + air_why);
    }
    return true;
}

bool VerifyRCStage3RoleAirSections(const RCStage3SuccinctProof& proof,
                                   std::string* why)
{
    std::string structure_why;
    if (!ValidateRCStage3ProofStructure(proof, &structure_why)) {
        return Fail(why, "structure:" + structure_why);
    }
    const uint256 expected_transcript =
        ComputeRCStage3TranscriptCommitment(proof);
    if (proof.public_inputs.transcript_commitment != expected_transcript) {
        return Fail(why, "transcript_commitment_mismatch");
    }

    const auto required = RequiredRCStage3RelationRoles(proof.statement);
    for (size_t i = 0; i < required.size(); ++i) {
        const RCStage3RelationRole role = required[i];
        const std::string tag = std::string(RCStage3RelationRoleName(role)) + ":";
        if (proof.sections[i].role != role ||
            proof.commitments[i].role != role) {
            return Fail(why, tag + "role_order");
        }
        std::string decode_why;
        const auto section =
            DeserializeRCStage3RoleAirSection(proof.sections[i].proof,
                                              &decode_why);
        if (!section.has_value()) return Fail(why, tag + decode_why);
        if (section->role != role) return Fail(why, tag + "section_role");
        if (ComputeRCStage3RoleAirSectionCommitment(*section) !=
            proof.commitments[i].root) {
            return Fail(why, tag + "commitment_mismatch");
        }

        std::string section_why;
        if (!VerifyRCStage3RoleAirSection(proof, *section, &section_why)) {
            return Fail(why, tag + section_why);
        }
    }
    return true;
}

RCStage3EndpointAnchorSource
RCStage3EndpointAnchorSourceFor(RCStage3RelationEndpoint endpoint)
{
    using E = RCStage3RelationEndpoint;
    using S = RCStage3EndpointAnchorSource;
    switch (endpoint) {
    // ---- Direct statement public inputs (repack). ----
    case E::EpisodeDigestValue: return S::StatementEpisodeDigest;
    case E::EpisodeDigestHeaderTarget: return S::StatementHeaderCommitment;
    case E::EpisodeDigestPow: return S::StatementTarget;
    case E::CoupledDigestValue: return S::StatementCoupledDigest;

    // ---- The committed round root at the declared round index. ----
    // The tile-tree ROOT of a round is exactly that round's transcript root;
    // the digest role's round-roots endpoint pins the same value; the Extract
    // ChaCha stream endpoint repacks it; the GEMM signed-range wired closer's
    // only free input is it.
    case E::EpisodeTileTreeRoot: return S::EpisodeRoundRoot;
    case E::EpisodeDigestRoundRoots: return S::EpisodeRoundRoot;
    case E::EpisodeExtractChaCha: return S::EpisodeRoundRoot;
    case E::EpisodeGemmSignedRange: return S::EpisodeRoundRoot;

    // ---- Header preimage (bound by statement.header_commitment). ----
    case E::EpisodeBuilderSeedChain: return S::HeaderPreimage;
    case E::EpisodeBuilderOperandXof: return S::HeaderPreimage;

    // ---- Resolved episode shape (cross-checked by the digest root chain). ----
    case E::EpisodeBuilderParams: return S::EpisodeShapeParam;

    // ---- Round stream cells / tile-tree nodes (bound via the tile tree). ----
    case E::EpisodeGemmOperandA:
    case E::EpisodeGemmOperandB:
    case E::EpisodeGemmOutputY:
    case E::EpisodeExtractInput:
    case E::EpisodeExtractSampler:
    case E::EpisodeExtractScale:
    case E::EpisodeExtractOutput:
    case E::EpisodeWiringCopy:
    case E::EpisodeTileTreeStream:
    case E::EpisodeTileTreeLeafHash:
    case E::EpisodeTileTreeInternalHash:
        return S::EpisodeStreamCell;

    // ---- Hard-coded wired ledger-fold leaf rows: pinned, but placeholders. ----
    case E::EpisodeBuilderTrace:
    case E::EpisodeGemmSumcheck:
    case E::EpisodeWiringTranspose:
    case E::EpisodeWiringResidual:
    case E::EpisodeWiringRoundOrder:
        return S::ProtocolConstant;

    default: return S::None;
    }
}

bool RCStage3StreamAuthorityRootFromUint256(const uint256& root,
                                            alg_hash::Digest& out)
{
    out = {};
    if (root.IsNull()) return false;
    const unsigned char* b = root.begin();
    for (uint32_t i = 0; i < 4; ++i) {
        uint64_t limb = 0;
        for (uint32_t j = 0; j < 8; ++j) {
            limb |= static_cast<uint64_t>(b[8 * i + j]) << (8 * j);
        }
        if (limb >= gkr_field::kP) return false;
        out[i] = limb;
    }
    return true;
}

namespace {

const char* AnchorName(RCStage3EndpointAnchorSource source)
{
    switch (source) {
    case RCStage3EndpointAnchorSource::StatementEpisodeDigest:
        return "statement.episode_digest";
    case RCStage3EndpointAnchorSource::StatementHeaderCommitment:
        return "statement.header_commitment";
    case RCStage3EndpointAnchorSource::StatementTarget:
        return "statement.target";
    case RCStage3EndpointAnchorSource::StatementCoupledDigest:
        return "statement.coupled_digest";
    case RCStage3EndpointAnchorSource::EpisodeRoundRoot:
        return "episode_digest_root_chain.round_roots[round_index]";
    case RCStage3EndpointAnchorSource::HeaderPreimage:
        return "header_preimage_bound_by_statement.header_commitment";
    case RCStage3EndpointAnchorSource::EpisodeStreamCell:
        return "round_stream_cell_or_tile_tree_node_rooted_at_the_round_root";
    case RCStage3EndpointAnchorSource::EpisodeShapeParam:
        return "resolved_episode_round_count";
    case RCStage3EndpointAnchorSource::ProtocolConstant:
        return "immutable_role_builder_constant_not_block_data";
    case RCStage3EndpointAnchorSource::None: return "none";
    }
    return "none";
}

/** SHA256d root -> the eight little-endian uint32 the stream builders take. */
std::array<uint32_t, 8> Root8Of(const uint256& h)
{
    std::array<uint32_t, 8> r{};
    const unsigned char* b = h.begin();
    for (int j = 0; j < 8; ++j) {
        r[j] = static_cast<uint32_t>(b[4 * j]) |
               (static_cast<uint32_t>(b[4 * j + 1]) << 8) |
               (static_cast<uint32_t>(b[4 * j + 2]) << 16) |
               (static_cast<uint32_t>(b[4 * j + 3]) << 24);
    }
    return r;
}

void CountAnchored(RCStage3EndpointProvenanceReport* report,
                   RCStage3EndpointAnchorSource source)
{
    if (report == nullptr) return;
    switch (source) {
    case RCStage3EndpointAnchorSource::StatementEpisodeDigest:
    case RCStage3EndpointAnchorSource::StatementHeaderCommitment:
    case RCStage3EndpointAnchorSource::StatementTarget:
    case RCStage3EndpointAnchorSource::StatementCoupledDigest:
        ++report->anchored_to_statement;
        return;
    case RCStage3EndpointAnchorSource::EpisodeRoundRoot:
        ++report->anchored_to_round_roots;
        return;
    case RCStage3EndpointAnchorSource::HeaderPreimage:
        ++report->anchored_to_header_preimage;
        return;
    case RCStage3EndpointAnchorSource::EpisodeStreamCell:
        ++report->anchored_to_episode_stream;
        return;
    case RCStage3EndpointAnchorSource::EpisodeShapeParam:
        ++report->anchored_to_episode_shape;
        return;
    case RCStage3EndpointAnchorSource::ProtocolConstant:
        ++report->anchored_to_protocol_constant;
        return;
    case RCStage3EndpointAnchorSource::None:
        ++report->unanchored;
        return;
    }
}

/** Which verified material an endpoint's derivation consumes. Absent material
 * means "report unanchored", never "accept". */
bool MaterialAvailableFor(const RCStage3VerifiedEndpointMaterial& m,
                          RCStage3EndpointAnchorSource source,
                          std::string& missing)
{
    switch (source) {
    case RCStage3EndpointAnchorSource::EpisodeRoundRoot:
        if (!m.have_round_roots) { missing = "no_verified_episode_digest_root_chain"; return false; }
        return true;
    case RCStage3EndpointAnchorSource::HeaderPreimage:
        if (!m.have_header) { missing = "no_verified_header_preimage"; return false; }
        return true;
    case RCStage3EndpointAnchorSource::EpisodeStreamCell:
        if (!m.have_tile_tree) { missing = "no_verified_round_tile_tree"; return false; }
        return true;
    case RCStage3EndpointAnchorSource::EpisodeShapeParam:
        if (m.episode_rounds == 0) { missing = "no_resolved_episode_round_count"; return false; }
        return true;
    default:
        return true;
    }
}

bool StatementValueForAnchor(const RCStage3SuccinctProof& statement,
                             RCStage3EndpointAnchorSource source,
                             uint256& out)
{
    const auto& p = statement.public_inputs;
    switch (source) {
    case RCStage3EndpointAnchorSource::StatementEpisodeDigest:
        out = p.episode_digest;
        return !out.IsNull();
    case RCStage3EndpointAnchorSource::StatementHeaderCommitment:
        out = p.header_commitment;
        return !out.IsNull();
    case RCStage3EndpointAnchorSource::StatementTarget:
        out = p.target;
        return !out.IsNull();
    case RCStage3EndpointAnchorSource::StatementCoupledDigest:
        out = p.coupled_digest;
        return !out.IsNull();
    default: return false;
    }
}

/**
 * The uint256 an endpoint's authority root must be a pure REPACK of, when such
 * a value exists. Returns false for endpoints whose root is an alg-hash of an
 * opened value / a Poseidon ledger fold — those go through the canonical role
 * rebuild instead.
 */
bool DirectAnchorValue(RCStage3RelationEndpoint endpoint,
                       const RCStage3SuccinctProof& statement,
                       const RCStage3VerifiedEndpointMaterial& material,
                       uint256& out)
{
    using E = RCStage3RelationEndpoint;
    switch (endpoint) {
    case E::EpisodeDigestValue:
    case E::EpisodeDigestHeaderTarget:
    case E::EpisodeDigestPow:
    case E::CoupledDigestValue:
        return StatementValueForAnchor(
            statement, RCStage3EndpointAnchorSourceFor(endpoint), out);

    // The tile-tree root, the digest role's round-root pin and the Extract
    // ChaCha stream root are all the SAME committed round root, repacked.
    case E::EpisodeTileTreeRoot:
    case E::EpisodeDigestRoundRoots:
    case E::EpisodeExtractChaCha:
        if (!material.have_round_roots) return false;
        out = material.round_root;
        return !out.IsNull();

    case E::EpisodeBuilderSeedChain:
        if (!material.have_header) return false;
        out = material.header.seed_a;
        return !out.IsNull();
    case E::EpisodeBuilderOperandXof:
        if (!material.have_header) return false;
        out = material.header.seed_b;
        return !out.IsNull();

    // Tile-tree nodes: the canonical manifest commitment, leaf 0, and the last
    // internal node. The manifest revalidated canonically and its root is the
    // committed round root, so each of these is block data.
    case E::EpisodeTileTreeStream:
        if (!material.have_tile_tree) return false;
        out = material.tile_tree->commitment;
        return !out.IsNull();
    case E::EpisodeTileTreeLeafHash:
        if (!material.have_tile_tree) return false;
        out = material.tile_tree->leaf_hashes.empty()
                  ? material.tile_tree->root
                  : material.tile_tree->leaf_hashes[0];
        return !out.IsNull();
    case E::EpisodeTileTreeInternalHash:
        if (!material.have_tile_tree) return false;
        out = material.tile_tree->hash_nodes.empty()
                  ? material.tile_tree->root
                  : material.tile_tree->hash_nodes.back().digest;
        return !out.IsNull();

    default:
        return false;
    }
}

/**
 * CompositionLink's three authority roots, which no endpoint registry knows
 * about. Order is fixed by BuildRCStage3CompositionLinkRoleAirCS:
 *   [0] EPISODE leg authority root -> repack of statement.episode_digest
 *   [1] COUPLED leg authority root -> repack of statement.coupled_digest
 *   [2] the committed LINK digest  -> an alg_hash sponge fold of the two
 *       absorbed LEG VALUES, which are producer-chosen Fp3 scalars with no
 *       statement-carried source. UNANCHORED, and reported as such.
 *
 * The two leg roots are exactly the semantic endpoints the g2 builder itself
 * declares for them (out.endpoints = {EpisodeDigestValue, CoupledDigestValue}),
 * so this is that declaration made enforceable rather than a new convention.
 */
bool VerifyCompositionLinkEndpointProvenance(
    const RCStage3SuccinctProof& statement,
    const RCStage3RoleAirSection& section,
    const std::string& tag,
    RCStage3EndpointProvenanceReport* report,
    std::string* why)
{
    if (report != nullptr) {
        report->endpoints_total += kRCStage3CompositionLinkInCsClosers;
    }
    if (section.endpoint_authority_roots.size() !=
        kRCStage3CompositionLinkInCsClosers) {
        return Fail(why, tag + "composition_link_root_count");
    }

    const std::array<RCStage3EndpointAnchorSource, 2> leg_sources{
        RCStage3EndpointAnchorSource::StatementEpisodeDigest,
        RCStage3EndpointAnchorSource::StatementCoupledDigest};
    const std::array<const char*, 2> leg_names{"episode_leg", "coupled_leg"};

    for (size_t i = 0; i < leg_sources.size(); ++i) {
        const std::string leg_tag = tag + leg_names[i] + ":";
        uint256 value;
        if (!StatementValueForAnchor(statement, leg_sources[i], value)) {
            // A statement that does not carry this digest (e.g. an Episode
            // statement) anchors nothing here. Counted, never assumed checked.
            if (report != nullptr) {
                ++report->unanchored;
                report->unanchored_reasons.push_back(
                    leg_tag + "statement_does_not_carry:" +
                    AnchorName(leg_sources[i]));
            }
            continue;
        }
        alg_hash::Digest expected;
        if (!RCStage3StreamAuthorityRootFromUint256(value, expected)) {
            return Fail(why, leg_tag +
                                 "anchor_value_not_representable_as_authority_"
                                 "digest:" + AnchorName(leg_sources[i]));
        }
        if (expected != section.endpoint_authority_roots[i]) {
            return Fail(why, leg_tag + "declared_root_mismatch_vs_" +
                                 AnchorName(leg_sources[i]));
        }
        CountAnchored(report, leg_sources[i]);
    }

    // The link digest. The g2 AIR forces the sponge's absorbed message to BE
    // the two bound leg VALUES, so the digest is determined in-CS by them — but
    // those values are not themselves pinned to anything the statement carries,
    // so the digest is only as anchored as they are, which is not at all.
    if (report != nullptr) {
        ++report->unanchored;
        report->unanchored_reasons.push_back(
            tag + "link_digest:absorbed_leg_values_have_no_statement_derivable_"
                  "source");
    }
    return true;
}

} // namespace

bool VerifyRCStage3EndpointProvenanceMaterial(
    const RCStage3SuccinctProof& statement,
    const RCStage3EndpointProvenance& provenance,
    uint32_t expected_rounds,
    RCStage3VerifiedEndpointMaterial& out,
    std::string* why)
{
    out = {};
    out.episode_rounds = expected_rounds;

    // (1) Ordered round roots <- episode digest root chain <- statement digest.
    if (provenance.has_digest_chain) {
        std::string chain_why;
        if (!VerifyRCStage3EpisodeDigestRootChain(
                statement, expected_rounds, provenance.digest_chain,
                &chain_why)) {
            return Fail(why, "provenance:digest_root_chain:" + chain_why);
        }
        out.round_roots = provenance.digest_chain.manifest.round_roots;
        if (out.round_roots.empty()) {
            return Fail(why, "provenance:digest_root_chain_has_no_round_roots");
        }
        if (provenance.round_index >= out.round_roots.size()) {
            return Fail(why, "provenance:round_index_out_of_range");
        }
        out.round_index = provenance.round_index;
        out.round_root = out.round_roots[out.round_index];
        if (out.round_root.IsNull()) {
            return Fail(why, "provenance:null_round_root");
        }
        out.have_round_roots = true;
    }

    // (2) Header preimage <- statement.header_commitment.
    if (provenance.has_header) {
        if (RCStage3HeaderCommitment(provenance.header) !=
            statement.public_inputs.header_commitment) {
            return Fail(why,
                        "provenance:header_preimage_does_not_match_statement_"
                        "header_commitment");
        }
        out.header = provenance.header;
        out.have_header = true;
    }

    // (3) Round tile tree <- canonical revalidation AND the round root at the
    // declared index. Without (1) there is nothing to root it to, so a tile
    // tree offered on its own is REJECTED rather than used unanchored.
    if (provenance.has_tile_tree) {
        std::string tt_why;
        if (!stage3_hash_air::ValidateTileTreeManifest(provenance.tile_tree,
                                                       &tt_why)) {
            return Fail(why, "provenance:tile_tree_noncanonical:" + tt_why);
        }
        if (!out.have_round_roots) {
            return Fail(why,
                        "provenance:tile_tree_supplied_without_a_verified_"
                        "digest_root_chain");
        }
        if (provenance.tile_tree.root != out.round_root) {
            return Fail(why,
                        "provenance:tile_tree_root_is_not_the_committed_round_"
                        "root_at_this_round_index");
        }
        out.tile_tree = &provenance.tile_tree;
        out.have_tile_tree = true;
    }
    return true;
}

bool RCStage3CanonicalEpisodeRoleEndpointRoots(
    const RCStage3VerifiedEndpointMaterial& material,
    RCStage3RelationRole role,
    std::vector<alg_hash::Digest>& out,
    std::string* why)
{
    using Role = RCStage3RelationRole;
    out.clear();

    // The two pure-stream episode roles need no rebuild: every one of their
    // endpoint roots is a pure repack (DirectAnchorValue covers them).
    if (role == Role::EpisodeTileTree || role == Role::EpisodeDigest) {
        return Fail(why, "canonical:pure_stream_role_uses_direct_repack");
    }

    // Round stream cells. tile_tree.stream is the round byte stream itself:
    // the manifest revalidated canonically FROM these bytes and its root is the
    // committed round root, so a cell of it is block data.
    const std::vector<uint8_t>* stream =
        material.have_tile_tree ? &material.tile_tree->stream : nullptr;
    const auto cell_i8 = [&](size_t i) -> int64_t {
        return static_cast<int64_t>(
            static_cast<int8_t>((*stream)[i % stream->size()]));
    };

    RCStage3RoleAirProduct product;
    switch (role) {
    case Role::EpisodeDeterministicBuilder: {
        if (!material.have_header) return Fail(why, "canonical:needs_header_preimage");
        if (material.episode_rounds == 0) {
            return Fail(why, "canonical:needs_episode_round_count");
        }
        const std::vector<gkr_field::Fp3> open = {
            gkr_field::Fp3::FromFp(gkr_field::FromU64(material.episode_rounds))};
        const std::vector<std::array<uint32_t, 8>> sroots = {
            Root8Of(material.header.seed_a), Root8Of(material.header.seed_b)};
        product = BuildRCStage3NoKernelRoleAir(role, nullptr, &open, &sroots);
        break;
    }
    case Role::EpisodeGemm: {
        if (stream == nullptr || stream->empty()) {
            return Fail(why, "canonical:needs_round_tile_tree");
        }
        if (!material.have_round_roots) {
            return Fail(why, "canonical:needs_round_root");
        }
        const int64_t a = cell_i8(0);
        const int64_t b = stream->size() > 1 ? cell_i8(1) : cell_i8(0);
        const uint256 sr = material.round_root;
        product = BuildRCStage3EpisodeGemmRoleAir(nullptr, &a, &b, &sr);
        break;
    }
    case Role::EpisodeExtract: {
        if (stream == nullptr || stream->empty()) {
            return Fail(why, "canonical:needs_round_tile_tree");
        }
        if (!material.have_round_roots) {
            return Fail(why, "canonical:needs_round_root");
        }
        const std::vector<gkr_field::Fp3> open = {
            gkr_field::FromSigned3(cell_i8(0)), gkr_field::FromSigned3(cell_i8(2)),
            gkr_field::FromSigned3(cell_i8(4)), gkr_field::FromSigned3(cell_i8(6))};
        const std::vector<std::array<uint32_t, 8>> sroots = {
            Root8Of(material.round_root)};
        product = BuildRCStage3NoKernelRoleAir(role, nullptr, &open, &sroots);
        break;
    }
    case Role::EpisodeWiring: {
        if (stream == nullptr || stream->empty()) {
            return Fail(why, "canonical:needs_round_tile_tree");
        }
        const gkr_field::Fp3 copy = gkr_field::FromSigned3(cell_i8(0));
        product = BuildRCStage3EpisodeWiringRoleAir(nullptr, &copy);
        break;
    }
    default:
        return Fail(why, "canonical:role_has_no_episode_derivation");
    }

    if (!product.ok) return Fail(why, "canonical:builder:" + product.note);
    if (product.endpoint_committed_roots.size() !=
        RequiredRCStage3RelationEndpoints(role).size()) {
        return Fail(why, "canonical:builder_root_count");
    }
    out = product.endpoint_committed_roots;
    return true;
}

bool VerifyRCStage3RoleAirSectionEndpointProvenance(
    const RCStage3SuccinctProof& statement,
    const RCStage3RoleAirSection& section,
    const RCStage3EndpointProvenance& provenance,
    uint32_t expected_rounds,
    RCStage3EndpointProvenanceReport* report,
    std::string* why)
{
    const std::string tag =
        std::string(RCStage3RelationRoleName(section.role)) + ":provenance:";

    // CompositionLink is sized by NAME, not by the endpoint registry.
    //
    // It carries no entry in RequiredRCStage3RelationEndpoints, so every
    // registry-sized quantity reads 0 for it. Left alone, this function would
    // add 0 to endpoints_total and then hard-fail "endpoint_root_count" on a
    // perfectly well-formed 3-root section: either way its three authority
    // roots would be INVISIBLE to the accounting. They are enumerated
    // explicitly instead, exactly as c690764 states
    // kRCStage3CompositionLinkInCsClosers rather than deriving it from a
    // registry that would have answered 0.
    if (section.role == RCStage3RelationRole::CompositionLink) {
        return VerifyCompositionLinkEndpointProvenance(statement, section, tag,
                                                       report, why);
    }

    const auto& required = RequiredRCStage3RelationEndpoints(section.role);
    if (report != nullptr) {
        report->endpoints_total += static_cast<uint32_t>(required.size());
    }
    if (section.endpoint_authority_roots.size() != required.size()) {
        return Fail(why, tag + "endpoint_root_count");
    }

    // Material messages are per-proof, not per-role, so they are forwarded
    // unchanged rather than re-tagged.
    RCStage3VerifiedEndpointMaterial material;
    if (!VerifyRCStage3EndpointProvenanceMaterial(
            statement, provenance, expected_rounds, material, why)) {
        return false;
    }

    // The canonical role rebuild is computed at most once per section, and only
    // for the endpoints that are not pure repacks.
    bool canonical_tried = false;
    bool canonical_ok = false;
    std::string canonical_why;
    std::vector<alg_hash::Digest> canonical;

    for (size_t i = 0; i < required.size(); ++i) {
        const RCStage3RelationEndpoint endpoint = required[i];
        const RCStage3EndpointAnchorSource source =
            RCStage3EndpointAnchorSourceFor(endpoint);
        const std::string endpoint_tag =
            tag + "endpoint" + std::to_string(static_cast<uint16_t>(endpoint)) +
            ":";

        if (source == RCStage3EndpointAnchorSource::None) {
            if (report != nullptr) {
                ++report->unanchored;
                report->unanchored_reasons.push_back(
                    endpoint_tag + "no_statement_derivable_source");
            }
            continue;
        }
        std::string missing;
        if (!MaterialAvailableFor(material, source, missing)) {
            if (report != nullptr) {
                ++report->unanchored;
                report->unanchored_reasons.push_back(endpoint_tag + missing);
            }
            continue;
        }

        // (A) REPACK route.
        uint256 value;
        if (DirectAnchorValue(endpoint, statement, material, value)) {
            alg_hash::Digest expected;
            if (!RCStage3StreamAuthorityRootFromUint256(value, expected)) {
                return Fail(why, endpoint_tag +
                                     "anchor_value_not_representable_as_"
                                     "authority_digest:" + AnchorName(source));
            }
            if (expected != section.endpoint_authority_roots[i]) {
                return Fail(why, endpoint_tag + "declared_root_mismatch_vs_" +
                                     AnchorName(source));
            }
            CountAnchored(report, source);
            continue;
        }

        // (B) CANONICAL REBUILD route.
        if (!canonical_tried) {
            canonical_tried = true;
            canonical_ok = RCStage3CanonicalEpisodeRoleEndpointRoots(
                material, section.role, canonical, &canonical_why);
        }
        if (!canonical_ok || canonical.size() != required.size()) {
            if (report != nullptr) {
                ++report->unanchored;
                report->unanchored_reasons.push_back(endpoint_tag +
                                                     canonical_why);
            }
            continue;
        }
        if (canonical[i] != section.endpoint_authority_roots[i]) {
            return Fail(why, endpoint_tag +
                                 "declared_root_mismatch_vs_canonical_role_"
                                 "rebuild:" + AnchorName(source));
        }
        CountAnchored(report, source);
    }
    return true;
}

bool VerifyRCStage3RoleAirSectionsWithProvenance(
    const RCStage3SuccinctProof& proof,
    const RCStage3EndpointProvenance& provenance,
    uint32_t expected_rounds,
    RCStage3EndpointProvenanceReport* report,
    std::string* why)
{
    if (!VerifyRCStage3RoleAirSections(proof, why)) return false;
    const auto required = RequiredRCStage3RelationRoles(proof.statement);
    for (size_t i = 0; i < required.size(); ++i) {
        std::string decode_why;
        const auto section = DeserializeRCStage3RoleAirSection(
            proof.sections[i].proof, &decode_why);
        if (!section.has_value()) return Fail(why, decode_why);
        if (!VerifyRCStage3RoleAirSectionEndpointProvenance(
                proof, *section, provenance, expected_rounds, report, why)) {
            return false;
        }
    }
    return true;
}

bool BuildRCStage3RelationPrecommitForHeaderV3(
    const CBlockHeader& header,
    const Consensus::Params& params,
    int32_t height,
    RCStage3StatementKind kind,
    const ProductionProgramConsensusPinV1& program_pin,
    RCStage3RelationPrecommitV3& out,
    std::string* why)
{
    out = {};
    if (height < 0) return Fail(why, "negative_height");
    if (kind != RCStage3StatementKind::Episode &&
        kind != RCStage3StatementKind::Coupled &&
        kind != RCStage3StatementKind::Composed) {
        return Fail(why, "unknown_statement");
    }
    std::string pin_why;
    if (!ValidateProductionProgramConsensusPinV1(program_pin, &pin_why)) {
        return Fail(why, "program_pin:" + pin_why);
    }

    out.statement = kind;
    auto& p = out.public_inputs;
    p.height = height;
    p.n_bits = header.nBits;
    // A Composed statement is governed by the coupled transcript family.
    // Consensus binding applies the same rule in ExpectedTranscriptVersion.
    // Using the episode V1 constant here made every production-profile
    // Composed proof unattachable (V1 statement versus V3/V4 verifier).
    p.transcript_version =
        kind == RCStage3StatementKind::Episode
            ? kRCTranscriptVersion
            : ResolveRCCoupOptions(params).transcript_version;
    p.program_consensus_pin = program_pin;
    p.header_commitment = RCStage3HeaderCommitment(header);
    p.params_commitment = RCStage3ParamsCommitment(params, height, kind);
    p.sigma = matmul::v4::DeriveSigma(header);

    arith_uint256 target;
    bool negative{false};
    bool overflow{false};
    target.SetCompact(header.nBits, &negative, &overflow);
    if (negative || overflow || target == 0) return Fail(why, "bad_nbits");
    p.target = ArithToUint256(target);

    if (kind == RCStage3StatementKind::Episode ||
        kind == RCStage3StatementKind::Composed) {
        p.episode_profile = params.nMatMulRCProfile;
        if (p.episode_profile == 0) return Fail(why, "zero_episode_profile");
    }
    if (kind == RCStage3StatementKind::Coupled ||
        kind == RCStage3StatementKind::Composed) {
        p.coupled_profile = params.nMatMulRCCoupledProfile;
        if (p.coupled_profile == 0) return Fail(why, "zero_coupled_profile");
    }

    if (p.header_commitment.IsNull() || p.params_commitment.IsNull() ||
        p.sigma.IsNull()) {
        return Fail(why, "null_public_input");
    }
    RCStage3SuccinctProof relation_statement;
    relation_statement.statement = kind;
    relation_statement.public_inputs = p;
    if (kind == RCStage3StatementKind::Episode ||
        kind == RCStage3StatementKind::Composed) {
        out.episode_relation_precommit =
            RCStage3EpisodeStatementCommitment(
                relation_statement);
        if (out.episode_relation_precommit.IsNull()) {
            return Fail(
                why, "null_episode_relation_precommit");
        }
    }
    if (kind == RCStage3StatementKind::Coupled ||
        kind == RCStage3StatementKind::Composed) {
        out.coupled_relation_precommit =
            CommitRCStage3CoupledStatement(p);
        if (out.coupled_relation_precommit.IsNull()) {
            return Fail(
                why, "null_coupled_relation_precommit");
        }
    }
    return true;
}

bool BuildRCStage3StatementForHeader(
    const CBlockHeader& header,
    const Consensus::Params& params,
    int32_t height,
    RCStage3StatementKind kind,
    const ProductionProgramConsensusPinV1& program_pin,
    const uint256& episode_digest,
    const uint256& coupled_digest,
    RCStage3SuccinctProof& out,
    std::string* why)
{
    out = {};
    RCStage3RelationPrecommitV3 precommit;
    if (!BuildRCStage3RelationPrecommitForHeaderV3(
            header, params, height, kind,
            program_pin, precommit, why)) {
        return false;
    }
    out.statement = kind;
    out.public_inputs = precommit.public_inputs;
    auto& p = out.public_inputs;
    if (kind == RCStage3StatementKind::Episode ||
        kind == RCStage3StatementKind::Composed) {
        if (episode_digest.IsNull()) {
            return Fail(why, "null_episode_digest");
        }
        p.episode_digest = episode_digest;
    }
    if (kind == RCStage3StatementKind::Coupled ||
        kind == RCStage3StatementKind::Composed) {
        if (coupled_digest.IsNull()) {
            return Fail(why, "null_coupled_digest");
        }
        p.coupled_digest = coupled_digest;
    }
    p.final_digest = ComputeRCStage3FinalDigest(out);
    if (p.final_digest.IsNull()) {
        return Fail(why, "null_final_digest");
    }
    if ((kind == RCStage3StatementKind::Episode ||
         kind == RCStage3StatementKind::Composed) &&
        RCStage3EpisodeStatementCommitment(out) !=
            precommit.episode_relation_precommit) {
        return Fail(
            why, "episode_relation_precommit_drift");
    }
    if ((kind == RCStage3StatementKind::Coupled ||
         kind == RCStage3StatementKind::Composed) &&
        CommitRCStage3CoupledStatement(p) !=
            precommit.coupled_relation_precommit) {
        return Fail(
            why, "coupled_relation_precommit_drift");
    }
    return true;
}

static_assert(!kRCStage3RoleSectionEndpointProvenanceReady,
              "endpoint authority roots are not yet bound to block commitments");
static_assert(!kRCStage3SuccinctAuthorityReady,
              "section verification grants no consensus authority");

} // namespace matmul::v4::rc
