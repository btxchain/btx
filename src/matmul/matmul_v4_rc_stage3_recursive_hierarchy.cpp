// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_recursive_hierarchy.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace matmul::v4::rc::recursive_hierarchy {
namespace {

constexpr char MANIFEST_DOMAIN[] =
    "BTX_RC_STAGE3_SHARD_ORDINAL_MANIFEST_V1";
constexpr char MANIFEST_EXACT_SET_DOMAIN_V2[] =
    "BTX_RC_STAGE3_SHARD_ORDINAL_EXACT_SET_MANIFEST_V2";
constexpr char COVERAGE_DOMAIN[] =
    "BTX_RC_STAGE3_SHARD_ORDINAL_COVERAGE_V1";
constexpr char COVERED_STATEMENTS_DOMAIN[] =
    "BTX_RC_STAGE3_COVERED_SHARD_STATEMENTS_V1";
constexpr char CONSTRAINT_SYSTEM_DOMAIN[] =
    "BTX_RC_STAGE3_HIERARCHY_CONSTRAINT_SYSTEM_V1";
constexpr char PROOF_BYTES_DOMAIN[] =
    "BTX_RC_STAGE3_HIERARCHY_PROOF_BYTES_V1";
constexpr char NODE_ROOT_DOMAIN[] =
    "BTX_RC_STAGE3_RETAINED_HIERARCHY_NODE_V1";
constexpr uint32_t kNodeEnvelopeMagicV1 = 0x31485252U; // "RRH1" LE

constexpr uint64_t kNodeEnvelopeFixedBytes =
    4 + // magic
    2 + // version
    4 + // level
    4 + // node ordinal
    4 + 4 + 8 + 8 + // exact coverage coordinates
    32 * 7 + // manifest, coverage, statement, CS, seed, proof, node roots
    4 + // q terminal count
    8 + // proof byte count
    8; // full byte count

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:recursive_hierarchy:" + detail;
    }
    return false;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

void WriteU16(
    std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(
        static_cast<unsigned char>(value >> 8));
}

void WriteU32(
    std::vector<unsigned char>& out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(
            value >> (8 * i)));
    }
}

void WriteU64(
    std::vector<unsigned char>& out, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>(
            value >> (8 * i)));
    }
}

void WriteHash(
    std::vector<unsigned char>& out,
    const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

bool CanonicalFp3(const gf::Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

void HashFp3(HashWriter& hash, const gf::Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

uint256 ProofBytesCommitment(
    const std::vector<unsigned char>& bytes)
{
    if (bytes.empty()) return {};
    HashWriter hash;
    hash << PROOF_BYTES_DOMAIN;
    hash << static_cast<uint64_t>(bytes.size());
    hash << bytes;
    return hash.GetHash();
}

bool ConstraintSystemShapeValid(
    const aq::AirConstraintSystem<gf::Fp3>& cs)
{
    if (cs.n_rows < 2 ||
        (cs.n_rows & (cs.n_rows - 1)) != 0 ||
        cs.n_columns == 0 ||
        cs.constraints.empty()) {
        return false;
    }
    for (const auto& constraint : cs.constraints) {
        if (constraint.name == nullptr ||
            constraint.name[0] == '\0' ||
            constraint.alg_degree == 0 ||
            !constraint.eval) {
            return false;
        }
    }
    for (const auto& [column, values] : cs.preprocessed) {
        if (column >= cs.n_columns ||
            values.size() != cs.n_rows ||
            !std::all_of(
                values.begin(), values.end(), CanonicalFp3)) {
            return false;
        }
    }
    for (const auto& [column, root] :
         cs.preprocessed_roots) {
        if (column >= cs.n_columns || root.IsNull()) {
            return false;
        }
    }
    for (const auto& group :
         cs.preprocessed_row_group_roots) {
        if (group.root.IsNull() ||
            group.ordered_columns.empty()) {
            return false;
        }
        uint32_t previous = 0;
        bool first = true;
        for (uint32_t column : group.ordered_columns) {
            if (column >= cs.n_columns ||
                (!first && column <= previous)) {
                return false;
            }
            previous = column;
            first = false;
        }
    }
    return true;
}

bool SameConstraintSystemDescription(
    const aq::AirConstraintSystem<gf::Fp3>& a,
    const aq::AirConstraintSystem<gf::Fp3>& b)
{
    return
        ComputeHierarchyConstraintSystemCommitmentV1(a) ==
            ComputeHierarchyConstraintSystemCommitmentV1(b);
}

bool SameFp3Vector(
    const std::vector<gf::Fp3>& lhs,
    const std::vector<gf::Fp3>& rhs)
{
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (!gf::Eq(lhs[i], rhs[i])) return false;
    }
    return true;
}

} // namespace

uint256 CommitShardOrdinalManifestV1(
    const ShardOrdinalManifestV1& manifest)
{
    HashWriter hash;
    hash << MANIFEST_DOMAIN;
    hash << manifest.version;
    hash << manifest.total_ordinals;
    hash << static_cast<uint64_t>(manifest.entries.size());
    for (const auto& entry : manifest.entries) {
        hash << entry.shard_ordinal;
        hash << entry.first_ordinal;
        hash << entry.ordinal_count;
        hash << entry.statement_root;
    }
    return hash.GetHash();
}

ShardOrdinalManifestV1 BuildShardOrdinalManifestV1(
    uint64_t total_ordinals,
    const std::vector<ShardOrdinalEntryV1>& entries)
{
    ShardOrdinalManifestV1 out;
    out.total_ordinals = total_ordinals;
    out.entries = entries;
    out.commitment = CommitShardOrdinalManifestV1(out);
    if (!ValidateShardOrdinalManifestV1(out)) return {};
    return out;
}

bool ValidateShardOrdinalManifestV1(
    const ShardOrdinalManifestV1& manifest,
    std::string* why)
{
    if (manifest.version !=
            kShardOrdinalManifestVersionV1 ||
        manifest.total_ordinals == 0 ||
        manifest.entries.empty() ||
        manifest.entries.size() >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "manifest_shape");
    }
    uint64_t cursor = 0;
    for (size_t i = 0; i < manifest.entries.size(); ++i) {
        const auto& entry = manifest.entries[i];
        if (entry.shard_ordinal != i ||
            entry.first_ordinal != cursor ||
            entry.ordinal_count == 0 ||
            entry.statement_root.IsNull()) {
            return Fail(why, "manifest_partition");
        }
        if (!CheckedAdd(
                cursor, entry.ordinal_count, cursor) ||
            cursor > manifest.total_ordinals) {
            return Fail(why, "manifest_overflow");
        }
    }
    if (cursor != manifest.total_ordinals) {
        return Fail(why, "manifest_incomplete");
    }
    if (manifest.commitment.IsNull() ||
        manifest.commitment !=
            CommitShardOrdinalManifestV1(manifest)) {
        return Fail(why, "manifest_commitment");
    }
    return true;
}

uint256 CommitShardOrdinalManifestV2(
    const ShardOrdinalManifestV2& manifest)
{
    HashWriter hash;
    hash << MANIFEST_EXACT_SET_DOMAIN_V2;
    hash << manifest.version;
    hash << manifest.total_ordinals;
    hash << static_cast<uint64_t>(manifest.entries.size());
    for (const auto& entry : manifest.entries) {
        hash << entry.shard_ordinal;
        hash << static_cast<uint64_t>(
            entry.program_ordinals.size());
        for (uint64_t ordinal : entry.program_ordinals) {
            hash << ordinal;
        }
        hash << entry.statement_root;
    }
    return hash.GetHash();
}

ShardOrdinalManifestV2 BuildShardOrdinalManifestV2(
    uint64_t total_ordinals,
    const std::vector<ShardOrdinalEntryV2>& entries)
{
    ShardOrdinalManifestV2 out;
    out.total_ordinals = total_ordinals;
    out.entries = entries;
    out.commitment = CommitShardOrdinalManifestV2(out);
    if (!ValidateShardOrdinalManifestV2(out)) return {};
    return out;
}

bool ValidateShardOrdinalManifestV2(
    const ShardOrdinalManifestV2& manifest,
    std::string* why)
{
    if (manifest.version !=
            kShardOrdinalManifestVersionV2 ||
        manifest.total_ordinals == 0 ||
        manifest.entries.empty() ||
        manifest.entries.size() >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "manifest_v2_shape");
    }

    uint64_t supplied_ordinals = 0;
    for (size_t i = 0; i < manifest.entries.size(); ++i) {
        const auto& entry = manifest.entries[i];
        if (entry.shard_ordinal != i ||
            entry.program_ordinals.empty() ||
            entry.statement_root.IsNull()) {
            return Fail(why, "manifest_v2_entry");
        }
        uint64_t previous = 0;
        bool have_previous = false;
        for (uint64_t ordinal : entry.program_ordinals) {
            if (ordinal >= manifest.total_ordinals ||
                (have_previous && ordinal <= previous)) {
                return Fail(
                    why, "manifest_v2_ordinal_order");
            }
            previous = ordinal;
            have_previous = true;
        }
        if (entry.program_ordinals.size() >
                std::numeric_limits<uint64_t>::max() -
                    supplied_ordinals) {
            return Fail(why, "manifest_v2_count_overflow");
        }
        supplied_ordinals +=
            static_cast<uint64_t>(
                entry.program_ordinals.size());
    }
    if (supplied_ordinals != manifest.total_ordinals ||
        supplied_ordinals >
            std::numeric_limits<size_t>::max()) {
        return Fail(why, "manifest_v2_incomplete");
    }

    // The input order remains load-bearing above.  Sort only a validator-owned
    // copy to prove that the union is exactly {0, ..., total_ordinals - 1}.
    // Equal adjacent values expose both within- and cross-shard duplication;
    // any missing ordinal necessarily changes the value at its sorted index.
    std::vector<uint64_t> exact_union;
    exact_union.reserve(
        static_cast<size_t>(supplied_ordinals));
    for (const auto& entry : manifest.entries) {
        exact_union.insert(
            exact_union.end(),
            entry.program_ordinals.begin(),
            entry.program_ordinals.end());
    }
    std::sort(exact_union.begin(), exact_union.end());
    for (size_t i = 0; i < exact_union.size(); ++i) {
        if (exact_union[i] != static_cast<uint64_t>(i)) {
            return Fail(why, "manifest_v2_not_exact_union");
        }
    }

    if (manifest.commitment.IsNull() ||
        manifest.commitment !=
            CommitShardOrdinalManifestV2(manifest)) {
        return Fail(why, "manifest_v2_commitment");
    }
    return true;
}

ShardOrdinalCoverageV1 BuildShardOrdinalCoverageV1(
    const ShardOrdinalManifestV1& manifest,
    uint32_t first_shard_ordinal,
    uint32_t shard_count)
{
    ShardOrdinalCoverageV1 out;
    if (!ValidateShardOrdinalManifestV1(manifest) ||
        shard_count == 0 ||
        first_shard_ordinal >= manifest.entries.size() ||
        shard_count >
            manifest.entries.size() - first_shard_ordinal) {
        return out;
    }
    out.first_shard_ordinal = first_shard_ordinal;
    out.shard_count = shard_count;
    out.first_ordinal =
        manifest.entries[first_shard_ordinal].first_ordinal;
    const auto& last =
        manifest.entries[
            static_cast<size_t>(first_shard_ordinal) +
            shard_count - 1];
    uint64_t end = 0;
    if (!CheckedAdd(
            last.first_ordinal, last.ordinal_count, end)) {
        return {};
    }
    out.ordinal_count = end - out.first_ordinal;
    out.commitment =
        CommitShardOrdinalCoverageV1(manifest, out);
    return out;
}

uint256 CommitShardOrdinalCoverageV1(
    const ShardOrdinalManifestV1& manifest,
    const ShardOrdinalCoverageV1& coverage)
{
    HashWriter hash;
    hash << COVERAGE_DOMAIN;
    hash << manifest.commitment;
    hash << coverage.first_shard_ordinal;
    hash << coverage.shard_count;
    hash << coverage.first_ordinal;
    hash << coverage.ordinal_count;
    return hash.GetHash();
}

bool ValidateShardOrdinalCoverageV1(
    const ShardOrdinalManifestV1& manifest,
    const ShardOrdinalCoverageV1& coverage,
    std::string* why)
{
    if (!ValidateShardOrdinalManifestV1(
            manifest, why)) {
        return false;
    }
    if (coverage.shard_count == 0 ||
        coverage.first_shard_ordinal >=
            manifest.entries.size() ||
        coverage.shard_count >
            manifest.entries.size() -
                coverage.first_shard_ordinal) {
        return Fail(why, "coverage_shape");
    }
    const auto expected = BuildShardOrdinalCoverageV1(
        manifest,
        coverage.first_shard_ordinal,
        coverage.shard_count);
    if (expected.shard_count == 0 ||
        expected.first_ordinal != coverage.first_ordinal ||
        expected.ordinal_count != coverage.ordinal_count ||
        coverage.commitment.IsNull() ||
        expected.commitment != coverage.commitment) {
        return Fail(why, "coverage_commitment");
    }
    return true;
}

bool ValidateExactHierarchyLevelCoverageV1(
    const ShardOrdinalManifestV1& manifest,
    const std::vector<ShardOrdinalCoverageV1>& level,
    std::string* why)
{
    if (!ValidateShardOrdinalManifestV1(
            manifest, why)) {
        return false;
    }
    if (level.empty()) {
        return Fail(why, "level_empty");
    }
    uint32_t shard_cursor = 0;
    uint64_t ordinal_cursor = 0;
    for (const auto& coverage : level) {
        if (!ValidateShardOrdinalCoverageV1(
                manifest, coverage, why)) {
            return false;
        }
        if (coverage.first_shard_ordinal !=
                shard_cursor ||
            coverage.first_ordinal != ordinal_cursor) {
            return Fail(why, "level_noncanonical");
        }
        if (coverage.shard_count >
            std::numeric_limits<uint32_t>::max() -
                shard_cursor) {
            return Fail(why, "level_shard_overflow");
        }
        shard_cursor += coverage.shard_count;
        if (!CheckedAdd(
                ordinal_cursor,
                coverage.ordinal_count,
                ordinal_cursor)) {
            return Fail(why, "level_ordinal_overflow");
        }
    }
    if (shard_cursor != manifest.entries.size() ||
        ordinal_cursor != manifest.total_ordinals) {
        return Fail(why, "level_incomplete");
    }
    return true;
}

uint256 ComputeHierarchyConstraintSystemCommitmentV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs)
{
    if (!ConstraintSystemShapeValid(cs)) return {};
    HashWriter hash;
    hash << CONSTRAINT_SYSTEM_DOMAIN;
    hash << cs.n_rows;
    hash << cs.n_columns;
    hash << static_cast<uint64_t>(cs.constraints.size());
    for (const auto& constraint : cs.constraints) {
        hash << std::string(constraint.name);
        hash << static_cast<uint8_t>(constraint.kind);
        hash << constraint.alg_degree;
    }
    hash << cs.preprocessed_pin_ood;
    hash << static_cast<uint64_t>(
        cs.preprocessed.size());
    for (const auto& [column, values] :
         cs.preprocessed) {
        hash << column;
        hash << static_cast<uint64_t>(values.size());
        for (const auto& value : values) {
            HashFp3(hash, value);
        }
    }
    hash << static_cast<uint64_t>(
        cs.preprocessed_roots.size());
    for (const auto& [column, root] :
         cs.preprocessed_roots) {
        hash << column;
        hash << root;
    }
    hash << static_cast<uint64_t>(
        cs.preprocessed_row_group_roots.size());
    for (const auto& group :
         cs.preprocessed_row_group_roots) {
        hash << group.version;
        hash << static_cast<uint8_t>(group.role);
        hash << static_cast<uint64_t>(
            group.ordered_columns.size());
        for (uint32_t column : group.ordered_columns) {
            hash << column;
        }
        hash << group.root;
    }
    return hash.GetHash();
}

uint256 ComputeCoveredShardStatementRootV1(
    const ShardOrdinalManifestV1& manifest,
    const ShardOrdinalCoverageV1& coverage)
{
    if (!ValidateShardOrdinalCoverageV1(
            manifest, coverage)) {
        return {};
    }
    HashWriter hash;
    hash << COVERED_STATEMENTS_DOMAIN;
    hash << manifest.commitment;
    hash << coverage.commitment;
    hash << coverage.shard_count;
    const size_t end =
        static_cast<size_t>(
            coverage.first_shard_ordinal) +
        coverage.shard_count;
    for (size_t i =
             coverage.first_shard_ordinal;
         i < end; ++i) {
        hash << manifest.entries[i].shard_ordinal;
        hash << manifest.entries[i].statement_root;
    }
    return hash.GetHash();
}

uint64_t ComputeRetainedHierarchyNodeFullBytesV1(
    const RetainedHierarchyNodeV1& node)
{
    uint64_t q_bytes = 0;
    if (node.quotient_terminals.size() >
        std::numeric_limits<uint64_t>::max() / 24) {
        return 0;
    }
    q_bytes =
        static_cast<uint64_t>(
            node.quotient_terminals.size()) *
        24;
    uint64_t total = 0;
    if (!CheckedAdd(
            kNodeEnvelopeFixedBytes, q_bytes, total) ||
        !CheckedAdd(
            total,
            static_cast<uint64_t>(
                node.proof_bytes.size()),
            total)) {
        return 0;
    }
    return total;
}

bool SerializeRetainedHierarchyNodeEnvelopeV1(
    const RetainedHierarchyNodeV1& node,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    const uint64_t expected =
        ComputeRetainedHierarchyNodeFullBytesV1(node);
    if (expected == 0 ||
        expected >
            std::numeric_limits<size_t>::max() ||
        node.quotient_terminals.size() >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "node_envelope_size");
    }
    out.reserve(static_cast<size_t>(expected));
    WriteU32(out, kNodeEnvelopeMagicV1);
    WriteU16(out, node.version);
    WriteU32(out, node.level);
    WriteU32(out, node.node_ordinal);
    WriteU32(
        out, node.coverage.first_shard_ordinal);
    WriteU32(out, node.coverage.shard_count);
    WriteU64(out, node.coverage.first_ordinal);
    WriteU64(out, node.coverage.ordinal_count);
    WriteHash(out, node.manifest_commitment);
    WriteHash(out, node.coverage.commitment);
    WriteHash(out, node.covered_statement_root);
    WriteHash(out, node.constraint_system_commitment);
    WriteHash(out, node.fs_seed);
    WriteHash(out, node.proof_commitment);
    WriteHash(out, node.node_root);
    WriteU32(
        out,
        static_cast<uint32_t>(
            node.quotient_terminals.size()));
    for (const auto& value : node.quotient_terminals) {
        WriteU64(out, gf::Canonical(value.c0));
        WriteU64(out, gf::Canonical(value.c1));
        WriteU64(out, gf::Canonical(value.c2));
    }
    WriteU64(
        out,
        static_cast<uint64_t>(
            node.proof_bytes.size()));
    WriteU64(out, node.full_byte_count);
    out.insert(
        out.end(),
        node.proof_bytes.begin(),
        node.proof_bytes.end());
    if (out.size() != expected ||
        node.full_byte_count != expected) {
        out.clear();
        return Fail(why, "node_envelope_count");
    }
    return true;
}

uint256 ComputeRetainedHierarchyNodeRootV1(
    const RetainedHierarchyNodeV1& node)
{
    if (node.version !=
            kRetainedHierarchyNodeVersionV1 ||
        node.manifest_commitment.IsNull() ||
        node.coverage.commitment.IsNull() ||
        node.covered_statement_root.IsNull() ||
        node.constraint_system_commitment.IsNull() ||
        node.fs_seed.IsNull() ||
        node.proof_commitment.IsNull() ||
        node.proof_bytes.empty() ||
        node.quotient_terminals.empty() ||
        node.full_byte_count == 0 ||
        !std::all_of(
            node.quotient_terminals.begin(),
            node.quotient_terminals.end(),
            CanonicalFp3)) {
        return {};
    }
    const uint256 proof_bytes_root =
        ProofBytesCommitment(node.proof_bytes);
    if (proof_bytes_root.IsNull()) return {};

    HashWriter hash;
    hash << NODE_ROOT_DOMAIN;
    hash << node.version;
    hash << node.level;
    hash << node.node_ordinal;
    hash << node.manifest_commitment;
    hash << node.coverage.commitment;
    hash << node.coverage.first_shard_ordinal;
    hash << node.coverage.shard_count;
    hash << node.coverage.first_ordinal;
    hash << node.coverage.ordinal_count;
    hash << node.covered_statement_root;
    hash << node.constraint_system_commitment;
    hash << node.fs_seed;
    hash << node.proof_commitment;
    hash << proof_bytes_root;
    hash << static_cast<uint64_t>(
        node.quotient_terminals.size());
    for (const auto& value : node.quotient_terminals) {
        HashFp3(hash, value);
    }
    hash << node.full_byte_count;
    return hash.GetHash();
}

bool ExtractProofQuotientTerminalsV1(
    const aq::AirConstraintSystem<gf::Fp3>&
        constraint_system,
    const fp::AlgAirProof& proof,
    std::vector<gf::Fp3>& out,
    std::string* why)
{
    out.clear();
    if (constraint_system.n_columns == 0 ||
        proof.batch.queries.empty()) {
        return Fail(why, "proof_q_shape");
    }
    out.reserve(proof.batch.queries.size());
    for (const auto& query : proof.batch.queries) {
        if (query.row.values.size() !=
                static_cast<size_t>(
                    constraint_system.n_columns) +
                    1) {
            out.clear();
            return Fail(why, "proof_q_row_width");
        }
        const gf::Fp3& value =
            query.row.values[
                constraint_system.n_columns];
        if (!CanonicalFp3(value)) {
            out.clear();
            return Fail(why, "proof_q_noncanonical");
        }
        out.push_back(value);
    }
    return !out.empty();
}

RetainedHierarchyNodeV1 RetainVerifiedHierarchyNodeV1(
    const ShardOrdinalManifestV1& manifest,
    const ShardOrdinalCoverageV1& coverage,
    uint32_t level,
    uint32_t node_ordinal,
    const aq::AirConstraintSystem<gf::Fp3>&
        constraint_system,
    const fp::AlgAirProof& proof,
    const uint256& fs_seed,
    const std::vector<gf::Fp3>& quotient_terminals)
{
    RetainedHierarchyNodeV1 out;
    out.level = level;
    out.node_ordinal = node_ordinal;
    out.coverage = coverage;
    out.manifest_commitment = manifest.commitment;
    out.constraint_system = constraint_system;
    out.proof = proof;
    out.fs_seed = fs_seed;

    std::string why;
    if (!ValidateShardOrdinalCoverageV1(
            manifest, coverage, &why)) {
        out.note = why;
        return out;
    }
    if (fs_seed.IsNull()) {
        out.note =
            "stage3:recursive_hierarchy:null_fs_seed";
        return out;
    }
    std::vector<gf::Fp3> proof_q;
    if (!ExtractProofQuotientTerminalsV1(
            constraint_system, proof, proof_q, &why) ||
        quotient_terminals.empty() ||
        !std::all_of(
            quotient_terminals.begin(),
            quotient_terminals.end(),
            CanonicalFp3) ||
        !SameFp3Vector(
            quotient_terminals, proof_q)) {
        out.note =
            "stage3:recursive_hierarchy:"
            "proof_q_terminal_mismatch";
        return out;
    }
    out.quotient_terminals = proof_q;
    out.covered_statement_root =
        ComputeCoveredShardStatementRootV1(
            manifest, coverage);
    out.constraint_system_commitment =
        ComputeHierarchyConstraintSystemCommitmentV1(
            constraint_system);
    out.proof_commitment =
        fp::ComputeNormalizedAlgAirProofCommitment(proof);
    if (out.covered_statement_root.IsNull() ||
        out.constraint_system_commitment.IsNull() ||
        out.proof_commitment.IsNull() ||
        !SerializeAirQuotientProofAlg(
            proof, out.proof_bytes, &why) ||
        out.proof_bytes.empty()) {
        out.note =
            "stage3:recursive_hierarchy:retain:" + why;
        return out;
    }
    out.proof_retained = true;
    if (!aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            constraint_system,
            proof,
            fs_seed,
            &why)) {
        out.note =
            "stage3:recursive_hierarchy:"
            "native_verify:" + why;
        return out;
    }
    out.native_proof_verified = true;
    out.cryptographic_child = true;
    out.full_byte_count =
        ComputeRetainedHierarchyNodeFullBytesV1(out);
    out.node_root =
        ComputeRetainedHierarchyNodeRootV1(out);
    if (out.full_byte_count == 0 ||
        out.node_root.IsNull()) {
        out.note =
            "stage3:recursive_hierarchy:"
            "node_commitment";
        return out;
    }
    out.valid = true;
    out.note =
        "stage3:recursive_hierarchy:"
        "retained_verified";
    return out;
}

bool ValidateRetainedHierarchyNodeV1(
    const ShardOrdinalManifestV1& manifest,
    const aq::AirConstraintSystem<gf::Fp3>& expected_cs,
    const RetainedHierarchyNodeV1& node,
    std::string* why)
{
    if (node.version !=
            kRetainedHierarchyNodeVersionV1 ||
        !node.valid ||
        !node.proof_retained ||
        !node.native_proof_verified ||
        !node.cryptographic_child) {
        return Fail(why, "node_evidence_labels");
    }
    if (!ValidateShardOrdinalCoverageV1(
            manifest, node.coverage, why)) {
        return false;
    }
    if (node.manifest_commitment !=
            manifest.commitment ||
        node.covered_statement_root !=
            ComputeCoveredShardStatementRootV1(
                manifest, node.coverage)) {
        return Fail(why, "node_manifest_binding");
    }
    const uint256 expected_cs_commitment =
        ComputeHierarchyConstraintSystemCommitmentV1(
            expected_cs);
    if (expected_cs_commitment.IsNull() ||
        node.constraint_system_commitment !=
            expected_cs_commitment ||
        !SameConstraintSystemDescription(
            node.constraint_system,
            expected_cs)) {
        return Fail(why, "node_constraint_system");
    }
    if (node.fs_seed.IsNull() ||
        node.quotient_terminals.empty() ||
        !std::all_of(
            node.quotient_terminals.begin(),
            node.quotient_terminals.end(),
            CanonicalFp3)) {
        return Fail(why, "node_public_values");
    }

    std::string codec_why;
    std::vector<unsigned char> encoded;
    if (!SerializeAirQuotientProofAlg(
            node.proof, encoded, &codec_why) ||
        encoded.empty() ||
        encoded != node.proof_bytes) {
        return Fail(
            why, "node_proof_codec:" + codec_why);
    }
    const auto decoded =
        DeserializeAirQuotientProofAlg(
            node.proof_bytes, &codec_why);
    if (!decoded.has_value() ||
        node.proof_commitment !=
            fp::ComputeNormalizedAlgAirProofCommitment(
                *decoded)) {
        return Fail(
            why, "node_proof_commitment:" +
                codec_why);
    }
    std::vector<gf::Fp3> proof_q;
    if (!ExtractProofQuotientTerminalsV1(
            expected_cs, *decoded, proof_q,
            &codec_why) ||
        !SameFp3Vector(
            node.quotient_terminals, proof_q)) {
        return Fail(
            why, "node_q_not_proof_owned:" +
                codec_why);
    }
    if (node.full_byte_count !=
            ComputeRetainedHierarchyNodeFullBytesV1(
                node) ||
        node.node_root.IsNull() ||
        node.node_root !=
            ComputeRetainedHierarchyNodeRootV1(node)) {
        return Fail(why, "node_root_or_bytes");
    }
    std::vector<unsigned char> envelope;
    if (!SerializeRetainedHierarchyNodeEnvelopeV1(
            node, envelope, &codec_why) ||
        envelope.size() != node.full_byte_count) {
        return Fail(
            why, "node_envelope:" + codec_why);
    }
    std::string verify_why;
    if (!aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            expected_cs,
            *decoded,
            node.fs_seed,
            &verify_why)) {
        return Fail(
            why, "node_native_verify:" + verify_why);
    }
    return true;
}

bool ValidateRetainedHierarchyLevelV1(
    const ShardOrdinalManifestV1& manifest,
    const std::vector<
        aq::AirConstraintSystem<gf::Fp3>>& expected_css,
    const std::vector<RetainedHierarchyNodeV1>& nodes,
    std::string* why)
{
    if (nodes.empty() ||
        nodes.size() != expected_css.size() ||
        nodes.size() >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "retained_level_shape");
    }
    const uint32_t level = nodes.front().level;
    std::vector<ShardOrdinalCoverageV1> coverage;
    coverage.reserve(nodes.size());
    for (size_t i = 0; i < nodes.size(); ++i) {
        if (nodes[i].level != level ||
            nodes[i].node_ordinal != i) {
            return Fail(
                why, "retained_level_order");
        }
        coverage.push_back(nodes[i].coverage);
    }
    if (!ValidateExactHierarchyLevelCoverageV1(
            manifest, coverage, why)) {
        return false;
    }
    for (size_t i = 0; i < nodes.size(); ++i) {
        if (!ValidateRetainedHierarchyNodeV1(
                manifest,
                expected_css[i],
                nodes[i],
                why)) {
            return false;
        }
    }
    return true;
}

} // namespace matmul::v4::rc::recursive_hierarchy
