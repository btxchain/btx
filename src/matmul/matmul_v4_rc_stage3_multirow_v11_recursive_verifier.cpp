// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_recursive_verifier.h>

#include <hash.h>

#include <algorithm>
#include <limits>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v11_recursive_verifier {
namespace {

constexpr uint64_t kReceiptDomainV1 =
    0x31565253'50434552ULL; // "RECPSRV1"
constexpr uint64_t kSetDomainV1 =
    0x31565253'54455352ULL; // "RSE TSRV1"
constexpr uint64_t kAbiDomainV1 =
    0x31565253'49424152ULL; // "RABISRV1"
constexpr uint64_t kWireDomainV1 =
    0x31565253'45524957ULL; // "WIERSRV1"
constexpr uint64_t kTranscriptDomainV1 =
    0x31565253'4e525454ULL; // "TTRNSRV1"

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2) return 2;
    if (value > (uint64_t{1} << 31)) return 0;
    uint32_t out = 1;
    while (out < value) out <<= 1;
    return out;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 &&
        b > std::numeric_limits<uint64_t>::max() / a) {
        return false;
    }
    out = a * b;
    return true;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a > std::numeric_limits<uint64_t>::max() - b) {
        return false;
    }
    out = a + b;
    return true;
}

uint256 HashAbi(const backend::ProofV1& proof)
{
    std::vector<uint32_t> words;
    if (!abi::EncodeCanonicalV1(
            proof.envelope, words, nullptr, nullptr) ||
        words.empty()) {
        return {};
    }
    HashWriter hash;
    hash << kAbiDomainV1;
    hash << static_cast<uint32_t>(words.size());
    for (uint32_t word : words) hash << word;
    return hash.GetHash();
}

uint256 HashWire(const backend::ProofV1& proof)
{
    std::vector<unsigned char> wire;
    if (backend::SerializeV1(proof, wire) != wire.size() ||
        wire.empty()) {
        return {};
    }
    HashWriter hash;
    hash << kWireDomainV1;
    hash << static_cast<uint32_t>(wire.size());
    for (unsigned char byte : wire) hash << byte;
    return hash.GetHash();
}

std::optional<abi::DecodedV1> Decode(
    const backend::ProofV1& proof,
    std::string* why)
{
    std::vector<uint32_t> words;
    if (!abi::EncodeCanonicalV1(
            proof.envelope, words, nullptr, why)) {
        return std::nullopt;
    }
    return abi::DecodeCanonicalV1(words, why);
}

bool RootFor(
    const air_quotient::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns,
    const std::vector<uint32_t>& ordered,
    uint256& root)
{
    if (ordered.empty()) return false;
    const auto session =
        air_quotient::AirQuotientBuildTwoEpochBaseRowSession(
            cs, columns, ordered);
    if (!session.valid || session.base_row_commitment.IsNull()) {
        return false;
    }
    root = session.base_row_commitment;
    return true;
}

std::vector<uint32_t> Preprocessed(
    const air_quotient::AirConstraintSystem<gf::Fp3>& cs)
{
    std::vector<uint32_t> out;
    out.reserve(cs.preprocessed.size());
    for (const auto& item : cs.preprocessed) {
        out.push_back(item.first);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

uint32_t CountDuplicateQueries(const backend::ProofV1& proof)
{
    std::set<uint32_t> indices;
    uint32_t duplicates = 0;
    for (const auto& query :
         proof.envelope.split.batch.queries) {
        if (!indices.insert(query.index).second) ++duplicates;
    }
    return duplicates;
}

} // namespace

CapAuditV1 AuditDirectAndQ64RowsV1(
    uint32_t child_columns,
    uint32_t child_constraints,
    uint32_t assumed_instructions_per_constraint)
{
    CapAuditV1 out;
    out.child_columns = child_columns;
    out.child_constraints = child_constraints;
    out.assumed_instructions_per_constraint =
        assumed_instructions_per_constraint;
    if (child_columns == 0 || child_constraints == 0 ||
        assumed_instructions_per_constraint == 0) {
        out.note = "stage3:v11_recursive_verifier:cap:zero_shape";
        return out;
    }
    uint64_t instruction_rows = 0;
    if (!CheckedMul(
            child_constraints,
            assumed_instructions_per_constraint,
            instruction_rows)) {
        out.note = "stage3:v11_recursive_verifier:cap:overflow";
        return out;
    }
    uint64_t per_query = 0;
    if (!CheckedAdd(
            child_columns, instruction_rows, per_query) ||
        !CheckedAdd(per_query, 2, per_query) ||
        !CheckedMul(
            per_query, abi::kQueryCountV11,
            out.direct_q192_vm_rows) ||
        !CheckedMul(
            per_query, kQueriesPerShardV1,
            out.q64_vm_rows)) {
        out.note = "stage3:v11_recursive_verifier:cap:overflow";
        return out;
    }
    out.q64_trace_rows = NextPowerOfTwo(out.q64_vm_rows);
    uint64_t lde = 0;
    if (out.q64_trace_rows != 0 &&
        CheckedMul(
            out.q64_trace_rows, kRCFriBlowup, lde) &&
        lde <= std::numeric_limits<uint32_t>::max()) {
        out.q64_lde_rows = static_cast<uint32_t>(lde);
    }
    out.direct_exceeds_trace_cap =
        out.direct_q192_vm_rows > kTraceRowsCapV1;
    out.q64_fits_trace_cap =
        out.q64_trace_rows != 0 &&
        out.q64_trace_rows <= kTraceRowsCapV1;
    out.q64_fits_lde_cap =
        out.q64_lde_rows != 0 &&
        out.q64_lde_rows <= kLdeRowsCapV1;
    out.valid =
        out.direct_exceeds_trace_cap &&
        out.q64_fits_trace_cap &&
        out.q64_fits_lde_cap;
    out.note = out.valid
        ? "stage3:v11_recursive_verifier:cap:q64_required_and_fits"
        : "stage3:v11_recursive_verifier:cap:shape_not_closed";
    return out;
}

uint256 ComputeShardReceiptRootV1(
    const ShardReceiptV1& receipt)
{
    HashWriter hash;
    hash << kReceiptDomainV1;
    hash << receipt.version;
    hash << receipt.range.ordinal;
    hash << receipt.range.first_query;
    hash << receipt.range.query_count;
    hash << receipt.child_abi_root;
    hash << receipt.child_wire_root;
    hash << receipt.child_statement_root;
    hash << receipt.full_q192_transcript_root;
    hash << receipt.public_fs_seed;
    for (gf::Fp limb : receipt.program_root) hash << limb;
    hash << receipt.parent_join_r0_root;
    hash << receipt.merkle_hash_r0_root;
    hash << receipt.merkle_fold_r0_root;
    hash << receipt.deep_vm_r0_root;
    hash << receipt.decoder_join_r0_root;
    hash << receipt.merkle_hash_rows;
    hash << receipt.merkle_hash_columns;
    hash << receipt.merkle_fold_rows;
    hash << receipt.merkle_fold_columns;
    hash << receipt.deep_vm_rows;
    hash << receipt.deep_vm_columns;
    hash << receipt.decoder_join_rows;
    hash << receipt.decoder_join_columns;
    hash << receipt.materialized_trace_cells;
    hash << receipt.measured_unaggregated_wire_bytes;
    return hash.GetHash();
}

uint256 ComputeFullTranscriptRootV1(
    const tp::ReceiptV1& transcript)
{
    if (!transcript.valid ||
        !transcript.q192_with_replacement) {
        return {};
    }
    HashWriter hash;
    hash << kTranscriptDomainV1;
    hash << transcript.statement_version;
    hash << transcript.protocol_version;
    hash << transcript.protocol_domain;
    for (gf::Fp limb : transcript.shape_commit) hash << limb;
    hash << transcript.air_lambda.c0;
    hash << transcript.air_lambda.c1;
    hash << transcript.air_lambda.c2;
    for (gf::Fp limb : transcript.fri_seed) hash << limb;
    for (const auto& candidate : transcript.z1_candidates) {
        hash << candidate.c0 << candidate.c1 << candidate.c2;
    }
    for (const auto& candidate : transcript.z2_candidates) {
        hash << candidate.c0 << candidate.c1 << candidate.c2;
    }
    hash << transcript.z1_selected << transcript.z2_selected;
    hash << transcript.z1.c0 << transcript.z1.c1 << transcript.z1.c2;
    hash << transcript.z2.c0 << transcript.z2.c1 << transcript.z2.c2;
    for (gf::Fp limb : transcript.ood_eval_commit) hash << limb;
    for (gf::Fp limb : transcript.batch_seed) hash << limb;
    hash << static_cast<uint32_t>(
        transcript.batching_coefficients.size());
    for (const auto& coefficient :
         transcript.batching_coefficients) {
        hash << coefficient.c0 << coefficient.c1 << coefficient.c2;
    }
    hash << transcript.w1.c0 << transcript.w1.c1 << transcript.w1.c2;
    hash << transcript.w2.c0 << transcript.w2.c1 << transcript.w2.c2;
    hash << static_cast<uint32_t>(
        transcript.fold_challenges.size());
    for (const auto& challenge : transcript.fold_challenges) {
        hash << challenge.c0 << challenge.c1 << challenge.c2;
    }
    for (gf::Fp limb : transcript.query_seed) hash << limb;
    hash << static_cast<uint32_t>(transcript.queries.size());
    for (uint32_t query = 0;
         query < transcript.queries.size(); ++query) {
        const auto& item = transcript.queries[query];
        hash << query << item.selected_ordinal << item.index;
        for (const auto& candidate : item.candidate_digest) {
            for (gf::Fp limb : candidate) hash << limb;
        }
    }
    return hash.GetHash();
}

uint256 ComputeShardSetRootV1(
    const std::array<ShardReceiptV1, kQueryShardsV1>& receipts)
{
    HashWriter hash;
    hash << kSetDomainV1;
    hash << kRecursiveVerifierVersionV1;
    hash << kQueryShardsV1;
    for (const auto& receipt : receipts) {
        hash << receipt.receipt_root;
    }
    return hash.GetHash();
}

ShardProductV1 BuildSingleShardAuditV1(
    const InputV1& input,
    const QueryRangeV1& range)
{
    ShardProductV1 out;
    out.range = range;
    auto fail = [&out](const std::string& why) -> ShardProductV1 {
        out.note =
            "stage3:v11_recursive_verifier:single_shard:" + why;
        return out;
    };
    if (range.query_count == 0 ||
        range.first_query >= abi::kQueryCountV11 ||
        range.query_count >
            abi::kQueryCountV11 - range.first_query ||
        input.expected_child_statement_root.IsNull()) {
        return fail("range_or_statement");
    }
    std::string why;
    const auto decoded = Decode(input.proof, &why);
    if (!decoded.has_value() ||
        !decoded->canonical || !decoded->complete) {
        return fail("codec:" + why);
    }
    if (!cb::ValidateProgramTable(input.child_program, &why) ||
        cb::CommitProgramTableAlgHash(input.child_program) !=
            input.expected_child_program_root) {
        return fail("program:" + why);
    }
    if (!input.parent_join.valid ||
        pj::RecountViolationsV1(
            input.parent_join,
            input.parent_join.columns) != 0) {
        return fail("parent_join");
    }

    out.merkle_fold = mf::BuildShardV1(
        *decoded, input.transcript,
        range.first_query, range.query_count);
    if (!out.merkle_fold.valid) {
        return fail("merkle:" + out.merkle_fold.note);
    }
    out.deep_vm = dvm::BuildProductV1(
        input.proof, input.transcript,
        input.child_program,
        input.expected_child_program_root,
        range.first_query, range.query_count);
    if (!out.deep_vm.valid) {
        return fail("deep_vm:" + out.deep_vm.note);
    }
    const auto decoder = dj::BuildProductV1(
        *decoded, input.parent_join, {out.merkle_fold});
    if (!decoder.valid ||
        dj::RecountViolationsV1(decoder, decoder.columns) != 0) {
        return fail("decoder:" + decoder.note);
    }

    uint256 hash_root;
    uint256 fold_root;
    uint256 deep_root;
    if (!RootFor(
            out.merkle_fold.hash_cs,
            out.merkle_fold.hash_columns,
            Preprocessed(out.merkle_fold.hash_cs),
            hash_root) ||
        !RootFor(
            out.merkle_fold.fold_cs,
            out.merkle_fold.fold_columns,
            Preprocessed(out.merkle_fold.fold_cs),
            fold_root) ||
        !RootFor(
            out.deep_vm.cs,
            out.deep_vm.columns,
            out.deep_vm.preprocessed_columns,
            deep_root)) {
        return fail("component_root");
    }
    auto& receipt = out.receipt;
    receipt.range = range;
    receipt.child_abi_root = HashAbi(input.proof);
    receipt.child_wire_root = HashWire(input.proof);
    receipt.child_statement_root =
        input.expected_child_statement_root;
    receipt.full_q192_transcript_root =
        ComputeFullTranscriptRootV1(input.transcript);
    for (uint32_t word = 0; word < 8; ++word) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            receipt.public_fs_seed.data()[4 * word + byte] =
                static_cast<unsigned char>(
                    input.proof.envelope.public_fs_seed[word] >>
                    (8 * byte));
        }
    }
    receipt.program_root = input.expected_child_program_root;
    receipt.parent_join_r0_root =
        input.parent_join.preprocessed_row_group_root;
    receipt.merkle_hash_r0_root = hash_root;
    receipt.merkle_fold_r0_root = fold_root;
    receipt.deep_vm_r0_root = deep_root;
    receipt.decoder_join_r0_root =
        decoder.preprocessed_row_group_root;
    receipt.merkle_hash_rows =
        out.merkle_fold.hash_cs.n_rows;
    receipt.merkle_hash_columns =
        out.merkle_fold.hash_cs.n_columns;
    receipt.merkle_fold_rows =
        out.merkle_fold.fold_cs.n_rows;
    receipt.merkle_fold_columns =
        out.merkle_fold.fold_cs.n_columns;
    receipt.deep_vm_rows = out.deep_vm.cs.n_rows;
    receipt.deep_vm_columns = out.deep_vm.cs.n_columns;
    receipt.decoder_join_rows = decoder.cs.n_rows;
    receipt.decoder_join_columns = decoder.cs.n_columns;
    receipt.materialized_trace_cells =
        uint64_t{receipt.merkle_hash_rows} *
            receipt.merkle_hash_columns +
        uint64_t{receipt.merkle_fold_rows} *
            receipt.merkle_fold_columns +
        uint64_t{receipt.deep_vm_rows} *
            receipt.deep_vm_columns +
        uint64_t{receipt.decoder_join_rows} *
            receipt.decoder_join_columns;
    receipt.receipt_root =
        ComputeShardReceiptRootV1(receipt);

    out.exact_query_range = true;
    out.merkle_and_fold_air_executable =
        out.merkle_fold.hash_violations == 0 &&
        out.merkle_fold.fold_violations == 0 &&
        out.merkle_fold.fold_equations_air_constrained &&
        out.merkle_fold.terminal_value_air_constrained;
    out.deep_quotient_vm_air_executable =
        out.deep_vm.violations == 0 &&
        out.deep_vm.deep_rlc_air_constrained &&
        out.deep_vm.first_fold_equality_air_constrained &&
        out.deep_vm.quotient_identity_air_constrained &&
        out.deep_vm.canonical_bytecode_vm_air_constrained;
    out.identical_child_statement_bound = true;
    out.proof_owned_roots_recomputed = true;
    out.recursive_receipt_verified_in_air = false;
    out.valid =
        !receipt.child_abi_root.IsNull() &&
        !receipt.child_wire_root.IsNull() &&
        !receipt.full_q192_transcript_root.IsNull() &&
        !receipt.receipt_root.IsNull() &&
        out.merkle_and_fold_air_executable &&
        out.deep_quotient_vm_air_executable &&
        out.proof_owned_roots_recomputed &&
        !out.recursive_receipt_verified_in_air;
    out.note = out.valid
        ? "stage3:v11_recursive_verifier:single_shard:"
          "actual_child_materialized;receipt_air_pending"
        : "stage3:v11_recursive_verifier:single_shard:invalid";
    return out;
}

ProductV1 BuildProductV1(const InputV1& input)
{
    ProductV1 out;
    auto fail = [&out](const std::string& why) -> ProductV1 {
        out.note =
            "stage3:v11_recursive_verifier:" + why;
        return out;
    };

    std::string why;
    const auto decoded = Decode(input.proof, &why);
    if (!decoded.has_value() ||
        !decoded->canonical || !decoded->complete) {
        return fail("codec:" + why);
    }
    if (!cb::ValidateProgramTable(input.child_program, &why) ||
        cb::CommitProgramTableAlgHash(input.child_program) !=
            input.expected_child_program_root) {
        return fail("program:" + why);
    }
    if (!input.parent_join.valid ||
        pj::RecountViolationsV1(
            input.parent_join,
            input.parent_join.columns) != 0) {
        return fail("parent_join");
    }

    out.child_abi_root = HashAbi(input.proof);
    out.child_wire_root = HashWire(input.proof);
    out.full_q192_transcript_root =
        ComputeFullTranscriptRootV1(input.transcript);
    if (out.child_abi_root.IsNull() ||
        out.child_wire_root.IsNull() ||
        out.full_q192_transcript_root.IsNull() ||
        input.expected_child_statement_root.IsNull()) {
        return fail("child_roots");
    }

    const auto ranges = CanonicalQueryRangesV1();
    std::vector<mf::ShardProductV1> merkle_products;
    merkle_products.reserve(kQueryShardsV1);
    std::array<ShardReceiptV1, kQueryShardsV1> receipts{};
    uint32_t next_query = 0;
    for (uint32_t shard_index = 0;
         shard_index < kQueryShardsV1; ++shard_index) {
        auto& shard = out.shards[shard_index];
        shard.range = ranges[shard_index];
        shard.exact_query_range =
            shard.range.ordinal == shard_index &&
            shard.range.first_query == next_query &&
            shard.range.query_count == kQueriesPerShardV1;
        if (!shard.exact_query_range) {
            return fail("query_partition");
        }
        next_query += shard.range.query_count;

        shard.merkle_fold = mf::BuildShardV1(
            *decoded, input.transcript,
            shard.range.first_query,
            shard.range.query_count);
        if (!shard.merkle_fold.valid) {
            return fail(
                "merkle_shard_" +
                std::to_string(shard_index) + ":" +
                shard.merkle_fold.note);
        }
        shard.deep_vm = dvm::BuildProductV1(
            input.proof, input.transcript,
            input.child_program,
            input.expected_child_program_root,
            shard.range.first_query,
            shard.range.query_count);
        if (!shard.deep_vm.valid) {
            return fail(
                "deep_vm_shard_" +
                std::to_string(shard_index) + ":" +
                shard.deep_vm.note);
        }

        uint256 hash_root;
        uint256 fold_root;
        uint256 deep_root;
        if (!RootFor(
                shard.merkle_fold.hash_cs,
                shard.merkle_fold.hash_columns,
                Preprocessed(shard.merkle_fold.hash_cs),
                hash_root) ||
            !RootFor(
                shard.merkle_fold.fold_cs,
                shard.merkle_fold.fold_columns,
                Preprocessed(shard.merkle_fold.fold_cs),
                fold_root) ||
            !RootFor(
                shard.deep_vm.cs,
                shard.deep_vm.columns,
                shard.deep_vm.preprocessed_columns,
                deep_root)) {
            return fail(
                "shard_root_" +
                std::to_string(shard_index));
        }

        shard.merkle_and_fold_air_executable =
            shard.merkle_fold.hash_violations == 0 &&
            shard.merkle_fold.fold_violations == 0 &&
            shard.merkle_fold.fold_equations_air_constrained &&
            shard.merkle_fold.terminal_value_air_constrained;
        shard.deep_quotient_vm_air_executable =
            shard.deep_vm.violations == 0 &&
            shard.deep_vm.deep_rlc_air_constrained &&
            shard.deep_vm.first_fold_equality_air_constrained &&
            shard.deep_vm.quotient_identity_air_constrained &&
            shard.deep_vm.canonical_bytecode_vm_air_constrained;
        shard.identical_child_statement_bound = true;
        shard.proof_owned_roots_recomputed = true;
        shard.recursive_receipt_verified_in_air = false;

        auto& receipt = shard.receipt;
        receipt.range = shard.range;
        receipt.child_abi_root = out.child_abi_root;
        receipt.child_wire_root = out.child_wire_root;
        receipt.child_statement_root =
            input.expected_child_statement_root;
        receipt.full_q192_transcript_root =
            out.full_q192_transcript_root;
        for (uint32_t word = 0; word < 8; ++word) {
            const uint64_t limb =
                input.proof.envelope.public_fs_seed[word];
            for (uint32_t byte = 0; byte < 4; ++byte) {
                receipt.public_fs_seed.data()[4 * word + byte] =
                    static_cast<unsigned char>(
                        limb >> (8 * byte));
            }
        }
        receipt.program_root =
            input.expected_child_program_root;
        receipt.parent_join_r0_root =
            input.parent_join.preprocessed_row_group_root;
        receipt.merkle_hash_r0_root = hash_root;
        receipt.merkle_fold_r0_root = fold_root;
        receipt.deep_vm_r0_root = deep_root;
        receipt.merkle_hash_rows =
            shard.merkle_fold.hash_trace_rows;
        receipt.merkle_hash_columns =
            shard.merkle_fold.hash_cs.n_columns;
        receipt.merkle_fold_rows =
            shard.merkle_fold.fold_trace_rows;
        receipt.merkle_fold_columns =
            shard.merkle_fold.fold_cs.n_columns;
        receipt.deep_vm_rows = shard.deep_vm.trace_rows;
        receipt.deep_vm_columns = shard.deep_vm.cs.n_columns;
        receipt.materialized_trace_cells =
            uint64_t{receipt.merkle_hash_rows} *
                receipt.merkle_hash_columns +
            uint64_t{receipt.merkle_fold_rows} *
                receipt.merkle_fold_columns +
            uint64_t{receipt.deep_vm_rows} *
                receipt.deep_vm_columns;
        receipt.receipt_root =
            ComputeShardReceiptRootV1(receipt);
        if (receipt.receipt_root.IsNull()) {
            return fail("receipt_root");
        }
        receipts[shard_index] = receipt;
        merkle_products.push_back(shard.merkle_fold);
    }

    if (next_query != abi::kQueryCountV11) {
        return fail("q192_coverage");
    }
    out.exact_queries_covered = next_query;
    out.exact_disjoint_q192_partition = true;
    out.duplicate_query_occurrences_preserved =
        CountDuplicateQueries(input.proof);

    out.decoder_join = dj::BuildProductV1(
        *decoded, input.parent_join, merkle_products);
    if (!out.decoder_join.valid ||
        dj::RecountViolationsV1(
            out.decoder_join,
            out.decoder_join.columns) != 0) {
        return fail("decoder_join:" + out.decoder_join.note);
    }
    for (auto& shard : out.shards) {
        shard.receipt.decoder_join_r0_root =
            out.decoder_join.preprocessed_row_group_root;
        shard.receipt.decoder_join_rows =
            out.decoder_join.trace_rows;
        shard.receipt.decoder_join_columns =
            out.decoder_join.cs.n_columns;
        shard.receipt.materialized_trace_cells +=
            uint64_t{shard.receipt.decoder_join_rows} *
            shard.receipt.decoder_join_columns;
        shard.receipt.receipt_root =
            ComputeShardReceiptRootV1(shard.receipt);
        shard.valid =
            shard.exact_query_range &&
            shard.merkle_and_fold_air_executable &&
            shard.deep_quotient_vm_air_executable &&
            shard.identical_child_statement_bound &&
            shard.proof_owned_roots_recomputed &&
            !shard.recursive_receipt_verified_in_air;
        receipts[shard.range.ordinal] = shard.receipt;
    }
    out.shard_set_root = ComputeShardSetRootV1(receipts);
    if (out.shard_set_root.IsNull()) {
        return fail("shard_set_root");
    }

    out.direct_parent_join_cap_audit =
        AuditDirectAndQ64RowsV1(
            input.parent_join.cs.n_columns,
            static_cast<uint32_t>(
                input.parent_join.cs.constraints.size()),
            5);
    out.identical_commitment_transcript_statement =
        std::all_of(
            out.shards.begin(), out.shards.end(),
            [&out](const ShardProductV1& shard) {
                return
                    shard.receipt.child_abi_root ==
                        out.child_abi_root &&
                    shard.receipt.child_wire_root ==
                        out.child_wire_root &&
                    shard.receipt.full_q192_transcript_root ==
                        out.full_q192_transcript_root;
            });
    out.every_merkle_fold_shard_air_executable =
        std::all_of(
            out.shards.begin(), out.shards.end(),
            [](const ShardProductV1& shard) {
                return shard.merkle_and_fold_air_executable;
            });
    out.every_deep_vm_shard_air_executable =
        std::all_of(
            out.shards.begin(), out.shards.end(),
            [](const ShardProductV1& shard) {
                return shard.deep_quotient_vm_air_executable;
            });
    out.decoder_ownership_join_executable =
        out.decoder_join.dual_rational_identity_air_constrained &&
        out.decoder_join.terminal_sums_zero &&
        out.decoder_join.duplicate_query_identity_preserved;
    out.binary_receipt_tree_executable = false;
    out.binary_join_internal_nodes = kQueryShardsV1 - 1;
    out.binary_join_depth = 2;
    out.canonical_recursive_verifier_program_executable = false;
    out.residual_mask =
        kResidualSameParentR0Alias |
        kResidualRecursiveReceiptVerification |
        kResidualCanonicalVerifierProgram |
        kResidualBinaryReceiptJoin |
        kResidualCodecAbiSponge;
    out.recursive_authority_ready = false;
    out.valid =
        out.exact_disjoint_q192_partition &&
        out.identical_commitment_transcript_statement &&
        out.every_merkle_fold_shard_air_executable &&
        out.every_deep_vm_shard_air_executable &&
        out.decoder_ownership_join_executable &&
        out.residual_mask != 0 &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v11_recursive_verifier:q64_shards_executable;"
          "recursive_receipt_and_same_parent_alias_pending"
        : "stage3:v11_recursive_verifier:invalid";
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_recursive_verifier
