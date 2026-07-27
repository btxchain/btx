// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_recursive_parent.h>

#include <hash.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <limits>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v11_recursive_parent {
namespace {

using gf::Fp3;

constexpr uint64_t kChildDomainV1 =
    0x31564c49'48434452ULL; // "RDCHILV1"
constexpr uint64_t kParentDomainV1 =
    0x31564c49'52505256ULL; // "VRPRILV1"
constexpr uint64_t kAbiDomainV1 =
    0x31564c49'49424156ULL; // "VABILV1"
constexpr uint64_t kWireDomainV1 =
    0x31564c49'45524957ULL; // "WIREILV1"
constexpr uint64_t kJoinDomainV1 =
    0x31564c49'4e494f4aULL; // "JOINILV1"
constexpr uint64_t kMerkleDomainV1 =
    0x31564c49'4b52454dULL; // "MERKILV1"
constexpr uint64_t kParentProgramDomainV1 =
    0x31564c49'474f5250ULL; // "PROGILV1"

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

uint256 SeedFromWords(const std::array<uint32_t, 8>& words)
{
    uint256 out;
    for (uint32_t word = 0; word < words.size(); ++word) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            out.data()[4 * word + byte] =
                static_cast<unsigned char>(
                    words[word] >> (8 * byte));
        }
    }
    return out;
}

std::array<uint32_t, kRootWordsV1> HashWords(const uint256& root)
{
    std::array<uint32_t, kRootWordsV1> out{};
    for (uint32_t word = 0; word < out.size(); ++word) {
        const uint32_t byte = 4 * word;
        out[word] =
            uint32_t{root.data()[byte]} |
            (uint32_t{root.data()[byte + 1]} << 8) |
            (uint32_t{root.data()[byte + 2]} << 16) |
            (uint32_t{root.data()[byte + 3]} << 24);
    }
    return out;
}

void HashChildIdentity(HashWriter& hash, const ChildReceiptV1& child)
{
    hash << child.ordinal;
    hash << child.role;
    hash << child.trace_rows;
    hash << child.trace_columns;
    hash << child.quotient_len;
    hash << child.proof_bytes;
    hash << child.shard_count;
    hash << child.shard_queries;
    hash << child.program_root;
    hash << child.application_statement_root;
    hash << child.public_fs_seed;
    hash << child.proof_abi_root;
    hash << child.proof_wire_root;
    hash << child.parent_join_root;
    hash << child.merkle_fold_root;
}

void HashChild(HashWriter& hash, const ChildReceiptV1& child)
{
    HashChildIdentity(hash, child);
    hash << child.child_statement_root;
}

uint256 HashAbiWords(const std::vector<uint32_t>& words)
{
    HashWriter hash;
    hash << kAbiDomainV1;
    hash << static_cast<uint32_t>(words.size());
    for (uint32_t word : words) hash << word;
    return hash.GetHash();
}

uint256 HashWire(const std::vector<unsigned char>& wire)
{
    HashWriter hash;
    hash << kWireDomainV1;
    hash << static_cast<uint32_t>(wire.size());
    for (unsigned char byte : wire) hash << byte;
    return hash.GetHash();
}

bool EqualRef(
    const mf::ParentConsumerCellRefV1& a,
    const mf::ParentConsumerCellRefV1& b)
{
    return
        a.kind == b.kind &&
        a.query == b.query &&
        a.group == b.group &&
        a.item == b.item &&
        a.coordinate == b.coordinate &&
        a.limb == b.limb &&
        a.source_address == b.source_address &&
        a.value == b.value;
}

std::vector<uint32_t> PreprocessedColumns(
    const aq::AirConstraintSystem<Fp3>& cs)
{
    std::vector<uint32_t> out;
    out.reserve(cs.preprocessed.size());
    for (const auto& column : cs.preprocessed) {
        out.push_back(column.first);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

bool RootForProduct(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    uint256& root)
{
    const auto ordered = PreprocessedColumns(cs);
    if (ordered.empty()) return false;
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            cs, columns, ordered);
    if (!session.valid || session.base_row_commitment.IsNull()) {
        return false;
    }
    root = session.base_row_commitment;
    return true;
}

uint256 HashParentJoin(
    const pj::ProductV1& product,
    bool& valid)
{
    valid = false;
    if (!product.valid ||
        !product.public_inventory_exact ||
        !product.public_parent_columns_root_pinned ||
        !product.public_claims_equal_parent_air_constrained ||
        !product.public_claims_equal_replay_air_constrained ||
        !product.derived_candidates_equal_replay_air_constrained ||
        !product.selected_ordinals_equal_replay_air_constrained ||
        !product.selected_query_indices_equal_proof_air_constrained ||
        !product.canonical_u64_decomposition_air_constrained ||
        !product.exact_ordered_preprocessed_root ||
        product.preprocessed_row_group_root.IsNull() ||
        pj::RecountViolationsV1(product, product.columns) != 0) {
        return {};
    }
    uint256 recomputed;
    if (!RootForProduct(product.cs, product.columns, recomputed) ||
        recomputed != product.preprocessed_row_group_root) {
        return {};
    }
    HashWriter hash;
    hash << kJoinDomainV1;
    hash << kRecursiveParentVersionV1;
    hash << recomputed;
    hash << product.cs.n_rows;
    hash << product.cs.n_columns;
    hash << static_cast<uint32_t>(product.cs.constraints.size());
    hash << product.public_source_cells;
    hash << product.derived_candidate_cells;
    hash << product.query_index_cells;
    valid = true;
    return hash.GetHash();
}

struct MerkleBinding {
    uint256 root{};
    uint32_t shard_count{0};
    uint32_t shard_queries{0};
    bool full_coverage{false};
    bool valid{false};
};

MerkleBinding HashMerkleFold(
    const abi::DecodedV1& decoded,
    const std::vector<mf::ShardProductV1>& shards)
{
    MerkleBinding out;
    if (shards.empty()) return out;
    const auto expected = mf::BuildParentConsumerCellRefsV1(decoded);
    std::array<uint8_t, abi::kQueryCountV11> coverage{};
    HashWriter hash;
    hash << kMerkleDomainV1;
    hash << kRecursiveParentVersionV1;
    hash << static_cast<uint32_t>(shards.size());
    for (const auto& shard : shards) {
        if (!shard.valid ||
            !shard.canonical_abi ||
            !shard.transcript_receipt_verified ||
            !shard.current_group_paths_verified ||
            !shard.next_group_paths_verified ||
            !shard.fold_paths_verified ||
            !shard.fold_equations_air_constrained ||
            !shard.terminal_value_air_constrained ||
            !shard.proof_owned_pins_ood_bound ||
            !shard.constant_width_schedule ||
            !shard.literal_parent_consumer_refs ||
            shard.query_count == 0 ||
            shard.first_query >= abi::kQueryCountV11 ||
            shard.query_count >
                abi::kQueryCountV11 - shard.first_query) {
            return {};
        }
        for (uint32_t q = shard.first_query;
             q < shard.first_query + shard.query_count; ++q) {
            if (coverage[q] != 0) return {};
            coverage[q] = 1;
        }
        std::vector<mf::ParentConsumerCellRefV1> expected_refs;
        for (const auto& ref : expected) {
            if (ref.query >= shard.first_query &&
                ref.query < shard.first_query + shard.query_count) {
                expected_refs.push_back(ref);
            }
        }
        if (expected_refs.size() !=
            shard.parent_consumer_refs.size()) {
            return {};
        }
        for (uint32_t i = 0; i < expected_refs.size(); ++i) {
            if (!EqualRef(
                    expected_refs[i],
                    shard.parent_consumer_refs[i])) {
                return {};
            }
        }
        uint256 hash_root;
        uint256 fold_root;
        if (!RootForProduct(
                shard.hash_cs, shard.hash_columns, hash_root) ||
            !RootForProduct(
                shard.fold_cs, shard.fold_columns, fold_root)) {
            return {};
        }
        hash << shard.first_query;
        hash << shard.query_count;
        hash << hash_root;
        hash << fold_root;
        hash << shard.hash_real_rows;
        hash << shard.fold_real_rows;
        hash << static_cast<uint32_t>(
            shard.parent_consumer_refs.size());
        out.shard_queries += shard.query_count;
    }
    out.shard_count = static_cast<uint32_t>(shards.size());
    out.full_coverage = std::all_of(
        coverage.begin(), coverage.end(),
        [](uint8_t value) { return value == 1; });
    out.root = hash.GetHash();
    out.valid = !out.root.IsNull();
    return out;
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

uint64_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    std::vector<Fp3> cur(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    uint64_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        for (uint32_t column = 0; column < cs.n_columns; ++column) {
            if (columns[column].size() != cs.n_rows) {
                return std::numeric_limits<uint64_t>::max();
            }
            cur[column] = columns[column][row];
            next[column] =
                columns[column][(row + 1) % cs.n_rows];
        }
        for (const auto& constraint : cs.constraints) {
            bool applies = false;
            switch (constraint.kind) {
            case aq::AirKind::kEverywhere:
                applies = true;
                break;
            case aq::AirKind::kTransition:
                applies = row + 1 < cs.n_rows;
                break;
            case aq::AirKind::kFirstRow:
                applies = row == 0;
                break;
            case aq::AirKind::kLastRow:
                applies = row + 1 == cs.n_rows;
                break;
            }
            if (applies &&
                !gf::IsZero(constraint.eval(cur, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

std::array<uint256, kRootSlotsV1> Roots(
    const ChildReceiptV1& child)
{
    return {
        child.program_root,
        child.application_statement_root,
        child.public_fs_seed,
        child.proof_abi_root,
        child.proof_wire_root,
        child.parent_join_root,
        child.merkle_fold_root,
        child.child_statement_root,
    };
}

struct ChildBuild {
    ChildReceiptV1 receipt{};
    tp::ReceiptV1 transcript{};
    bool full_shards{false};
    bool valid{false};
    std::string note;
};

ChildBuild BuildChild(
    const ChildInputV1& input,
    uint32_t ordinal)
{
    ChildBuild out;
    auto fail = [&](const std::string& why) {
        out.note = "stage3:v11_recursive_parent:child:" + why;
        return out;
    };
    if (ordinal >= kRecursiveParentArityV1 ||
        input.statement.role == 0 ||
        input.statement.program_root.IsNull() ||
        input.statement.application_statement_root.IsNull() ||
        input.statement.public_fs_seed.IsNull()) {
        return fail("statement");
    }
    std::string why;
    if (!backend::VerifyAirQuotientV1(
            input.cs, input.proof,
            input.base_column_indices,
            input.statement.public_fs_seed, &why)) {
        return fail("native:" + why);
    }
    if (!backend::VerifyV1(
            input.proof, &out.transcript, &why)) {
        return fail("native_transcript:" + why);
    }
    std::vector<uint32_t> words;
    std::vector<abi::SourceCellV1> sources;
    if (!abi::EncodeCanonicalV1(
            input.proof.envelope, words, &sources, &why)) {
        return fail("abi:" + why);
    }
    const auto decoded = abi::DecodeCanonicalV1(words, &why);
    if (!decoded.has_value() ||
        !decoded->canonical || !decoded->complete) {
        return fail("abi_decode:" + why);
    }
    std::vector<unsigned char> wire;
    const size_t proof_bytes =
        backend::SerializeV1(input.proof, wire);
    if (proof_bytes == 0 ||
        proof_bytes != wire.size() ||
        proof_bytes > std::numeric_limits<uint32_t>::max()) {
        return fail("proof_codec");
    }
    bool parent_valid = false;
    const uint256 parent_root =
        HashParentJoin(input.parent_join, parent_valid);
    if (!parent_valid) return fail("parent_join");
    const auto merkle =
        HashMerkleFold(*decoded, input.merkle_fold_shards);
    if (!merkle.valid) return fail("merkle_fold");
    auto& child = out.receipt;
    child.ordinal = ordinal;
    child.role = input.statement.role;
    child.trace_rows = input.cs.n_rows;
    child.trace_columns = input.cs.n_columns;
    child.quotient_len = input.cs.QuotientLen();
    child.proof_bytes = static_cast<uint32_t>(proof_bytes);
    child.shard_count = merkle.shard_count;
    child.shard_queries = merkle.shard_queries;
    child.program_root = input.statement.program_root;
    child.application_statement_root =
        input.statement.application_statement_root;
    child.public_fs_seed = input.statement.public_fs_seed;
    child.proof_abi_root = HashAbiWords(words);
    child.proof_wire_root = HashWire(wire);
    child.parent_join_root = parent_root;
    child.merkle_fold_root = merkle.root;
    child.child_statement_root =
        ComputeChildStatementRootV1(child);
    out.full_shards = merkle.full_coverage;
    out.valid =
        !child.proof_abi_root.IsNull() &&
        !child.proof_wire_root.IsNull() &&
        !child.child_statement_root.IsNull();
    out.note = out.valid
        ? "stage3:v11_recursive_parent:child_native_verified"
        : "stage3:v11_recursive_parent:child_roots";
    return out;
}

bool EqualChild(
    const ChildReceiptV1& a,
    const ChildReceiptV1& b)
{
    return
        a.ordinal == b.ordinal &&
        a.role == b.role &&
        a.trace_rows == b.trace_rows &&
        a.trace_columns == b.trace_columns &&
        a.quotient_len == b.quotient_len &&
        a.proof_bytes == b.proof_bytes &&
        a.shard_count == b.shard_count &&
        a.shard_queries == b.shard_queries &&
        a.program_root == b.program_root &&
        a.application_statement_root ==
            b.application_statement_root &&
        a.public_fs_seed == b.public_fs_seed &&
        a.proof_abi_root == b.proof_abi_root &&
        a.proof_wire_root == b.proof_wire_root &&
        a.parent_join_root == b.parent_join_root &&
        a.merkle_fold_root == b.merkle_fold_root &&
        a.child_statement_root == b.child_statement_root;
}

uint256 ParentApplicationRoot(
    const std::array<ChildReceiptV1, kRecursiveParentArityV1>& children)
{
    HashWriter hash;
    hash << kParentDomainV1;
    hash << uint32_t{0x41505031U}; // "APP1"
    for (const auto& child : children) {
        hash << child.ordinal;
        hash << child.child_statement_root;
    }
    return hash.GetHash();
}

uint256 ParentSeed(
    const uint256& program,
    const uint256& application,
    const uint256& acceptance)
{
    HashWriter hash;
    hash << kParentDomainV1;
    hash << uint32_t{0x53454544U}; // "SEED"
    hash << program;
    hash << application;
    hash << acceptance;
    return hash.GetHash();
}

void PopulateAcceptance(
    ProductV1& out,
    const std::array<ChildReceiptV1, kRecursiveParentArityV1>& children)
{
    out.layout = CanonicalLayoutV1();
    out.acceptance_cs.n_rows =
        kRecursiveParentTraceRowsV1;
    out.acceptance_cs.n_columns = out.layout.n_columns;
    out.acceptance_columns.assign(
        out.layout.n_columns,
        std::vector<Fp3>(
            kRecursiveParentTraceRowsV1, Fp3::Zero()));
    const auto put = [&](uint32_t column, uint32_t row, uint64_t value) {
        out.acceptance_columns[column][row] = U(value);
    };
    for (uint32_t row = 0; row < kRecursiveParentArityV1; ++row) {
        const auto& child = children[row];
        put(out.layout.active, row, 1);
        put(out.layout.ordinal, row, child.ordinal);
        put(out.layout.accepted, row, 1);
        put(out.layout.role, row, child.role);
        put(out.layout.trace_rows, row, child.trace_rows);
        put(out.layout.trace_columns, row, child.trace_columns);
        put(out.layout.quotient_len, row, child.quotient_len);
        put(out.layout.proof_bytes, row, child.proof_bytes);
        put(out.layout.shard_count, row, child.shard_count);
        put(out.layout.shard_queries, row, child.shard_queries);
        const auto roots = Roots(child);
        for (uint32_t root = 0; root < roots.size(); ++root) {
            const auto words = HashWords(roots[root]);
            for (uint32_t word = 0; word < words.size(); ++word) {
                put(out.layout.RootWord(root, word), row, words[word]);
            }
        }
    }
    AddConstraint(
        out.acceptance_cs,
        "stage3.v11_recursive_parent.active_boolean",
        aq::AirKind::kEverywhere, 2,
        [layout = out.layout](const auto& cur, const auto&) {
            return gf::Mul(
                cur[layout.active],
                gf::Sub(cur[layout.active], Fp3::One()));
        });
    AddConstraint(
        out.acceptance_cs,
        "stage3.v11_recursive_parent.ordinal_boolean",
        aq::AirKind::kEverywhere, 2,
        [layout = out.layout](const auto& cur, const auto&) {
            return gf::Mul(
                cur[layout.ordinal],
                gf::Sub(cur[layout.ordinal], Fp3::One()));
        });
    AddConstraint(
        out.acceptance_cs,
        "stage3.v11_recursive_parent.accepted_equals_active",
        aq::AirKind::kEverywhere, 1,
        [layout = out.layout](const auto& cur, const auto&) {
            return gf::Sub(
                cur[layout.accepted],
                cur[layout.active]);
        });
    AddConstraint(
        out.acceptance_cs,
        "stage3.v11_recursive_parent.padding_ordinal_zero",
        aq::AirKind::kEverywhere, 2,
        [layout = out.layout](const auto& cur, const auto&) {
            return gf::Mul(
                gf::Sub(Fp3::One(), cur[layout.active]),
                cur[layout.ordinal]);
        });
    AddConstraint(
        out.acceptance_cs,
        "stage3.v11_recursive_parent.ordinal_first",
        aq::AirKind::kFirstRow, 1,
        [layout = out.layout](const auto& cur, const auto&) {
            return cur[layout.ordinal];
        });
    AddConstraint(
        out.acceptance_cs,
        "stage3.v11_recursive_parent.padding_last",
        aq::AirKind::kLastRow, 1,
        [layout = out.layout](const auto& cur, const auto&) {
            return cur[layout.active];
        });
    AddConstraint(
        out.acceptance_cs,
        "stage3.v11_recursive_parent.first_to_second_active",
        aq::AirKind::kTransition, 3,
        [layout = out.layout](const auto& cur, const auto& next) {
            const Fp3 first = gf::Mul(
                cur[layout.active],
                gf::Sub(Fp3::One(), cur[layout.ordinal]));
            return gf::Mul(
                first,
                gf::Sub(next[layout.active], Fp3::One()));
        });
    AddConstraint(
        out.acceptance_cs,
        "stage3.v11_recursive_parent.first_to_second_ordinal",
        aq::AirKind::kTransition, 3,
        [layout = out.layout](const auto& cur, const auto& next) {
            const Fp3 first = gf::Mul(
                cur[layout.active],
                gf::Sub(Fp3::One(), cur[layout.ordinal]));
            return gf::Mul(
                first,
                gf::Sub(next[layout.ordinal], Fp3::One()));
        });
    AddConstraint(
        out.acceptance_cs,
        "stage3.v11_recursive_parent.second_to_padding",
        aq::AirKind::kTransition, 3,
        [layout = out.layout](const auto& cur, const auto& next) {
            const Fp3 second = gf::Mul(
                cur[layout.active],
                cur[layout.ordinal]);
            return gf::Mul(second, next[layout.active]);
        });
    AddConstraint(
        out.acceptance_cs,
        "stage3.v11_recursive_parent.padding_stays_padding",
        aq::AirKind::kTransition, 2,
        [layout = out.layout](const auto& cur, const auto& next) {
            return gf::Mul(
                gf::Sub(Fp3::One(), cur[layout.active]),
                next[layout.active]);
        });
    // Pin both exact rows in the mirror AIR. These constants are host-built
    // from the child statement and are not called canonical bytecode.
    for (uint32_t column = 0; column < out.layout.n_columns; ++column) {
        const Fp3 first = out.acceptance_columns[column][0];
        const Fp3 last = out.acceptance_columns[column][1];
        AddConstraint(
            out.acceptance_cs,
            "stage3.v11_recursive_parent.pin_first",
            aq::AirKind::kEverywhere, 3,
            [layout = out.layout, column, first](
                const auto& cur, const auto&) {
                const Fp3 selector = gf::Mul(
                    cur[layout.active],
                    gf::Sub(
                        Fp3::One(),
                        cur[layout.ordinal]));
                return gf::Mul(
                    selector,
                    gf::Sub(cur[column], first));
            });
        AddConstraint(
            out.acceptance_cs,
            "stage3.v11_recursive_parent.pin_last",
            aq::AirKind::kEverywhere, 3,
            [layout = out.layout, column, last](
                const auto& cur, const auto&) {
                const Fp3 selector = gf::Mul(
                    cur[layout.active],
                    cur[layout.ordinal]);
                return gf::Mul(
                    selector,
                    gf::Sub(cur[column], last));
            });
        AddConstraint(
            out.acceptance_cs,
            "stage3.v11_recursive_parent.pin_padding_zero",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout, column](
                const auto& cur, const auto&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[layout.active]),
                    cur[column]);
            });
    }
    out.preprocessed_columns.resize(out.layout.n_columns);
    for (uint32_t column = 0; column < out.layout.n_columns; ++column) {
        out.preprocessed_columns[column] = column;
        out.acceptance_cs.preprocessed.push_back(
            {column, out.acceptance_columns[column]});
    }
    out.acceptance_cs.preprocessed_pin_ood = true;
}

bool FinalizeAcceptanceRoot(ProductV1& out)
{
    if (CountViolations(
            out.acceptance_cs, out.acceptance_columns) != 0) {
        return false;
    }
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.acceptance_cs, out.acceptance_columns,
            out.preprocessed_columns);
    if (!session.valid || session.base_row_commitment.IsNull()) {
        return false;
    }
    out.receipt.acceptance_row_root =
        session.base_row_commitment;
    out.acceptance_cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role = aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = out.preprocessed_columns,
        .root = out.receipt.acceptance_row_root,
    });
    out.parent_proof_cs = out.acceptance_cs;
    out.parent_proof_cs.preprocessed.clear();
    out.parent_proof_cs.preprocessed_roots.clear();
    out.parent_proof_cs.preprocessed_row_group_roots.clear();
    out.parent_proof_cs.preprocessed_pin_ood = false;
    out.parent_base_column_indices.clear();
    for (uint32_t column = 0;
         column + 1 < out.layout.n_columns; ++column) {
        out.parent_base_column_indices.push_back(column);
    }
    return !out.parent_base_column_indices.empty();
}

uint256 ProofRoot(const backend::ProofV1& proof)
{
    std::vector<unsigned char> wire;
    if (backend::SerializeV1(proof, wire) == 0) return {};
    return HashWire(wire);
}

void Write16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void Write32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void WriteHash(std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes)
        : m_cur(bytes.data()), m_end(bytes.data() + bytes.size())
    {
    }

    bool U16(uint16_t& out)
    {
        if (Remaining() < 2) return false;
        out = uint16_t{m_cur[0]} |
            (uint16_t{m_cur[1]} << 8);
        m_cur += 2;
        return true;
    }

    bool U32(uint32_t& out)
    {
        if (Remaining() < 4) return false;
        out =
            uint32_t{m_cur[0]} |
            (uint32_t{m_cur[1]} << 8) |
            (uint32_t{m_cur[2]} << 16) |
            (uint32_t{m_cur[3]} << 24);
        m_cur += 4;
        return true;
    }

    bool Hash(uint256& out)
    {
        if (Remaining() < out.size()) return false;
        std::copy(m_cur, m_cur + out.size(), out.begin());
        m_cur += out.size();
        return true;
    }

    bool Bytes(uint32_t size, std::vector<unsigned char>& out)
    {
        if (Remaining() < size) return false;
        out.assign(m_cur, m_cur + size);
        m_cur += size;
        return true;
    }

    [[nodiscard]] size_t Remaining() const
    {
        return static_cast<size_t>(m_end - m_cur);
    }

private:
    const unsigned char* m_cur;
    const unsigned char* m_end;
};

void WriteChild(
    std::vector<unsigned char>& out,
    const ChildReceiptV1& child)
{
    Write32(out, child.ordinal);
    Write32(out, child.role);
    Write32(out, child.trace_rows);
    Write32(out, child.trace_columns);
    Write32(out, child.quotient_len);
    Write32(out, child.proof_bytes);
    Write32(out, child.shard_count);
    Write32(out, child.shard_queries);
    WriteHash(out, child.program_root);
    WriteHash(out, child.application_statement_root);
    WriteHash(out, child.public_fs_seed);
    WriteHash(out, child.proof_abi_root);
    WriteHash(out, child.proof_wire_root);
    WriteHash(out, child.parent_join_root);
    WriteHash(out, child.merkle_fold_root);
    WriteHash(out, child.child_statement_root);
}

bool ReadChild(Reader& reader, ChildReceiptV1& child)
{
    return
        reader.U32(child.ordinal) &&
        reader.U32(child.role) &&
        reader.U32(child.trace_rows) &&
        reader.U32(child.trace_columns) &&
        reader.U32(child.quotient_len) &&
        reader.U32(child.proof_bytes) &&
        reader.U32(child.shard_count) &&
        reader.U32(child.shard_queries) &&
        reader.Hash(child.program_root) &&
        reader.Hash(child.application_statement_root) &&
        reader.Hash(child.public_fs_seed) &&
        reader.Hash(child.proof_abi_root) &&
        reader.Hash(child.proof_wire_root) &&
        reader.Hash(child.parent_join_root) &&
        reader.Hash(child.merkle_fold_root) &&
        reader.Hash(child.child_statement_root);
}

} // namespace

LayoutV1 CanonicalLayoutV1()
{
    LayoutV1 out;
    out.active = out.n_columns++;
    out.ordinal = out.n_columns++;
    out.accepted = out.n_columns++;
    out.role = out.n_columns++;
    out.trace_rows = out.n_columns++;
    out.trace_columns = out.n_columns++;
    out.quotient_len = out.n_columns++;
    out.proof_bytes = out.n_columns++;
    out.shard_count = out.n_columns++;
    out.shard_queries = out.n_columns++;
    out.roots_base = out.n_columns;
    out.n_columns += kRootSlotsV1 * kRootWordsV1;
    return out;
}

uint256 CanonicalParentProgramRootV1()
{
    HashWriter hash;
    hash << kParentProgramDomainV1;
    hash << kRecursiveParentVersionV1;
    hash << kRecursiveParentArityV1;
    hash << CanonicalLayoutV1().n_columns;
    hash << uint32_t{2}; // first/last exact-row relation family
    return hash.GetHash();
}

uint256 ComputeChildStatementRootV1(
    const ChildReceiptV1& child)
{
    HashWriter hash;
    hash << kChildDomainV1;
    hash << kRecursiveParentVersionV1;
    HashChildIdentity(hash, child);
    return hash.GetHash();
}

uint256 ComputeParentReceiptRootV1(
    const ParentReceiptV1& receipt)
{
    HashWriter hash;
    hash << kParentDomainV1;
    hash << receipt.version;
    hash << receipt.arity;
    hash << receipt.acceptance_rows;
    hash << receipt.acceptance_columns;
    hash << receipt.parent_program_root;
    hash << receipt.parent_application_statement_root;
    hash << receipt.parent_fs_seed;
    hash << receipt.acceptance_row_root;
    hash << receipt.parent_proof_root;
    for (const auto& child : receipt.children) {
        HashChild(hash, child);
    }
    return hash.GetHash();
}

ProductV1 BuildProductV1(
    const std::array<ChildInputV1, kRecursiveParentArityV1>& children)
{
    ProductV1 out;
    auto fail = [&](const std::string& why) {
        out.note = "stage3:v11_recursive_parent:" + why;
        return out;
    };
    std::array<ChildBuild, kRecursiveParentArityV1> built;
    for (uint32_t child = 0;
         child < kRecursiveParentArityV1; ++child) {
        built[child] = BuildChild(children[child], child);
        if (!built[child].valid) {
            return fail(built[child].note);
        }
        out.receipt.children[child] =
            built[child].receipt;
        ++out.native_children_verified;
        ++out.published_parent_joins_consumed;
        out.published_merkle_fold_products_consumed +=
            built[child].receipt.shard_count;
        if (built[child].full_shards) {
            ++out.fully_materialized_children;
        }
    }
    out.receipt.version = kRecursiveParentVersionV1;
    out.receipt.arity = kRecursiveParentArityV1;
    out.receipt.parent_program_root =
        CanonicalParentProgramRootV1();
    out.receipt.parent_application_statement_root =
        ParentApplicationRoot(out.receipt.children);
    PopulateAcceptance(out, out.receipt.children);
    out.receipt.acceptance_rows = out.acceptance_cs.n_rows;
    out.receipt.acceptance_columns =
        out.acceptance_cs.n_columns;
    if (!FinalizeAcceptanceRoot(out)) {
        return fail("acceptance_root");
    }
    out.receipt.parent_fs_seed = ParentSeed(
        out.receipt.parent_program_root,
        out.receipt.parent_application_statement_root,
        out.receipt.acceptance_row_root);
    const auto prove_start =
        std::chrono::steady_clock::now();
    const auto proved = backend::ProveAirQuotientV1(
        out.parent_proof_cs,
        out.acceptance_columns,
        out.parent_base_column_indices,
        out.receipt.parent_fs_seed);
    out.parent_prove_micros =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - prove_start)
            .count();
    if (!proved.ok || !proved.proximity.ok) {
        return fail("parent_prove:" + proved.note);
    }
    out.receipt.parent_proof = proved.proximity.proof;
    out.parent_proof_bytes = proved.proximity.proof_bytes;
    out.parent_transcript = proved.proximity.transcript;
    out.receipt.parent_proof_root =
        ProofRoot(out.receipt.parent_proof);
    if (out.receipt.parent_proof_root.IsNull()) {
        return fail("parent_proof_root");
    }
    std::string why;
    const auto verify_start =
        std::chrono::steady_clock::now();
    const bool parent_verified =
        backend::VerifyAirQuotientV1(
            out.parent_proof_cs,
            out.receipt.parent_proof,
            out.parent_base_column_indices,
            out.receipt.parent_fs_seed,
            &why);
    out.parent_verify_micros =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - verify_start)
            .count();
    if (!parent_verified) {
        return fail("parent_verify:" + why);
    }
    out.receipt.receipt_root =
        ComputeParentReceiptRootV1(out.receipt);
    std::vector<unsigned char> wire;
    out.encoded_bytes =
        SerializeReceiptV1(out.receipt, wire);
    if (out.encoded_bytes == 0 ||
        out.encoded_bytes != wire.size()) {
        return fail("receipt_codec");
    }
    out.residual_mask =
        kResidualSameParentDecoderJoin |
        kResidualDeepQuotientChip |
        kResidualCanonicalConstraintVm |
        kResidualRecursiveV11Verifier |
        kResidualCanonicalParentProgram;
    if (out.fully_materialized_children !=
        kRecursiveParentArityV1) {
        out.residual_mask |=
            kResidualFullShardMaterialization;
    }
    out.width_slope_per_child_proof_column = 0;
    out.exact_arity_and_order = true;
    out.role_program_statement_seed_bound = true;
    out.proof_abi_roots_recomputed = true;
    out.child_proof_payloads_native_verified = true;
    out.parent_join_roots_recomputed = true;
    out.merkle_fold_roots_recomputed = true;
    out.acceptance_rows_root_pinned = true;
    out.constant_width_acceptance =
        out.layout.n_columns ==
            CanonicalLayoutV1().n_columns;
    out.parent_own_v11_proof_executed = true;
    out.parent_own_v11_proof_verified = true;
    out.level_two_native_reentry_supported = true;
    out.child_verifier_executed_in_parent_air = false;
    out.canonical_recursive_verifier_executable = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.native_children_verified ==
            kRecursiveParentArityV1 &&
        out.acceptance_rows_root_pinned &&
        out.constant_width_acceptance &&
        out.parent_own_v11_proof_verified &&
        out.residual_mask != 0;
    out.note = out.valid
        ? "stage3:v11_recursive_parent:arity2_native_parent;"
          "decoder_deep_vm_recursive_verifier_pending"
        : "stage3:v11_recursive_parent:invalid";
    return out;
}

bool VerifyReceiptV1(
    const std::array<ChildInputV1, kRecursiveParentArityV1>& expected_children,
    const ParentReceiptV1& receipt,
    std::string* why)
{
    const auto fail = [&](const std::string& detail) {
        if (why) {
            *why =
                "stage3:v11_recursive_parent_verify:" +
                detail;
        }
        return false;
    };
    if (receipt.version != kRecursiveParentVersionV1 ||
        receipt.arity != kRecursiveParentArityV1 ||
        receipt.acceptance_rows !=
            kRecursiveParentTraceRowsV1 ||
        receipt.acceptance_columns !=
            CanonicalLayoutV1().n_columns ||
        receipt.parent_program_root !=
            CanonicalParentProgramRootV1()) {
        return fail("header");
    }
    std::array<ChildReceiptV1, kRecursiveParentArityV1> expected{};
    for (uint32_t child = 0;
         child < kRecursiveParentArityV1; ++child) {
        const auto built =
            BuildChild(expected_children[child], child);
        if (!built.valid) return fail(built.note);
        expected[child] = built.receipt;
        if (!EqualChild(expected[child], receipt.children[child]) ||
            receipt.children[child].ordinal != child ||
            receipt.children[child].child_statement_root !=
                ComputeChildStatementRootV1(
                    receipt.children[child])) {
            return fail("child_order_or_identity");
        }
    }
    if (receipt.parent_application_statement_root !=
        ParentApplicationRoot(expected)) {
        return fail("parent_statement");
    }
    ProductV1 rebuilt;
    rebuilt.receipt.children = expected;
    PopulateAcceptance(rebuilt, expected);
    rebuilt.receipt.acceptance_rows =
        rebuilt.acceptance_cs.n_rows;
    rebuilt.receipt.acceptance_columns =
        rebuilt.acceptance_cs.n_columns;
    if (!FinalizeAcceptanceRoot(rebuilt) ||
        rebuilt.receipt.acceptance_row_root !=
            receipt.acceptance_row_root) {
        return fail("acceptance_root");
    }
    const uint256 expected_seed = ParentSeed(
        receipt.parent_program_root,
        receipt.parent_application_statement_root,
        receipt.acceptance_row_root);
    if (receipt.parent_fs_seed != expected_seed ||
        SeedFromWords(
            receipt.parent_proof.envelope.public_fs_seed) !=
            expected_seed) {
        return fail("parent_seed");
    }
    std::string backend_why;
    if (!backend::VerifyAirQuotientV1(
            rebuilt.parent_proof_cs,
            receipt.parent_proof,
            rebuilt.parent_base_column_indices,
            expected_seed, &backend_why)) {
        return fail("parent_proof:" + backend_why);
    }
    if (ProofRoot(receipt.parent_proof) !=
            receipt.parent_proof_root ||
        receipt.receipt_root !=
            ComputeParentReceiptRootV1(receipt)) {
        return fail("proof_or_receipt_root");
    }
    if (why) {
        *why =
            "stage3:v11_recursive_parent_verify:"
            "native_children_and_parent";
    }
    return true;
}

size_t SerializeReceiptV1(
    const ParentReceiptV1& receipt,
    std::vector<unsigned char>& out)
{
    out.clear();
    if (receipt.version != kRecursiveParentVersionV1 ||
        receipt.arity != kRecursiveParentArityV1 ||
        receipt.receipt_root !=
            ComputeParentReceiptRootV1(receipt)) {
        return 0;
    }
    std::vector<unsigned char> proof;
    if (backend::SerializeV1(receipt.parent_proof, proof) == 0 ||
        proof.size() > std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    Write32(out, kRecursiveParentWireMagicV1);
    Write16(out, receipt.version);
    Write16(out, 0);
    Write32(out, receipt.arity);
    Write32(out, receipt.acceptance_rows);
    Write32(out, receipt.acceptance_columns);
    WriteHash(out, receipt.parent_program_root);
    WriteHash(out, receipt.parent_application_statement_root);
    WriteHash(out, receipt.parent_fs_seed);
    WriteHash(out, receipt.acceptance_row_root);
    WriteHash(out, receipt.parent_proof_root);
    for (const auto& child : receipt.children) {
        WriteChild(out, child);
    }
    Write32(out, static_cast<uint32_t>(proof.size()));
    out.insert(out.end(), proof.begin(), proof.end());
    WriteHash(out, receipt.receipt_root);
    if (out.size() > kMaxReceiptBytesV1) {
        out.clear();
        return 0;
    }
    return out.size();
}

std::optional<ParentReceiptV1> DeserializeReceiptV1(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    const auto fail =
        [&](const std::string& detail)
            -> std::optional<ParentReceiptV1> {
        if (why) {
            *why =
                "stage3:v11_recursive_parent_decode:" +
                detail;
        }
        return std::nullopt;
    };
    if (bytes.empty() || bytes.size() > kMaxReceiptBytesV1) {
        return fail("size");
    }
    Reader reader(bytes);
    ParentReceiptV1 out;
    uint32_t magic = 0;
    uint16_t reserved = 0;
    if (!reader.U32(magic) ||
        !reader.U16(out.version) ||
        !reader.U16(reserved) ||
        !reader.U32(out.arity) ||
        !reader.U32(out.acceptance_rows) ||
        !reader.U32(out.acceptance_columns) ||
        magic != kRecursiveParentWireMagicV1 ||
        out.version != kRecursiveParentVersionV1 ||
        reserved != 0 ||
        out.arity != kRecursiveParentArityV1 ||
        out.acceptance_rows !=
            kRecursiveParentTraceRowsV1 ||
        out.acceptance_columns !=
            CanonicalLayoutV1().n_columns ||
        !reader.Hash(out.parent_program_root) ||
        !reader.Hash(
            out.parent_application_statement_root) ||
        !reader.Hash(out.parent_fs_seed) ||
        !reader.Hash(out.acceptance_row_root) ||
        !reader.Hash(out.parent_proof_root)) {
        return fail("header");
    }
    for (uint32_t child = 0;
         child < kRecursiveParentArityV1; ++child) {
        if (!ReadChild(reader, out.children[child]) ||
            out.children[child].ordinal != child ||
            out.children[child].child_statement_root !=
                ComputeChildStatementRootV1(
                    out.children[child])) {
            return fail("child");
        }
    }
    uint32_t proof_size = 0;
    std::vector<unsigned char> proof;
    if (!reader.U32(proof_size) ||
        proof_size == 0 ||
        proof_size > kMaxReceiptBytesV1 ||
        !reader.Bytes(proof_size, proof) ||
        !reader.Hash(out.receipt_root) ||
        reader.Remaining() != 0) {
        return fail("payload");
    }
    std::string proof_why;
    const auto decoded =
        backend::DeserializeV1(proof, &proof_why);
    if (!decoded.has_value()) {
        return fail("parent_proof:" + proof_why);
    }
    out.parent_proof = *decoded;
    if (ProofRoot(out.parent_proof) !=
            out.parent_proof_root ||
        out.receipt_root !=
            ComputeParentReceiptRootV1(out)) {
        return fail("root");
    }
    std::vector<unsigned char> canonical;
    if (SerializeReceiptV1(out, canonical) != bytes.size() ||
        canonical != bytes) {
        return fail("noncanonical");
    }
    if (why) {
        *why =
            "stage3:v11_recursive_parent_decode:canonical";
    }
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_recursive_parent
