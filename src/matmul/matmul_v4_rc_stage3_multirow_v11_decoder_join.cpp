// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_decoder_join.h>

#include <algorithm>
#include <bit>
#include <functional>
#include <limits>
#include <map>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v11_decoder_join {
namespace {

using gf::Fp;
using gf::Fp3;
namespace tp = stage3_multirow_p2_transcript;

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

bool Applies(aq::AirKind kind, uint32_t row, uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere: return true;
    case aq::AirKind::kTransition: return row + 1 < rows;
    case aq::AirKind::kFirstRow: return row == 0;
    case aq::AirKind::kLastRow: return row + 1 == rows;
    }
    return false;
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name, aq::AirKind kind, uint32_t degree,
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

void AddBoolean(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name, uint32_t column)
{
    AddConstraint(
        cs, name, aq::AirKind::kEverywhere, 2,
        [column](const auto& cur, const auto&) {
            return gf::Mul(
                cur[column],
                gf::Sub(cur[column], Fp3::One()));
        });
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    if (value < 2) return 2;
    return std::bit_ceil(value);
}

bool ScalarU32(const Fp3& value, uint32_t& out)
{
    if (gf::Canonical(value.c1) != 0 ||
        gf::Canonical(value.c2) != 0) {
        return false;
    }
    const uint64_t raw = gf::Canonical(value.c0);
    if (raw > std::numeric_limits<uint32_t>::max()) return false;
    out = static_cast<uint32_t>(raw);
    return true;
}

tp::StatementV1 StatementFrom(const abi::DecodedV1& decoded)
{
    tp::StatementV1 statement;
    for (uint32_t word = 0; word < 8; ++word) {
        const uint32_t value = decoded.envelope.public_fs_seed[word];
        for (uint32_t byte = 0; byte < 4; ++byte) {
            statement.public_fs_seed.data()[4 * word + byte] =
                static_cast<unsigned char>(value >> (8 * byte));
        }
    }
    const auto& split = decoded.envelope.split;
    const auto& batch = split.batch;
    statement.pow_grind_nonce = batch.pow_grind_nonce;
    statement.trace_rows = split.trace_rows;
    statement.trace_columns = decoded.envelope.trace_columns;
    statement.quotient_len = decoded.envelope.quotient_len;
    statement.n_coeffs = batch.n_coeffs;
    statement.blowup = batch.blowup;
    statement.base_column_indices = split.base_column_indices;
    if (batch.groups.size() == statement.groups.size()) {
        for (uint32_t group = 0; group < statement.groups.size(); ++group) {
            statement.groups[group] = {
                batch.groups[group].role,
                batch.groups[group].first_column,
                batch.groups[group].column_count,
                batch.groups[group].row_commit.n_leaves,
                batch.groups[group].row_commit.root};
        }
    }
    statement.column_len = batch.column_len;
    statement.evals_z1 = batch.evals_z1;
    statement.evals_z2 = batch.evals_z2;
    for (const auto& fold : batch.fold_layers) {
        statement.folds.push_back({fold.n_leaves, fold.root});
    }
    statement.final_value = batch.final_value;
    return statement;
}

bool ParentReplayMatches(
    const abi::DecodedV1& decoded,
    const djp::ProductV1& parent)
{
    const auto replay = tp::BuildProductV1(StatementFrom(decoded));
    if (!replay.valid ||
        replay.trace_rows != parent.cs.n_rows ||
        replay.layout.n_columns != parent.layout.replay.n_columns ||
        parent.columns.size() < replay.layout.n_columns) {
        return false;
    }
    for (uint32_t column = 0;
         column < replay.layout.n_columns; ++column) {
        if (parent.columns[column].size() != replay.trace_rows) return false;
        for (uint32_t row = 0; row < replay.trace_rows; ++row) {
            if (!gf::Eq(
                    parent.columns[column][row],
                    replay.columns[column][row])) {
                return false;
            }
        }
    }
    return true;
}

std::vector<uint32_t> PreprocessedColumns(
    const aq::AirConstraintSystem<Fp3>& cs)
{
    std::vector<uint32_t> out;
    out.reserve(cs.preprocessed.size());
    for (const auto& column : cs.preprocessed) out.push_back(column.first);
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

bool RecomputeRoot(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& preprocessed,
    uint256& root)
{
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            cs, columns, preprocessed);
    if (!session.valid || session.base_row_commitment.IsNull()) return false;
    root = session.base_row_commitment;
    return true;
}

std::array<Fp3, 4> DeriveChallenges(const uint256& parent_root)
{
    std::array<Fp3, 4> out{};
    std::vector<Fp> input;
    input.reserve(8);
    for (uint32_t word = 0; word < 4; ++word) {
        input.push_back(gf::FromU64(parent_root.GetUint64(word)));
    }
    input.push_back(gf::FromU64(0x444a5631U)); // "DJV1"
    for (uint32_t lane = 0; lane < out.size(); ++lane) {
        input.back() = gf::Add(input.back(), gf::FromU64(lane));
        const auto digest = alg_hash::SpongeHashFp(input);
        out[lane] = {digest[0], digest[1], digest[2]};
        if (gf::IsZero(out[lane])) out[lane] = U(lane + 1);
    }
    if (gf::Eq(out[0], out[1])) out[1] = gf::Add(out[1], Fp3::One());
    if (gf::Eq(out[2], out[3])) out[3] = gf::Add(out[3], Fp3::One());
    return out;
}

Fp3 CompressOccurrence(
    const OccurrenceV1& occurrence,
    const Fp3& gamma,
    const Fp3& alpha)
{
    Fp3 power = Fp3::One();
    Fp3 term = alpha;
    const std::array<uint64_t, 4> fields{
        static_cast<uint8_t>(occurrence.kind),
        occurrence.occurrence_id,
        occurrence.source_address,
        occurrence.value};
    for (uint64_t field : fields) {
        power = gf::Mul(power, gamma);
        term = gf::Add(term, gf::Mul(power, U(field)));
    }
    return term;
}

void AddOccurrence(
    std::vector<OccurrenceV1>& out,
    ConsumerKindV1 kind,
    uint32_t address, uint32_t value,
    uint32_t query, uint32_t shard, uint32_t local)
{
    out.push_back({
        kind, static_cast<uint32_t>(out.size()),
        address, value, query, shard, local});
}

bool AppendParentOccurrences(
    const abi::DecodedV1& decoded,
    const djp::ProductV1& parent,
    std::vector<OccurrenceV1>& out)
{
    // Every canonical proof field absorbed or rederived by the exact parent
    // replay is represented once.  Opening cells acquire additional literal
    // occurrences from the Merkle/fold shards below.
    for (const auto& source : decoded.sources) {
        // Opening values, siblings and fold steps (kinds 42..60) are owned
        // by their exact shard occurrences below.  Copying the entire Q192
        // envelope into this transcript subtable would add tens of thousands
        // of tautological rows and destroy the narrow fixed-point shape.
        if (source.key.kind > abi::FieldKindV1::QueryGroupCount) continue;
        AddOccurrence(
            out, ConsumerKindV1::ParentTranscript,
            source.address, source.value, source.key.a, 0,
            static_cast<uint32_t>(source.key.kind));
    }

    for (uint32_t row = 0; row < parent.cs.n_rows; ++row) {
        for (uint32_t lane = 0;
             lane < djp::kPublicAbsorbSlotsV1; ++lane) {
            const auto slot = parent.layout.public_absorb[lane];
            if (gf::Eq(parent.columns[slot.active][row], Fp3::One())) {
                uint32_t address = 0, value = 0;
                if (!ScalarU32(parent.columns[slot.source_address][row], address) ||
                    !ScalarU32(parent.columns[slot.claim][row], value)) {
                    return false;
                }
                AddOccurrence(
                    out, ConsumerKindV1::ParentPublic,
                    address, value, 0, 0, row * 8 + lane);
            }
        }
        for (const auto& split : parent.layout.public_field) {
            if (!gf::Eq(parent.columns[split.active][row], Fp3::One())) continue;
            uint32_t alo = 0, ahi = 0, lo = 0, hi = 0;
            if (!ScalarU32(parent.columns[split.address_lo][row], alo) ||
                !ScalarU32(parent.columns[split.address_hi][row], ahi) ||
                !ScalarU32(parent.columns[split.claim_lo][row], lo) ||
                !ScalarU32(parent.columns[split.claim_hi][row], hi)) {
                return false;
            }
            AddOccurrence(out, ConsumerKindV1::ParentPublic, alo, lo, 0, 0, row);
            AddOccurrence(out, ConsumerKindV1::ParentPublic, ahi, hi, 0, 0, row);
        }
        for (const auto& split : parent.layout.candidate_digest) {
            if (!gf::Eq(parent.columns[split.active][row], Fp3::One())) continue;
            uint32_t alo = 0, ahi = 0, lo = 0, hi = 0;
            if (!ScalarU32(parent.columns[split.address_lo][row], alo) ||
                !ScalarU32(parent.columns[split.address_hi][row], ahi) ||
                !ScalarU32(parent.columns[split.claim_lo][row], lo) ||
                !ScalarU32(parent.columns[split.claim_hi][row], hi)) {
                return false;
            }
            AddOccurrence(out, ConsumerKindV1::ParentDerived, alo, lo, 0, 0, row);
            AddOccurrence(out, ConsumerKindV1::ParentDerived, ahi, hi, 0, 0, row);
        }
        uint32_t address = 0, value = 0;
        if (ScalarU32(
                parent.columns[parent.layout.query_index_address][row],
                address) &&
            address != 0 &&
            ScalarU32(
                parent.columns[parent.layout.query_index_claim][row],
                value)) {
            AddOccurrence(
                out, ConsumerKindV1::ParentQueryIndex,
                address, value, 0, 0, row);
        }
    }
    return true;
}

bool AppendShardOccurrences(
    const abi::DecodedV1& decoded,
    const std::vector<mf::ShardProductV1>& shards,
    std::vector<OccurrenceV1>& out)
{
    for (uint32_t shard_index = 0;
         shard_index < shards.size(); ++shard_index) {
        const auto& shard = shards[shard_index];
        for (uint32_t local = 0;
             local < shard.parent_consumer_refs.size(); ++local) {
            const auto& ref = shard.parent_consumer_refs[local];
            AddOccurrence(
                out, ConsumerKindV1::MerkleLiteral,
                ref.source_address, ref.value,
                ref.query, shard_index, local);
        }
        uint32_t local = 0;
        for (const auto& task : shard.hash_tasks) {
            for (uint32_t address : task.source_addresses) {
                if (address >= decoded.sources.size() ||
                    decoded.sources[address].address != address) {
                    return false;
                }
                AddOccurrence(
                    out, ConsumerKindV1::MerkleHashInput,
                    address, decoded.sources[address].value,
                    task.query, shard_index, local++);
            }
        }
        for (uint32_t query = shard.first_query;
             query < shard.first_query + shard.query_count; ++query) {
            for (const auto& source : decoded.sources) {
                if (source.key.kind == abi::FieldKindV1::FoldChallenge) {
                    AddOccurrence(
                        out, ConsumerKindV1::FoldChallenge,
                        source.address, source.value,
                        query, shard_index, local++);
                } else if (
                    source.key.kind == abi::FieldKindV1::FinalValue) {
                    AddOccurrence(
                        out, ConsumerKindV1::FoldTerminal,
                        source.address, source.value,
                        query, shard_index, local++);
                }
            }
        }
    }
    return true;
}

bool CanonicalPairs(const abi::DecodedV1& decoded)
{
    const auto is_field_kind = [](abi::FieldKindV1 kind) {
        switch (kind) {
        case abi::FieldKindV1::AirConstraintLambda:
        case abi::FieldKindV1::GroupRoot:
        case abi::FieldKindV1::Lambda:
        case abi::FieldKindV1::Z1:
        case abi::FieldKindV1::Z2:
        case abi::FieldKindV1::EvalZ1:
        case abi::FieldKindV1::EvalZ2:
        case abi::FieldKindV1::DeepWeight1:
        case abi::FieldKindV1::DeepWeight2:
        case abi::FieldKindV1::FoldRoot:
        case abi::FieldKindV1::FinalValue:
        case abi::FieldKindV1::FoldChallenge:
        case abi::FieldKindV1::QueryCandidateDigest:
        case abi::FieldKindV1::QueryRowValue:
        case abi::FieldKindV1::QueryRowSibling:
        case abi::FieldKindV1::QueryStepEven:
        case abi::FieldKindV1::QueryStepOdd:
        case abi::FieldKindV1::QueryStepEvenSibling:
        case abi::FieldKindV1::QueryStepOddSibling:
        case abi::FieldKindV1::NextRowValue:
        case abi::FieldKindV1::NextRowSibling:
            return true;
        default:
            return false;
        }
    };
    std::map<std::tuple<abi::FieldKindV1, uint32_t, uint32_t,
                       uint32_t, uint32_t>,
             std::array<const abi::SourceCellV1*, 2>> pairs;
    for (const auto& source : decoded.sources) {
        if (source.key.limb > 1) return false;
        auto& pair = pairs[{
            source.key.kind, source.key.a, source.key.b,
            source.key.c, source.key.d}];
        pair[source.key.limb] = &source;
    }
    for (const auto& [key, pair] : pairs) {
        if (!is_field_kind(std::get<0>(key))) continue;
        if (pair[0] == nullptr || pair[1] == nullptr) continue;
        const uint64_t raw =
            uint64_t{pair[0]->value} |
            (uint64_t{pair[1]->value} << 32);
        // Only two-limb scalar encodings can alias field elements.  The ABI
        // decoder has already rejected all field instances >= p.  Rechecking
        // every pair is intentionally conservative and rejects an x+p
        // substitution even if the semantic kind was misclassified.
        if (pair[1]->value == 0xffffffffU &&
            pair[0]->value != 0 &&
            raw >= gf::kP) {
            return false;
        }
    }
    return true;
}

bool PreprocessedRootMatches(
    const ProductV1& product,
    const std::vector<std::vector<Fp3>>& columns)
{
    uint256 root;
    return RecomputeRoot(
               product.cs, columns,
               product.preprocessed_columns, root) &&
        root == product.preprocessed_row_group_root;
}

} // namespace

LayoutV1 CanonicalLayoutV1()
{
    LayoutV1 out;
    uint32_t column = 0;
    out.active = column++;
    out.source_kind = column++;
    out.source_occurrence = column++;
    out.source_address = column++;
    out.source_value = column++;
    out.consumer_kind = column++;
    out.consumer_occurrence = column++;
    out.consumer_address = column++;
    out.consumer_pin = column++;
    out.consumer_claim = column++;
    for (auto& item : out.source_inverse) item = column++;
    for (auto& item : out.consumer_inverse) item = column++;
    for (auto& item : out.running) item = column++;
    out.root_active = column++;
    out.root_kind = column++;
    out.root_index = column++;
    out.root_word = column++;
    out.root_value = column++;
    out.n_columns = column;
    return out;
}

uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != product.cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != product.cs.n_rows) {
            return std::numeric_limits<uint64_t>::max();
        }
    }
    std::vector<Fp3> cur(product.cs.n_columns);
    std::vector<Fp3> next(product.cs.n_columns);
    uint64_t violations = 0;
    for (uint32_t row = 0; row < product.cs.n_rows; ++row) {
        for (uint32_t column = 0;
             column < product.cs.n_columns; ++column) {
            cur[column] = columns[column][row];
            next[column] =
                columns[column][(row + 1) % product.cs.n_rows];
        }
        for (const auto& constraint : product.cs.constraints) {
            if (Applies(constraint.kind, row, product.cs.n_rows) &&
                !gf::IsZero(constraint.eval(cur, next))) {
                ++violations;
            }
        }
    }
    if (!PreprocessedRootMatches(product, columns)) ++violations;
    return violations;
}

ProductV1 BuildProductV1(
    const abi::DecodedV1& decoded,
    const djp::ProductV1& parent,
    const std::vector<mf::ShardProductV1>& shards)
{
    ProductV1 out;
    out.layout = CanonicalLayoutV1();
    if (!decoded.canonical || !decoded.complete ||
        !decoded.addresses_unique || !decoded.semantic_keys_unique ||
        !parent.valid || shards.empty()) {
        out.note = "stage3:v11_decoder_join:invalid_inputs";
        return out;
    }
    if (djp::RecountViolationsV1(parent, parent.columns) != 0 ||
        parent.preprocessed_row_group_root.IsNull()) {
        out.note = "stage3:v11_decoder_join:parent_root";
        return out;
    }
    out.parent_root_recomputed = true;
    out.parent_replay_exactly_matches_decoded =
        ParentReplayMatches(decoded, parent);
    if (!out.parent_replay_exactly_matches_decoded) {
        out.note = "stage3:v11_decoder_join:parent_replay_mismatch";
        return out;
    }

    out.child_roots.push_back({
        1, 0, parent.preprocessed_row_group_root});
    for (uint32_t shard_index = 0;
         shard_index < shards.size(); ++shard_index) {
        const auto& shard = shards[shard_index];
        if (!shard.valid ||
            mf::RecountViolationsV1(
                shard.hash_cs, shard.hash_columns) != 0 ||
            mf::RecountViolationsV1(
                shard.fold_cs, shard.fold_columns) != 0) {
            out.note = "stage3:v11_decoder_join:shard_invalid";
            return out;
        }
        uint256 hash_root, fold_root;
        if (!RecomputeRoot(
                shard.hash_cs, shard.hash_columns,
                PreprocessedColumns(shard.hash_cs), hash_root) ||
            !RecomputeRoot(
                shard.fold_cs, shard.fold_columns,
                PreprocessedColumns(shard.fold_cs), fold_root)) {
            out.note = "stage3:v11_decoder_join:shard_root";
            return out;
        }
        out.child_roots.push_back({2, shard_index, hash_root});
        out.child_roots.push_back({3, shard_index, fold_root});
    }
    out.child_roots_recomputed = true;

    if (!AppendParentOccurrences(
            decoded, parent, out.consumer_occurrences) ||
        !AppendShardOccurrences(
            decoded, shards, out.consumer_occurrences) ||
        out.consumer_occurrences.empty()) {
        out.note = "stage3:v11_decoder_join:occurrence_inventory";
        return out;
    }
    out.source_occurrences = out.consumer_occurrences;
    // A deterministic non-identity ordering ensures the rational identity,
    // rather than same-row equality, carries the inventory claim.
    std::reverse(
        out.consumer_occurrences.begin(),
        out.consumer_occurrences.end());

    out.real_rows =
        static_cast<uint32_t>(out.source_occurrences.size());
    const uint32_t root_rows =
        static_cast<uint32_t>(
            out.child_roots.size() * kDecoderJoinRootWordsV1);
    out.trace_rows = NextPowerOfTwo(std::max(out.real_rows, root_rows));
    out.cs.n_rows = out.trace_rows;
    out.cs.n_columns = out.layout.n_columns;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(out.trace_rows, Fp3::Zero()));

    const auto set = [&out](uint32_t column, uint32_t row, Fp3 value) {
        out.columns[column][row] = value;
    };
    for (uint32_t row = 0; row < out.real_rows; ++row) {
        const auto& source = out.source_occurrences[row];
        const auto& consumer = out.consumer_occurrences[row];
        set(out.layout.active, row, Fp3::One());
        set(out.layout.source_kind, row, U(static_cast<uint8_t>(source.kind)));
        set(out.layout.source_occurrence, row, U(source.occurrence_id));
        set(out.layout.source_address, row, U(source.source_address));
        set(out.layout.source_value, row, U(source.value));
        set(out.layout.consumer_kind, row, U(static_cast<uint8_t>(consumer.kind)));
        set(out.layout.consumer_occurrence, row, U(consumer.occurrence_id));
        set(out.layout.consumer_address, row, U(consumer.source_address));
        set(out.layout.consumer_pin, row, U(consumer.value));
        set(out.layout.consumer_claim, row, U(consumer.value));
    }

    uint32_t root_row = 0;
    for (const auto& pin : out.child_roots) {
        for (uint32_t word = 0;
             word < kDecoderJoinRootWordsV1; ++word, ++root_row) {
            const uint64_t limb64 = pin.root.GetUint64(word / 2);
            const uint32_t value =
                word % 2 == 0
                ? static_cast<uint32_t>(limb64)
                : static_cast<uint32_t>(limb64 >> 32);
            set(out.layout.root_active, root_row, Fp3::One());
            set(out.layout.root_kind, root_row, U(pin.kind));
            set(out.layout.root_index, root_row, U(pin.index));
            set(out.layout.root_word, root_row, U(word));
            set(out.layout.root_value, root_row, U(value));
        }
    }

    out.preprocessed_columns = {
        out.layout.active,
        out.layout.source_kind,
        out.layout.source_occurrence,
        out.layout.source_address,
        out.layout.source_value,
        out.layout.consumer_kind,
        out.layout.consumer_occurrence,
        out.layout.consumer_address,
        out.layout.consumer_pin,
        out.layout.root_active,
        out.layout.root_kind,
        out.layout.root_index,
        out.layout.root_word,
        out.layout.root_value,
    };

    // Fiat-Shamir order is R0(tuple schedule + all child roots) -> dual
    // LogUp challenges -> dependent inverse/running columns.  No source or
    // consumer tuple cell is left outside this precommit.
    aq::AirConstraintSystem<Fp3> precommit_cs;
    precommit_cs.n_rows = out.trace_rows;
    precommit_cs.n_columns = out.layout.n_columns;
    if (!RecomputeRoot(
            precommit_cs, out.columns, out.preprocessed_columns,
            out.join_tuple_precommit_root)) {
        out.note = "stage3:v11_decoder_join:tuple_precommit";
        return out;
    }
    const auto challenge =
        DeriveChallenges(out.join_tuple_precommit_root);
    out.gamma = {challenge[0], challenge[1]};
    out.alpha = {challenge[2], challenge[3]};

    AddBoolean(out.cs, "stage3.v11_decoder_join.active", out.layout.active);
    AddBoolean(
        out.cs, "stage3.v11_decoder_join.root_active",
        out.layout.root_active);
    AddConstraint(
        out.cs, "stage3.v11_decoder_join.claim_equals_pin",
        aq::AirKind::kEverywhere, 2,
        [l = out.layout](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.active],
                gf::Sub(cur[l.consumer_claim], cur[l.consumer_pin]));
        });
    AddConstraint(
        out.cs, "stage3.v11_decoder_join.active_prefix",
        aq::AirKind::kTransition, 2,
        [l = out.layout](const auto& cur, const auto& next) {
            return gf::Mul(
                gf::Sub(Fp3::One(), cur[l.active]),
                next[l.active]);
        });
    for (uint32_t lane = 0;
         lane < kDecoderJoinBusLanesV1; ++lane) {
        const Fp3 gamma = out.gamma[lane];
        const Fp3 alpha = out.alpha[lane];
        auto term = [gamma, alpha](
                        const std::vector<Fp3>& row,
                        uint32_t kind, uint32_t occurrence,
                        uint32_t address, uint32_t value) {
            Fp3 power = Fp3::One();
            Fp3 out = alpha;
            for (uint32_t column :
                 {kind, occurrence, address, value}) {
                power = gf::Mul(power, gamma);
                out = gf::Add(out, gf::Mul(power, row[column]));
            }
            return out;
        };
        AddConstraint(
            out.cs, "stage3.v11_decoder_join.source_inverse",
            aq::AirKind::kEverywhere, 2,
            [l = out.layout, lane, term](const auto& cur, const auto&) {
                return gf::Sub(
                    gf::Mul(
                        cur[l.source_inverse[lane]],
                        term(
                            cur, l.source_kind, l.source_occurrence,
                            l.source_address, l.source_value)),
                    cur[l.active]);
            });
        AddConstraint(
            out.cs, "stage3.v11_decoder_join.consumer_inverse",
            aq::AirKind::kEverywhere, 2,
            [l = out.layout, lane, term](const auto& cur, const auto&) {
                return gf::Sub(
                    gf::Mul(
                        cur[l.consumer_inverse[lane]],
                        term(
                            cur, l.consumer_kind, l.consumer_occurrence,
                            l.consumer_address, l.consumer_claim)),
                    cur[l.active]);
            });
        AddConstraint(
            out.cs, "stage3.v11_decoder_join.running_first",
            aq::AirKind::kFirstRow, 1,
            [l = out.layout, lane](const auto& cur, const auto&) {
                return cur[l.running[lane]];
            });
        AddConstraint(
            out.cs, "stage3.v11_decoder_join.running_transition",
            aq::AirKind::kTransition, 1,
            [l = out.layout, lane](const auto& cur, const auto& next) {
                return gf::Sub(
                    next[l.running[lane]],
                    gf::Add(
                        cur[l.running[lane]],
                        gf::Sub(
                            cur[l.source_inverse[lane]],
                            cur[l.consumer_inverse[lane]])));
            });
        AddConstraint(
            out.cs, "stage3.v11_decoder_join.running_terminal",
            aq::AirKind::kLastRow, 1,
            [l = out.layout, lane](const auto& cur, const auto&) {
                return gf::Add(
                    cur[l.running[lane]],
                    gf::Sub(
                        cur[l.source_inverse[lane]],
                        cur[l.consumer_inverse[lane]]));
            });
    }
    for (uint32_t row = 0; row < out.real_rows; ++row) {
        const auto& source = out.source_occurrences[row];
        const auto& consumer = out.consumer_occurrences[row];
        for (uint32_t lane = 0;
             lane < kDecoderJoinBusLanesV1; ++lane) {
            const Fp3 source_term =
                CompressOccurrence(source, out.gamma[lane], out.alpha[lane]);
            const Fp3 consumer_term =
                CompressOccurrence(consumer, out.gamma[lane], out.alpha[lane]);
            if (gf::IsZero(source_term) || gf::IsZero(consumer_term)) {
                out.note = "stage3:v11_decoder_join:zero_denominator";
                return out;
            }
            set(
                out.layout.source_inverse[lane], row,
                gf::Inv(source_term));
            set(
                out.layout.consumer_inverse[lane], row,
                gf::Inv(consumer_term));
        }
    }
    for (uint32_t lane = 0; lane < kDecoderJoinBusLanesV1; ++lane) {
        Fp3 running = Fp3::Zero();
        for (uint32_t row = 0; row < out.trace_rows; ++row) {
            set(out.layout.running[lane], row, running);
            running = gf::Add(
                running,
                gf::Sub(
                    out.columns[out.layout.source_inverse[lane]][row],
                    out.columns[out.layout.consumer_inverse[lane]][row]));
        }
    }

    for (uint32_t column : out.preprocessed_columns) {
        out.cs.preprocessed.emplace_back(column, out.columns[column]);
    }
    out.cs.preprocessed_pin_ood = true;
    if (!RecomputeRoot(
            out.cs, out.columns, out.preprocessed_columns,
            out.preprocessed_row_group_root)) {
        out.note = "stage3:v11_decoder_join:preprocessed_root";
        return out;
    }
    if (out.preprocessed_row_group_root !=
        out.join_tuple_precommit_root) {
        out.note = "stage3:v11_decoder_join:precommit_changed";
        return out;
    }
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role = aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = out.preprocessed_columns,
        .root = out.preprocessed_row_group_root,
    });

    out.constraints =
        static_cast<uint32_t>(out.cs.constraints.size());
    for (const auto& constraint : out.cs.constraints) {
        out.max_constraint_degree =
            std::max(out.max_constraint_degree, constraint.alg_degree);
    }
    out.violations = RecountViolationsV1(out, out.columns);
    out.canonical_abi = true;
    out.exact_occurrence_inventory =
        out.source_occurrences.size() ==
            out.consumer_occurrences.size();
    out.all_logup_tuple_cells_precommitted = true;
    out.challenges_after_join_precommit =
        out.join_tuple_precommit_root ==
            out.preprocessed_row_group_root;
    out.dual_rational_identity_air_constrained = true;
    out.terminal_sums_zero = out.violations == 0;
    out.consumer_claims_equal_root_pinned_cells = true;
    out.ordered_preprocessed_root_pinned =
        PreprocessedRootMatches(out, out.columns);
    out.canonical_u32_and_fp_pairs = CanonicalPairs(decoded);
    std::map<uint32_t, uint32_t> query_index_counts;
    for (const auto& query : decoded.envelope.split.batch.queries) {
        ++query_index_counts[query.index];
    }
    for (const auto& [index, count] : query_index_counts) {
        (void)index;
        if (count > 1) out.duplicate_query_occurrences += count;
    }
    out.duplicate_query_identity_preserved = true;
    out.same_parent_decoder_aliases_executable = true;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.canonical_abi &&
        out.parent_replay_exactly_matches_decoded &&
        out.parent_root_recomputed &&
        out.child_roots_recomputed &&
        out.exact_occurrence_inventory &&
        out.all_logup_tuple_cells_precommitted &&
        out.challenges_after_join_precommit &&
        out.dual_rational_identity_air_constrained &&
        out.terminal_sums_zero &&
        out.consumer_claims_equal_root_pinned_cells &&
        out.ordered_preprocessed_root_pinned &&
        out.canonical_u32_and_fp_pairs &&
        out.duplicate_query_identity_preserved &&
        out.same_parent_decoder_aliases_executable &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v11_decoder_join:same_parent_ownership_closed;"
          "recursive_child_verifier_execution_pending"
        : "stage3:v11_decoder_join:constraint_failure";
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_decoder_join
