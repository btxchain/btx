// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_merkle_fold.h>

#include <algorithm>
#include <bit>
#include <functional>
#include <limits>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v11_merkle_fold {
namespace {

namespace ar = air_recurse;
using gf::Fp;
using gf::Fp3;
using Digest = alg_hash::Digest;
using State = alg_hash::State;

constexpr Fp kOmega2_32 = 0x185629dcda58878cULL;

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out > std::numeric_limits<uint32_t>::max() / 2) return 0;
        out <<= 1;
    }
    return out;
}

Fp PowBase(Fp base, uint64_t exponent)
{
    Fp out = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) out = gf::Mul(out, base);
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

Fp OmegaForSize(uint32_t size)
{
    uint32_t log = 0;
    for (uint32_t cursor = size; cursor > 1; cursor >>= 1) ++log;
    return PowBase(kOmega2_32, uint64_t{1} << (32 - log));
}

bool DigestEq(const Digest& left, const Digest& right)
{
    for (uint32_t limb = 0; limb < left.size(); ++limb) {
        if (gf::Canonical(left[limb]) != gf::Canonical(right[limb])) {
            return false;
        }
    }
    return true;
}

bool Fp3Canonical(const Fp3& value)
{
    return value.c0 < gf::kP && value.c1 < gf::kP && value.c2 < gf::kP;
}

abi::SourceKeyV1 Key(
    abi::FieldKindV1 kind,
    uint32_t a = 0,
    uint32_t b = 0,
    uint32_t c = 0,
    uint32_t d = 0,
    uint8_t limb = 0)
{
    return {kind, a, b, c, d, limb};
}

class AddressBook
{
public:
    explicit AddressBook(const abi::DecodedV1& decoded)
        : m_decoded(decoded)
    {
    }

    std::vector<uint32_t> U32(const abi::SourceKeyV1& key)
    {
        return One(key);
    }

    std::vector<uint32_t> Field3(abi::SourceKeyV1 key)
    {
        std::vector<uint32_t> out;
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            key.d = coordinate;
            for (uint8_t limb = 0; limb < 2; ++limb) {
                key.limb = limb;
                Append(out, key);
            }
        }
        return out;
    }

    std::vector<uint32_t> Digest4(abi::SourceKeyV1 key)
    {
        std::vector<uint32_t> out;
        for (uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
            key.d = coordinate;
            for (uint8_t limb = 0; limb < 2; ++limb) {
                key.limb = limb;
                Append(out, key);
            }
        }
        return out;
    }

    [[nodiscard]] bool Good() const { return m_good; }
    [[nodiscard]] uint64_t Unique() const { return m_unique.size(); }

private:
    std::vector<uint32_t> One(const abi::SourceKeyV1& key)
    {
        std::vector<uint32_t> out;
        Append(out, key);
        return out;
    }

    void Append(std::vector<uint32_t>& out, const abi::SourceKeyV1& key)
    {
        const auto address = abi::FindSourceAddressV1(m_decoded.sources, key);
        if (!address.has_value()) {
            m_good = false;
            return;
        }
        out.push_back(*address);
        m_unique.insert(*address);
    }

    const abi::DecodedV1& m_decoded;
    bool m_good{true};
    std::set<uint32_t> m_unique;
};

void Append(std::vector<uint32_t>& target,
            const std::vector<uint32_t>& source)
{
    target.insert(target.end(), source.begin(), source.end());
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
    statement.folds.reserve(batch.fold_layers.size());
    for (const auto& fold : batch.fold_layers) {
        statement.folds.push_back({fold.n_leaves, fold.root});
    }
    statement.final_value = batch.final_value;
    return statement;
}

struct Recorder {
    std::vector<HashTaskV1>* tasks{nullptr};
    uint64_t permutations{0};

    State Permutation(
        State input, HashTaskKindV1 kind,
        uint32_t query, uint32_t group,
        uint32_t fold, uint32_t level,
        const std::vector<uint32_t>& addresses)
    {
        State output = input;
        alg_hash::Permute(output);
        ++permutations;
        if (tasks != nullptr) {
            tasks->push_back({
                kind, query, group, fold, level,
                input, output, addresses});
        }
        return output;
    }
};

Digest RowLeaf(
    const std::vector<Fp3>& values, uint32_t index,
    uint32_t query, uint32_t group,
    const std::vector<uint32_t>& addresses,
    Recorder& recorder)
{
    std::vector<Fp> input;
    input.reserve(3 * values.size() + 1 + alg_hash::kAlgHashRate);
    for (const auto& value : values) {
        input.push_back(gf::Canonical(value.c0));
        input.push_back(gf::Canonical(value.c1));
        input.push_back(gf::Canonical(value.c2));
    }
    input.push_back(gf::FromU64(index));
    input.push_back(1);
    while (input.size() % alg_hash::kAlgHashRate != 0) input.push_back(0);

    State state{};
    uint32_t block = 0;
    for (uint32_t offset = 0; offset < input.size();
         offset += alg_hash::kAlgHashRate, ++block) {
        for (uint32_t lane = 0; lane < alg_hash::kAlgHashRate; ++lane) {
            state[lane] = gf::Add(state[lane], input[offset + lane]);
        }
        state = recorder.Permutation(
            state, HashTaskKindV1::RowLeaf,
            query, group, 0, block, addresses);
    }
    return {state[0], state[1], state[2], state[3]};
}

Digest FoldLeaf(
    const Fp3& value, uint32_t index,
    uint32_t query, uint32_t fold, bool odd,
    const std::vector<uint32_t>& addresses,
    Recorder& recorder)
{
    State input{};
    input[0] = gf::Canonical(value.c0);
    input[1] = gf::Canonical(value.c1);
    input[2] = gf::Canonical(value.c2);
    input[3] = gf::FromU64(index);
    input[4] = alg_hash::GetAlgHashConstants().leaf_domain;
    const State output = recorder.Permutation(
        input, HashTaskKindV1::FoldLeaf,
        query, odd ? 1U : 0U, fold, 0, addresses);
    return {output[0], output[1], output[2], output[3]};
}

Digest Compress(
    const Digest& left, const Digest& right,
    uint32_t query, uint32_t group,
    uint32_t fold, uint32_t level,
    const std::vector<uint32_t>& addresses,
    Recorder& recorder)
{
    State input{};
    for (uint32_t limb = 0; limb < left.size(); ++limb) {
        input[limb] = gf::Canonical(left[limb]);
        input[left.size() + limb] = gf::Canonical(right[limb]);
    }
    input[8] = alg_hash::GetAlgHashConstants().node_domain;
    const State output = recorder.Permutation(
        input, HashTaskKindV1::MerkleNode,
        query, group, fold, level, addresses);
    return {output[0], output[1], output[2], output[3]};
}

bool VerifyPath(
    Digest leaf, uint32_t index,
    const std::vector<Digest>& siblings,
    const Digest& root, uint32_t n_leaves,
    uint32_t query, uint32_t group, uint32_t fold,
    const std::vector<std::vector<uint32_t>>& sibling_addresses,
    Recorder& recorder)
{
    if (!PowerOfTwo(n_leaves) || index >= n_leaves ||
        siblings.size() != sibling_addresses.size()) {
        return false;
    }
    uint32_t width = n_leaves;
    for (uint32_t level = 0; width > 1; ++level) {
        if (level >= siblings.size()) return false;
        const bool right = (index & 1U) != 0;
        leaf = right
            ? Compress(
                  siblings[level], leaf, query, group, fold,
                  level, sibling_addresses[level], recorder)
            : Compress(
                  leaf, siblings[level], query, group, fold,
                  level, sibling_addresses[level], recorder);
        index >>= 1;
        width >>= 1;
    }
    return siblings.size() == static_cast<size_t>(
               std::countr_zero(n_leaves)) &&
        DigestEq(leaf, root);
}

struct FoldWitness {
    Fp3 even{};
    Fp3 odd{};
    Fp3 beta{};
    Fp3 x{};
    Fp3 even_part{};
    Fp3 odd_part{};
    Fp3 folded{};
    Fp3 here{};
    Fp3 final_value{};
    uint32_t index{0};
    uint32_t even_index{0};
    uint32_t odd_index{0};
    uint32_t half{0};
    bool side{false};
    bool chain_next{false};
    bool terminal{false};
};

struct RangeAudit {
    NativeAuditV1 audit;
    std::vector<HashTaskV1> tasks;
    std::vector<FoldWitness> folds;
};

RangeAudit AuditRange(
    const abi::DecodedV1& decoded,
    const tp::ReceiptV1& transcript,
    uint32_t first_query,
    uint32_t query_count,
    bool retain)
{
    RangeAudit out;
    auto fail = [&](const std::string& reason) {
        out.audit.note = "stage3:multirow_v11_merkle_fold:" + reason;
        out.audit.valid = false;
        return out;
    };
    out.audit.canonical_abi =
        decoded.canonical && decoded.complete &&
        decoded.addresses_unique && decoded.semantic_keys_unique;
    if (!out.audit.canonical_abi) return fail("canonical_abi_required");

    const auto& split = decoded.envelope.split;
    const auto& batch = split.batch;
    if (first_query > batch.queries.size() ||
        query_count == 0 ||
        query_count > batch.queries.size() - first_query ||
        batch.queries.size() != kProductionQueriesV1 ||
        split.next_trace_group_rows.size() != kProductionQueriesV1 ||
        batch.groups.size() != 3 ||
        batch.fold_challenges.empty() ||
        batch.fold_layers.size() != batch.fold_challenges.size() + 1) {
        return fail("range_or_shape");
    }

    const tp::StatementV1 statement = StatementFrom(decoded);
    std::string transcript_why;
    out.audit.transcript_receipt_verified =
        tp::VerifyReceiptV1(statement, transcript, &transcript_why);
    if (!out.audit.transcript_receipt_verified) {
        return fail("transcript:" + transcript_why);
    }
    if (transcript.fold_challenges.size() != batch.fold_challenges.size()) {
        return fail("fold_challenge_count");
    }
    for (uint32_t fold = 0; fold < batch.fold_challenges.size(); ++fold) {
        if (!gf::Eq(
                transcript.fold_challenges[fold],
                batch.fold_challenges[fold])) {
            return fail("fold_beta_not_transcript");
        }
    }

    const uint32_t n_lde = batch.n_coeffs * batch.blowup;
    if (!PowerOfTwo(n_lde) ||
        split.trace_rows == 0 ||
        n_lde % split.trace_rows != 0) {
        return fail("lde_shape");
    }
    AddressBook addresses(decoded);
    Recorder recorder{retain ? &out.tasks : nullptr};
    out.audit.query_indices_transcript_bound = true;
    out.audit.current_group_paths_verified = true;
    out.audit.next_group_paths_verified = true;
    out.audit.fold_paths_verified = true;
    out.audit.fold_equations_verified = true;
    out.audit.terminal_value_verified = true;

    for (uint32_t q = first_query; q < first_query + query_count; ++q) {
        const auto& query = batch.queries[q];
        if (query.index != transcript.queries[q].index) {
            out.audit.query_indices_transcript_bound = false;
            return fail("query_index_not_transcript");
        }
        const auto query_index_address =
            addresses.U32(Key(abi::FieldKindV1::QueryIndex, q));
        for (uint32_t group = 0; group < 3; ++group) {
            const auto& opened = query.group_rows[group];
            std::vector<uint32_t> leaf_addresses = query_index_address;
            for (uint32_t value = 0; value < opened.values.size(); ++value) {
                Append(
                    leaf_addresses,
                    addresses.Field3(Key(
                        abi::FieldKindV1::QueryRowValue,
                        q, group, value)));
            }
            const Digest leaf = RowLeaf(
                opened.values, query.index, q, group,
                leaf_addresses, recorder);
            std::vector<std::vector<uint32_t>> path_addresses;
            path_addresses.reserve(opened.siblings.size());
            for (uint32_t level = 0; level < opened.siblings.size(); ++level) {
                path_addresses.push_back(addresses.Digest4(Key(
                    abi::FieldKindV1::QueryRowSibling,
                    q, group, level)));
            }
            const auto root_addresses = addresses.Digest4(
                Key(abi::FieldKindV1::GroupRoot, group));
            if (!path_addresses.empty()) {
                Append(path_addresses.back(), root_addresses);
            }
            if (!VerifyPath(
                    leaf, query.index, opened.siblings,
                    batch.groups[group].row_commit.root, n_lde,
                    q, group, 0, path_addresses, recorder)) {
                out.audit.current_group_paths_verified = false;
                return fail("current_path");
            }
            ++out.audit.current_paths_checked;
        }

        const uint32_t next_index =
            (query.index + n_lde / split.trace_rows) % n_lde;
        const auto& next = split.next_trace_group_rows[q];
        for (uint32_t group = 0; group < 2; ++group) {
            const auto& opened = next[group];
            std::vector<uint32_t> leaf_addresses;
            for (uint32_t value = 0; value < opened.values.size(); ++value) {
                Append(
                    leaf_addresses,
                    addresses.Field3(Key(
                        abi::FieldKindV1::NextRowValue,
                        q, group, value)));
            }
            const Digest leaf = RowLeaf(
                opened.values, next_index, q, 3 + group,
                leaf_addresses, recorder);
            std::vector<std::vector<uint32_t>> path_addresses;
            for (uint32_t level = 0; level < opened.siblings.size(); ++level) {
                path_addresses.push_back(addresses.Digest4(Key(
                    abi::FieldKindV1::NextRowSibling,
                    q, group, level)));
            }
            const auto root_addresses = addresses.Digest4(
                Key(abi::FieldKindV1::GroupRoot, group));
            if (!path_addresses.empty()) {
                Append(path_addresses.back(), root_addresses);
            }
            if (!VerifyPath(
                    leaf, next_index, opened.siblings,
                    batch.groups[group].row_commit.root, n_lde,
                    q, 3 + group, 0, path_addresses, recorder)) {
                out.audit.next_group_paths_verified = false;
                return fail("next_path");
            }
            ++out.audit.next_paths_checked;
        }

        uint32_t index = query.index;
        Fp3 prior{};
        bool have_prior = false;
        for (uint32_t fold = 0; fold < batch.fold_challenges.size(); ++fold) {
            const auto& step = query.steps[fold];
            const uint32_t width = n_lde >> fold;
            const uint32_t half = width / 2;
            const uint32_t even_index = index % half;
            if (step.even_index != even_index ||
                step.odd_index != even_index + half) {
                return fail("fold_indices");
            }
            std::vector<uint32_t> even_addresses = addresses.Field3(Key(
                abi::FieldKindV1::QueryStepEven, q, fold));
            Append(even_addresses, addresses.U32(Key(
                abi::FieldKindV1::QueryStepEvenIndex, q, fold)));
            std::vector<uint32_t> odd_addresses = addresses.Field3(Key(
                abi::FieldKindV1::QueryStepOdd, q, fold));
            Append(odd_addresses, addresses.U32(Key(
                abi::FieldKindV1::QueryStepOddIndex, q, fold)));
            const Digest even_leaf = FoldLeaf(
                step.even, step.even_index, q, fold, false,
                even_addresses, recorder);
            const Digest odd_leaf = FoldLeaf(
                step.odd, step.odd_index, q, fold, true,
                odd_addresses, recorder);

            std::vector<std::vector<uint32_t>> even_path_addresses;
            std::vector<std::vector<uint32_t>> odd_path_addresses;
            for (uint32_t level = 0;
                 level < step.even_siblings.size(); ++level) {
                even_path_addresses.push_back(addresses.Digest4(Key(
                    abi::FieldKindV1::QueryStepEvenSibling,
                    q, fold, level)));
            }
            for (uint32_t level = 0;
                 level < step.odd_siblings.size(); ++level) {
                odd_path_addresses.push_back(addresses.Digest4(Key(
                    abi::FieldKindV1::QueryStepOddSibling,
                    q, fold, level)));
            }
            const auto root_addresses = addresses.Digest4(
                Key(abi::FieldKindV1::FoldRoot, fold));
            if (!even_path_addresses.empty()) {
                Append(even_path_addresses.back(), root_addresses);
            }
            if (!odd_path_addresses.empty()) {
                Append(odd_path_addresses.back(), root_addresses);
            }
            if (!VerifyPath(
                    even_leaf, step.even_index, step.even_siblings,
                    batch.fold_layers[fold].root, width,
                    q, 5, fold, even_path_addresses, recorder) ||
                !VerifyPath(
                    odd_leaf, step.odd_index, step.odd_siblings,
                    batch.fold_layers[fold].root, width,
                    q, 6, fold, odd_path_addresses, recorder)) {
                out.audit.fold_paths_verified = false;
                return fail("fold_path");
            }
            out.audit.fold_paths_checked += 2;

            const Fp3 x = Fp3::FromFp(
                PowBase(OmegaForSize(width), even_index));
            if (gf::IsZero(x)) return fail("fold_x_zero");
            const Fp3 inv2 = Fp3::FromFp(gf::Inv(gf::FromU64(2)));
            const Fp3 even_part =
                gf::Mul(gf::Add(step.even, step.odd), inv2);
            const Fp3 odd_part = gf::Mul(
                gf::Mul(gf::Sub(step.even, step.odd), inv2),
                gf::Inv(x));
            const Fp3 folded = gf::Add(
                even_part,
                gf::Mul(batch.fold_challenges[fold], odd_part));
            const bool side = index >= half;
            const Fp3 here = side ? step.odd : step.even;
            if ((have_prior && !gf::Eq(here, prior)) ||
                !Fp3Canonical(folded)) {
                out.audit.fold_equations_verified = false;
                return fail("fold_chain");
            }
            const bool terminal =
                fold + 1 == batch.fold_challenges.size();
            if (terminal && !gf::Eq(folded, batch.final_value)) {
                out.audit.terminal_value_verified = false;
                return fail("final_value");
            }
            if (retain) {
                out.folds.push_back({
                    step.even, step.odd,
                    batch.fold_challenges[fold], x,
                    even_part, odd_part, folded, here,
                    batch.final_value, index,
                    step.even_index, step.odd_index, half,
                    side, !terminal, terminal});
            }
            addresses.Field3(Key(
                abi::FieldKindV1::FoldChallenge, fold));
            addresses.Field3(Key(abi::FieldKindV1::FinalValue));
            ++out.audit.fold_equations_checked;
            prior = folded;
            have_prior = true;
            index = even_index;
        }
        ++out.audit.queries_checked;
    }

    out.audit.poseidon_permutations = recorder.permutations;
    out.audit.exact_source_addresses = addresses.Good();
    out.audit.source_cells_consumed = addresses.Unique();
    out.audit.full_q192_coverage =
        first_query == 0 && query_count == kProductionQueriesV1;
    out.audit.valid =
        out.audit.canonical_abi &&
        out.audit.transcript_receipt_verified &&
        out.audit.query_indices_transcript_bound &&
        out.audit.current_group_paths_verified &&
        out.audit.next_group_paths_verified &&
        out.audit.fold_paths_verified &&
        out.audit.fold_equations_verified &&
        out.audit.terminal_value_verified &&
        out.audit.exact_source_addresses;
    out.audit.note = out.audit.valid
        ? "stage3:multirow_v11_merkle_fold:exact_paths_and_folds"
        : "stage3:multirow_v11_merkle_fold:incomplete";
    return out;
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

uint32_t MaxDegree(const aq::AirConstraintSystem<Fp3>& cs)
{
    uint32_t out = 0;
    for (const auto& constraint : cs.constraints) {
        out = std::max(out, constraint.alg_degree);
    }
    return out;
}

std::optional<abi::DecodedV1> DecodeProof(
    const backend::ProofV1& proof, std::string* why = nullptr)
{
    std::vector<uint32_t> words;
    if (!abi::EncodeCanonicalV1(
            proof.envelope, words, nullptr, why)) {
        return std::nullopt;
    }
    return abi::DecodeCanonicalV1(words, why);
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

} // namespace

HashLayoutV1 CanonicalHashLayoutV1()
{
    HashLayoutV1 out;
    out.poseidon = pa::CanonicalLayout();
    out.input_pin_base = out.poseidon.End();
    out.output_pin_base =
        out.input_pin_base + alg_hash::kAlgHashT;
    out.n_columns =
        out.output_pin_base + alg_hash::kAlgHashDigestLen;
    return out;
}

FoldLayoutV1 CanonicalFoldLayoutV1()
{
    FoldLayoutV1 out;
    uint32_t column = 0;
    out.even = column++;
    out.odd = column++;
    out.beta = column++;
    out.x = column++;
    out.even_part = column++;
    out.odd_part = column++;
    out.folded = column++;
    out.here = column++;
    out.final_value = column++;
    out.index = column++;
    out.even_index = column++;
    out.odd_index = column++;
    out.half = column++;
    out.side = column++;
    out.chain_next = column++;
    out.terminal = column++;
    out.n_columns = column;
    return out;
}

std::vector<ParentConsumerCellRefV1>
BuildParentConsumerCellRefsV1(const abi::DecodedV1& decoded)
{
    std::vector<ParentConsumerCellRefV1> out;
    if (!decoded.canonical || !decoded.complete) return out;
    const auto& split = decoded.envelope.split;
    const auto& batch = split.batch;
    if (batch.queries.size() != kProductionQueriesV1 ||
        split.next_trace_group_rows.size() != kProductionQueriesV1) {
        return {};
    }
    const auto add =
        [&](ParentConsumerKindV1 kind,
            uint32_t query, uint32_t group, uint32_t item,
            abi::SourceKeyV1 key, uint32_t coordinates) {
            for (uint32_t coordinate = 0;
                 coordinate < coordinates; ++coordinate) {
                key.d = coordinate;
                const uint32_t limbs = coordinates == 1 ? 1 : 2;
                for (uint8_t limb = 0; limb < limbs; ++limb) {
                    key.limb = limb;
                    const auto address =
                        abi::FindSourceAddressV1(decoded.sources, key);
                    if (!address.has_value() ||
                        *address >= decoded.sources.size()) {
                        out.clear();
                        return false;
                    }
                    out.push_back({
                        kind, query, group, item, coordinate, limb,
                        *address, decoded.sources[*address].value});
                }
            }
            return true;
        };
    for (uint32_t query = 0; query < kProductionQueriesV1; ++query) {
        if (!add(
                ParentConsumerKindV1::QueryIndex,
                query, 0, 0,
                Key(abi::FieldKindV1::QueryIndex, query), 1)) {
            return {};
        }
        for (uint32_t group = 0;
             group < batch.queries[query].group_rows.size(); ++group) {
            for (uint32_t item = 0;
                 item <
                 batch.queries[query].group_rows[group].values.size();
                 ++item) {
                if (!add(
                        ParentConsumerKindV1::CurrentRowValue,
                        query, group, item,
                        Key(
                            abi::FieldKindV1::QueryRowValue,
                            query, group, item),
                        3)) {
                    return {};
                }
            }
        }
        for (uint32_t group = 0;
             group <
             split.next_trace_group_rows[query].size(); ++group) {
            for (uint32_t item = 0;
                 item <
                 split.next_trace_group_rows[query][group].values.size();
                 ++item) {
                if (!add(
                        ParentConsumerKindV1::NextRowValue,
                        query, group, item,
                        Key(
                            abi::FieldKindV1::NextRowValue,
                            query, group, item),
                        3)) {
                    return {};
                }
            }
        }
    }
    return out;
}

NativeAuditV1 AuditAllV1(
    const abi::DecodedV1& decoded,
    const tp::ReceiptV1& transcript)
{
    auto audit = AuditRange(
        decoded, transcript, 0, kProductionQueriesV1, false).audit;
    std::set<uint32_t> indices;
    for (const auto& query : decoded.envelope.split.batch.queries) {
        if (!indices.insert(query.index).second) {
            ++audit.duplicate_query_count;
        }
    }
    const auto refs = BuildParentConsumerCellRefsV1(decoded);
    audit.parent_consumer_cells = static_cast<uint32_t>(refs.size());
    audit.duplicate_queries_preserved =
        decoded.envelope.split.batch.queries.size() ==
        kProductionQueriesV1;
    audit.literal_parent_consumer_refs = !refs.empty();
    audit.valid =
        audit.valid &&
        audit.duplicate_queries_preserved &&
        audit.literal_parent_consumer_refs;
    if (!audit.valid && audit.note.find("exact_paths") != std::string::npos) {
        audit.note =
            "stage3:multirow_v11_merkle_fold:parent_consumer_refs";
    }
    return audit;
}

NativeAuditV1 AuditAllV1(
    const backend::ProofV1& proof,
    const tp::ReceiptV1& transcript)
{
    std::string why;
    const auto decoded = DecodeProof(proof, &why);
    if (!decoded.has_value()) {
        NativeAuditV1 out;
        out.note =
            "stage3:multirow_v11_merkle_fold:proof_v1_decode:" + why;
        return out;
    }
    return AuditAllV1(*decoded, transcript);
}

ShardProductV1 BuildShardV1(
    const abi::DecodedV1& decoded,
    const tp::ReceiptV1& transcript,
    uint32_t first_query,
    uint32_t query_count)
{
    ShardProductV1 out;
    out.first_query = first_query;
    out.query_count = query_count;
    auto range =
        AuditRange(decoded, transcript, first_query, query_count, true);
    const auto& audit = range.audit;
    out.canonical_abi = audit.canonical_abi;
    out.transcript_receipt_verified =
        audit.transcript_receipt_verified;
    out.current_group_paths_verified =
        audit.current_group_paths_verified;
    out.next_group_paths_verified =
        audit.next_group_paths_verified;
    out.fold_paths_verified = audit.fold_paths_verified;
    out.source_cells_consumed = audit.source_cells_consumed;
    out.hash_tasks = std::move(range.tasks);
    const auto all_consumer_refs = BuildParentConsumerCellRefsV1(decoded);
    for (const auto& ref : all_consumer_refs) {
        if (ref.query >= first_query &&
            ref.query < first_query + query_count) {
            out.parent_consumer_refs.push_back(ref);
        }
    }
    if (!audit.valid || out.hash_tasks.empty() || range.folds.empty()) {
        out.note = audit.note;
        return out;
    }

    out.hash_layout = CanonicalHashLayoutV1();
    out.hash_real_rows = static_cast<uint32_t>(out.hash_tasks.size());
    out.hash_trace_rows = NextPowerOfTwo(out.hash_real_rows);
    std::string why;
    if (out.hash_trace_rows == 0 ||
        !pa::BuildFixedSystem(
            out.hash_trace_rows, out.hash_cs, &why)) {
        out.note = "stage3:multirow_v11_merkle_fold:hash_cs:" + why;
        return out;
    }
    out.hash_cs.n_columns = out.hash_layout.n_columns;
    for (uint32_t lane = 0; lane < alg_hash::kAlgHashT; ++lane) {
        AddConstraint(
            out.hash_cs, "stage3.v11_merkle_fold.hash_input_pin",
            aq::AirKind::kEverywhere, 1,
            [layout = out.hash_layout, lane](
                const auto& cur, const auto&) {
                return gf::Sub(
                    cur[layout.poseidon.perm.InputCol(lane)],
                    cur[layout.InputPin(lane)]);
            });
    }
    for (uint32_t lane = 0; lane < alg_hash::kAlgHashDigestLen; ++lane) {
        AddConstraint(
            out.hash_cs, "stage3.v11_merkle_fold.hash_output_pin",
            aq::AirKind::kEverywhere, 1,
            [layout = out.hash_layout, lane](
                const auto& cur, const auto&) {
                return gf::Sub(
                    ar::PermOutputLane(
                        layout.poseidon.perm, cur, lane),
                    cur[layout.OutputPin(lane)]);
            });
    }
    out.hash_columns.assign(
        out.hash_cs.n_columns,
        std::vector<Fp3>(out.hash_trace_rows, Fp3::Zero()));
    std::vector<std::vector<Fp3>> hash_rows(
        out.hash_trace_rows,
        std::vector<Fp3>(out.hash_cs.n_columns, Fp3::Zero()));
    for (uint32_t row = 0; row < out.hash_trace_rows; ++row) {
        State input{};
        State output{};
        if (row < out.hash_real_rows) {
            input = out.hash_tasks[row].input;
            output = out.hash_tasks[row].output;
        } else {
            output = input;
            alg_hash::Permute(output);
        }
        const auto witness =
            pa::BuildWitness(out.hash_layout.poseidon, input);
        std::copy(
            witness.row.begin(), witness.row.end(),
            hash_rows[row].begin());
        for (uint32_t lane = 0; lane < alg_hash::kAlgHashT; ++lane) {
            hash_rows[row][out.hash_layout.InputPin(lane)] =
                Fp3::FromFp(input[lane]);
        }
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashDigestLen; ++lane) {
            hash_rows[row][out.hash_layout.OutputPin(lane)] =
                Fp3::FromFp(output[lane]);
        }
    }
    for (uint32_t column = 0; column < out.hash_cs.n_columns; ++column) {
        for (uint32_t row = 0; row < out.hash_trace_rows; ++row) {
            out.hash_columns[column][row] = hash_rows[row][column];
        }
    }
    for (uint32_t lane = 0; lane < alg_hash::kAlgHashT; ++lane) {
        out.hash_cs.preprocessed.push_back({
            out.hash_layout.InputPin(lane),
            out.hash_columns[out.hash_layout.InputPin(lane)]});
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashDigestLen; ++lane) {
        out.hash_cs.preprocessed.push_back({
            out.hash_layout.OutputPin(lane),
            out.hash_columns[out.hash_layout.OutputPin(lane)]});
    }
    out.hash_cs.preprocessed_pin_ood = true;

    out.fold_layout = CanonicalFoldLayoutV1();
    out.fold_real_rows = static_cast<uint32_t>(range.folds.size());
    out.fold_trace_rows = NextPowerOfTwo(out.fold_real_rows);
    if (out.fold_trace_rows == 0) {
        out.note = "stage3:multirow_v11_merkle_fold:fold_rows";
        return out;
    }
    out.fold_cs.n_rows = out.fold_trace_rows;
    out.fold_cs.n_columns = out.fold_layout.n_columns;
    const Fp3 inv2 = Fp3::FromFp(gf::Inv(gf::FromU64(2)));
    AddConstraint(
        out.fold_cs, "stage3.v11_merkle_fold.fold_even_part",
        aq::AirKind::kEverywhere, 1,
        [l = out.fold_layout, inv2](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.even_part],
                gf::Mul(gf::Add(cur[l.even], cur[l.odd]), inv2));
        });
    AddConstraint(
        out.fold_cs, "stage3.v11_merkle_fold.fold_odd_part",
        aq::AirKind::kEverywhere, 2,
        [l = out.fold_layout, inv2](const auto& cur, const auto&) {
            return gf::Sub(
                gf::Mul(cur[l.odd_part], cur[l.x]),
                gf::Mul(gf::Sub(cur[l.even], cur[l.odd]), inv2));
        });
    AddConstraint(
        out.fold_cs, "stage3.v11_merkle_fold.fold_equation",
        aq::AirKind::kEverywhere, 2,
        [l = out.fold_layout](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.folded],
                gf::Add(
                    cur[l.even_part],
                    gf::Mul(cur[l.beta], cur[l.odd_part])));
        });
    for (uint32_t column :
         {out.fold_layout.side,
          out.fold_layout.chain_next,
          out.fold_layout.terminal}) {
        AddConstraint(
            out.fold_cs, "stage3.v11_merkle_fold.boolean",
            aq::AirKind::kEverywhere, 2,
            [column](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[column],
                    gf::Sub(cur[column], Fp3::One()));
            });
    }
    AddConstraint(
        out.fold_cs, "stage3.v11_merkle_fold.row_kind",
        aq::AirKind::kEverywhere, 1,
        [l = out.fold_layout](const auto& cur, const auto&) {
            return gf::Sub(
                gf::Add(cur[l.chain_next], cur[l.terminal]),
                Fp3::One());
        });
    AddConstraint(
        out.fold_cs, "stage3.v11_merkle_fold.here_side",
        aq::AirKind::kEverywhere, 2,
        [l = out.fold_layout](const auto& cur, const auto&) {
            const Fp3 selected = gf::Add(
                gf::Mul(
                    gf::Sub(Fp3::One(), cur[l.side]), cur[l.even]),
                gf::Mul(cur[l.side], cur[l.odd]));
            return gf::Sub(cur[l.here], selected);
        });
    AddConstraint(
        out.fold_cs, "stage3.v11_merkle_fold.odd_index",
        aq::AirKind::kEverywhere, 1,
        [l = out.fold_layout](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.odd_index],
                gf::Add(cur[l.even_index], cur[l.half]));
        });
    AddConstraint(
        out.fold_cs, "stage3.v11_merkle_fold.index_side",
        aq::AirKind::kEverywhere, 2,
        [l = out.fold_layout](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.index],
                gf::Add(
                    cur[l.even_index],
                    gf::Mul(cur[l.side], cur[l.half])));
        });
    AddConstraint(
        out.fold_cs, "stage3.v11_merkle_fold.chain",
        aq::AirKind::kTransition, 2,
        [l = out.fold_layout](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[l.chain_next],
                gf::Sub(next[l.here], cur[l.folded]));
        });
    AddConstraint(
        out.fold_cs, "stage3.v11_merkle_fold.index_chain",
        aq::AirKind::kTransition, 2,
        [l = out.fold_layout](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[l.chain_next],
                gf::Sub(next[l.index], cur[l.even_index]));
        });
    AddConstraint(
        out.fold_cs, "stage3.v11_merkle_fold.terminal",
        aq::AirKind::kEverywhere, 2,
        [l = out.fold_layout](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.terminal],
                gf::Sub(cur[l.folded], cur[l.final_value]));
        });

    out.fold_columns.assign(
        out.fold_cs.n_columns,
        std::vector<Fp3>(out.fold_trace_rows, Fp3::Zero()));
    const auto write_fold =
        [&](uint32_t row, const FoldWitness& witness) {
            const auto& l = out.fold_layout;
            out.fold_columns[l.even][row] = witness.even;
            out.fold_columns[l.odd][row] = witness.odd;
            out.fold_columns[l.beta][row] = witness.beta;
            out.fold_columns[l.x][row] = witness.x;
            out.fold_columns[l.even_part][row] = witness.even_part;
            out.fold_columns[l.odd_part][row] = witness.odd_part;
            out.fold_columns[l.folded][row] = witness.folded;
            out.fold_columns[l.here][row] = witness.here;
            out.fold_columns[l.final_value][row] = witness.final_value;
            out.fold_columns[l.index][row] = gf::FromU64_3(witness.index);
            out.fold_columns[l.even_index][row] =
                gf::FromU64_3(witness.even_index);
            out.fold_columns[l.odd_index][row] =
                gf::FromU64_3(witness.odd_index);
            out.fold_columns[l.half][row] = gf::FromU64_3(witness.half);
            out.fold_columns[l.side][row] =
                witness.side ? Fp3::One() : Fp3::Zero();
            out.fold_columns[l.chain_next][row] =
                witness.chain_next ? Fp3::One() : Fp3::Zero();
            out.fold_columns[l.terminal][row] =
                witness.terminal ? Fp3::One() : Fp3::Zero();
        };
    for (uint32_t row = 0; row < out.fold_real_rows; ++row) {
        write_fold(row, range.folds[row]);
    }
    for (uint32_t row = out.fold_real_rows;
         row < out.fold_trace_rows; ++row) {
        FoldWitness padding;
        padding.x = Fp3::One();
        padding.odd_index = 1;
        padding.half = 1;
        padding.terminal = true;
        write_fold(row, padding);
    }
    for (uint32_t column = 0; column < out.fold_cs.n_columns; ++column) {
        out.fold_cs.preprocessed.push_back(
            {column, out.fold_columns[column]});
    }
    out.fold_cs.preprocessed_pin_ood = true;

    out.hash_constraints =
        static_cast<uint32_t>(out.hash_cs.constraints.size());
    out.fold_constraints =
        static_cast<uint32_t>(out.fold_cs.constraints.size());
    out.hash_max_degree = MaxDegree(out.hash_cs);
    out.fold_max_degree = MaxDegree(out.fold_cs);
    out.hash_violations =
        RecountViolationsV1(out.hash_cs, out.hash_columns);
    out.fold_violations =
        RecountViolationsV1(out.fold_cs, out.fold_columns);
    out.fold_equations_air_constrained = out.fold_violations == 0;
    out.terminal_value_air_constrained = out.fold_violations == 0;
    out.proof_owned_pins_ood_bound = true;
    // The row-wise backend cannot regenerate a per-column root. Exact root
    // equality arrives only when these columns are placed in a Split-RAP
    // preprocessed row group by the same-parent decoder join.
    out.proof_owned_pins_root_pinned = false;
    out.constant_width_schedule =
        out.hash_layout.n_columns == pa::kFixedColumns +
            kHashPinColumnsV1 &&
        out.fold_layout.n_columns == 16;
    std::set<uint32_t> query_indices;
    out.duplicate_queries_preserved = true;
    for (uint32_t query = first_query;
         query < first_query + query_count; ++query) {
        query_indices.insert(
            decoded.envelope.split.batch.queries[query].index);
    }
    out.literal_parent_consumer_refs =
        !out.parent_consumer_refs.empty();
    out.same_parent_decoder_aliases = false;
    out.deep_quotient_constrained = false;
    out.canonical_vm_constrained = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.hash_violations == 0 &&
        out.fold_violations == 0 &&
        out.constant_width_schedule &&
        out.proof_owned_pins_ood_bound &&
        out.duplicate_queries_preserved &&
        out.literal_parent_consumer_refs;
    out.note = out.valid
        ? "stage3:multirow_v11_merkle_fold:bounded_shard;"
          "decoder_deep_vm_joins_pending"
        : "stage3:multirow_v11_merkle_fold:shard_invalid";
    return out;
}

ShardProductV1 BuildShardV1(
    const backend::ProofV1& proof,
    const tp::ReceiptV1& transcript,
    uint32_t first_query,
    uint32_t query_count)
{
    std::string why;
    const auto decoded = DecodeProof(proof, &why);
    if (!decoded.has_value()) {
        ShardProductV1 out;
        out.first_query = first_query;
        out.query_count = query_count;
        out.note =
            "stage3:multirow_v11_merkle_fold:proof_v1_decode:" + why;
        return out;
    }
    return BuildShardV1(
        *decoded, transcript, first_query, query_count);
}

uint64_t RecountViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return std::numeric_limits<uint64_t>::max();
        }
    }
    std::vector<Fp3> current(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    uint64_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row = (row + 1) % cs.n_rows;
        for (uint32_t column = 0; column < cs.n_columns; ++column) {
            current[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            if (Applies(constraint.kind, row, cs.n_rows) &&
                !gf::IsZero(constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_merkle_fold
