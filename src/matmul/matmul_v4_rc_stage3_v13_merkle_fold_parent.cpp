// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_merkle_fold_parent.h>
#include <matmul/matmul_v4_rc_stage3_v13_terminal_fold_parent.h>

#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <utility>

namespace matmul::v4::rc::stage3_v13_merkle_fold_parent {
namespace {

using Fp3 = gf::Fp3;
using Fp = gf::Fp;
namespace ar = air_recurse;

constexpr Fp kOmega2_32 =
    UINT64_C(0x185629dcda58878c);

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:v13_merkle_fold_parent:" +
            detail;
    }
    return false;
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

std::optional<uint32_t> Address(
    const abi::DecodedV1& decoded,
    abi::SourceKeyV1 key)
{
    return abi::FindSourceAddressV1(
        decoded.sources, key);
}

std::optional<std::array<uint32_t, 2>>
FieldCoordinate(
    const abi::DecodedV1& decoded,
    abi::SourceKeyV1 key,
    uint32_t coordinate)
{
    std::array<uint32_t, 2> out{};
    key.d = coordinate;
    for (uint32_t limb = 0; limb < 2; ++limb) {
        key.limb = static_cast<uint8_t>(limb);
        const auto address =
            Address(decoded, key);
        if (!address.has_value()) {
            return std::nullopt;
        }
        out[limb] = *address;
    }
    return out;
}

std::optional<std::vector<uint32_t>>
FieldAddresses(
    const abi::DecodedV1& decoded,
    abi::SourceKeyV1 key,
    uint32_t coordinates)
{
    std::vector<uint32_t> out;
    out.reserve(
        size_t{coordinates} * 2);
    for (uint32_t coordinate = 0;
         coordinate < coordinates;
         ++coordinate) {
        const auto addresses =
            FieldCoordinate(
                decoded, key,
                coordinate);
        if (!addresses.has_value()) {
            return std::nullopt;
        }
        out.push_back((*addresses)[0]);
        out.push_back((*addresses)[1]);
    }
    return out;
}

bool CanonicalAddress(
    const abi::DecodedV1& decoded,
    uint32_t address)
{
    return address < decoded.sources.size() &&
        decoded.sources[address].address == address;
}

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

Fp PowBase(Fp base, uint64_t exponent)
{
    Fp out = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

Fp OmegaForSize(uint32_t size)
{
    if (size < 2 ||
        (size & (size - 1)) != 0) {
        return 0;
    }
    const uint32_t log =
        std::countr_zero(size);
    return PowBase(
        kOmega2_32,
        uint64_t{1} << (32 - log));
}

Fp3 Basis(uint32_t coordinate)
{
    if (coordinate == 0) {
        return {1, 0, 0};
    }
    if (coordinate == 1) {
        return {0, 1, 0};
    }
    return {0, 0, 1};
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
    cs.constraints.push_back(
        std::move(constraint));
}

bool IsPinColumn(
    const mf::HashLayoutV1& layout,
    uint32_t column)
{
    return
        (column >= layout.input_pin_base &&
         column <
             layout.input_pin_base +
                 alg_hash::kAlgHashT) ||
        (column >= layout.output_pin_base &&
         column <
             layout.output_pin_base +
                 alg_hash::kAlgHashDigestLen);
}

uint64_t SourceValue(
    const abi::DecodedV1& decoded,
    uint32_t address)
{
    return decoded.sources[address].value;
}

HashLaneExpressionV1 ConstantExpression(
    uint32_t row, uint32_t lane,
    Fp3 constant)
{
    HashLaneExpressionV1 out;
    out.task_row = row;
    out.lane = lane;
    out.kind =
        HashLaneExpressionKindV1::Constant;
    out.constant = constant;
    out.resolved = true;
    return out;
}

HashLaneExpressionV1 AbiU32Expression(
    uint32_t row, uint32_t lane,
    uint32_t address)
{
    HashLaneExpressionV1 out;
    out.task_row = row;
    out.lane = lane;
    out.kind =
        HashLaneExpressionKindV1::AbiU32;
    out.source_addresses[0] = address;
    out.resolved = true;
    return out;
}

HashLaneExpressionV1 AbiFpExpression(
    uint32_t row, uint32_t lane,
    std::array<uint32_t, 2> addresses)
{
    HashLaneExpressionV1 out;
    out.task_row = row;
    out.lane = lane;
    out.kind =
        HashLaneExpressionKindV1::
            AbiFpCoordinate;
    out.source_addresses = addresses;
    out.resolved = true;
    return out;
}

HashLaneExpressionV1 PriorExpression(
    uint32_t row, uint32_t lane,
    uint32_t prior_row, uint32_t prior_lane)
{
    HashLaneExpressionV1 out;
    out.task_row = row;
    out.lane = lane;
    out.kind =
        HashLaneExpressionKindV1::PriorOutput;
    out.prior_task_row = prior_row;
    out.prior_output_lane = prior_lane;
    out.resolved = prior_row < row;
    return out;
}

HashLaneExpressionV1 AddPrior(
    HashLaneExpressionV1 absorbed,
    uint32_t prior_row)
{
    absorbed.prior_task_row = prior_row;
    absorbed.prior_output_lane =
        absorbed.lane;
    switch (absorbed.kind) {
    case HashLaneExpressionKindV1::Constant:
        absorbed.kind =
            HashLaneExpressionKindV1::
                PriorOutputPlusConstant;
        break;
    case HashLaneExpressionKindV1::AbiU32:
        absorbed.kind =
            HashLaneExpressionKindV1::
                PriorOutputPlusAbiU32;
        break;
    case HashLaneExpressionKindV1::
        AbiFpCoordinate:
        absorbed.kind =
            HashLaneExpressionKindV1::
                PriorOutputPlusAbiFpCoordinate;
        break;
    case HashLaneExpressionKindV1::
        DerivedNextIndex:
        absorbed.kind =
            HashLaneExpressionKindV1::
                PriorOutputPlusDerivedNextIndex;
        break;
    default:
        absorbed.resolved = false;
        break;
    }
    absorbed.resolved =
        absorbed.resolved &&
        prior_row < absorbed.task_row;
    return absorbed;
}

struct AbsorbWordV1 {
    HashLaneExpressionKindV1 kind{
        HashLaneExpressionKindV1::Unresolved};
    std::array<uint32_t, 2> addresses{
        UINT32_MAX, UINT32_MAX};
    uint32_t selector_address{UINT32_MAX};
    Fp3 constant{};
    bool resolved{false};
};

HashLaneExpressionV1 MaterializeWord(
    const AbsorbWordV1& word,
    uint32_t row, uint32_t lane)
{
    HashLaneExpressionV1 out;
    out.task_row = row;
    out.lane = lane;
    out.kind = word.kind;
    out.source_addresses = word.addresses;
    out.selector_address =
        word.selector_address;
    out.constant = word.constant;
    out.resolved = word.resolved;
    return out;
}

std::optional<std::vector<AbsorbWordV1>>
RowLeafWords(
    const abi::DecodedV1& decoded,
    const mf::HashTaskV1& task)
{
    if (task.query >=
            decoded.envelope.split.batch
                .queries.size() ||
        task.group > 4) {
        return std::nullopt;
    }
    std::vector<AbsorbWordV1> out;
    const uint32_t query = task.query;
    uint32_t value_count = 0;
    abi::FieldKindV1 kind{};
    uint32_t group = task.group;
    if (group < 3) {
        value_count = static_cast<uint32_t>(
            decoded.envelope.split.batch
                .queries[query]
                .group_rows[group]
                .values.size());
        kind =
            abi::FieldKindV1::QueryRowValue;
    } else {
        const uint32_t next_group = group - 3;
        if (query >=
                decoded.envelope.split
                    .next_trace_group_rows
                    .size() ||
            next_group >= 2) {
            return std::nullopt;
        }
        value_count = static_cast<uint32_t>(
            decoded.envelope.split
                .next_trace_group_rows[query]
                [next_group].values.size());
        kind =
            abi::FieldKindV1::NextRowValue;
        group = next_group;
    }
    for (uint32_t value = 0;
         value < value_count; ++value) {
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            const auto addresses =
                FieldCoordinate(
                    decoded,
                    Key(kind, query, group, value),
                    coordinate);
            if (!addresses.has_value()) {
                return std::nullopt;
            }
            AbsorbWordV1 word;
            word.kind =
                HashLaneExpressionKindV1::
                    AbiFpCoordinate;
            word.addresses = *addresses;
            word.resolved = true;
            out.push_back(word);
        }
    }
    const auto query_address =
        Address(
            decoded,
            Key(
                abi::FieldKindV1::QueryIndex,
                query));
    if (!query_address.has_value()) {
        return std::nullopt;
    }
    AbsorbWordV1 index;
    if (task.group < 3) {
        index.kind =
            HashLaneExpressionKindV1::AbiU32;
        index.addresses[0] = *query_address;
    } else {
        index.kind =
            HashLaneExpressionKindV1::
                DerivedNextIndex;
        index.selector_address =
            *query_address;
    }
    index.resolved = true;
    out.push_back(index);
    AbsorbWordV1 delimiter;
    delimiter.kind =
        HashLaneExpressionKindV1::Constant;
    delimiter.constant = Fp3::One();
    delimiter.resolved = true;
    out.push_back(delimiter);
    while (out.size() %
               alg_hash::kAlgHashRate !=
           0) {
        AbsorbWordV1 zero;
        zero.kind =
            HashLaneExpressionKindV1::Constant;
        zero.constant = Fp3::Zero();
        zero.resolved = true;
        out.push_back(zero);
    }
    return out;
}

uint32_t PathIndexAddress(
    const abi::DecodedV1& decoded,
    const mf::HashTaskV1& task)
{
    if (task.group <= 4) {
        const auto address =
            Address(
                decoded,
                Key(
                    abi::FieldKindV1::
                        QueryIndex,
                    task.query));
        return address.value_or(UINT32_MAX);
    }
    if (task.group == 5 ||
        task.group == 6) {
        const auto kind =
            task.group == 5
            ? abi::FieldKindV1::
                  QueryStepEvenIndex
            : abi::FieldKindV1::
                  QueryStepOddIndex;
        const auto address =
            Address(
                decoded,
                Key(
                    kind, task.query,
                    task.fold));
        return address.value_or(UINT32_MAX);
    }
    return UINT32_MAX;
}

bool UsesDerivedNextIndex(
    const mf::HashTaskV1& task)
{
    return task.group == 3 ||
        task.group == 4;
}

} // namespace

TypedHashPlanV1 BuildTypedHashPlanV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard)
{
    TypedHashPlanV1 out;
    out.task_rows =
        static_cast<uint32_t>(
            shard.hash_tasks.size());
    out.expected_input_lanes =
        out.task_rows * alg_hash::kAlgHashT;
    const auto fail =
        [&out](const std::string& detail) {
            out.valid = false;
            out.note =
                "stage3:v13_merkle_fold_parent:"
                "hash_plan:" + detail;
            return out;
        };
    if (!decoded.canonical ||
        !decoded.complete ||
        !decoded.addresses_unique ||
        !decoded.semantic_keys_unique ||
        !shard.valid ||
        shard.hash_real_rows !=
            out.task_rows ||
        out.task_rows == 0) {
        return fail("input");
    }

    using PathKey =
        std::tuple<uint32_t, uint32_t, uint32_t>;
    std::map<PathKey, uint32_t>
        last_path_output;
    std::vector<std::vector<uint32_t>>
        terminal_levels(1);
    std::map<uint32_t, uint32_t>
        terminal_node_ordinal;
    std::set<std::pair<uint32_t, uint32_t>>
        lane_owners;
    bool prior_order = true;
    bool addresses_canonical = true;

    const auto append =
        [&](HashLaneExpressionV1 expression) {
            prior_order =
                prior_order &&
                (expression.prior_task_row ==
                     UINT32_MAX ||
                 expression.prior_task_row <
                     expression.task_row);
            for (uint32_t address :
                 expression.source_addresses) {
                if (address != UINT32_MAX) {
                    addresses_canonical =
                        addresses_canonical &&
                        CanonicalAddress(
                            decoded, address);
                }
            }
            if (expression.selector_address !=
                UINT32_MAX) {
                addresses_canonical =
                    addresses_canonical &&
                    CanonicalAddress(
                        decoded,
                        expression
                            .selector_address);
            }
            lane_owners.emplace(
                expression.task_row,
                expression.lane);
            out.resolved_input_lanes +=
                expression.resolved ? 1 : 0;
            out.inputs.push_back(
                std::move(expression));
        };

    for (uint32_t row = 0;
         row < out.task_rows; ++row) {
        const auto& task =
            shard.hash_tasks[row];
        std::array<HashLaneExpressionV1,
                   alg_hash::kAlgHashT>
            expressions;
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashT;
             ++lane) {
            expressions[lane].task_row = row;
            expressions[lane].lane = lane;
        }

        if (task.kind ==
            mf::HashTaskKindV1::RowLeaf) {
            const auto words =
                RowLeafWords(decoded, task);
            if (!words.has_value() ||
                task.level *
                        alg_hash::kAlgHashRate >=
                    words->size()) {
                return fail("row_leaf_words");
            }
            const bool chained =
                task.level != 0;
            if (chained) {
                if (row == 0) {
                    return fail(
                        "row_leaf_prior");
                }
                const auto& prior =
                    shard.hash_tasks[row - 1];
                if (prior.kind !=
                        mf::HashTaskKindV1::
                            RowLeaf ||
                    prior.query != task.query ||
                    prior.group != task.group ||
                    prior.level + 1 !=
                        task.level) {
                    return fail(
                        "row_leaf_chain");
                }
            }
            for (uint32_t lane = 0;
                 lane <
                     alg_hash::kAlgHashRate;
                 ++lane) {
                const uint32_t offset =
                    task.level *
                        alg_hash::kAlgHashRate +
                    lane;
                auto expression =
                    MaterializeWord(
                        (*words)[offset],
                        row, lane);
                if (chained) {
                    expression =
                        AddPrior(
                            std::move(
                                expression),
                            row - 1);
                }
                expressions[lane] =
                    std::move(expression);
            }
            for (uint32_t lane =
                     alg_hash::kAlgHashRate;
                 lane < alg_hash::kAlgHashT;
                 ++lane) {
                expressions[lane] =
                    chained
                    ? PriorExpression(
                          row, lane,
                          row - 1, lane)
                    : ConstantExpression(
                          row, lane,
                          Fp3::Zero());
            }
            last_path_output[
                PathKey{
                    task.query,
                    task.group,
                    task.fold}] = row;
        } else if (
            task.kind ==
            mf::HashTaskKindV1::FoldLeaf) {
            const bool terminal =
                task.group == 7;
            if (!terminal &&
                task.group > 1) {
                return fail(
                    "fold_leaf_group");
            }
            const auto value_addresses =
                FieldAddresses(
                    decoded,
                    terminal
                    ? Key(
                          abi::FieldKindV1::
                              FinalValue)
                    : Key(
                          task.group == 0
                          ? abi::FieldKindV1::
                                QueryStepEven
                          : abi::FieldKindV1::
                                QueryStepOdd,
                          task.query,
                          task.fold),
                    3);
            if (!value_addresses.has_value()) {
                return fail(
                    "fold_leaf_value_sources");
            }
            std::vector<uint32_t>
                expected_sources =
                    *value_addresses;
            uint32_t index_address =
                UINT32_MAX;
            if (!terminal) {
                const auto index =
                    Address(
                        decoded,
                        Key(
                            task.group == 0
                            ? abi::FieldKindV1::
                                  QueryStepEvenIndex
                            : abi::FieldKindV1::
                                  QueryStepOddIndex,
                            task.query,
                            task.fold));
                if (!index.has_value()) {
                    return fail(
                        "fold_leaf_index_source");
                }
                index_address = *index;
                expected_sources.push_back(
                    index_address);
            }
            if (task.source_addresses !=
                expected_sources) {
                return fail(
                    "fold_leaf_source_schema");
            }
            for (uint32_t coordinate = 0;
                 coordinate < 3;
                 ++coordinate) {
                expressions[coordinate] =
                    AbiFpExpression(
                        row, coordinate,
                        {(*value_addresses)[
                             2 * coordinate],
                         (*value_addresses)[
                             2 * coordinate +
                             1]});
            }
            expressions[3] =
                terminal
                ? ConstantExpression(
                      row, 3,
                      U(terminal_levels[0]
                            .size()))
                : AbiU32Expression(
                      row, 3,
                      index_address);
            expressions[4] =
                ConstantExpression(
                    row, 4,
                    Fp3::FromFp(
                        alg_hash::
                            GetAlgHashConstants()
                            .leaf_domain));
            for (uint32_t lane = 5;
                 lane < alg_hash::kAlgHashT;
                 ++lane) {
                expressions[lane] =
                    ConstantExpression(
                        row, lane,
                        Fp3::Zero());
            }
            if (terminal) {
                terminal_levels[0]
                    .push_back(row);
            } else {
                // FoldLeaf records use group 0/1 for even/odd, while
                // their MerkleNode consumers use the disjoint path groups
                // 5/6.  Normalize the leaf key to the consumer namespace so
                // an independently valid path cannot be detached from its
                // exact leaf.
                const uint32_t path_group =
                    task.group == 0 ? 5U : 6U;
                last_path_output[
                    PathKey{
                        task.query,
                        path_group,
                        task.fold}] = row;
            }
        } else if (
            task.kind ==
            mf::HashTaskKindV1::
                MerkleNode) {
            if (task.group == 7) {
                const uint32_t level =
                    task.level;
                if (level + 1 >=
                    terminal_levels.size()) {
                    terminal_levels.resize(
                        level + 2);
                }
                const uint32_t ordinal =
                    terminal_node_ordinal[
                        level]++;
                if (2 * ordinal + 1 >=
                    terminal_levels[level]
                        .size()) {
                    return fail(
                        "terminal_tree_edge");
                }
                const uint32_t left =
                    terminal_levels[level]
                        [2 * ordinal];
                const uint32_t right =
                    terminal_levels[level]
                        [2 * ordinal + 1];
                for (uint32_t lane = 0;
                     lane < 4; ++lane) {
                    expressions[lane] =
                        PriorExpression(
                            row, lane,
                            left, lane);
                    expressions[4 + lane] =
                        PriorExpression(
                            row, 4 + lane,
                            right, lane);
                }
                terminal_levels[level + 1]
                    .push_back(row);
                expressions[8] =
                    ConstantExpression(
                        row, 8,
                        Fp3::FromFp(
                            alg_hash::
                                GetAlgHashConstants()
                                .node_domain));
                for (uint32_t lane = 9;
                     lane <
                         alg_hash::kAlgHashT;
                     ++lane) {
                    expressions[lane] =
                        ConstantExpression(
                            row, lane,
                            Fp3::Zero());
                }
                if (task.source_addresses
                        .size() == 8) {
                    const auto root_addresses =
                        FieldAddresses(
                            decoded,
                            Key(
                                abi::FieldKindV1::
                                    FoldRoot,
                                static_cast<uint32_t>(
                                    decoded.envelope
                                        .split.batch
                                        .fold_challenges
                                        .size())),
                            4);
                    if (!root_addresses.has_value() ||
                        task.source_addresses !=
                            *root_addresses) {
                        return fail(
                            "terminal_root_schema");
                    }
                    for (uint32_t lane = 0;
                         lane < 4; ++lane) {
                        out.outputs.push_back({
                            row, lane,
                            {(*root_addresses)[
                                 2 * lane],
                             (*root_addresses)[
                                 2 * lane + 1]}});
                    }
                } else if (
                    !task.source_addresses
                         .empty()) {
                    return fail(
                        "terminal_root_sources");
                }
            } else {
                const PathKey key{
                    task.query,
                    task.group,
                    task.fold};
                const auto prior_it =
                    last_path_output.find(key);
                if (prior_it ==
                    last_path_output.end()) {
                    return fail(
                        "path_prior");
                }
                const uint32_t prior =
                    prior_it->second;
                abi::SourceKeyV1 sibling_key;
                abi::SourceKeyV1 root_key;
                uint32_t path_width = 0;
                const uint64_t n_lde64 =
                    uint64_t{
                        decoded.envelope.split
                            .batch.n_coeffs} *
                    decoded.envelope.split
                        .batch.blowup;
                if (n_lde64 == 0 ||
                    n_lde64 > UINT32_MAX) {
                    return fail(
                        "path_width");
                }
                const uint32_t n_lde =
                    static_cast<uint32_t>(
                        n_lde64);
                if (task.group <= 2) {
                    sibling_key = Key(
                        abi::FieldKindV1::
                            QueryRowSibling,
                        task.query,
                        task.group,
                        task.level);
                    root_key = Key(
                        abi::FieldKindV1::
                            GroupRoot,
                        task.group);
                    path_width = n_lde;
                } else if (
                    task.group <= 4) {
                    sibling_key = Key(
                        abi::FieldKindV1::
                            NextRowSibling,
                        task.query,
                        task.group - 3,
                        task.level);
                    root_key = Key(
                        abi::FieldKindV1::
                            GroupRoot,
                        task.group - 3);
                    path_width = n_lde;
                } else if (
                    task.group <= 6 &&
                    task.fold < 32) {
                    sibling_key = Key(
                        task.group == 5
                        ? abi::FieldKindV1::
                              QueryStepEvenSibling
                        : abi::FieldKindV1::
                              QueryStepOddSibling,
                        task.query,
                        task.fold,
                        task.level);
                    root_key = Key(
                        abi::FieldKindV1::
                            FoldRoot,
                        task.fold);
                    path_width =
                        n_lde >> task.fold;
                } else {
                    return fail(
                        "path_group");
                }
                if (path_width < 2 ||
                    (path_width &
                     (path_width - 1)) != 0) {
                    return fail(
                        "path_width");
                }
                const auto sibling_addresses =
                    FieldAddresses(
                        decoded,
                        sibling_key, 4);
                if (!sibling_addresses
                         .has_value()) {
                    return fail(
                        "path_sibling_schema");
                }
                const uint32_t path_depth =
                    std::countr_zero(
                        path_width);
                const bool final_node =
                    task.level + 1 ==
                        path_depth;
                std::vector<uint32_t>
                    expected_sources =
                        *sibling_addresses;
                std::optional<
                    std::vector<uint32_t>>
                    root_addresses;
                if (final_node) {
                    root_addresses =
                        FieldAddresses(
                            decoded,
                            root_key, 4);
                    if (!root_addresses
                             .has_value()) {
                        return fail(
                            "path_root_schema");
                    }
                    expected_sources.insert(
                        expected_sources.end(),
                        root_addresses->begin(),
                        root_addresses->end());
                }
                if (task.source_addresses !=
                    expected_sources) {
                    return fail(
                        "path_source_schema");
                }
                const uint32_t selector =
                    PathIndexAddress(
                        decoded, task);
                if (selector == UINT32_MAX) {
                    return fail(
                        "path_index");
                }
                for (uint32_t lane = 0;
                     lane < 4; ++lane) {
                    const std::array<uint32_t, 2>
                        sibling{
                            (*sibling_addresses)[
                                2 * lane],
                            (*sibling_addresses)[
                                2 * lane + 1]};
                    auto left =
                        AbiFpExpression(
                            row, lane,
                            sibling);
                    left.kind =
                        HashLaneExpressionKindV1::
                            SelectPriorOrSiblingLeft;
                    left.prior_task_row = prior;
                    left.prior_output_lane = lane;
                    left.selector_address =
                        selector;
                    left.selector_bit =
                        static_cast<uint8_t>(
                            task.level);
                    expressions[lane] =
                        std::move(left);
                    auto right =
                        AbiFpExpression(
                            row, 4 + lane,
                            sibling);
                    right.kind =
                        HashLaneExpressionKindV1::
                            SelectPriorOrSiblingRight;
                    right.prior_task_row =
                        prior;
                    right.prior_output_lane =
                        lane;
                    right.selector_address =
                        selector;
                    right.selector_bit =
                        static_cast<uint8_t>(
                            task.level);
                    expressions[4 + lane] =
                        std::move(right);
                }
                expressions[8] =
                    ConstantExpression(
                        row, 8,
                        Fp3::FromFp(
                            alg_hash::
                                GetAlgHashConstants()
                                .node_domain));
                for (uint32_t lane = 9;
                     lane <
                         alg_hash::kAlgHashT;
                     ++lane) {
                    expressions[lane] =
                        ConstantExpression(
                            row, lane,
                            Fp3::Zero());
                }
                if (final_node) {
                    for (uint32_t lane = 0;
                         lane < 4; ++lane) {
                        out.outputs.push_back({
                            row, lane,
                            {(*root_addresses)[
                                 2 * lane],
                             (*root_addresses)[
                                 2 * lane +
                                 1]}});
                    }
                }
                last_path_output[key] = row;
            }
        } else {
            return fail(
                "unsupported_task_kind");
        }
        for (auto& expression :
             expressions) {
            if (UsesDerivedNextIndex(task) &&
                (expression.kind ==
                     HashLaneExpressionKindV1::
                         SelectPriorOrSiblingLeft ||
                 expression.kind ==
                     HashLaneExpressionKindV1::
                         SelectPriorOrSiblingRight)) {
                // The selector address is still the canonical query
                // index.  The constraint builder derives the next-row
                // index bits before selecting the path orientation.
                expression
                    .selector_is_derived_next =
                    true;
            }
            append(std::move(expression));
        }
    }

    for (const auto& output : out.outputs) {
        addresses_canonical =
            addresses_canonical &&
            output.task_row <
                out.task_rows &&
            output.lane <
                alg_hash::kAlgHashDigestLen &&
            CanonicalAddress(
                decoded,
                output.source_addresses[0]) &&
            CanonicalAddress(
                decoded,
                output.source_addresses[1]);
    }
    out.output_aliases =
        static_cast<uint32_t>(
            out.outputs.size());
    const uint32_t fold_count =
        static_cast<uint32_t>(
            decoded.envelope.split.batch
                .fold_challenges.size());
    out.expected_output_aliases =
        alg_hash::kAlgHashDigestLen *
        (1 +
         shard.query_count *
             (5 + 2 * fold_count));
    out.every_input_lane_resolved =
        out.resolved_input_lanes ==
            out.expected_input_lanes;
    out.every_prior_precedes_consumer =
        prior_order;
    out.every_source_address_canonical =
        addresses_canonical;
    out.lane_ownership_unique =
        lane_owners.size() ==
            out.expected_input_lanes;
    out.output_inventory_complete =
        out.output_aliases ==
            out.expected_output_aliases;
    out.valid =
        out.every_input_lane_resolved &&
        out.every_prior_precedes_consumer &&
        out.every_source_address_canonical &&
        out.lane_ownership_unique &&
        out.output_inventory_complete;
    out.note = out.valid
        ? "stage3:v13_merkle_fold_parent:"
          "typed_hash_lane_plan"
        : "stage3:v13_merkle_fold_parent:"
          "hash_plan_incomplete:resolved=" +
              std::to_string(
                  out.resolved_input_lanes) +
              "/" +
              std::to_string(
                  out.expected_input_lanes) +
              ":prior=" +
              std::to_string(
                  out.every_prior_precedes_consumer) +
              ":canonical=" +
              std::to_string(
                  out.every_source_address_canonical) +
              ":unique=" +
              std::to_string(
                  out.lane_ownership_unique) +
              ":outputs=" +
              std::to_string(
                  out.output_aliases) +
              "/" +
              std::to_string(
                  out.expected_output_aliases);
    return out;
}

OrdinaryHashProductV1 BuildOrdinaryHashProductV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard)
{
    OrdinaryHashProductV1 out;
    out.plan =
        BuildTypedHashPlanV1(
            decoded, shard);
    const auto fail =
        [&out](const std::string& detail) {
            out.valid = false;
            out.note =
                "stage3:v13_merkle_fold_parent:"
                "ordinary_hash:" + detail;
            return out;
        };
    if (!out.plan.valid ||
        shard.hash_cs.n_rows !=
            shard.hash_trace_rows ||
        shard.hash_columns.size() !=
            shard.hash_cs.n_columns) {
        return fail(
            std::string{"input:"} +
            out.plan.note +
            ":resolved=" +
            std::to_string(
                out.plan.resolved_input_lanes) +
            "/" +
            std::to_string(
                out.plan.expected_input_lanes) +
            ":outputs=" +
            std::to_string(
                out.plan.output_aliases) +
            ":rows=" +
            std::to_string(
                shard.hash_cs.n_rows) +
            "/" +
            std::to_string(
                shard.hash_trace_rows) +
            ":columns=" +
            std::to_string(
                shard.hash_columns.size()) +
            "/" +
            std::to_string(
                shard.hash_cs.n_columns));
    }
    out.cs = shard.hash_cs;
    out.columns = shard.hash_columns;
    out.cs.preprocessed.erase(
        std::remove_if(
            out.cs.preprocessed.begin(),
            out.cs.preprocessed.end(),
            [&shard](const auto& item) {
                return IsPinColumn(
                    shard.hash_layout,
                    item.first);
            }),
        out.cs.preprocessed.end());
    out.cs.preprocessed_pin_ood = false;

    const auto append_column =
        [&out](std::vector<Fp3> values) {
            const uint32_t column =
                out.cs.n_columns++;
            out.columns.push_back(
                std::move(values));
            return column;
        };
    const auto constant_column =
        [&out, &append_column](Fp3 value) {
            return append_column(
                std::vector<Fp3>(
                    out.cs.n_rows, value));
        };
    const auto add_public =
        [&out, &append_column](
            std::vector<Fp3> values) {
            const uint32_t column =
                append_column(values);
            out.cs.preprocessed.emplace_back(
                column, std::move(values));
            return column;
        };

    std::set<uint32_t> source_addresses;
    std::set<uint32_t> index_addresses;
    std::set<uint32_t> derived_addresses;
    std::set<std::pair<uint32_t, uint32_t>>
        prior_outputs;
    for (const auto& expression :
         out.plan.inputs) {
        for (uint32_t address :
             expression.source_addresses) {
            if (address != UINT32_MAX) {
                source_addresses.insert(
                    address);
            }
        }
        if (expression.selector_address !=
            UINT32_MAX) {
            source_addresses.insert(
                expression.selector_address);
            index_addresses.insert(
                expression.selector_address);
            if (expression
                    .selector_is_derived_next ||
                expression.kind ==
                    HashLaneExpressionKindV1::
                        DerivedNextIndex ||
                expression.kind ==
                    HashLaneExpressionKindV1::
                        PriorOutputPlusDerivedNextIndex) {
                derived_addresses.insert(
                    expression.selector_address);
            }
        }
        if (expression.prior_task_row !=
            UINT32_MAX) {
            prior_outputs.emplace(
                expression.prior_task_row,
                expression.prior_output_lane);
        }
    }
    for (const auto& alias :
         out.plan.outputs) {
        source_addresses.insert(
            alias.source_addresses[0]);
        source_addresses.insert(
            alias.source_addresses[1]);
    }

    std::map<uint32_t, uint32_t>
        source_columns;
    for (uint32_t address :
         source_addresses) {
        if (!CanonicalAddress(
                decoded, address)) {
            return fail(
                "source_address");
        }
        const uint32_t column =
            constant_column(
                U(SourceValue(
                    decoded, address)));
        source_columns[address] = column;
        out.source_carriers.push_back(
            {address,
             decoded.sources[address].key,
             {column, 0}});
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.hash_source_carry",
            aq::AirKind::kTransition, 1,
            [column](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[column],
                    current[column]);
            });
    }

    std::map<uint32_t, uint32_t>
        index_bit_bases;
    for (uint32_t address :
         index_addresses) {
        const uint32_t base =
            out.cs.n_columns;
        index_bit_bases[address] = base;
        const uint32_t raw =
            static_cast<uint32_t>(
                SourceValue(
                    decoded, address));
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            const uint32_t column =
                constant_column(
                    U((raw >> bit) & 1U));
            AddConstraint(
                out.cs,
                "stage3.v13_merkle_fold.hash_index_bit",
                aq::AirKind::kEverywhere, 2,
                [column](
                    const auto& current,
                    const auto&) {
                    return gf::Mul(
                        current[column],
                        gf::Sub(
                            current[column],
                            Fp3::One()));
                });
        }
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.hash_index_recompose",
            aq::AirKind::kEverywhere, 1,
            [base,
             source =
                 source_columns.at(address)](
                const auto& current,
                const auto&) {
                Fp3 value = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            U(weight),
                            current[base + bit]));
                    weight <<= 1;
                }
                return gf::Sub(
                    current[source], value);
            });
    }

    struct DerivedIndexV1 {
        uint32_t value{UINT32_MAX};
        uint32_t bit_base{UINT32_MAX};
        uint32_t wrap{UINT32_MAX};
    };
    std::map<uint32_t, DerivedIndexV1>
        derived;
    const auto& split =
        decoded.envelope.split;
    const uint64_t n_lde64 =
        uint64_t{
            split.batch.n_coeffs} *
        split.batch.blowup;
    if (n_lde64 == 0 ||
        n_lde64 > UINT32_MAX ||
        (n_lde64 &
         (n_lde64 - 1)) != 0 ||
        split.trace_rows == 0 ||
        n_lde64 % split.trace_rows != 0) {
        return fail(
            "derived_index_shape");
    }
    const uint32_t n_lde =
        static_cast<uint32_t>(
            n_lde64);
    const uint32_t stride =
        n_lde / split.trace_rows;
    const uint32_t domain_bits =
        std::countr_zero(n_lde);
    for (uint32_t address :
         derived_addresses) {
        const uint32_t query =
            static_cast<uint32_t>(
                SourceValue(
                    decoded, address));
        if (query >= n_lde) {
            return fail(
                "query_out_of_domain");
        }
        const uint64_t sum =
            uint64_t{query} + stride;
        const bool wraps =
            sum >= n_lde;
        const uint32_t next =
            static_cast<uint32_t>(
                wraps
                ? sum - n_lde
                : sum);
        DerivedIndexV1 item;
        item.value =
            constant_column(U(next));
        item.wrap =
            constant_column(
                wraps
                ? Fp3::One()
                : Fp3::Zero());
        item.bit_base =
            out.cs.n_columns;
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            const uint32_t column =
                constant_column(
                    U((next >> bit) & 1U));
            AddConstraint(
                out.cs,
                "stage3.v13_merkle_fold.next_index_bit",
                aq::AirKind::kEverywhere, 2,
                [column](
                    const auto& current,
                    const auto&) {
                    return gf::Mul(
                        current[column],
                        gf::Sub(
                            current[column],
                            Fp3::One()));
                });
            if (bit >= domain_bits) {
                AddConstraint(
                    out.cs,
                    "stage3.v13_merkle_fold.next_index_range",
                    aq::AirKind::kEverywhere, 1,
                    [column](
                        const auto& current,
                        const auto&) {
                        return current[column];
                    });
                const uint32_t query_bit =
                    index_bit_bases.at(
                        address) + bit;
                AddConstraint(
                    out.cs,
                    "stage3.v13_merkle_fold.query_index_range",
                    aq::AirKind::kEverywhere, 1,
                    [query_bit](
                        const auto& current,
                        const auto&) {
                        return current[
                            query_bit];
                    });
            }
        }
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.next_index_recompose",
            aq::AirKind::kEverywhere, 1,
            [item](
                const auto& current,
                const auto&) {
                Fp3 value = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            U(weight),
                            current[
                                item.bit_base +
                                bit]));
                    weight <<= 1;
                }
                return gf::Sub(
                    current[item.value],
                    value);
            });
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.next_index_wrap_boolean",
            aq::AirKind::kEverywhere, 2,
            [column = item.wrap](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[column],
                    gf::Sub(
                        current[column],
                        Fp3::One()));
            });
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.next_index_add",
            aq::AirKind::kEverywhere, 1,
            [query =
                 source_columns.at(address),
             item, stride, n_lde](
                const auto& current,
                const auto&) {
                return gf::Sub(
                    gf::Add(
                        current[query],
                        U(stride)),
                    gf::Add(
                        current[item.value],
                        gf::Mul(
                            U(n_lde),
                            current[
                                item.wrap])));
            });
        derived[address] = item;
    }

    std::vector<uint32_t> task_selectors(
        out.plan.task_rows);
    for (uint32_t row = 0;
         row < out.plan.task_rows; ++row) {
        std::vector<Fp3> selector(
            out.cs.n_rows, Fp3::Zero());
        selector[row] = Fp3::One();
        task_selectors[row] =
            add_public(std::move(selector));
    }
    std::vector<Fp3> padding_selector(
        out.cs.n_rows, Fp3::Zero());
    for (uint32_t row =
             out.plan.task_rows;
         row < out.cs.n_rows; ++row) {
        padding_selector[row] =
            Fp3::One();
    }
    const uint32_t padding_column =
        add_public(
            std::move(
                padding_selector));

    struct PriorCarrierV1 {
        uint32_t value{UINT32_MAX};
        uint32_t source_selector{
            UINT32_MAX};
    };
    std::map<std::pair<uint32_t, uint32_t>,
             PriorCarrierV1>
        priors;
    for (const auto& key :
         prior_outputs) {
        const auto [row, lane] = key;
        if (row >= out.plan.task_rows ||
            lane >=
                alg_hash::kAlgHashT) {
            return fail(
                "prior_key");
        }
        PriorCarrierV1 item;
        item.value =
            constant_column(
                Fp3::FromFp(
                    shard.hash_tasks[row]
                        .output[lane]));
        std::vector<Fp3> selector(
            out.cs.n_rows, Fp3::Zero());
        selector[row] = Fp3::One();
        item.source_selector =
            add_public(
                std::move(selector));
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.prior_output_carry",
            aq::AirKind::kTransition, 1,
            [column = item.value](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[column],
                    current[column]);
            });
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.prior_output_source",
            aq::AirKind::kEverywhere, 2,
            [item, lane,
             perm =
                 shard.hash_layout
                     .poseidon.perm](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[
                        item.source_selector],
                    gf::Sub(
                        current[item.value],
                        ar::PermOutputLane(
                            perm, current,
                            lane)));
            });
        priors[key] = item;
    }

    for (const auto& expression :
         out.plan.inputs) {
        const uint32_t selector =
            task_selectors[
                expression.task_row];
        const uint32_t input =
            shard.hash_layout.InputPin(
                expression.lane);
        const uint32_t source_low =
            expression.source_addresses[0] !=
                UINT32_MAX
            ? source_columns.at(
                  expression
                      .source_addresses[0])
            : UINT32_MAX;
        const uint32_t source_high =
            expression.source_addresses[1] !=
                UINT32_MAX
            ? source_columns.at(
                  expression
                      .source_addresses[1])
            : UINT32_MAX;
        const uint32_t prior_column =
            expression.prior_task_row !=
                UINT32_MAX
            ? priors.at({
                  expression.prior_task_row,
                  expression
                      .prior_output_lane})
                  .value
            : UINT32_MAX;
        const uint32_t derived_column =
            expression.selector_address !=
                    UINT32_MAX &&
                derived.contains(
                    expression
                        .selector_address)
            ? derived.at(
                  expression
                      .selector_address)
                  .value
            : UINT32_MAX;
        uint32_t select_bit_column =
            UINT32_MAX;
        if (expression.kind ==
                HashLaneExpressionKindV1::
                    SelectPriorOrSiblingLeft ||
            expression.kind ==
                HashLaneExpressionKindV1::
                    SelectPriorOrSiblingRight) {
            select_bit_column =
                expression
                    .selector_is_derived_next
                ? derived.at(
                      expression
                          .selector_address)
                      .bit_base +
                      expression.selector_bit
                : index_bit_bases.at(
                      expression
                          .selector_address) +
                      expression.selector_bit;
        }
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.typed_hash_input",
            aq::AirKind::kEverywhere, 3,
            [expression, selector, input,
             source_low, source_high,
             prior_column, derived_column,
             select_bit_column](
                const auto& current,
                const auto&) {
                Fp3 expected =
                    Fp3::Zero();
                const auto abi_value =
                    [&]() {
                        if (expression.kind ==
                                HashLaneExpressionKindV1::
                                    AbiU32 ||
                            expression.kind ==
                                HashLaneExpressionKindV1::
                                    PriorOutputPlusAbiU32) {
                            return current[
                                source_low];
                        }
                        return gf::Add(
                            current[source_low],
                            gf::Mul(
                                U(uint64_t{1}
                                  << 32),
                                current[
                                    source_high]));
                    };
                switch (expression.kind) {
                case HashLaneExpressionKindV1::
                    Constant:
                    expected =
                        expression.constant;
                    break;
                case HashLaneExpressionKindV1::
                    AbiU32:
                case HashLaneExpressionKindV1::
                    AbiFpCoordinate:
                    expected =
                        abi_value();
                    break;
                case HashLaneExpressionKindV1::
                    PriorOutput:
                    expected =
                        current[prior_column];
                    break;
                case HashLaneExpressionKindV1::
                    PriorOutputPlusConstant:
                    expected = gf::Add(
                        current[prior_column],
                        expression.constant);
                    break;
                case HashLaneExpressionKindV1::
                    PriorOutputPlusAbiU32:
                case HashLaneExpressionKindV1::
                    PriorOutputPlusAbiFpCoordinate:
                    expected = gf::Add(
                        current[prior_column],
                        abi_value());
                    break;
                case HashLaneExpressionKindV1::
                    DerivedNextIndex:
                    expected =
                        current[derived_column];
                    break;
                case HashLaneExpressionKindV1::
                    PriorOutputPlusDerivedNextIndex:
                    expected = gf::Add(
                        current[prior_column],
                        current[derived_column]);
                    break;
                case HashLaneExpressionKindV1::
                    SelectPriorOrSiblingLeft:
                case HashLaneExpressionKindV1::
                    SelectPriorOrSiblingRight: {
                    const Fp3 prior =
                        current[prior_column];
                    const Fp3 sibling =
                        abi_value();
                    const Fp3 bit =
                        current[
                            select_bit_column];
                    expected =
                        expression.kind ==
                            HashLaneExpressionKindV1::
                                SelectPriorOrSiblingLeft
                        ? gf::Add(
                              prior,
                              gf::Mul(
                                  bit,
                                  gf::Sub(
                                      sibling,
                                      prior)))
                        : gf::Add(
                              sibling,
                              gf::Mul(
                                  bit,
                                  gf::Sub(
                                      prior,
                                      sibling)));
                    break;
                }
                case HashLaneExpressionKindV1::
                    Unresolved:
                    expected =
                        gf::Add(
                            current[input],
                            Fp3::One());
                    break;
                }
                return gf::Mul(
                    current[selector],
                    gf::Sub(
                        current[input],
                        expected));
            });
    }
    for (const auto& alias :
         out.plan.outputs) {
        const uint32_t selector =
            task_selectors[
                alias.task_row];
        const uint32_t output =
            shard.hash_layout.OutputPin(
                alias.lane);
        const uint32_t low =
            source_columns.at(
                alias.source_addresses[0]);
        const uint32_t high =
            source_columns.at(
                alias.source_addresses[1]);
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.hash_root_output",
            aq::AirKind::kEverywhere, 2,
            [selector, output, low, high](
                const auto& current,
                const auto&) {
                const Fp3 expected =
                    gf::Add(
                        current[low],
                        gf::Mul(
                            U(uint64_t{1} << 32),
                            current[high]));
                return gf::Mul(
                    current[selector],
                    gf::Sub(
                        current[output],
                        expected));
            });
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        const uint32_t input =
            shard.hash_layout.InputPin(lane);
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.hash_padding_input",
            aq::AirKind::kEverywhere, 2,
            [padding_column, input](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[padding_column],
                    current[input]);
            });
    }
    const uint32_t acceptance =
        append_column(
            std::vector<Fp3>(
                out.cs.n_rows,
                Fp3::Zero()));
    out.columns[acceptance][0] =
        Fp3::One();
    AddConstraint(
        out.cs,
        "stage3.v13_merkle_fold.hash_acceptance",
        aq::AirKind::kFirstRow, 1,
        [acceptance](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[acceptance],
                Fp3::One());
        });
    out.acceptance = {acceptance, 0};

    out.violations =
        CountViolationsV1(
            out.cs, out.columns);
    out.proof_pins_ordinary = true;
    out.selectors_and_constants_only_preprocessed =
        std::none_of(
            out.cs.preprocessed.begin(),
            out.cs.preprocessed.end(),
            [&shard](const auto& item) {
                return IsPinColumn(
                    shard.hash_layout,
                    item.first);
            });
    out.all_abi_words_exported =
        out.source_carriers.size() ==
            source_addresses.size();
    out.all_prior_edges_constrained =
        priors.size() ==
            prior_outputs.size();
    out.all_output_roots_constrained =
        !out.plan.outputs.empty();
    out.valid =
        out.violations == 0 &&
        out.proof_pins_ordinary &&
        out.selectors_and_constants_only_preprocessed &&
        out.all_abi_words_exported &&
        out.all_prior_edges_constrained &&
        out.all_output_roots_constrained;
    out.note = out.valid
        ? "stage3:v13_merkle_fold_parent:"
          "ordinary_typed_hash_product"
        : "stage3:v13_merkle_fold_parent:"
          "ordinary_hash_invalid";
    return out;
}

TypedFoldPlanV1 BuildTypedFoldPlanV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard)
{
    TypedFoldPlanV1 out;
    const auto& batch =
        decoded.envelope.split.batch;
    const uint32_t fold_count =
        static_cast<uint32_t>(
            batch.fold_challenges.size());
    const auto fail =
        [&out](const std::string& detail) {
            out.valid = false;
            out.note =
                "stage3:v13_merkle_fold_parent:"
                "fold_plan:" + detail;
            return out;
        };
    if (!decoded.canonical ||
        !decoded.complete ||
        !shard.valid ||
        fold_count == 0 ||
        shard.first_query >
            batch.queries.size() ||
        shard.query_count >
            batch.queries.size() -
                shard.first_query) {
        return fail("input");
    }
    out.expected_real_rows =
        shard.query_count * fold_count;
    if (shard.fold_real_rows !=
        out.expected_real_rows) {
        return fail("row_count");
    }
    const uint64_t n_lde64 =
        uint64_t{batch.n_coeffs} *
        batch.blowup;
    if (n_lde64 == 0 ||
        n_lde64 > UINT32_MAX ||
        (n_lde64 &
         (n_lde64 - 1)) != 0) {
        return fail("domain");
    }
    const uint32_t n_lde =
        static_cast<uint32_t>(
            n_lde64);
    bool addresses_canonical = true;
    const auto field6 =
        [&](abi::SourceKeyV1 key,
            std::array<uint32_t, 6>& target) {
            for (uint32_t coordinate = 0;
                 coordinate < 3;
                 ++coordinate) {
                const auto addresses =
                    FieldCoordinate(
                        decoded, key,
                        coordinate);
                if (!addresses.has_value()) {
                    return false;
                }
                target[2 * coordinate] =
                    (*addresses)[0];
                target[
                    2 * coordinate + 1] =
                    (*addresses)[1];
            }
            return true;
        };
    uint32_t row = 0;
    for (uint32_t query =
             shard.first_query;
         query <
             shard.first_query +
                 shard.query_count;
         ++query) {
        for (uint32_t fold = 0;
             fold < fold_count;
             ++fold, ++row) {
            FoldRowSourcePlanV1 item;
            item.row = row;
            item.query = query;
            item.fold = fold;
            if (!field6(
                    Key(
                        abi::FieldKindV1::
                            QueryStepEven,
                        query, fold),
                    item.even) ||
                !field6(
                    Key(
                        abi::FieldKindV1::
                            QueryStepOdd,
                        query, fold),
                    item.odd) ||
                !field6(
                    Key(
                        abi::FieldKindV1::
                            FoldChallenge,
                        fold),
                    item.beta) ||
                !field6(
                    Key(
                        abi::FieldKindV1::
                            FinalValue),
                    item.final_value)) {
                return fail(
                    "field_source");
            }
            const auto index =
                Address(
                    decoded,
                    fold == 0
                    ? Key(
                          abi::FieldKindV1::
                              QueryIndex,
                          query)
                    : Key(
                          abi::FieldKindV1::
                              QueryStepEvenIndex,
                          query, fold - 1));
            const auto even_index =
                Address(
                    decoded,
                    Key(
                        abi::FieldKindV1::
                            QueryStepEvenIndex,
                        query, fold));
            const auto odd_index =
                Address(
                    decoded,
                    Key(
                        abi::FieldKindV1::
                            QueryStepOddIndex,
                        query, fold));
            if (!index.has_value() ||
                !even_index.has_value() ||
                !odd_index.has_value()) {
                return fail(
                    "index_source");
            }
            item.index = *index;
            item.even_index =
                *even_index;
            item.odd_index =
                *odd_index;
            item.half =
                (n_lde >> fold) / 2;
            item.terminal =
                fold + 1 == fold_count;
            for (uint32_t address :
                 item.even) {
                addresses_canonical =
                    addresses_canonical &&
                    CanonicalAddress(
                        decoded, address);
            }
            for (uint32_t address :
                 item.odd) {
                addresses_canonical =
                    addresses_canonical &&
                    CanonicalAddress(
                        decoded, address);
            }
            for (uint32_t address :
                 item.beta) {
                addresses_canonical =
                    addresses_canonical &&
                    CanonicalAddress(
                        decoded, address);
            }
            for (uint32_t address :
                 item.final_value) {
                addresses_canonical =
                    addresses_canonical &&
                    CanonicalAddress(
                        decoded, address);
            }
            addresses_canonical =
                addresses_canonical &&
                CanonicalAddress(
                    decoded, item.index) &&
                CanonicalAddress(
                    decoded,
                    item.even_index) &&
                CanonicalAddress(
                    decoded,
                    item.odd_index);
            item.valid =
                item.half != 0;
            out.rows.push_back(item);
        }
    }
    out.real_rows = row;
    out.every_source_address_canonical =
        addresses_canonical;
    out.exact_query_fold_schedule =
        out.real_rows ==
            out.expected_real_rows;
    out.valid =
        out.every_source_address_canonical &&
        out.exact_query_fold_schedule &&
        std::all_of(
            out.rows.begin(),
            out.rows.end(),
            [](const auto& item) {
                return item.valid;
            });
    out.note = out.valid
        ? "stage3:v13_merkle_fold_parent:"
          "typed_fold_source_plan"
        : "stage3:v13_merkle_fold_parent:"
          "fold_plan_incomplete";
    return out;
}

OrdinaryFoldProductV1 BuildOrdinaryFoldProductV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard)
{
    OrdinaryFoldProductV1 out;
    out.plan =
        BuildTypedFoldPlanV1(
            decoded, shard);
    const auto fail =
        [&out](const std::string& detail) {
            out.valid = false;
            out.note =
                "stage3:v13_merkle_fold_parent:"
                "ordinary_fold:" + detail;
            return out;
        };
    if (!out.plan.valid ||
        shard.fold_cs.n_rows !=
            shard.fold_trace_rows ||
        shard.fold_columns.size() !=
            shard.fold_cs.n_columns) {
        return fail("input");
    }
    out.cs = shard.fold_cs;
    out.columns = shard.fold_columns;
    const auto& layout =
        shard.fold_layout;
    const std::set<uint32_t>
        public_schedule_columns{
            layout.chain_next,
            layout.terminal,
            layout.half};
    out.cs.preprocessed.erase(
        std::remove_if(
            out.cs.preprocessed.begin(),
            out.cs.preprocessed.end(),
            [&public_schedule_columns](
                const auto& item) {
                return
                    !public_schedule_columns
                         .contains(
                             item.first);
            }),
        out.cs.preprocessed.end());
    out.cs.preprocessed_pin_ood = false;

    const auto append_column =
        [&out](std::vector<Fp3> values) {
            const uint32_t column =
                out.cs.n_columns++;
            out.columns.push_back(
                std::move(values));
            return column;
        };
    const auto constant_column =
        [&out, &append_column](Fp3 value) {
            return append_column(
                std::vector<Fp3>(
                    out.cs.n_rows, value));
        };
    const auto add_public =
        [&out, &append_column](
            std::vector<Fp3> values) {
            const uint32_t column =
                append_column(values);
            out.cs.preprocessed.emplace_back(
                column, std::move(values));
            return column;
        };

    std::set<uint32_t> addresses;
    for (const auto& row :
         out.plan.rows) {
        addresses.insert(
            row.even.begin(),
            row.even.end());
        addresses.insert(
            row.odd.begin(),
            row.odd.end());
        addresses.insert(
            row.beta.begin(),
            row.beta.end());
        addresses.insert(
            row.final_value.begin(),
            row.final_value.end());
        addresses.insert(row.index);
        addresses.insert(row.even_index);
        addresses.insert(row.odd_index);
    }
    std::map<uint32_t, uint32_t>
        source_columns;
    for (uint32_t address : addresses) {
        if (!CanonicalAddress(
                decoded, address)) {
            return fail(
                "source_address");
        }
        const uint32_t column =
            constant_column(
                U(SourceValue(
                    decoded, address)));
        source_columns[address] = column;
        out.source_carriers.push_back(
            {address,
             decoded.sources[address].key,
             {column, 0}});
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.fold_source_carry",
            aq::AirKind::kTransition, 1,
            [column](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[column],
                    current[column]);
            });
    }

    std::vector<uint32_t> row_selectors(
        out.plan.real_rows);
    for (uint32_t row = 0;
         row < out.plan.real_rows;
         ++row) {
        std::vector<Fp3> selector(
            out.cs.n_rows, Fp3::Zero());
        selector[row] = Fp3::One();
        row_selectors[row] =
            add_public(
                std::move(selector));
    }

    const auto field_columns =
        [&source_columns](
            const std::array<uint32_t, 6>&
                source) {
            std::array<uint32_t, 6> out{};
            for (uint32_t index = 0;
                 index < out.size();
                 ++index) {
                out[index] =
                    source_columns.at(
                        source[index]);
            }
            return out;
        };
    for (const auto& row :
         out.plan.rows) {
        const uint32_t selector =
            row_selectors[row.row];
        const auto add_field_alias =
            [&out, selector,
             &field_columns](
                uint32_t target,
                const std::array<uint32_t, 6>&
                    source) {
                const auto columns =
                    field_columns(source);
                AddConstraint(
                    out.cs,
                    "stage3.v13_merkle_fold.fold_field_source",
                    aq::AirKind::kEverywhere,
                    2,
                    [selector, target,
                     columns](
                        const auto& current,
                        const auto&) {
                        Fp3 expected =
                            Fp3::Zero();
                        for (uint32_t coordinate =
                                 0;
                             coordinate < 3;
                             ++coordinate) {
                            const Fp3 word =
                                gf::Add(
                                    current[
                                        columns[
                                            2 *
                                            coordinate]],
                                    gf::Mul(
                                        U(uint64_t{1}
                                          << 32),
                                        current[
                                            columns[
                                                2 *
                                                coordinate +
                                                1]]));
                            expected =
                                gf::Add(
                                    expected,
                                    gf::Mul(
                                        Basis(
                                            coordinate),
                                        word));
                        }
                        return gf::Mul(
                            current[selector],
                            gf::Sub(
                                current[target],
                                expected));
                    });
            };
        add_field_alias(
            layout.even, row.even);
        add_field_alias(
            layout.odd, row.odd);
        add_field_alias(
            layout.beta, row.beta);
        add_field_alias(
            layout.final_value,
            row.final_value);
        const std::array<
            std::pair<uint32_t, uint32_t>, 3>
            u32_aliases{{
                {layout.index, row.index},
                {layout.even_index,
                 row.even_index},
                {layout.odd_index,
                 row.odd_index},
            }};
        for (const auto& [target, address] :
             u32_aliases) {
            const uint32_t source =
                source_columns.at(address);
            AddConstraint(
                out.cs,
                "stage3.v13_merkle_fold.fold_u32_source",
                aq::AirKind::kEverywhere,
                2,
                [selector, target, source](
                    const auto& current,
                    const auto&) {
                    return gf::Mul(
                        current[selector],
                        gf::Sub(
                            current[target],
                            current[source]));
                });
        }
    }

    const uint32_t bit_base =
        out.cs.n_columns;
    for (uint32_t bit = 0;
         bit < 32; ++bit) {
        std::vector<Fp3> values(
            out.cs.n_rows, Fp3::Zero());
        for (const auto& row :
             out.plan.rows) {
            const uint32_t value =
                static_cast<uint32_t>(
                    SourceValue(
                        decoded,
                        row.even_index));
            values[row.row] =
                U((value >> bit) & 1U);
        }
        const uint32_t column =
            append_column(
                std::move(values));
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.fold_index_bit",
            aq::AirKind::kEverywhere, 2,
            [column](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[column],
                    gf::Sub(
                        current[column],
                        Fp3::One()));
            });
    }
    AddConstraint(
        out.cs,
        "stage3.v13_merkle_fold.fold_index_recompose",
        aq::AirKind::kEverywhere, 1,
        [bit_base, index = layout.even_index](
            const auto& current,
            const auto&) {
            Fp3 expected = Fp3::Zero();
            uint64_t weight = 1;
            for (uint32_t bit = 0;
                 bit < 32; ++bit) {
                expected = gf::Add(
                    expected,
                    gf::Mul(
                        U(weight),
                        current[
                            bit_base + bit]));
                weight <<= 1;
            }
            return gf::Sub(
                current[index], expected);
        });

    const uint32_t power_base =
        out.cs.n_columns;
    for (uint32_t bit = 0;
         bit < 32; ++bit) {
        std::vector<Fp3> values(
            out.cs.n_rows, Fp3::One());
        for (const auto& row :
             out.plan.rows) {
            const uint32_t width =
                row.half * 2;
            const Fp omega =
                OmegaForSize(width);
            if (omega == 0) {
                return fail(
                    "omega");
            }
            values[row.row] =
                Fp3::FromFp(
                    PowBase(
                        omega,
                        uint64_t{1}
                            << bit));
        }
        add_public(std::move(values));
    }
    const uint32_t allowed_base =
        out.cs.n_columns;
    for (uint32_t bit = 0;
         bit < 32; ++bit) {
        std::vector<Fp3> values(
            out.cs.n_rows, Fp3::Zero());
        for (const auto& row :
             out.plan.rows) {
            const uint32_t bits =
                std::countr_zero(
                    row.half);
            values[row.row] =
                bit < bits
                ? Fp3::One()
                : Fp3::Zero();
        }
        add_public(std::move(values));
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.fold_index_range",
            aq::AirKind::kEverywhere, 2,
            [bit_column =
                 bit_base + bit,
             allowed_column =
                 allowed_base + bit](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[bit_column],
                    gf::Sub(
                        Fp3::One(),
                        current[
                            allowed_column]));
            });
    }

    const uint32_t accumulator_base =
        out.cs.n_columns;
    std::array<std::vector<Fp3>, 33>
        accumulator_values;
    for (auto& values :
         accumulator_values) {
        values.assign(
            out.cs.n_rows,
            Fp3::One());
    }
    for (uint32_t row = 0;
         row < out.cs.n_rows; ++row) {
        Fp3 accumulator = Fp3::One();
        accumulator_values[0][row] =
            accumulator;
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            const Fp3 selected =
                out.columns[
                    bit_base + bit][row];
            const Fp3 power =
                out.columns[
                    power_base + bit][row];
            accumulator = gf::Mul(
                accumulator,
                gf::Add(
                    Fp3::One(),
                    gf::Mul(
                        selected,
                        gf::Sub(
                            power,
                            Fp3::One()))));
            accumulator_values[
                bit + 1][row] =
                accumulator;
        }
    }
    for (uint32_t step = 0;
         step <= 32; ++step) {
        append_column(
            std::move(
                accumulator_values[step]));
    }
    AddConstraint(
        out.cs,
        "stage3.v13_merkle_fold.fold_x_acc_start",
        aq::AirKind::kEverywhere, 1,
        [column = accumulator_base](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[column],
                Fp3::One());
        });
    for (uint32_t bit = 0;
         bit < 32; ++bit) {
        AddConstraint(
            out.cs,
            "stage3.v13_merkle_fold.fold_x_acc_step",
            aq::AirKind::kEverywhere, 3,
            [bit_column =
                 bit_base + bit,
             power_column =
                 power_base + bit,
             current_acc =
                 accumulator_base + bit,
             next_acc =
                 accumulator_base + bit + 1](
                const auto& current,
                const auto&) {
                const Fp3 factor =
                    gf::Add(
                        Fp3::One(),
                        gf::Mul(
                            current[
                                bit_column],
                            gf::Sub(
                                current[
                                    power_column],
                                Fp3::One())));
                return gf::Sub(
                    current[next_acc],
                    gf::Mul(
                        current[
                            current_acc],
                        factor));
            });
    }
    AddConstraint(
        out.cs,
        "stage3.v13_merkle_fold.fold_x_bind",
        aq::AirKind::kEverywhere, 1,
        [x = layout.x,
         final_acc =
             accumulator_base + 32](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[x],
                current[final_acc]);
        });

    const uint32_t acceptance =
        append_column(
            std::vector<Fp3>(
                out.cs.n_rows,
                Fp3::Zero()));
    out.columns[acceptance][0] =
        Fp3::One();
    AddConstraint(
        out.cs,
        "stage3.v13_merkle_fold.fold_acceptance",
        aq::AirKind::kFirstRow, 1,
        [acceptance](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[acceptance],
                Fp3::One());
        });
    out.acceptance = {acceptance, 0};

    out.violations =
        CountViolationsV1(
            out.cs, out.columns);
    out.proof_pins_ordinary = true;
    out.schedule_only_preprocessed =
        std::all_of(
            out.cs.preprocessed.begin(),
            out.cs.preprocessed.end(),
            [&public_schedule_columns,
             first_new =
                 shard.fold_cs.n_columns](
                const auto& item) {
                return
                    public_schedule_columns
                        .contains(item.first) ||
                    item.first >= first_new;
            });
    out.all_abi_words_exported =
        out.source_carriers.size() ==
            addresses.size();
    out.index_bits_constrained = true;
    out.domain_point_exponentiation_constrained =
        true;
    out.fold_chain_constrained =
        std::any_of(
            out.cs.constraints.begin(),
            out.cs.constraints.end(),
            [](const auto& constraint) {
                return constraint.name ==
                    "stage3.v11_merkle_fold.chain";
            });
    out.valid =
        out.violations == 0 &&
        out.proof_pins_ordinary &&
        out.schedule_only_preprocessed &&
        out.all_abi_words_exported &&
        out.index_bits_constrained &&
        out.domain_point_exponentiation_constrained &&
        out.fold_chain_constrained;
    out.note = out.valid
        ? "stage3:v13_merkle_fold_parent:"
          "ordinary_typed_fold_product"
        : "stage3:v13_merkle_fold_parent:"
          "ordinary_fold_invalid";
    return out;
}

bool AppendProofTapeAliasesV1(
    aq::AirConstraintSystem<Fp3>& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    const tape::ProductV1& tape_product,
    const composer::ChildAttachmentV1&
        tape_attachment,
    const OrdinaryHashProductV1& hash_product,
    const composer::ChildAttachmentV1&
        hash_attachment,
    const OrdinaryFoldProductV1& fold_product,
    const composer::ChildAttachmentV1&
        fold_attachment,
    ParentAliasAttachmentV1& out,
    std::string* why)
{
    namespace terminal =
        stage3_v13_terminal_fold_parent;
    out = {};
    if (!tape_product.valid ||
        !hash_product.valid ||
        !fold_product.valid ||
        !tape_attachment.valid ||
        !hash_attachment.valid ||
        !fold_attachment.valid ||
        tape_attachment.semantic_child_columns !=
            tape_product.cs.n_columns ||
        hash_attachment.semantic_child_columns !=
            hash_product.cs.n_columns ||
        fold_attachment.semantic_child_columns !=
            fold_product.cs.n_columns) {
        return Fail(
            why, "parent_alias_input");
    }
    std::map<uint32_t,
             tape::SourceAddressCellV1>
        tape_cells;
    for (const auto& cell :
         tape_product.source_cells) {
        if (!tape_cells.emplace(
                cell.address, cell)
                 .second) {
            return Fail(
                why,
                "duplicate_tape_address");
        }
    }
    std::vector<std::pair<
        terminal::CellRefV1,
        terminal::CellRefV1>>
        aliases;
    aliases.reserve(
        hash_product.source_carriers.size() +
        fold_product.source_carriers.size());
    const auto append_child =
        [&](const std::vector<SourceCarrierV1>&
                carriers,
            const composer::ChildAttachmentV1&
                attachment) {
            for (const auto& carrier :
                 carriers) {
                const auto tape_it =
                    tape_cells.find(
                        carrier.source_address);
                if (tape_it ==
                        tape_cells.end() ||
                    !(tape_it->second.key ==
                      carrier.source_key)) {
                    return false;
                }
                aliases.push_back({
                    {
                        tape_attachment
                            .ParentColumn(
                                tape_it->second
                                    .value_column),
                        tape_it->second.row,
                    },
                    {
                        attachment.ParentColumn(
                            carrier.cell.column),
                        carrier.cell.row,
                    }});
            }
            return true;
        };
    if (!append_child(
            hash_product.source_carriers,
            hash_attachment) ||
        !append_child(
            fold_product.source_carriers,
            fold_attachment) ||
        aliases.empty()) {
        return Fail(
            why, "missing_tape_address");
    }
    terminal::LiteralAliasAttachmentV1
        literal;
    if (!terminal::AppendLiteralAliasesV1(
            parent_cs, parent_columns,
            aliases, literal, why)) {
        return false;
    }
    out.source_aliases =
        literal.literal_aliases;
    out.constraints =
        literal.constraints;
    out.violations =
        literal.violations;
    out.tape_cells_literal =
        out.source_aliases ==
            hash_product.source_carriers.size() +
                fold_product.source_carriers.size();
    out.child_carriers_ordinary =
        literal.endpoints_ordinary;
    out.cross_row_transport_constrained =
        literal
            .cross_row_transport_constrained;
    out.global_r0_pending =
        literal.global_r0_pending;
    out.valid =
        literal.valid &&
        out.tape_cells_literal &&
        out.child_carriers_ordinary &&
        out.cross_row_transport_constrained &&
        out.global_r0_pending;
    out.note = out.valid
        ? "stage3:v13_merkle_fold_parent:"
          "all_proof_sources_physically_aliased;"
          "global_r0_pending"
        : "stage3:v13_merkle_fold_parent:"
          "parent_alias_invalid";
    if (!out.valid) {
        return Fail(
            why, "parent_alias_invalid");
    }
    if (why != nullptr) {
        *why = out.note;
    }
    return true;
}

uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>&
        columns)
{
    if (cs.n_rows < 2 ||
        columns.size() != cs.n_columns) {
        return UINT64_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return UINT64_MAX;
        }
    }
    uint64_t violations = 0;
    std::vector<Fp3> current(
        cs.n_columns);
    std::vector<Fp3> next(
        cs.n_columns);
    for (uint32_t row = 0;
         row < cs.n_rows; ++row) {
        for (uint32_t column = 0;
             column < cs.n_columns;
             ++column) {
            current[column] =
                columns[column][row];
            next[column] =
                columns[column][
                    row + 1 < cs.n_rows
                    ? row + 1
                    : row];
        }
        for (const auto& constraint :
             cs.constraints) {
            const bool applies =
                constraint.kind ==
                    aq::AirKind::kEverywhere ||
                (constraint.kind ==
                     aq::AirKind::kTransition &&
                 row + 1 < cs.n_rows) ||
                (constraint.kind ==
                     aq::AirKind::kFirstRow &&
                 row == 0) ||
                (constraint.kind ==
                     aq::AirKind::kLastRow &&
                 row + 1 == cs.n_rows);
            if (applies &&
                !gf::IsZero(
                    constraint.eval(
                        current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_v13_merkle_fold_parent
