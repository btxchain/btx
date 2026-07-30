// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_extract_stream_ctl.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_gkr_air.h>

#include <algorithm>
#include <array>
#include <functional>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace ga = gkr_air;
namespace gf = gkr_field;
using gf::Fp3;
using AirCS = aq::AirConstraintSystem<Fp3>;

constexpr uint32_t NAMESPACE_ID = 0x45531914U;
constexpr char TRANSCRIPT_DOMAIN[] =
    "BTX_RC_STAGE3_EXTRACT_STREAM_CTL_TRANSCRIPT_V1";
constexpr char CHILD_DOMAIN[] =
    "BTX_RC_STAGE3_EXTRACT_STREAM_CTL_CHILD_V1";
constexpr char PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_EXTRACT_STREAM_CTL_PRODUCT_V1";
constexpr char TILE_DOMAIN[] =
    "BTX_RC_STAGE3_EXTRACT_STREAM_CTL_TILE_V1";
constexpr char COLLECTION_DOMAIN[] =
    "BTX_RC_STAGE3_EXTRACT_STREAM_CTL_COLLECTION_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:extract_stream_ctl:" + detail;
    }
    return false;
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

void Add(
    AirCS& cs,
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

RCStage3CtlSchedule Schedule(
    uint32_t tile, int8_t multiplicity)
{
    RCStage3CtlSchedule out;
    out.events.reserve(kRCMxBlockLen);
    for (uint32_t row = 0;
         row < kRCMxBlockLen; ++row) {
        out.events.push_back({
            NAMESPACE_ID, tile, row, multiplicity});
    }
    return out;
}

RCStage3CtlParticipantSpec Participant(
    RCStage3RelationRole role,
    const RCStage3CtlSchedule& schedule,
    bool sends)
{
    RCStage3CtlParticipantSpec out;
    out.role = role;
    out.event_count = schedule.events.size();
    out.send_count = sends ? out.event_count : 0;
    out.receive_count = sends ? 0 : out.event_count;
    out.schedule_commitment =
        CommitRCStage3CtlSchedule(schedule);
    return out;
}

Fp3 Tuple(
    uint32_t tile,
    const Fp3& address,
    const Fp3& value,
    const Fp3& gamma)
{
    const Fp3 gamma2 = gf::Mul(gamma, gamma);
    const Fp3 gamma3 = gf::Mul(gamma2, gamma);
    return gf::Add(
        U(NAMESPACE_ID),
        gf::Add(
            gf::Mul(gamma, U(tile)),
            gf::Add(
                gf::Mul(gamma2, address),
                gf::Mul(gamma3, value))));
}

struct SelectedLayout {
    uint32_t mask{0};
    uint32_t address{0};
    uint32_t inverse1{0};
    uint32_t inverse2{0};
    uint32_t running1{0};
    uint32_t running2{0};
};

bool AppendSelectedCtl(
    uint32_t source_column,
    uint32_t selected_begin,
    uint32_t selected_count,
    uint32_t tile,
    int8_t multiplicity,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal,
    AirCS& cs,
    std::vector<std::vector<Fp3>>* columns,
    SelectedLayout& layout,
    std::string* why)
{
    if (source_column >= cs.n_columns ||
        selected_count != kRCMxBlockLen ||
        selected_begin > cs.n_rows ||
        cs.n_rows - selected_begin < selected_count ||
        (multiplicity != 1 && multiplicity != -1)) {
        return Fail(why, "selected_shape");
    }
    layout.mask = cs.n_columns;
    layout.address = cs.n_columns + 1;
    layout.inverse1 = cs.n_columns + 2;
    layout.inverse2 = cs.n_columns + 3;
    layout.running1 = cs.n_columns + 4;
    layout.running2 = cs.n_columns + 5;
    cs.n_columns += 6;

    std::vector<Fp3> mask(
        cs.n_rows, Fp3::Zero());
    std::vector<Fp3> address(
        cs.n_rows, Fp3::Zero());
    for (uint32_t local = 0;
         local < selected_count; ++local) {
        mask[selected_begin + local] =
            Fp3::One();
        address[selected_begin + local] = U(local);
    }
    cs.preprocessed.emplace_back(layout.mask, mask);
    cs.preprocessed.emplace_back(layout.address, address);

    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t inverse =
            lane == 0
            ? layout.inverse1 : layout.inverse2;
        const uint32_t running =
            lane == 0
            ? layout.running1 : layout.running2;
        const Fp3 gamma =
            lane == 0
            ? challenges.gamma1 : challenges.gamma2;
        const Fp3 alpha =
            lane == 0
            ? challenges.alpha1 : challenges.alpha2;
        const Fp3 expected =
            lane == 0
            ? terminal.alpha1_sum : terminal.alpha2_sum;
        Add(
            cs, "stage3.extract_stream.mask_boolean",
            aq::AirKind::kEverywhere, 2,
            [=](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[layout.mask],
                    gf::Sub(
                        cur[layout.mask], Fp3::One()));
            });
        Add(
            cs, "stage3.extract_stream.inverse",
            aq::AirKind::kEverywhere, 2,
            [=](const auto& cur, const auto&) {
                return gf::Sub(
                    gf::Mul(
                        cur[inverse],
                        gf::Sub(
                            alpha,
                            Tuple(
                                tile,
                                cur[layout.address],
                                cur[source_column],
                                gamma))),
                    cur[layout.mask]);
            });
        Add(
            cs, "stage3.extract_stream.inverse_inactive",
            aq::AirKind::kEverywhere, 2,
            [=](const auto& cur, const auto&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(), cur[layout.mask]),
                    cur[inverse]);
            });
        Add(
            cs, "stage3.extract_stream.running_first",
            aq::AirKind::kFirstRow, 1,
            [running](const auto& cur, const auto&) {
                return cur[running];
            });
        Add(
            cs, "stage3.extract_stream.running_transition",
            aq::AirKind::kTransition, 2,
            [=](const auto& cur, const auto& next) {
                const Fp3 selected =
                    gf::Mul(
                        cur[layout.mask],
                        cur[inverse]);
                const Fp3 contribution =
                    multiplicity == 1
                    ? selected
                    : gf::Neg(selected);
                return gf::Sub(
                    next[running],
                    gf::Add(cur[running], contribution));
            });
        Add(
            cs, "stage3.extract_stream.running_last",
            aq::AirKind::kLastRow, 2,
            [=](const auto& cur, const auto&) {
                const Fp3 selected =
                    gf::Mul(
                        cur[layout.mask],
                        cur[inverse]);
                const Fp3 contribution =
                    multiplicity == 1
                    ? selected
                    : gf::Neg(selected);
                return gf::Sub(
                    gf::Add(cur[running], contribution),
                    expected);
            });
    }

    if (columns == nullptr) return true;
    columns->resize(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    (*columns)[layout.mask] = mask;
    (*columns)[layout.address] = address;
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        (*columns)[layout.running1][row] = running1;
        (*columns)[layout.running2][row] = running2;
        if (row < selected_begin ||
            row >= selected_begin + selected_count) {
            continue;
        }
        const Fp3 value =
            (*columns)[source_column][row];
        const Fp3 d1 = gf::Sub(
            challenges.alpha1,
            Tuple(
                tile, address[row], value,
                challenges.gamma1));
        const Fp3 d2 = gf::Sub(
            challenges.alpha2,
            Tuple(
                tile, address[row], value,
                challenges.gamma2));
        if (gf::IsZero(d1) || gf::IsZero(d2)) {
            return Fail(why, "selected_pole");
        }
        const Fp3 i1 = gf::Inv(d1);
        const Fp3 i2 = gf::Inv(d2);
        (*columns)[layout.inverse1][row] = i1;
        (*columns)[layout.inverse2][row] = i2;
        running1 = multiplicity == 1
            ? gf::Add(running1, i1)
            : gf::Sub(running1, i1);
        running2 = multiplicity == 1
            ? gf::Add(running2, i2)
            : gf::Sub(running2, i2);
    }
    if (!gf::Eq(running1, terminal.alpha1_sum) ||
        !gf::Eq(running2, terminal.alpha2_sum)) {
        return Fail(why, "selected_terminal");
    }
    return true;
}

bool CheckWitness(
    const AirCS& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const char* side,
    std::string* why)
{
    if (columns.size() != cs.n_columns) {
        return Fail(
            why, std::string{side} + "_witness_width");
    }
    std::vector<Fp3> cur(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    for (const auto& constraint : cs.constraints) {
        uint32_t begin = 0;
        uint32_t end = cs.n_rows;
        switch (constraint.kind) {
        case aq::AirKind::kFirstRow:
            end = 1;
            break;
        case aq::AirKind::kLastRow:
            begin = cs.n_rows - 1;
            break;
        case aq::AirKind::kTransition:
            end = cs.n_rows - 1;
            break;
        case aq::AirKind::kEverywhere:
            break;
        }
        for (uint32_t row = begin; row < end; ++row) {
            for (uint32_t column = 0;
                 column < cs.n_columns; ++column) {
                cur[column] = columns[column][row];
                next[column] = columns[column][
                    std::min(row + 1, cs.n_rows - 1)];
            }
            if (!gf::IsZero(
                    constraint.eval(cur, next))) {
                return Fail(
                    why, std::string{side} +
                        "_witness_" + constraint.name +
                        "_row_" + std::to_string(row) +
                        "_value_" +
                        std::to_string(gf::Canonical(
                            constraint.eval(cur, next).c0)) +
                        "_active_" +
                        std::to_string(gf::Canonical(cur[0].c0)) +
                        "_value_col_" +
                        std::to_string(gf::Canonical(cur[5].c0)) +
                        "_export_col_" +
                        std::to_string(gf::Canonical(cur[6].c0)));
            }
        }
    }
    return true;
}

RCStage3CtlTerminal Terminal(
    uint32_t tile,
    const std::array<Fp3, kRCMxBlockLen>& values,
    int8_t multiplicity,
    const RCStage3CtlChallenges& challenges,
    std::string* why)
{
    RCStage3CtlTerminal out;
    for (uint32_t row = 0;
         row < values.size(); ++row) {
        const Fp3 d1 = gf::Sub(
            challenges.alpha1,
            Tuple(
                tile, U(row), values[row],
                challenges.gamma1));
        const Fp3 d2 = gf::Sub(
            challenges.alpha2,
            Tuple(
                tile, U(row), values[row],
                challenges.gamma2));
        if (gf::IsZero(d1) || gf::IsZero(d2)) {
            Fail(why, "terminal_pole");
            return {};
        }
        const Fp3 i1 = gf::Inv(d1);
        const Fp3 i2 = gf::Inv(d2);
        out.alpha1_sum = multiplicity == 1
            ? gf::Add(out.alpha1_sum, i1)
            : gf::Sub(out.alpha1_sum, i1);
        out.alpha2_sum = multiplicity == 1
            ? gf::Add(out.alpha2_sum, i2)
            : gf::Sub(out.alpha2_sum, i2);
    }
    return out;
}

void HashPath(HashWriter& hash, const Fri3MerklePath& path)
{
    hash << path.index;
    hash << gf::Canonical(path.leaf.c0);
    hash << gf::Canonical(path.leaf.c1);
    hash << gf::Canonical(path.leaf.c2);
    hash << static_cast<uint32_t>(path.siblings.size());
    for (const auto& sibling : path.siblings) hash << sibling;
}

uint256 CommitProduct(
    const aq::AirQuotientProof<Fp3>& proof)
{
    std::vector<unsigned char> batch;
    if (SerializeFri3BatchProof(
            proof.batch, batch) == 0) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCT_DOMAIN;
    hash << batch;
    hash << proof.trace_commit;
    hash << static_cast<uint32_t>(
        proof.next_openings.size());
    for (const auto& query : proof.next_openings) {
        hash << static_cast<uint32_t>(query.size());
        for (const auto& path : query) {
            HashPath(hash, path);
        }
    }
    return hash.GetHash();
}

uint256 Transcript(
    const RCStage3ExtractStreamCtlTileProof& proof)
{
    HashWriter hash;
    hash << TRANSCRIPT_DOMAIN;
    hash << proof.version;
    hash << proof.global_stream_tile;
    hash << proof.extract_tile_ordinal;
    hash << proof.round_index;
    hash << proof.memory_shard_index;
    hash << proof.memory_row_begin;
    hash << proof.statement_commitment;
    hash << proof.extract_collection_commitment;
    hash << proof.tile_stream_collection_commitment;
    hash << proof.sampler_output_root;
    hash << proof.memory_value_root;
    return hash.GetHash();
}

uint256 ChildSeed(
    const char* side,
    const RCStage3ExtractStreamCtlTileProof& proof)
{
    if (proof.pins.size() != 2) return {};
    HashWriter hash;
    hash << CHILD_DOMAIN;
    hash << side;
    hash << Transcript(proof);
    hash << proof.pins[0].challenge_commitment;
    for (const auto& pin : proof.pins) {
        hash << pin.trace_commitment;
        hash << gf::Canonical(
            pin.terminal.alpha1_sum.c0);
        hash << gf::Canonical(
            pin.terminal.alpha1_sum.c1);
        hash << gf::Canonical(
            pin.terminal.alpha1_sum.c2);
        hash << gf::Canonical(
            pin.terminal.alpha2_sum.c0);
        hash << gf::Canonical(
            pin.terminal.alpha2_sum.c1);
        hash << gf::Canonical(
            pin.terminal.alpha2_sum.c2);
    }
    return hash.GetHash();
}

uint256 CommitTile(
    const RCStage3ExtractStreamCtlTileProof& proof)
{
    const uint256 composition =
        CommitRCStage3CtlComposition(
            proof.manifest, proof.pins);
    if (composition.IsNull() ||
        proof.producer_product_commitment.IsNull() ||
        proof.consumer_product_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << TILE_DOMAIN;
    hash << Transcript(proof);
    hash << composition;
    hash << proof.producer_product_commitment;
    hash << proof.consumer_product_commitment;
    return hash.GetHash();
}

struct Identity {
    const RCStage3EpisodeExtractTileProduct* extract_tile{nullptr};
    const RCStage3EpisodeTileStreamShard* stream_tile{nullptr};
    const RCStage3EpisodeSemanticMemoryShard* memory_shard{nullptr};
    uint32_t extract_tile_ordinal{0};
    uint32_t round_index{0};
    uint32_t memory_row_begin{0};
    std::array<Fp3, kRCMxBlockLen> values{};
};

bool ResolveIdentity(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    Identity& out,
    std::string* why)
{
    out = {};
    if (global_stream_tile >=
            tile_stream.tiles.size()) {
        return Fail(why, "identity_stream_tile");
    }
    out.stream_tile =
        &tile_stream.tiles[global_stream_tile];
    if (out.stream_tile->global_stream_tile !=
            global_stream_tile ||
        out.stream_tile->layer_ordinal >=
            manifest.layers.size()) {
        return Fail(why, "identity_stream_order");
    }
    const auto& layer =
        manifest.layers[out.stream_tile->layer_ordinal];
    out.round_index = layer.round;
    if (out.round_index >= tile_stream.rounds.size()) {
        return Fail(why, "identity_round");
    }
    for (uint32_t ordinal = 0;
         ordinal < extract.tiles.size(); ++ordinal) {
        const auto& candidate = extract.tiles[ordinal];
        if (candidate.layer_ordinal ==
                out.stream_tile->layer_ordinal &&
            candidate.layer_tile_index ==
                out.stream_tile->layer_tile_index) {
            if (out.extract_tile != nullptr) {
                return Fail(why, "identity_duplicate_extract");
            }
            out.extract_tile = &candidate;
            out.extract_tile_ordinal = ordinal;
        }
    }
    if (out.extract_tile == nullptr ||
        out.extract_tile->sampler_pin !=
            out.stream_tile->pin) {
        return Fail(why, "identity_extract_alias");
    }
    const uint64_t begin =
        out.stream_tile->stream_byte_begin;
    const auto& round =
        tile_stream.rounds[out.round_index];
    if (begin > round.tree.tree_manifest.stream.size() ||
        round.tree.tree_manifest.stream.size() - begin <
            kRCMxBlockLen) {
        return Fail(why, "identity_stream_interval");
    }
    for (const auto& shard :
         round.stream_memory.shards) {
        if (begin >= shard.value_begin &&
            begin + kRCMxBlockLen <=
                shard.value_begin +
                    shard.manifest.logical_rows) {
            if (out.memory_shard != nullptr) {
                return Fail(why, "identity_duplicate_memory");
            }
            out.memory_shard = &shard;
            out.memory_row_begin =
                static_cast<uint32_t>(
                    begin - shard.value_begin);
        }
    }
    if (out.memory_shard == nullptr) {
        return Fail(why, "identity_memory_interval");
    }
    for (uint32_t row = 0;
         row < kRCMxBlockLen; ++row) {
        const uint8_t byte =
            round.tree.tree_manifest.stream[begin + row];
        out.values[row] = Fp3::FromFp(
            gf::FromSigned(
                byte < 128
                    ? static_cast<int64_t>(byte)
                    : static_cast<int64_t>(byte) - 256));
    }
    return true;
}

bool BuildSampler(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const Identity& identity,
    AirCS& cs,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    const auto& tile = *identity.extract_tile;
    const auto& layer =
        manifest.layers[tile.layer_ordinal];
    const uint32_t blocks_per_row =
        layer.n / kRCMxBlockLen;
    if (blocks_per_row == 0 ||
        tile.layer_tile_index >=
            layer.extract_tile_count) {
        return Fail(why, "sampler_shape");
    }
    const uint32_t row =
        tile.layer_tile_index / blocks_per_row;
    const uint32_t block =
        tile.layer_tile_index % blocks_per_row;
    const ga::TilePublic tile_public{
        layer.bindings.extract_prf, row, block};
    const ga::TileWitness witness =
        ga::TraceTile(tile_public, tile.input);
    const ga::TableTM table;
    const uint256 seed =
        ComputeRCStage3EpisodeAirSeed(
            statement, tile.sampler_pin);
    const auto sampler =
        aq::BuildRcSamplerInstance<Fp3>(
            witness, table, seed);
    if (!sampler.ok ||
        sampler.n_rows !=
            tile.sampler_pin.n_rows ||
        sampler.columns.size() !=
            tile.sampler_pin.column_roots.size()) {
        return Fail(
            why, "sampler_rebuild:" + sampler.note);
    }
    // Epoch-2 LogUp columns are challenge-derived and are re-proved in this
    // augmented trace. Equality to the original child is required only for
    // the complete epoch-1 base bank, which includes kColOut.
    for (uint32_t column = 0;
         column < aq::kRcSamplerBaseCols; ++column) {
        if (tile.sampler_pin.column_roots[column].column !=
                column ||
            aq::AirCommittedValuesRoot<Fp3>(
                sampler.columns[column],
                tile.sampler_pin.n_coeffs) !=
                tile.sampler_pin.column_roots[column].root) {
            return Fail(
                why, "sampler_root_" +
                    std::to_string(column));
        }
    }
    cs = sampler.cs;
    columns = sampler.columns;
    return true;
}

bool BuildMemory(
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    const Identity& identity,
    AirCS& cs,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    const auto& round =
        tile_stream.rounds[identity.round_index];
    const auto& shard = *identity.memory_shard;
    std::vector<Fp3> values;
    values.reserve(shard.manifest.logical_rows);
    for (uint32_t row = 0;
         row < shard.manifest.logical_rows; ++row) {
        const uint8_t byte =
            round.tree.tree_manifest.stream[
                shard.value_begin + row];
        values.push_back(Fp3::FromFp(
            gf::FromSigned(
                byte < 128
                    ? static_cast<int64_t>(byte)
                    : static_cast<int64_t>(byte) - 256)));
    }
    if (!BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
            shard.manifest, cs, why) ||
        !BuildRCStage3EpisodeSemanticMemoryWitness(
            shard.manifest, values, columns, why)) {
        return false;
    }
    // The standalone semantic-memory proof commits at n_coeffs == n_rows, so it
    // pins the value column by root equality against manifest.canonical_value_root
    // (committed at n_rows). Inside the extract/stream CTL the memory constraint
    // system is augmented with kFirstRow/kLastRow running-sum boundary
    // constraints whose composed degree (~3(N-1)) forces the batch to commit at
    // n_coeffs == 2*n_rows, at which the n_rows-committed canonical_value_root no
    // longer equals the batch column root. BuildRCStage3EpisodeSemanticMemoryWitness
    // above has already bound `values` to canonical_value_root at n_rows, so it is
    // sound to re-express value/export as fully-known preprocessed columns:
    // AirQuotientVerify then re-derives their roots at whatever n_coeffs the
    // augmented batch uses, keeping the binding n_coeffs-consistent.
    std::erase_if(
        cs.preprocessed_roots,
        [](const auto& entry) {
            return entry.first == kRCStage3EpisodeMemoryValue;
        });
    cs.preprocessed.emplace_back(
        kRCStage3EpisodeMemoryValue,
        columns[kRCStage3EpisodeMemoryValue]);
    cs.preprocessed.emplace_back(
        kRCStage3EpisodeMemoryExport,
        columns[kRCStage3EpisodeMemoryExport]);
    return true;
}

void FillIdentity(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    const Identity& identity,
    uint32_t global_stream_tile,
    RCStage3ExtractStreamCtlTileProof& out)
{
    out = {};
    out.global_stream_tile = global_stream_tile;
    out.extract_tile_ordinal =
        identity.extract_tile_ordinal;
    out.round_index = identity.round_index;
    out.memory_shard_index =
        identity.memory_shard->shard_index;
    out.memory_row_begin =
        identity.memory_row_begin;
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.extract_collection_commitment =
        extract.collection_commitment;
    out.tile_stream_collection_commitment =
        tile_stream.collection_commitment;
    out.sampler_output_root =
        identity.extract_tile->sampler_pin
            .column_roots[aq::kColOut].root;
    out.memory_value_root =
        identity.memory_shard->manifest
            .canonical_value_root;
}

bool ProveTile(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    RCStage3ExtractStreamCtlTileProof& out,
    std::string* why)
{
    Identity identity;
    if (!ResolveIdentity(
            manifest, extract, tile_stream,
            global_stream_tile, identity, why)) {
        return false;
    }
    FillIdentity(
        statement, extract, tile_stream, identity,
        global_stream_tile, out);
    AirCS producer_cs;
    AirCS consumer_cs;
    std::vector<std::vector<Fp3>> producer_columns;
    std::vector<std::vector<Fp3>> consumer_columns;
    if (!BuildSampler(
            statement, manifest, identity,
            producer_cs, producer_columns, why) ||
        !BuildMemory(
            tile_stream, identity,
            consumer_cs, consumer_columns, why)) {
        return false;
    }
    out.manifest.bus_id =
        kRCStage3ExtractStreamCtlBusId;
    out.manifest.transcript_seed = Transcript(out);
    const auto send =
        Schedule(global_stream_tile, 1);
    const auto receive =
        Schedule(global_stream_tile, -1);
    out.manifest.participants = {
        Participant(
            RCStage3RelationRole::EpisodeExtract,
            send, true),
        Participant(
            RCStage3RelationRole::EpisodeTileTree,
            receive, false),
    };
    out.pins.resize(2);
    for (size_t i = 0; i < 2; ++i) {
        const auto& participant =
            out.manifest.participants[i];
        auto& pin = out.pins[i];
        pin.role = participant.role;
        pin.bus_id = out.manifest.bus_id;
        pin.event_count = participant.event_count;
        pin.send_count = participant.send_count;
        pin.receive_count = participant.receive_count;
        pin.schedule_commitment =
            participant.schedule_commitment;
    }
    out.pins[0].trace_commitment =
        out.sampler_output_root;
    out.pins[1].trace_commitment =
        out.memory_value_root;
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            out.manifest, out.pins,
            challenges, why)) {
        return false;
    }
    out.pins[0].terminal =
        Terminal(
            global_stream_tile, identity.values,
            1, challenges, why);
    out.pins[1].terminal =
        Terminal(
            global_stream_tile, identity.values,
            -1, challenges, why);
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    for (auto& pin : out.pins) {
        pin.challenge_commitment =
            challenge_commitment;
    }
    SelectedLayout producer_layout;
    SelectedLayout consumer_layout;
    if (!AppendSelectedCtl(
            aq::kColOut, 0, kRCMxBlockLen,
            global_stream_tile, 1, challenges,
            out.pins[0].terminal,
            producer_cs, &producer_columns,
            producer_layout, why) ||
        !AppendSelectedCtl(
            kRCStage3EpisodeMemoryExport,
            identity.memory_row_begin,
            kRCMxBlockLen, global_stream_tile,
            -1, challenges,
            out.pins[1].terminal,
            consumer_cs, &consumer_columns,
            consumer_layout, why)) {
        return false;
    }
    if (!CheckWitness(
            producer_cs, producer_columns,
            "producer", why) ||
        !CheckWitness(
            consumer_cs, consumer_columns,
            "consumer", why)) {
        return false;
    }
    const auto producer_proved =
        aq::AirQuotientProve<Fp3>(
            producer_cs, producer_columns,
            ChildSeed("producer", out));
    const auto consumer_proved =
        aq::AirQuotientProve<Fp3>(
            consumer_cs, consumer_columns,
            ChildSeed("consumer", out));
    if (!producer_proved.ok ||
        !producer_proved.division_exact ||
        !consumer_proved.ok ||
        !consumer_proved.division_exact) {
        return Fail(
            why, "prove:" +
                producer_proved.note + ";" +
                consumer_proved.note);
    }
    out.producer_product =
        producer_proved.proof;
    out.consumer_product =
        consumer_proved.proof;
    out.producer_product_commitment =
        CommitProduct(out.producer_product);
    out.consumer_product_commitment =
        CommitProduct(out.consumer_product);
    out.pins[0].auxiliary_commitment =
        out.producer_product_commitment;
    out.pins[1].auxiliary_commitment =
        out.consumer_product_commitment;
    if (!VerifyRCStage3CtlPublicPinComposition(
            out.manifest, out.pins, why)) {
        return false;
    }
    out.proof_commitment = CommitTile(out);
    return !out.proof_commitment.IsNull() ||
        Fail(why, "tile_commitment");
}

bool VerifyTile(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    const RCStage3ExtractStreamCtlTileProof& proof,
    std::string* why)
{
    Identity identity;
    if (!ResolveIdentity(
            manifest, extract, tile_stream,
            global_stream_tile, identity, why)) {
        return false;
    }
    RCStage3ExtractStreamCtlTileProof expected;
    FillIdentity(
        statement, extract, tile_stream, identity,
        global_stream_tile, expected);
    if (proof.version != expected.version ||
        proof.global_stream_tile !=
            expected.global_stream_tile ||
        proof.extract_tile_ordinal !=
            expected.extract_tile_ordinal ||
        proof.round_index != expected.round_index ||
        proof.memory_shard_index !=
            expected.memory_shard_index ||
        proof.memory_row_begin !=
            expected.memory_row_begin ||
        proof.statement_commitment !=
            expected.statement_commitment ||
        proof.extract_collection_commitment !=
            expected.extract_collection_commitment ||
        proof.tile_stream_collection_commitment !=
            expected.tile_stream_collection_commitment ||
        proof.sampler_output_root !=
            expected.sampler_output_root ||
        proof.memory_value_root !=
            expected.memory_value_root ||
        proof.pins.size() != 2) {
        return Fail(why, "verify_identity");
    }
    expected.manifest.bus_id =
        kRCStage3ExtractStreamCtlBusId;
    expected.manifest.transcript_seed =
        Transcript(expected);
    const auto send =
        Schedule(global_stream_tile, 1);
    const auto receive =
        Schedule(global_stream_tile, -1);
    expected.manifest.participants = {
        Participant(
            RCStage3RelationRole::EpisodeExtract,
            send, true),
        Participant(
            RCStage3RelationRole::EpisodeTileTree,
            receive, false),
    };
    if (proof.manifest != expected.manifest) {
        return Fail(why, "verify_manifest");
    }
    for (size_t i = 0; i < 2; ++i) {
        const auto& participant =
            expected.manifest.participants[i];
        const auto& pin = proof.pins[i];
        if (pin.role != participant.role ||
            pin.bus_id != expected.manifest.bus_id ||
            pin.event_count != participant.event_count ||
            pin.send_count != participant.send_count ||
            pin.receive_count != participant.receive_count ||
            pin.schedule_commitment !=
                participant.schedule_commitment ||
            pin.trace_commitment !=
                (i == 0
                     ? expected.sampler_output_root
                     : expected.memory_value_root)) {
            return Fail(why, "verify_pin");
        }
    }
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            proof.manifest, proof.pins,
            challenges, why)) {
        return false;
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    if (proof.pins[0].challenge_commitment !=
            challenge_commitment ||
        proof.pins[1].challenge_commitment !=
            challenge_commitment ||
        !(proof.pins[0].terminal ==
          Terminal(
              global_stream_tile, identity.values,
              1, challenges, why)) ||
        !(proof.pins[1].terminal ==
          Terminal(
              global_stream_tile, identity.values,
              -1, challenges, why))) {
        return Fail(why, "verify_terminal");
    }
    AirCS producer_cs;
    AirCS consumer_cs;
    std::vector<std::vector<Fp3>> ignored;
    std::vector<std::vector<Fp3>> consumer_columns;
    if (!BuildSampler(
            statement, manifest, identity,
            producer_cs, ignored, why) ||
        !BuildMemory(
            tile_stream, identity,
            consumer_cs, consumer_columns, why)) {
        return false;
    }
    if (consumer_columns.size() <=
            kRCStage3EpisodeMemoryExport) {
        return Fail(why, "verify_consumer_columns");
    }
    const std::vector<Fp3> consumer_export_values =
        consumer_columns[kRCStage3EpisodeMemoryExport];
    SelectedLayout producer_layout;
    SelectedLayout consumer_layout;
    if (!AppendSelectedCtl(
            aq::kColOut, 0, kRCMxBlockLen,
            global_stream_tile, 1, challenges,
            proof.pins[0].terminal,
            producer_cs, nullptr,
            producer_layout, why) ||
        !AppendSelectedCtl(
            kRCStage3EpisodeMemoryExport,
            identity.memory_row_begin,
            kRCMxBlockLen, global_stream_tile,
            -1, challenges,
            proof.pins[1].terminal,
            consumer_cs, nullptr,
            consumer_layout, why)) {
        return false;
    }
    const auto shape = [](
        const aq::AirQuotientProof<Fp3>& product,
        const AirCS& cs) {
        return product.batch.n_coeffs >= cs.n_rows &&
            product.batch.columns.size() ==
                static_cast<size_t>(cs.n_columns) + 1 &&
            product.batch.column_len.size() ==
                product.batch.columns.size();
    };
    // Producer (sampler) source root binds at the batch n_coeffs, which the
    // sampler pin already carries (the sampler's own quotient degree dominates
    // the appended selected-CTL boundary constraints, so the augmented batch
    // n_coeffs equals sampler_pin.n_coeffs). The consumer (semantic memory)
    // batch, by contrast, is small: the appended kFirstRow/kLastRow running-sum
    // boundary constraints raise its quotient degree to ~2N-2, so the augmented
    // batch commits the value/export columns at n_coeffs == 2*n_rows, whereas
    // manifest.canonical_value_root is committed at n_coeffs == n_rows (its
    // documented definition and the standalone semantic-memory proof's fixed
    // shape). The two roots therefore never coincide. BuildMemory already binds
    // the reconstructed memory values to canonical_value_root at n_rows and
    // (below) re-registers value/export as fully-known preprocessed columns, so
    // AirQuotientVerify re-pins them at the correct augmented n_coeffs. The
    // remaining source-root gate re-derives the expected export root at the
    // consumer batch's own n_coeffs from those same bound values.
    const uint256 consumer_export_root =
        aq::AirCommittedValuesRoot<Fp3>(
            consumer_export_values,
            proof.consumer_product.batch.n_coeffs);
    if (!shape(proof.producer_product, producer_cs) ||
        !shape(proof.consumer_product, consumer_cs) ||
        proof.producer_product.batch.columns[
            aq::kColOut].root !=
            expected.sampler_output_root ||
        proof.consumer_product.batch.columns[
            kRCStage3EpisodeMemoryExport].root !=
            consumer_export_root) {
        return Fail(
            why, "verify_source_root_producer_n_" +
                std::to_string(
                    proof.producer_product.batch.n_coeffs) +
                "_sampler_n_" +
                std::to_string(
                    identity.extract_tile->sampler_pin.n_coeffs) +
                "_consumer_n_" +
                std::to_string(
                    proof.consumer_product.batch.n_coeffs));
    }
    expected.pins = proof.pins;
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            producer_cs, proof.producer_product,
            ChildSeed("producer", expected), &air_why) ||
        !aq::AirQuotientVerify<Fp3>(
            consumer_cs, proof.consumer_product,
            ChildSeed("consumer", expected), &air_why)) {
        return Fail(why, "verify_air:" + air_why);
    }
    const uint256 producer_commitment =
        CommitProduct(proof.producer_product);
    const uint256 consumer_commitment =
        CommitProduct(proof.consumer_product);
    if (producer_commitment.IsNull() ||
        consumer_commitment.IsNull() ||
        proof.producer_product_commitment !=
            producer_commitment ||
        proof.consumer_product_commitment !=
            consumer_commitment ||
        proof.pins[0].auxiliary_commitment !=
            producer_commitment ||
        proof.pins[1].auxiliary_commitment !=
            consumer_commitment ||
        proof.proof_commitment != CommitTile(proof) ||
        !VerifyRCStage3CtlPublicPinComposition(
            proof.manifest, proof.pins, why)) {
        return Fail(why, "verify_commitment");
    }
    return true;
}

uint256 CommitCollection(
    const RCStage3ExtractStreamCtlProof& proof)
{
    if (proof.version !=
            kRCStage3ExtractStreamCtlVersion ||
        proof.statement_commitment.IsNull() ||
        proof.extract_collection_commitment.IsNull() ||
        proof.tile_stream_collection_commitment.IsNull() ||
        proof.tiles.empty()) {
        return {};
    }
    HashWriter hash;
    hash << COLLECTION_DOMAIN;
    hash << proof.version;
    hash << proof.statement_commitment;
    hash << proof.extract_collection_commitment;
    hash << proof.tile_stream_collection_commitment;
    hash << static_cast<uint32_t>(
        proof.tiles.size());
    for (const auto& tile : proof.tiles) {
        if (tile.proof_commitment.IsNull()) return {};
        hash << tile.proof_commitment;
    }
    return hash.GetHash();
}

} // namespace

aq::AirConstraintSystem<Fp3>
BuildRCStage3ExtractStreamSelectedCtlConstraintSystem(
    uint32_t base_columns,
    uint32_t n_rows,
    uint32_t source_column,
    uint32_t tile,
    int8_t multiplicity,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal)
{
    AirCS cs;
    cs.n_rows = n_rows;
    cs.n_columns = base_columns;
    SelectedLayout layout;
    if (!AppendSelectedCtl(
            source_column, /*selected_begin=*/0, kRCMxBlockLen,
            tile, multiplicity, challenges, terminal, cs,
            /*columns=*/nullptr, layout, nullptr)) {
        return AirCS{};
    }
    return cs;
}

bool ProveRCStage3ExtractStreamCtlTile(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    RCStage3ExtractStreamCtlTileProof& out,
    std::string* why)
{
    return ProveTile(
        statement, manifest, extract, tile_stream,
        global_stream_tile, out, why);
}

bool VerifyRCStage3ExtractStreamCtlTile(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    const RCStage3ExtractStreamCtlTileProof& proof,
    std::string* why)
{
    return VerifyTile(
        statement, manifest, extract, tile_stream,
        global_stream_tile, proof, why);
}

bool ProveRCStage3ExtractStreamCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    RCStage3ExtractStreamCtlProof& out,
    std::string* why)
{
    out = {};
    if (!VerifyRCStage3EpisodeExtractProduct(
            statement, manifest, extract,
            tile_stream, why)) {
        return Fail(why, "prove_sources");
    }
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.extract_collection_commitment =
        extract.collection_commitment;
    out.tile_stream_collection_commitment =
        tile_stream.collection_commitment;
    out.tiles.reserve(tile_stream.tiles.size());
    for (uint32_t tile = 0;
         tile < tile_stream.tiles.size(); ++tile) {
        RCStage3ExtractStreamCtlTileProof child;
        if (!ProveTile(
                statement, manifest, extract,
                tile_stream, tile, child, why)) {
            return false;
        }
        out.tiles.push_back(std::move(child));
    }
    out.collection_commitment =
        CommitCollection(out);
    return !out.collection_commitment.IsNull() ||
        Fail(why, "prove_collection");
}

bool VerifyRCStage3ExtractStreamCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    const RCStage3ExtractStreamCtlProof& proof,
    std::string* why)
{
    if (proof.version !=
            kRCStage3ExtractStreamCtlVersion ||
        proof.statement_commitment !=
            RCStage3EpisodeStatementCommitment(statement) ||
        proof.extract_collection_commitment !=
            extract.collection_commitment ||
        proof.tile_stream_collection_commitment !=
            tile_stream.collection_commitment ||
        proof.tiles.size() !=
            tile_stream.tiles.size() ||
        !VerifyRCStage3EpisodeExtractProduct(
            statement, manifest, extract,
            tile_stream, why)) {
        return Fail(why, "verify_sources");
    }
    for (uint32_t tile = 0;
         tile < proof.tiles.size(); ++tile) {
        if (!VerifyTile(
                statement, manifest, extract,
                tile_stream, tile,
                proof.tiles[tile], why)) {
            return false;
        }
    }
    if (proof.collection_commitment !=
            CommitCollection(proof)) {
        return Fail(why, "verify_collection");
    }
    return true;
}

} // namespace matmul::v4::rc
