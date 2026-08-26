// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v5_v6_bus.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <numeric>
#include <optional>
#include <tuple>
#include <utility>

namespace matmul::v4::rc::stage3_v5_v6_bus {
namespace {

namespace gf = gkr_field;
namespace ha = stage3_hash_air;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) *why = "stage3:v5_v6_bus:" + detail;
    return false;
}

uint64_t MicrosSince(const std::chrono::steady_clock::time_point& start)
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start)
            .count());
}

bool SameLaneShape(const ar::ChildPublicInputs& a,
                   const ar::ChildPublicInputs& b)
{
    return a.ok && b.ok &&
           a.child_n_rows == b.child_n_rows &&
           a.child_w == b.child_w &&
           a.child_quotient_len == b.child_quotient_len &&
           a.child_n_coeffs == b.child_n_coeffs &&
           a.child_n_lde == b.child_n_lde &&
           a.merkle_depth == b.merkle_depth &&
           a.n_folds == b.n_folds &&
           a.fold_roots.size() == a.n_folds &&
           b.fold_roots.size() == b.n_folds &&
           a.evals_z1.size() == a.child_w + 1 &&
           a.evals_z2.size() == a.child_w + 1 &&
           b.evals_z1.size() == b.child_w + 1 &&
           b.evals_z2.size() == b.child_w + 1 &&
           !a.query_index.empty() &&
           a.query_index.size() == b.query_index.size();
}

v6::MasterBindingInput MasterInput(
    const std::vector<ar::ChildPublicInputs>& lane_pis,
    const std::array<uint8_t, 32>& public_statement_sha256d)
{
    v6::MasterBindingInput master;
    master.public_statement_sha256d = public_statement_sha256d;
    master.batch_columns = lane_pis[0].child_w + 1;
    master.n_coeffs = lane_pis[0].child_n_coeffs;
    master.n_lde = lane_pis[0].child_n_lde;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        master.ordered_lane_row_roots[lane] =
            lane_pis[lane].row_commit_root;
    }
    return master;
}

bool BuildFullInput(
    const std::vector<ar::ChildPublicInputs>& lane_pis,
    const std::array<uint8_t, 32>& public_statement_sha256d,
    v6::FullTranscriptInput& input,
    std::string* why)
{
    if (lane_pis.size() != 2 ||
        !SameLaneShape(lane_pis[0], lane_pis[1])) {
        return Fail(why, "ordered_lane_shape");
    }
    input.master = MasterInput(
        lane_pis, public_statement_sha256d);
    input.folds = lane_pis[0].n_folds;
    input.queries =
        static_cast<uint32_t>(lane_pis[0].query_index.size());
    if (input.folds == 0 || input.queries == 0) {
        return Fail(why, "empty_fold_or_query_schedule");
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const ar::ChildPublicInputs& pi = lane_pis[lane];
        v6::LaneProofInput& dst = input.lane[lane];
        dst.trace_root = pi.rt_root;
        dst.row_root = pi.row_commit_root;
        dst.evals_z1 = pi.evals_z1;
        dst.evals_z2 = pi.evals_z2;
        dst.fold_roots = pi.fold_roots;
    }
    return true;
}

bool ValidateNormalizedForLift(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>* columns,
    uint32_t target_rows,
    std::string* why)
{
    if (cs.n_rows < 2 || cs.n_columns == 0 ||
        target_rows < cs.n_rows ||
        (target_rows & (target_rows - 1)) != 0) {
        return Fail(why, "lift_shape");
    }
    for (const auto& constraint : cs.constraints) {
        // The wide V_CS deliberately evaluates every child query
        // independently. Repetition would not preserve a genuine outer
        // transition/first/last rule, so fail closed if that invariant ever
        // changes.
        if (constraint.kind != aq::AirKind::kEverywhere) {
            return Fail(why, "non_row_local_v5_constraint");
        }
    }
    for (const auto& [column, values] : cs.preprocessed) {
        if (column >= cs.n_columns || values.size() != cs.n_rows) {
            return Fail(why, "v5_preprocessed_shape");
        }
    }
    if (columns != nullptr) {
        if (columns->size() != cs.n_columns) {
            return Fail(why, "v5_witness_width");
        }
        for (const auto& column : *columns) {
            if (column.size() != cs.n_rows) {
                return Fail(why, "v5_witness_rows");
            }
        }
    }
    return true;
}

bool LiftAndPublish(
    const aq::AirConstraintSystem<Fp3>& base,
    const std::vector<std::vector<Fp3>>* base_columns,
    const v6::Program& program,
    const std::vector<ar::VerifierAirTranscriptOutput>& outputs,
    aq::AirConstraintSystem<Fp3>& out,
    std::vector<std::vector<Fp3>>* out_columns,
    uint32_t& export_base,
    uint32_t& selector_base,
    std::vector<PayloadMapping>* mappings,
    std::string* why)
{
    const uint32_t target_rows =
        std::max(base.n_rows, program.trace_rows);
    if (!ValidateNormalizedForLift(
            base, base_columns, target_rows, why)) {
        return false;
    }
    if (target_rows != program.trace_rows) {
        return Fail(why, "program_not_aligned");
    }
    std::vector<v6::PayloadCell> proof_cells;
    std::copy_if(
        program.payload_cells.begin(), program.payload_cells.end(),
        std::back_inserter(proof_cells),
        [](const v6::PayloadCell& cell) {
            return cell.origin == v6::WordOrigin::ProofDerived;
        });
    if (proof_cells.size() != outputs.size() ||
        proof_cells.empty()) {
        return Fail(
            why,
            "proof_payload_output_inventory_mismatch");
    }
    if (base.n_columns >
        std::numeric_limits<uint32_t>::max() -
            v6::kRate - proof_cells.size()) {
        return Fail(why, "column_overflow");
    }

    out = base;
    out.n_rows = target_rows;
    export_base = base.n_columns;
    selector_base = export_base + v6::kRate;
    out.n_columns =
        selector_base +
        static_cast<uint32_t>(proof_cells.size());
    out.preprocessed_pin_ood = true;

    for (auto& [column, values] : out.preprocessed) {
        const std::vector<Fp3> original = values;
        values.resize(target_rows);
        for (uint32_t row = 0; row < target_rows; ++row) {
            values[row] = original[row % base.n_rows];
        }
    }

    std::vector<std::vector<Fp3>> selectors(
        proof_cells.size());
    if (mappings != nullptr) {
        mappings->clear();
        mappings->reserve(proof_cells.size());
    }
    for (uint32_t index = 0;
         index < outputs.size(); ++index) {
        const v6::PayloadCell& cell = proof_cells[index];
        if (cell.trace_row >= target_rows ||
            cell.rate_lane >= v6::kRate) {
            return Fail(why, "row_root_payload_location");
        }
        selectors[index].assign(target_rows, Fp3::Zero());
        selectors[index][cell.trace_row] = Fp3::One();
        out.preprocessed.emplace_back(
            selector_base + index, selectors[index]);
        out.constraints.push_back(
            ar::BuildVerifierAIRTranscriptExportConstraint(
                outputs[index],
                export_base + cell.rate_lane,
                selector_base + index));
        if (mappings != nullptr) {
            mappings->push_back({
                cell,
                outputs[index],
                export_base + cell.rate_lane,
                selector_base + index,
                true,
                outputs[index].equation_consumer != nullptr,
                true});
        }
    }

    if (out_columns == nullptr) return true;
    out_columns->assign(
        out.n_columns,
        std::vector<Fp3>(target_rows, Fp3::Zero()));
    for (uint32_t column = 0; column < base.n_columns; ++column) {
        for (uint32_t row = 0; row < target_rows; ++row) {
            (*out_columns)[column][row] =
                (*base_columns)[column][row % base.n_rows];
        }
    }
    for (const auto& [column, values] : out.preprocessed) {
        (*out_columns)[column] = values;
    }
    std::vector<Fp3> row(base.n_columns);
    for (uint32_t index = 0;
         index < outputs.size(); ++index) {
        const v6::PayloadCell& cell = proof_cells[index];
        for (uint32_t column = 0;
             column < base.n_columns; ++column) {
            row[column] =
                (*out_columns)[column][cell.trace_row];
        }
        (*out_columns)[export_base + cell.rate_lane]
                      [cell.trace_row] =
            ar::EvaluateVerifierAIRTranscriptOutput(
                outputs[index], row);
    }
    return true;
}

uint32_t ProofDerivedCells(const v6::Program& program)
{
    return static_cast<uint32_t>(std::count_if(
        program.payload_cells.begin(), program.payload_cells.end(),
        [](const v6::PayloadCell& cell) {
            return cell.origin == v6::WordOrigin::ProofDerived;
        }));
}

bool FindFrameEndRow(
    const v6::Program& program,
    uint32_t frame,
    uint32_t& row_out)
{
    for (uint32_t row = 0; row < program.rows.size(); ++row) {
        if (program.rows[row].active &&
            program.rows[row].frame == frame &&
            program.rows[row].end) {
            row_out = row;
            return true;
        }
    }
    return false;
}

Fp Fp3Coordinate(const Fp3& value, uint32_t coordinate)
{
    if (coordinate == 0) return gf::Canonical(value.c0);
    if (coordinate == 1) return gf::Canonical(value.c1);
    if (coordinate == 2) return gf::Canonical(value.c2);
    return 0;
}

std::optional<V5EquationConsumer> ParseV5Consumer(
    const char* consumer)
{
    if (consumer == nullptr) return std::nullopt;
    if (std::strcmp(
            consumer, "vcs.per_point.identity") == 0) {
        return V5EquationConsumer::PerPointIdentity;
    }
    if (std::strcmp(consumer, "vcs.deep.identity") == 0) {
        return V5EquationConsumer::DeepIdentity;
    }
    if (std::strcmp(
            consumer,
            "vcs.deep.denominator_and_evaluation") == 0) {
        return V5EquationConsumer::
            DeepDenominatorAndEvaluation;
    }
    if (std::strcmp(consumer, "vcs.fold.relation") == 0) {
        return V5EquationConsumer::FoldRelation;
    }
    if (std::strcmp(
            consumer,
            "vcs.query.preprocessed_schedule") == 0) {
        return V5EquationConsumer::QueryPreprocessedSchedule;
    }
    return std::nullopt;
}

std::optional<V5EquationConsumer> ExpectedConsumerForFamily(
    ChallengeFeedbackFamily family)
{
    switch (family) {
    case ChallengeFeedbackFamily::AirQuotient:
        return V5EquationConsumer::PerPointIdentity;
    case ChallengeFeedbackFamily::BatchCoefficient:
    case ChallengeFeedbackFamily::DeepWeight:
        return V5EquationConsumer::DeepIdentity;
    case ChallengeFeedbackFamily::OodPoint:
        return V5EquationConsumer::
            DeepDenominatorAndEvaluation;
    case ChallengeFeedbackFamily::FoldChallenge:
        return V5EquationConsumer::FoldRelation;
    case ChallengeFeedbackFamily::QueryIndex:
        return V5EquationConsumer::QueryPreprocessedSchedule;
    }
    return std::nullopt;
}

std::optional<Fp> ExpectedV5ConsumerValue(
    const ChallengeFeedbackCell& cell,
    const std::vector<ar::ChildPublicInputs>& lane_pis)
{
    if (cell.lane >= lane_pis.size()) return std::nullopt;
    const auto& pi = lane_pis[cell.lane];
    if (cell.family == ChallengeFeedbackFamily::QueryIndex) {
        if (cell.coordinate != 0 ||
            cell.item_index >= pi.query_index.size()) {
            return std::nullopt;
        }
        return gf::FromU64(pi.query_index[cell.item_index]);
    }
    if (cell.coordinate >= 3) return std::nullopt;
    const Fp3* value = nullptr;
    switch (cell.family) {
    case ChallengeFeedbackFamily::AirQuotient:
        if (cell.item_index != 0) return std::nullopt;
        value = &pi.air_lambda;
        break;
    case ChallengeFeedbackFamily::BatchCoefficient:
        if (cell.item_index >=
            pi.fri_batch_coefficients.size()) {
            return std::nullopt;
        }
        value = &pi.fri_batch_coefficients[cell.item_index];
        break;
    case ChallengeFeedbackFamily::OodPoint:
        if (cell.item_index >= 2) return std::nullopt;
        value = cell.item_index == 0 ? &pi.z1 : &pi.z2;
        break;
    case ChallengeFeedbackFamily::DeepWeight:
        if (cell.item_index >= 2) return std::nullopt;
        value = cell.item_index == 0 ? &pi.w1 : &pi.w2;
        break;
    case ChallengeFeedbackFamily::FoldChallenge:
        if (cell.item_index >= pi.fold_challenges.size()) {
            return std::nullopt;
        }
        value = &pi.fold_challenges[cell.item_index];
        break;
    case ChallengeFeedbackFamily::QueryIndex:
        return std::nullopt;
    }
    return Fp3Coordinate(*value, cell.coordinate);
}

uint256 CommitNormalizedFeedbackScheduleV1(
    const std::vector<NormalizedChallengeFeedbackCellV1>& cells)
{
    if (cells.size() != kV5SemanticConsumerCells) return {};
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V6_V5_NORMALIZED_FEEDBACK_SCHEDULE_V1";
    hash << static_cast<uint32_t>(cells.size());
    for (uint32_t ordinal = 0;
         ordinal < cells.size(); ++ordinal) {
        const auto& cell = cells[ordinal];
        if (cell.ordinal != ordinal ||
            cell.lane >= 2 ||
            cell.coordinate >= 3) {
            return {};
        }
        hash << cell.ordinal;
        hash << static_cast<uint8_t>(cell.family);
        hash << cell.lane;
        hash << cell.item_index;
        hash << cell.coordinate;
        hash << cell.consumer;
        hash << cell.v6_trace_row;
        hash << cell.v6_source_column;
        hash << cell.v6_output_lane;
    }
    return hash.GetHash();
}

uint256 CommitNormalizedFeedbackValuesV1(
    const char* domain,
    const std::vector<NormalizedChallengeFeedbackCellV1>& cells,
    bool v6_values)
{
    if (cells.size() != kV5SemanticConsumerCells) return {};
    HashWriter hash;
    hash << domain;
    hash << static_cast<uint32_t>(cells.size());
    for (uint32_t ordinal = 0;
         ordinal < cells.size(); ++ordinal) {
        if (cells[ordinal].ordinal != ordinal) return {};
        hash << ordinal;
        hash << gf::Canonical(
            v6_values
                ? cells[ordinal].v6_output_value
                : cells[ordinal].v5_public_input);
    }
    return hash.GetHash();
}

uint256 CommitNormalizedFeedbackReceiptV1(
    const uint256& schedule,
    const uint256& v6_values,
    const uint256& v5_values)
{
    if (schedule.IsNull() ||
        v6_values.IsNull() ||
        v5_values.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V6_V5_NORMALIZED_FEEDBACK_RECEIPT_V1";
    hash << uint16_t{1};
    hash << schedule;
    hash << v6_values;
    hash << v5_values;
    hash << kV5SemanticConsumerCells;
    hash << kV5SemanticConsumerRows;
    hash << kNormalizedFeedbackColumns;
    return hash.GetHash();
}

uint256 CommitV5SemanticBoundary(
    const std::vector<V5SemanticConsumerCell>& cells)
{
    if (cells.size() != kV5SemanticConsumerCells) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_V5_SHA_SEMANTIC_BOUNDARY_V1";
    hash << static_cast<uint32_t>(cells.size());
    for (uint32_t row = 0; row < cells.size(); ++row) {
        const auto& cell = cells[row];
        if (cell.semantic_row != row ||
            cell.direct_v6_challenge_feedback) {
            return {};
        }
        hash << cell.semantic_row;
        hash << static_cast<uint8_t>(cell.family);
        hash << cell.lane << cell.item_index << cell.coordinate;
        hash << static_cast<uint8_t>(cell.consumer);
        hash << cell.algebraic_v6_trace_row;
        hash << cell.algebraic_v6_source_column;
        hash << cell.algebraic_v6_output_lane;
        hash << gf::Canonical(cell.expected_v5_value);
    }
    return hash.GetHash();
}

uint256 V5SemanticAirSeed(const uint256& boundary)
{
    if (boundary.IsNull()) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_V5_SHA_SEMANTIC_AIR_V1";
    hash << boundary;
    return hash.GetHash();
}

std::vector<ar::VerifierAirTranscriptOutput>
DescribeOutputs(
    const std::vector<ar::ChildPublicInputs>& lane_pis,
    TranscriptScope scope,
    const ar::VerifierAirFamilies& families)
{
    if (scope == TranscriptScope::FullTranscript) {
        return ar::DescribeVerifierAIRFullTranscriptOutputs(
            lane_pis, families);
    }
    std::vector<ar::VerifierAirTranscriptOutput> out;
    const auto roots =
        ar::DescribeVerifierAIRRowRootOutputs(
            lane_pis, families);
    out.reserve(roots.size());
    for (const auto& root : roots) {
        out.push_back({
            ar::VerifierAirTranscriptOutputKind::RowRoot,
            root.child_index, root.digest_limb, 0,
            root.terminal_permutation_base,
            "vcs.row.root.pin"});
    }
    return out;
}

v6::Program BuildCommittedFeedbackProgram(
    const V5SemanticMaterialization& semantic)
{
    if (!semantic.valid ||
        semantic.cells.size() != kV5SemanticConsumerCells ||
        semantic.public_boundary_commitment.IsNull()) {
        return {};
    }

    // The first frame binds the exact typed/value inventory reconstructed by
    // the verifier.  Subsequent frames carry one semantic item each.  Family,
    // lane, item, coordinate count and equation consumer are fixed words;
    // only the already-SHA-derived consumer values are proof words.
    v6::Frame master;
    master.kind = v6::FrameKind::MasterStatement;
    master.lane = 0;
    master.index = 0;
    master.payload.reserve(34);
    for (const unsigned char byte :
         semantic.public_boundary_commitment) {
        master.payload.push_back(
            {gf::FromU64(byte), v6::WordOrigin::PublicStatement});
    }
    master.payload.push_back({
        gf::FromU64(kV5SemanticConsumerCells),
        v6::WordOrigin::PublicStatement});
    master.payload.push_back({
        gf::FromU64(1), v6::WordOrigin::PublicStatement});

    std::vector<v6::Frame> frames;
    frames.reserve(1 + semantic.cells.size());
    frames.push_back(std::move(master));
    uint32_t group = 0;
    for (uint32_t first = 0;
         first < semantic.cells.size();) {
        const auto& head = semantic.cells[first];
        uint32_t end = first + 1;
        while (end < semantic.cells.size() &&
               semantic.cells[end].family == head.family &&
               semantic.cells[end].lane == head.lane &&
               semantic.cells[end].item_index == head.item_index &&
               semantic.cells[end].consumer == head.consumer) {
            ++end;
        }
        if (end - first == 0 || end - first > 3) return {};

        v6::Frame frame;
        frame.kind = v6::FrameKind::AbsorbEvaluation;
        frame.lane = static_cast<uint16_t>(head.lane);
        frame.index = group++;
        frame.payload.reserve(5 + end - first);
        frame.payload.push_back({
            gf::FromU64(static_cast<uint8_t>(head.family)),
            v6::WordOrigin::Fixed});
        frame.payload.push_back({
            gf::FromU64(head.lane), v6::WordOrigin::Fixed});
        frame.payload.push_back({
            gf::FromU64(head.item_index), v6::WordOrigin::Fixed});
        frame.payload.push_back({
            gf::FromU64(end - first), v6::WordOrigin::Fixed});
        frame.payload.push_back({
            gf::FromU64(static_cast<uint8_t>(head.consumer)),
            v6::WordOrigin::Fixed});
        for (uint32_t index = first; index < end; ++index) {
            if (semantic.cells[index].coordinate != index - first) {
                return {};
            }
            frame.payload.push_back({
                semantic.cells[index].expected_v5_value,
                v6::WordOrigin::ProofDerived});
        }
        frames.push_back(std::move(frame));
        first = end;
    }
    return v6::BuildProgram(frames);
}

uint256 V5CommittedFeedbackAirSeed(const uint256& boundary,
                                   const v6::Program& program)
{
    if (boundary.IsNull() || !program.valid) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_V5_V6_COMMITTED_FEEDBACK_AIR_V1";
    hash << boundary;
    hash << program.active_rows;
    hash << program.trace_rows;
    hash << static_cast<uint32_t>(program.frames.size());
    hash << static_cast<uint32_t>(program.payload_cells.size());
    return hash.GetHash();
}

void AppendLE32Feedback(std::vector<uint8_t>& out, uint32_t value)
{
    for (uint32_t byte = 0; byte < 4; ++byte) {
        out.push_back(
            static_cast<uint8_t>(value >> (8 * byte)));
    }
}

std::vector<uint8_t> AirLambdaPreimage(
    const ar::ChildPublicInputs& pi,
    const uint256& child_fs_seed)
{
    static constexpr char kTag[] = "BTX_RC_AIRQ_V1";
    static constexpr char kLabel[] = "airq_lambda";
    std::vector<uint8_t> out;
    out.insert(
        out.end(),
        reinterpret_cast<const uint8_t*>(kTag),
        reinterpret_cast<const uint8_t*>(kTag) +
            sizeof(kTag) - 1);
    out.insert(
        out.end(), child_fs_seed.begin(), child_fs_seed.end());
    AppendLE32Feedback(out, sizeof(kLabel) - 1);
    out.insert(
        out.end(),
        reinterpret_cast<const uint8_t*>(kLabel),
        reinterpret_cast<const uint8_t*>(kLabel) +
            sizeof(kLabel) - 1);
    AppendLE32Feedback(out, 1);
    const uint256 trace_root =
        Fri3AlgDigestToUint256(pi.rt_root);
    out.insert(
        out.end(), trace_root.begin(), trace_root.end());
    AppendLE32Feedback(out, 3);
    AppendLE32Feedback(out, pi.child_n_rows);
    AppendLE32Feedback(out, pi.child_quotient_len);
    AppendLE32Feedback(out, pi.child_w);
    return out;
}

struct AirLambdaShaPrefix {
    bool valid{false};
    std::string note;
    uint32_t real_compression_blocks{0};
    std::array<uint32_t, 8> digest_words{};
    ha::FixedProgramPackedProvenanceInstance packed;
};

AirLambdaShaPrefix BuildAirLambdaShaPrefix(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed)
{
    AirLambdaShaPrefix out;
    if (!composition.valid ||
        composition.lane_pis.size() != 2 ||
        child_fs_seed.IsNull() ||
        !gf::Eq(
            composition.lane_pis[0].air_lambda,
            composition.lane_pis[1].air_lambda)) {
        out.note = "air_lambda_sha:shape";
        return out;
    }
    const auto& pi = composition.lane_pis[0];
    const std::vector<uint8_t> preimage =
        AirLambdaPreimage(pi, child_fs_seed);
    const uint256 native_digest = aq::AirChallengeDigest(
        child_fs_seed, "airq_lambda",
        {Fri3AlgDigestToUint256(pi.rt_root)},
        {pi.child_n_rows, pi.child_quotient_len, pi.child_w});
    if (!gf::Eq(
            pi.air_lambda,
            gf::FromChallengeBytes3(native_digest.begin()))) {
        out.note = "air_lambda_sha:native_value";
        return out;
    }

    ha::ShaManifest manifest;
    std::string why;
    if (!ha::BuildShaManifest(
            preimage, ha::ShaMode::Double, manifest, &why)) {
        out.note = "air_lambda_sha:manifest:" + why;
        return out;
    }
    const uint256 manifest_digest{
        Span<const unsigned char>{
            manifest.digest.data(), manifest.digest.size()}};
    if (manifest_digest != native_digest) {
        out.note = "air_lambda_sha:digest_mismatch";
        return out;
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildShaManifestBoundaryInstances(
            manifest, boundaries, &why) ||
        boundaries.empty() ||
        boundaries.size() > ha::kFixedProgramPackedLanes) {
        out.note = "air_lambda_sha:boundaries:" + why;
        return out;
    }
    out.real_compression_blocks =
        static_cast<uint32_t>(boundaries.size());
    std::copy_n(
        boundaries.back().final_words.begin(),
        out.digest_words.size(), out.digest_words.begin());

    const ha::FixedProgram program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    std::array<ha::ProgramWitness,
               ha::kFixedProgramPackedLanes> witnesses;
    std::array<ha::FixedProgramPackedBoundaryInstance,
               ha::kFixedProgramPackedLanes> instances;
    for (uint32_t lane = 0;
         lane < ha::kFixedProgramPackedLanes; ++lane) {
        const auto& boundary =
            boundaries[std::min<size_t>(
                lane, boundaries.size() - 1)];
        instances[lane].ctl_namespace_id =
            UINT32_C(0x46534140) + lane;
        instances[lane].external_values =
            boundary.external_values;
        instances[lane].final_words =
            boundary.final_words;
        if (!ha::BuildProgramWitness(
                program, instances[lane].external_values,
                witnesses[lane], &why) ||
            witnesses[lane].final_words !=
                instances[lane].final_words) {
            out.note = "air_lambda_sha:witness:" + why;
            return out;
        }
    }
    HashWriter prefix_seed;
    prefix_seed <<
        "BTX_RC_STAGE3_V5_AIR_LAMBDA_SHA_PACKED_V1";
    prefix_seed << child_fs_seed;
    prefix_seed << manifest.commitment;
    out.packed =
        ha::BuildFixedProgramPackedProvenanceInstance(
            program, witnesses, instances,
            prefix_seed.GetHash());
    if (!out.packed.valid) {
        out.note =
            "air_lambda_sha:packed:" + out.packed.note;
        return out;
    }
    out.valid = true;
    out.note = "air_lambda_sha:packed_provenance_ok";
    return out;
}

void AppendLE64Feedback(std::vector<uint8_t>& out, uint64_t value)
{
    for (uint32_t byte = 0; byte < 8; ++byte) {
        out.push_back(
            static_cast<uint8_t>(value >> (8 * byte)));
    }
}

void AppendFp3Feedback(std::vector<uint8_t>& out, const Fp3& value)
{
    AppendLE64Feedback(out, gf::Canonical(value.c0));
    AppendLE64Feedback(out, gf::Canonical(value.c1));
    AppendLE64Feedback(out, gf::Canonical(value.c2));
}

void AppendAlgDigestFeedback(
    std::vector<uint8_t>& out, const alg_hash::Digest& digest)
{
    for (Fp limb : digest) {
        AppendLE64Feedback(out, gf::Canonical(limb));
    }
}

bool BuildCountedSha256d(
    const std::vector<uint8_t>& preimage,
    std::array<uint8_t, 32>& digest,
    uint32_t& compression_blocks)
{
    ha::ShaManifest manifest;
    std::string why;
    if (!ha::BuildShaManifest(
            preimage, ha::ShaMode::Double, manifest, &why)) {
        return false;
    }
    if (manifest.first.padded_blocks.size() >
            std::numeric_limits<uint32_t>::max() -
                manifest.second.padded_blocks.size()) {
        return false;
    }
    compression_blocks += static_cast<uint32_t>(
        manifest.first.padded_blocks.size() +
        manifest.second.padded_blocks.size());
    digest = manifest.digest;
    return true;
}

uint64_t ReadLE64Feedback(const uint8_t* bytes)
{
    uint64_t value = 0;
    for (uint32_t byte = 0; byte < 8; ++byte) {
        value |= uint64_t{bytes[byte]} << (8 * byte);
    }
    return value;
}

bool EqFp3Vectors(
    const std::vector<Fp3>& a, const std::vector<Fp3>& b)
{
    if (a.size() != b.size()) return false;
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (!gf::Eq(a[i], b[i])) return false;
    }
    return true;
}

bool EqFp3Matrices(
    const std::vector<std::vector<Fp3>>& a,
    const std::vector<std::vector<Fp3>>& b)
{
    if (a.size() != b.size()) return false;
    for (uint32_t column = 0; column < a.size(); ++column) {
        if (!EqFp3Vectors(a[column], b[column])) return false;
    }
    return true;
}

bool SameNormalizedFeedbackConstraintShape(
    const aq::AirConstraintSystem<Fp3>& a,
    const aq::AirConstraintSystem<Fp3>& b)
{
    if (a.n_rows != b.n_rows ||
        a.n_columns != b.n_columns ||
        a.preprocessed_pin_ood != b.preprocessed_pin_ood ||
        a.constraints.size() != b.constraints.size() ||
        a.preprocessed.size() != b.preprocessed.size() ||
        a.preprocessed_roots != b.preprocessed_roots) {
        return false;
    }
    for (uint32_t i = 0; i < a.constraints.size(); ++i) {
        const auto& lhs = a.constraints[i];
        const auto& rhs = b.constraints[i];
        if (lhs.name == nullptr || rhs.name == nullptr ||
            std::strcmp(lhs.name, rhs.name) != 0 ||
            lhs.kind != rhs.kind ||
            lhs.alg_degree != rhs.alg_degree) {
            return false;
        }
    }
    for (uint32_t i = 0; i < a.preprocessed.size(); ++i) {
        if (a.preprocessed[i].first !=
                b.preprocessed[i].first ||
            !EqFp3Vectors(
                a.preprocessed[i].second,
                b.preprocessed[i].second)) {
            return false;
        }
    }
    return true;
}

} // namespace

ChallengeFeedbackAssessment
AssessChallengeFeedback(
    const SameTraceComposition& composition)
{
    ChallengeFeedbackAssessment out;
    if (!composition.valid ||
        composition.scope != TranscriptScope::FullTranscript ||
        composition.lane_pis.size() != 2 ||
        composition.combined_columns.size() !=
            composition.combined.n_columns ||
        composition.transcript_layout.poseidon.perm.End() >
            composition.combined.n_columns) {
        out.note =
            "stage3:v5_v6_bus:challenge_feedback_shape";
        return out;
    }
    for (const auto& pi : composition.lane_pis) {
        if (!pi.independent_fri_batching ||
            pi.fri_batch_coefficients.size() !=
                pi.child_w + 1 ||
            pi.fold_challenges.size() != pi.n_folds ||
            pi.query_index.empty()) {
            out.note =
                "stage3:v5_v6_bus:challenge_feedback_v5_shape";
            return out;
        }
    }

    auto append_fp3 =
        [&](ChallengeFeedbackFamily family,
            uint32_t lane, uint32_t item_index,
            const char* consumer, uint32_t frame_index,
            const Fp3& expected) {
            uint32_t trace_row = 0;
            if (!FindFrameEndRow(
                    composition.program, frame_index,
                    trace_row) ||
                trace_row >= composition.combined.n_rows) {
                return false;
            }
            std::vector<Fp3> row(
                composition.combined.n_columns);
            for (uint32_t column = 0;
                 column < composition.combined.n_columns;
                 ++column) {
                row[column] =
                    composition.combined_columns[column]
                        [trace_row];
            }
            for (uint32_t coordinate = 0;
                 coordinate < 3; ++coordinate) {
                const Fp3 v6_word = ar::PermOutputLane(
                    composition.transcript_layout.poseidon.perm,
                    row, coordinate);
                const bool equal = gf::Eq(
                    v6_word,
                    Fp3::FromFp(
                        Fp3Coordinate(expected, coordinate)));
                out.cells.push_back({
                    family, lane, item_index, coordinate,
                    consumer,
                    false,
                    true,
                    true,
                    trace_row,
                    composition.transcript_layout.poseidon.perm.base,
                    coordinate,
                    equal,
                    false});
            }
            return true;
        };

    for (uint32_t frame_index = 0;
         frame_index < composition.program.frames.size();
         ++frame_index) {
        const v6::Frame& frame =
            composition.program.frames[frame_index];
        if (frame.lane >= composition.lane_pis.size()) {
            continue;
        }
        const auto& pi = composition.lane_pis[frame.lane];
        if (frame.kind ==
            v6::FrameKind::AirQuotientChallenge) {
            if (!append_fp3(
                    ChallengeFeedbackFamily::AirQuotient,
                    frame.lane, 0,
                    "vcs.per_point.identity",
                    frame_index, pi.air_lambda)) {
                out.note =
                    "stage3:v5_v6_bus:air_challenge_row";
                return out;
            }
        } else if (frame.kind ==
                   v6::FrameKind::BatchCoefficient) {
            if (frame.index >=
                    pi.fri_batch_coefficients.size() ||
                !append_fp3(
                    ChallengeFeedbackFamily::BatchCoefficient,
                    frame.lane, frame.index,
                    "vcs.deep.identity",
                    frame_index,
                    pi.fri_batch_coefficients[frame.index])) {
                out.note =
                    "stage3:v5_v6_bus:batch_challenge_row";
                return out;
            }
        } else if (frame.kind ==
                   v6::FrameKind::DeepWeight) {
            if (frame.index >= 2 ||
                !append_fp3(
                    ChallengeFeedbackFamily::DeepWeight,
                    frame.lane, frame.index,
                    "vcs.deep.identity",
                    frame_index,
                    frame.index == 0 ? pi.w1 : pi.w2)) {
                out.note =
                    "stage3:v5_v6_bus:deep_challenge_row";
                return out;
            }
        } else if (frame.kind ==
                   v6::FrameKind::FoldChallenge) {
            if (frame.index >= pi.fold_challenges.size() ||
                !append_fp3(
                    ChallengeFeedbackFamily::FoldChallenge,
                    frame.lane, frame.index,
                    "vcs.fold.relation",
                    frame_index,
                    pi.fold_challenges[frame.index])) {
                out.note =
                    "stage3:v5_v6_bus:fold_challenge_row";
                return out;
            }
        } else if (frame.kind ==
                       v6::FrameKind::QueryCandidate &&
                   frame.index %
                           v6::kQueryCandidatesPerIndex ==
                       v6::kQueryCandidatesPerIndex - 1) {
            const uint32_t query =
                frame.index /
                v6::kQueryCandidatesPerIndex;
            if (query >= pi.query_index.size()) {
                out.note =
                    "stage3:v5_v6_bus:query_challenge_index";
                return out;
            }
            uint32_t trace_row = 0;
            if (!FindFrameEndRow(
                    composition.program, frame_index,
                    trace_row)) {
                out.note =
                    "stage3:v5_v6_bus:query_challenge_row";
                return out;
            }
            const uint32_t source =
                composition.transcript_layout
                    .query_reduced_index;
            const bool equal = gf::Eq(
                composition.combined_columns[source]
                    [trace_row],
                Fp3::FromFp(gf::FromU64(
                    pi.query_index[query])));
            out.cells.push_back({
                ChallengeFeedbackFamily::QueryIndex,
                frame.lane, query, 0,
                "vcs.query.preprocessed_schedule",
                false,
                true,
                false,
                trace_row,
                source,
                0,
                equal,
                false});
        }
    }

    // V5 consumes two selected extension-field OOD points per lane. V6 now
    // exposes its own AIR-selected z1/z2 cells after two disjoint
    // two-candidate groups. These are structurally addressable outputs, but
    // they are not aliases: V5 derives candidates from SHA256d while V6
    // derives them from the algebraic transcript.
    bool all_ood_sources_present = true;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const std::array<Fp3, 2> points{
            composition.lane_pis[lane].z1,
            composition.lane_pis[lane].z2};
        for (uint32_t point = 0; point < points.size(); ++point) {
            uint32_t trace_row = 0;
            bool found = false;
            const uint32_t final_candidate =
                point == 0 ? 1 : 3;
            for (uint32_t row = 0;
                 row < composition.program.active_rows; ++row) {
                const v6::ProgramRow& spec =
                    composition.program.rows[row];
                if (!spec.ood_group_final) continue;
                const v6::Frame& frame =
                    composition.program.frames[spec.frame];
                if (frame.lane == lane &&
                    frame.index == final_candidate) {
                    trace_row = row;
                    found = true;
                    break;
                }
            }
            all_ood_sources_present =
                all_ood_sources_present && found;
            for (uint32_t coordinate = 0;
                 coordinate < 3; ++coordinate) {
                const uint32_t source = point == 0
                    ? composition.transcript_layout
                          .OodAcceptedZ1(coordinate)
                    : composition.transcript_layout
                          .OodAcceptedZ2(coordinate);
                const bool equal =
                    found && gf::Eq(
                        composition.combined_columns[source]
                            [trace_row],
                        Fp3::FromFp(Fp3Coordinate(
                            points[point], coordinate)));
                out.cells.push_back({
                    ChallengeFeedbackFamily::OodPoint,
                    lane, point, coordinate,
                    "vcs.deep.denominator_and_evaluation",
                    false,
                    found,
                    false,
                    trace_row, source, coordinate,
                    equal,
                    false});
            }
        }
    }
    out.ood_selection_output_in_v6 =
        all_ood_sources_present;

    out.required_cells =
        static_cast<uint32_t>(out.cells.size());
    out.structurally_addressable_v6_cells =
        static_cast<uint32_t>(std::count_if(
            out.cells.begin(), out.cells.end(),
            [](const ChallengeFeedbackCell& cell) {
                return cell.v6_source_present;
            }));
    out.honest_value_equal_cells =
        static_cast<uint32_t>(std::count_if(
            out.cells.begin(), out.cells.end(),
            [](const ChallengeFeedbackCell& cell) {
                return cell.honest_values_equal;
            }));
    out.direct_same_trace_alias_cells =
        static_cast<uint32_t>(std::count_if(
            out.cells.begin(), out.cells.end(),
            [](const ChallengeFeedbackCell& cell) {
                return cell.direct_same_trace_alias;
            }));
    out.feedback_complete =
        out.direct_same_trace_alias_cells ==
            out.required_cells &&
        out.required_cells != 0;
    out.valid = true;
    out.note =
        "stage3:v5_v6_bus:challenge_feedback_audited;"
        "sha_v5_and_algebraic_v6_domains_differ;"
        "v6_ood_selection_structurally_addressable_not_aliased";
    return out;
}

NormalizedChallengeFeedbackReceiptV1
BuildNormalizedChallengeFeedbackReceiptV1(
    const SameTraceComposition& composition)
{
    NormalizedChallengeFeedbackReceiptV1 out;
    if (!composition.valid ||
        composition.scope != TranscriptScope::FullTranscript ||
        !composition.native_v5_verified ||
        !composition.finite_v5_transcript_replayed_on_host ||
        composition.lane_pis.size() != 2 ||
        composition.combined_columns.size() !=
            composition.combined.n_columns) {
        out.note =
            "stage3:v5_v6_bus:normalized_feedback:"
            "unchecked_composition";
        return out;
    }
    out.v6_outputs_checked_locally =
        v6::CountViolations(
            composition.combined,
            composition.combined_columns) == 0;
    out.v5_public_inputs_checked_locally =
        composition.native_v5_verified &&
        composition.finite_v5_transcript_replayed_on_host;
    if (!out.v6_outputs_checked_locally) {
        out.note =
            "stage3:v5_v6_bus:normalized_feedback:"
            "v6_local_air_violations";
        return out;
    }

    const ChallengeFeedbackAssessment assessment =
        AssessChallengeFeedback(composition);
    if (!assessment.valid ||
        assessment.required_cells !=
            kV5SemanticConsumerCells ||
        assessment.structurally_addressable_v6_cells !=
            kV5SemanticConsumerCells ||
        assessment.cells.size() !=
            kV5SemanticConsumerCells) {
        out.note =
            "stage3:v5_v6_bus:normalized_feedback:"
            "cell_inventory";
        return out;
    }

    out.cells.reserve(kV5SemanticConsumerCells);
    out.witness_columns.assign(
        kNormalizedFeedbackColumns,
        std::vector<Fp3>(
            kV5SemanticConsumerRows,
            Fp3::Zero()));
    for (uint32_t ordinal = 0;
         ordinal < assessment.cells.size();
         ++ordinal) {
        const auto& source =
            assessment.cells[ordinal];
        const auto consumer =
            ParseV5Consumer(
                source.v5_equation_consumer);
        const auto family_consumer =
            ExpectedConsumerForFamily(
                source.family);
        const auto expected_v5 =
            ExpectedV5ConsumerValue(
                source, composition.lane_pis);
        if (!consumer.has_value() ||
            !family_consumer.has_value() ||
            *consumer != *family_consumer ||
            !expected_v5.has_value() ||
            !source.v6_source_present ||
            source.v6_trace_row >=
                composition.combined.n_rows ||
            source.v6_source_column >=
                composition.combined.n_columns) {
            out.note =
                "stage3:v5_v6_bus:normalized_feedback:"
                "cell_mapping";
            return out;
        }
        const Fp3& v6_word =
            composition.combined_columns[
                source.v6_source_column]
                [source.v6_trace_row];
        if (gf::Canonical(v6_word.c1) != 0 ||
            gf::Canonical(v6_word.c2) != 0) {
            out.note =
                "stage3:v5_v6_bus:normalized_feedback:"
                "v6_output_not_base_field";
            return out;
        }

        NormalizedChallengeFeedbackCellV1 cell;
        cell.ordinal = ordinal;
        cell.family = source.family;
        cell.lane = source.lane;
        cell.item_index = source.item_index;
        cell.coordinate = source.coordinate;
        cell.consumer =
            static_cast<uint8_t>(*consumer);
        cell.v6_trace_row =
            source.v6_trace_row;
        cell.v6_source_column =
            source.v6_source_column;
        cell.v6_output_lane =
            source.v6_output_lane;
        cell.v6_output_value =
            gf::Canonical(v6_word.c0);
        cell.v5_public_input =
            gf::Canonical(*expected_v5);
        cell.values_equal =
            cell.v6_output_value ==
            cell.v5_public_input;
        if (cell.values_equal) {
            ++out.locally_equal_cells;
        }
        out.cells.push_back(cell);

        auto& columns = out.witness_columns;
        columns[kNormalizedFeedbackActive][ordinal] =
            Fp3::One();
        columns[kNormalizedFeedbackFamily][ordinal] =
            Fp3::FromFp(gf::FromU64(
                static_cast<uint8_t>(cell.family)));
        columns[kNormalizedFeedbackLane][ordinal] =
            Fp3::FromFp(gf::FromU64(cell.lane));
        columns[kNormalizedFeedbackItem][ordinal] =
            Fp3::FromFp(
                gf::FromU64(cell.item_index));
        columns[kNormalizedFeedbackCoordinate][ordinal] =
            Fp3::FromFp(
                gf::FromU64(cell.coordinate));
        columns[kNormalizedFeedbackConsumer][ordinal] =
            Fp3::FromFp(
                gf::FromU64(cell.consumer));
        columns[kNormalizedFeedbackV6Row][ordinal] =
            Fp3::FromFp(
                gf::FromU64(cell.v6_trace_row));
        columns[kNormalizedFeedbackV6Column][ordinal] =
            Fp3::FromFp(
                gf::FromU64(cell.v6_source_column));
        columns[kNormalizedFeedbackExpectedV6][ordinal] =
            Fp3::FromFp(cell.v6_output_value);
        columns[kNormalizedFeedbackExpectedV5][ordinal] =
            Fp3::FromFp(cell.v5_public_input);
        columns[kNormalizedFeedbackWitnessV6][ordinal] =
            Fp3::FromFp(cell.v6_output_value);
        columns[kNormalizedFeedbackWitnessV5][ordinal] =
            Fp3::FromFp(cell.v5_public_input);
    }

    out.schedule_commitment =
        CommitNormalizedFeedbackScheduleV1(
            out.cells);
    out.v6_output_commitment =
        CommitNormalizedFeedbackValuesV1(
            "BTX_RC_STAGE3_V6_V5_NORMALIZED_FEEDBACK_V6_VALUES_V1",
            out.cells, true);
    out.v5_input_commitment =
        CommitNormalizedFeedbackValuesV1(
            "BTX_RC_STAGE3_V6_V5_NORMALIZED_FEEDBACK_V5_INPUTS_V1",
            out.cells, false);
    out.receipt_commitment =
        CommitNormalizedFeedbackReceiptV1(
            out.schedule_commitment,
            out.v6_output_commitment,
            out.v5_input_commitment);
    if (out.schedule_commitment.IsNull() ||
        out.v6_output_commitment.IsNull() ||
        out.v5_input_commitment.IsNull() ||
        out.receipt_commitment.IsNull()) {
        out.note =
            "stage3:v5_v6_bus:normalized_feedback:"
            "commitment";
        return out;
    }

    auto& cs = out.constraint_system;
    cs.n_rows = kV5SemanticConsumerRows;
    cs.n_columns = kNormalizedFeedbackColumns;
    cs.preprocessed_pin_ood = true;
    for (uint32_t column =
             kNormalizedFeedbackActive;
         column <=
             kNormalizedFeedbackExpectedV5;
         ++column) {
        cs.preprocessed.emplace_back(
            column,
            out.witness_columns[column]);
    }

    aq::AirConstraint<Fp3> active_boolean;
    active_boolean.name =
        "v6_v5.normalized_feedback.active_boolean";
    active_boolean.kind =
        aq::AirKind::kEverywhere;
    active_boolean.alg_degree = 2;
    active_boolean.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kNormalizedFeedbackActive],
            gf::Sub(
                row[kNormalizedFeedbackActive],
                Fp3::One()));
    };
    cs.constraints.push_back(
        std::move(active_boolean));

    aq::AirConstraint<Fp3> pin_v6;
    pin_v6.name =
        "v6_v5.normalized_feedback.pin_v6_output";
    pin_v6.kind = aq::AirKind::kEverywhere;
    pin_v6.alg_degree = 2;
    pin_v6.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kNormalizedFeedbackActive],
            gf::Sub(
                row[kNormalizedFeedbackWitnessV6],
                row[kNormalizedFeedbackExpectedV6]));
    };
    cs.constraints.push_back(std::move(pin_v6));

    aq::AirConstraint<Fp3> pin_v5;
    pin_v5.name =
        "v6_v5.normalized_feedback.pin_v5_input";
    pin_v5.kind = aq::AirKind::kEverywhere;
    pin_v5.alg_degree = 2;
    pin_v5.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kNormalizedFeedbackActive],
            gf::Sub(
                row[kNormalizedFeedbackWitnessV5],
                row[kNormalizedFeedbackExpectedV5]));
    };
    cs.constraints.push_back(std::move(pin_v5));

    aq::AirConstraint<Fp3> direct_feedback;
    direct_feedback.name =
        "v6_v5.normalized_feedback.direct_equality";
    direct_feedback.kind =
        aq::AirKind::kEverywhere;
    direct_feedback.alg_degree = 2;
    direct_feedback.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kNormalizedFeedbackActive],
            gf::Sub(
                row[kNormalizedFeedbackWitnessV6],
                row[kNormalizedFeedbackWitnessV5]));
    };
    cs.constraints.push_back(
        std::move(direct_feedback));

    for (uint32_t witness :
         std::array<uint32_t, 2>{
             kNormalizedFeedbackWitnessV6,
             kNormalizedFeedbackWitnessV5}) {
        aq::AirConstraint<Fp3> padding;
        padding.name =
            "v6_v5.normalized_feedback.padding_zero";
        padding.kind =
            aq::AirKind::kEverywhere;
        padding.alg_degree = 2;
        padding.eval = [witness](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    row[kNormalizedFeedbackActive]),
                row[witness]);
        };
        cs.constraints.push_back(
            std::move(padding));
    }

    out.required_cells =
        kV5SemanticConsumerCells;
    out.structurally_mapped_cells =
        static_cast<uint32_t>(
            out.cells.size());
    out.local_equality_obligations =
        kV5SemanticConsumerCells;
    out.trace_rows = cs.n_rows;
    out.trace_columns = cs.n_columns;
    out.canonical_order =
        std::all_of(
            out.cells.begin(),
            out.cells.end(),
            [ordinal = uint32_t{0}](
                const auto& cell) mutable {
                return cell.ordinal == ordinal++;
            });
    out.local_equality_violations =
        v6::CountViolations(
            cs, out.witness_columns);
    out.current_assignment_satisfies_local_equality =
        out.local_equality_violations == 0 &&
        out.locally_equal_cells ==
            kV5SemanticConsumerCells;
    out.recursively_child_proof_owned = false;
    out.local_binding_complete =
        out.v6_outputs_checked_locally &&
        out.v5_public_inputs_checked_locally &&
        out.structurally_mapped_cells ==
            kV5SemanticConsumerCells &&
        out.local_equality_obligations ==
            kV5SemanticConsumerCells &&
        out.schedule_commitment ==
            CommitNormalizedFeedbackScheduleV1(
                out.cells);
    out.valid = out.local_binding_complete;
    out.note = out.valid
        ? "stage3:v5_v6_bus:normalized_feedback:"
          "304_sources_and_inputs_bound;"
          "local_equalities_materialized;"
          "current_value_mismatches=" +
              std::to_string(
                  kV5SemanticConsumerCells -
                  out.locally_equal_cells) +
          ";recursive_child_ownership_open"
        : "stage3:v5_v6_bus:normalized_feedback:"
          "invalid";
    return out;
}

bool ValidateNormalizedChallengeFeedbackReceiptV1(
    const SameTraceComposition& composition,
    const NormalizedChallengeFeedbackReceiptV1& receipt,
    std::string* why)
{
    const auto expected =
        BuildNormalizedChallengeFeedbackReceiptV1(
            composition);
    if (!expected.valid ||
        receipt.version != 1 ||
        !receipt.valid) {
        return Fail(
            why,
            "normalized_feedback_receipt_shape");
    }
    if (receipt.cells != expected.cells) {
        return Fail(
            why,
            "normalized_feedback_receipt_cells");
    }
    if (!EqFp3Matrices(
            receipt.witness_columns,
            expected.witness_columns) ||
        !SameNormalizedFeedbackConstraintShape(
            receipt.constraint_system,
            expected.constraint_system) ||
        receipt.schedule_commitment !=
            expected.schedule_commitment ||
        receipt.v6_output_commitment !=
            expected.v6_output_commitment ||
        receipt.v5_input_commitment !=
            expected.v5_input_commitment ||
        receipt.receipt_commitment !=
            expected.receipt_commitment) {
        return Fail(
            why,
            "normalized_feedback_receipt_binding");
    }
    if (receipt.required_cells !=
            expected.required_cells ||
        receipt.structurally_mapped_cells !=
            expected.structurally_mapped_cells ||
        receipt.locally_equal_cells !=
            expected.locally_equal_cells ||
        receipt.local_equality_obligations !=
            expected.local_equality_obligations ||
        receipt.local_equality_violations !=
            expected.local_equality_violations ||
        receipt.trace_rows !=
            expected.trace_rows ||
        receipt.trace_columns !=
            expected.trace_columns ||
        receipt.canonical_order !=
            expected.canonical_order ||
        receipt.v6_outputs_checked_locally !=
            expected.v6_outputs_checked_locally ||
        receipt.v5_public_inputs_checked_locally !=
            expected.v5_public_inputs_checked_locally ||
        receipt.local_binding_complete !=
            expected.local_binding_complete ||
        receipt.current_assignment_satisfies_local_equality !=
            expected.current_assignment_satisfies_local_equality ||
        receipt.recursively_child_proof_owned) {
        return Fail(
            why,
            "normalized_feedback_receipt_summary");
    }
    return true;
}

bool VerifyNormalizedChallengeFeedbackLocalEqualityV1(
    const SameTraceComposition& composition,
    const NormalizedChallengeFeedbackReceiptV1& receipt,
    std::string* why)
{
    if (!ValidateNormalizedChallengeFeedbackReceiptV1(
            composition, receipt, why)) {
        return false;
    }
    if (!receipt.current_assignment_satisfies_local_equality ||
        receipt.locally_equal_cells !=
            kV5SemanticConsumerCells ||
        receipt.local_equality_violations != 0) {
        return Fail(
            why,
            "normalized_feedback_value_mismatch");
    }
    return true;
}

V5SemanticMaterialization BuildV5SemanticMaterialization(
    const SameTraceComposition& composition)
{
    V5SemanticMaterialization out;
    if (!composition.valid ||
        composition.scope != TranscriptScope::FullTranscript ||
        !composition.native_v5_verified ||
        !composition.finite_v5_transcript_replayed_on_host) {
        out.note =
            "stage3:v5_v6_bus:v5_semantic:unverified_boundary";
        return out;
    }
    const ChallengeFeedbackAssessment assessment =
        AssessChallengeFeedback(composition);
    if (!assessment.valid ||
        assessment.required_cells != kV5SemanticConsumerCells ||
        assessment.cells.size() != kV5SemanticConsumerCells) {
        out.note =
            "stage3:v5_v6_bus:v5_semantic:cell_inventory";
        return out;
    }

    out.cells.reserve(kV5SemanticConsumerCells);
    out.witness_columns.assign(
        kV5SemanticConsumerColumns,
        std::vector<Fp3>(
            kV5SemanticConsumerRows, Fp3::Zero()));
    for (uint32_t row = 0;
         row < assessment.cells.size(); ++row) {
        const auto& source = assessment.cells[row];
        const auto consumer =
            ParseV5Consumer(source.v5_equation_consumer);
        const auto family_consumer =
            ExpectedConsumerForFamily(source.family);
        const auto expected =
            ExpectedV5ConsumerValue(
                source, composition.lane_pis);
        if (!consumer.has_value() ||
            !family_consumer.has_value() ||
            *consumer != *family_consumer ||
            !expected.has_value() ||
            !source.v6_source_present) {
            out.note =
                "stage3:v5_v6_bus:v5_semantic:cell_mapping";
            return out;
        }
        V5SemanticConsumerCell cell;
        cell.semantic_row = row;
        cell.family = source.family;
        cell.lane = source.lane;
        cell.item_index = source.item_index;
        cell.coordinate = source.coordinate;
        cell.consumer = *consumer;
        cell.algebraic_v6_trace_row = source.v6_trace_row;
        cell.algebraic_v6_source_column =
            source.v6_source_column;
        cell.algebraic_v6_output_lane =
            source.v6_output_lane;
        cell.expected_v5_value = *expected;
        cell.direct_v6_challenge_feedback = false;
        out.cells.push_back(cell);

        auto& columns = out.witness_columns;
        columns[kV5SemanticActive][row] = Fp3::One();
        columns[kV5SemanticExpected][row] =
            Fp3::FromFp(*expected);
        columns[kV5SemanticFamily][row] =
            Fp3::FromFp(gf::FromU64(
                static_cast<uint8_t>(cell.family)));
        columns[kV5SemanticLane][row] =
            Fp3::FromFp(gf::FromU64(cell.lane));
        columns[kV5SemanticItem][row] =
            Fp3::FromFp(gf::FromU64(cell.item_index));
        columns[kV5SemanticCoordinate][row] =
            Fp3::FromFp(gf::FromU64(cell.coordinate));
        columns[kV5SemanticConsumer][row] =
            Fp3::FromFp(gf::FromU64(
                static_cast<uint8_t>(cell.consumer)));
        columns[kV5SemanticWitness][row] =
            Fp3::FromFp(*expected);
    }

    out.public_boundary_commitment =
        CommitV5SemanticBoundary(out.cells);
    out.air_seed =
        V5SemanticAirSeed(out.public_boundary_commitment);
    if (out.public_boundary_commitment.IsNull() ||
        out.air_seed.IsNull()) {
        out.note =
            "stage3:v5_v6_bus:v5_semantic:boundary_commitment";
        return out;
    }

    auto& cs = out.constraint_system;
    cs.n_rows = kV5SemanticConsumerRows;
    cs.n_columns = kV5SemanticConsumerColumns;
    cs.preprocessed_pin_ood = true;
    for (uint32_t column = kV5SemanticActive;
         column <= kV5SemanticConsumer; ++column) {
        cs.preprocessed.emplace_back(
            column, out.witness_columns[column]);
    }

    aq::AirConstraint<Fp3> active_boolean;
    active_boolean.name = "v5.semantic.active_boolean";
    active_boolean.kind = aq::AirKind::kEverywhere;
    active_boolean.alg_degree = 2;
    active_boolean.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kV5SemanticActive],
            gf::Sub(
                row[kV5SemanticActive], Fp3::One()));
    };
    cs.constraints.push_back(std::move(active_boolean));

    aq::AirConstraint<Fp3> expected_equality;
    expected_equality.name = "v5.semantic.public_value_equality";
    expected_equality.kind = aq::AirKind::kEverywhere;
    expected_equality.alg_degree = 2;
    expected_equality.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kV5SemanticActive],
            gf::Sub(
                row[kV5SemanticWitness],
                row[kV5SemanticExpected]));
    };
    cs.constraints.push_back(std::move(expected_equality));

    aq::AirConstraint<Fp3> padding_zero;
    padding_zero.name = "v5.semantic.padding_zero";
    padding_zero.kind = aq::AirKind::kEverywhere;
    padding_zero.alg_degree = 2;
    padding_zero.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            gf::Sub(
                Fp3::One(), row[kV5SemanticActive]),
            row[kV5SemanticWitness]);
    };
    cs.constraints.push_back(std::move(padding_zero));

    out.logical_cells = out.cells.size();
    out.trace_rows = cs.n_rows;
    out.total_columns = cs.n_columns;
    out.proof_owned_columns = 1;
    out.verifier_fixed_columns =
        kV5SemanticConsumerColumns - 1;
    out.width_overhead = cs.n_columns;
    out.trace_cell_overhead =
        uint64_t{cs.n_rows} * cs.n_columns;
    out.under_recursive_column_cap =
        out.width_overhead < kStage3RecursiveColumnCap;
    out.verifier_recomputed_sha_boundary = true;
    out.all_cells_semantically_mapped =
        out.logical_cells == kV5SemanticConsumerCells;
    out.all_cells_air_equality_constrained = true;
    out.direct_v6_challenge_feedback = false;
    if (v6::CountViolations(
            cs, out.witness_columns) != 0) {
        out.note =
            "stage3:v5_v6_bus:v5_semantic:honest_violations";
        return out;
    }
    out.valid =
        out.under_recursive_column_cap &&
        out.all_cells_semantically_mapped &&
        out.all_cells_air_equality_constrained;
    out.note = out.valid
        ? "stage3:v5_v6_bus:v5_semantic:304_sha_cells_"
          "materialized;v6_algebraic_feedback_not_claimed"
        : "stage3:v5_v6_bus:v5_semantic:invalid";
    return out;
}

bool VerifyV5SemanticMaterialization(
    const SameTraceComposition& composition,
    const uint256& public_boundary_commitment,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    const V5SemanticMaterialization expected =
        BuildV5SemanticMaterialization(composition);
    if (!expected.valid ||
        public_boundary_commitment.IsNull() ||
        public_boundary_commitment !=
            expected.public_boundary_commitment) {
        return Fail(why, "v5_semantic_public_boundary");
    }
    if (proof.batch.columns.size() !=
            kV5SemanticConsumerColumns + 1 ||
        proof.batch.column_len.size() !=
            kV5SemanticConsumerColumns + 1 ||
        proof.batch.n_coeffs != kV5SemanticConsumerRows) {
        return Fail(why, "v5_semantic_proof_shape");
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            expected.constraint_system, proof,
            expected.air_seed, &air_why)) {
        return Fail(why, "v5_semantic_air:" + air_why);
    }
    return true;
}

V5CommittedFeedbackComposition
BuildV5CommittedFeedbackComposition(
    const SameTraceComposition& composition)
{
    V5CommittedFeedbackComposition out;
    const V5SemanticMaterialization semantic =
        BuildV5SemanticMaterialization(composition);
    if (!semantic.valid ||
        semantic.cells.size() != kV5SemanticConsumerCells) {
        out.note =
            "stage3:v5_v6_bus:committed_feedback:semantic_boundary";
        return out;
    }
    out.public_boundary_commitment =
        semantic.public_boundary_commitment;
    out.program = BuildCommittedFeedbackProgram(semantic);
    if (!out.program.valid) {
        out.note =
            "stage3:v5_v6_bus:committed_feedback:program";
        return out;
    }

    std::vector<v6::PayloadCell> proof_cells;
    std::copy_if(
        out.program.payload_cells.begin(),
        out.program.payload_cells.end(),
        std::back_inserter(proof_cells),
        [](const v6::PayloadCell& cell) {
            return cell.origin == v6::WordOrigin::ProofDerived;
        });
    if (proof_cells.size() != semantic.cells.size()) {
        out.note =
            "stage3:v5_v6_bus:committed_feedback:payload_inventory";
        return out;
    }

    constexpr uint32_t kExportBase = 0;
    constexpr uint32_t kExpectedBase = kExportBase + v6::kRate;
    constexpr uint32_t kMaskBase = kExpectedBase + v6::kRate;
    constexpr uint32_t kBridgeColumns = kMaskBase + v6::kRate;
    aq::AirConstraintSystem<Fp3> bridge;
    bridge.n_rows = out.program.trace_rows;
    bridge.n_columns = kBridgeColumns;
    bridge.preprocessed_pin_ood = true;
    std::vector<std::vector<Fp3>> bridge_columns(
        bridge.n_columns,
        std::vector<Fp3>(bridge.n_rows, Fp3::Zero()));

    for (uint32_t index = 0;
         index < proof_cells.size(); ++index) {
        const auto& payload = proof_cells[index];
        if (payload.trace_row >= bridge.n_rows ||
            payload.rate_lane >= v6::kRate ||
            !gf::IsZero(
                bridge_columns[
                    kMaskBase + payload.rate_lane]
                    [payload.trace_row])) {
            out.note =
                "stage3:v5_v6_bus:committed_feedback:schedule_collision";
            return out;
        }
        const Fp3 value = Fp3::FromFp(
            semantic.cells[index].expected_v5_value);
        bridge_columns[
            kExportBase + payload.rate_lane]
            [payload.trace_row] = value;
        bridge_columns[
            kExpectedBase + payload.rate_lane]
            [payload.trace_row] = value;
        bridge_columns[
            kMaskBase + payload.rate_lane]
            [payload.trace_row] = Fp3::One();
    }
    for (uint32_t lane = 0; lane < v6::kRate; ++lane) {
        bridge.preprocessed.emplace_back(
            kExpectedBase + lane,
            bridge_columns[kExpectedBase + lane]);
        bridge.preprocessed.emplace_back(
            kMaskBase + lane,
            bridge_columns[kMaskBase + lane]);

        aq::AirConstraint<Fp3> alias;
        alias.name =
            "v5.feedback.sha_consumer.selected_alias";
        alias.kind = aq::AirKind::kEverywhere;
        alias.alg_degree = 2;
        alias.eval = [lane](
                         const std::vector<Fp3>& row,
                         const std::vector<Fp3>&) {
            return gf::Mul(
                row[kMaskBase + lane],
                gf::Sub(
                    row[kExportBase + lane],
                    row[kExpectedBase + lane]));
        };
        bridge.constraints.push_back(std::move(alias));

        aq::AirConstraint<Fp3> padding;
        padding.name = "v5.feedback.export.padding_zero";
        padding.kind = aq::AirKind::kEverywhere;
        padding.alg_degree = 2;
        padding.eval = [lane](
                           const std::vector<Fp3>& row,
                           const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(), row[kMaskBase + lane]),
                row[kExportBase + lane]);
        };
        bridge.constraints.push_back(std::move(padding));
    }

    v6::DirectAliasComposition alias;
    std::string why;
    if (!v6::BuildDirectAliasConstraintSystem(
            out.program, bridge, kExportBase, out.combined,
            &alias, &why)) {
        out.note =
            "stage3:v5_v6_bus:committed_feedback:compose:" +
            why;
        return out;
    }
    v6::Witness witness = v6::BuildDirectAliasWitness(
        out.program, bridge, bridge_columns, kExportBase);
    if (!witness.valid ||
        !witness.external_sources_owned_by_child_verifier) {
        out.note =
            "stage3:v5_v6_bus:committed_feedback:witness:" +
            witness.note;
        return out;
    }
    out.combined_columns = std::move(witness.columns);
    out.transcript_layout = alias.transcript;
    out.cells.reserve(semantic.cells.size());
    for (uint32_t index = 0;
         index < semantic.cells.size(); ++index) {
        const auto& source = semantic.cells[index];
        const auto& payload = proof_cells[index];
        out.cells.push_back({
            source.semantic_row,
            source.family,
            source.lane,
            source.item_index,
            source.coordinate,
            source.consumer,
            payload,
            kExportBase + payload.rate_lane,
            kExpectedBase + payload.rate_lane,
            kMaskBase + payload.rate_lane,
            true,
            true,
            true,
            false,
            false});
    }

    out.trace_rows = out.combined.n_rows;
    out.export_base = kExportBase;
    out.expected_base = kExpectedBase;
    out.mask_base = kMaskBase;
    out.bridge_columns = kBridgeColumns;
    out.combined_columns_count = out.combined.n_columns;
    out.combined_constraints =
        static_cast<uint32_t>(out.combined.constraints.size());
    out.combined_trace_cells =
        uint64_t{out.trace_rows} * out.combined_columns_count;
    out.committed_same_trace_feedback_alias_cells =
        static_cast<uint32_t>(std::count_if(
            out.cells.begin(), out.cells.end(),
            [](const V5CommittedFeedbackCell& cell) {
                return cell.v5_consumer_equality &&
                       cell.v6_proof_payload_equality &&
                       cell.same_trace_alias;
            }));
    out.algebraic_v6_challenge_derivation_cells = 0;
    out.recursive_sha_derivation_cells = 0;
    out.under_recursive_column_cap =
        out.combined_columns_count < kStage3RecursiveColumnCap;
    out.ordered_feedback_stream_bound =
        out.cells.size() == kV5SemanticConsumerCells &&
        out.committed_same_trace_feedback_alias_cells ==
            kV5SemanticConsumerCells;
    out.sha_rejection_sampling_in_air = false;
    out.production_authority_ready = false;
    const uint32_t violations =
        v6::CountViolations(
            out.combined, out.combined_columns);
    out.valid =
        violations == 0 &&
        out.under_recursive_column_cap &&
        out.ordered_feedback_stream_bound &&
        out.algebraic_v6_challenge_derivation_cells == 0 &&
        !out.sha_rejection_sampling_in_air &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:v5_v6_bus:committed_feedback:"
          "304_of_304_same_trace_aliases;"
          "algebraic_derivation_0_of_304;"
          "recursive_sha_derivation_0_of_304"
        : "stage3:v5_v6_bus:committed_feedback:invalid;"
          "violations=" + std::to_string(violations);
    return out;
}

bool VerifyV5CommittedFeedbackComposition(
    const SameTraceComposition& composition,
    const uint256& public_boundary_commitment,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    const V5CommittedFeedbackComposition expected =
        BuildV5CommittedFeedbackComposition(composition);
    if (!expected.valid ||
        public_boundary_commitment.IsNull() ||
        public_boundary_commitment !=
            expected.public_boundary_commitment) {
        return Fail(why, "committed_feedback_public_boundary");
    }
    const uint256 air_seed = V5CommittedFeedbackAirSeed(
        expected.public_boundary_commitment, expected.program);
    if (air_seed.IsNull()) {
        return Fail(why, "committed_feedback_air_seed");
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            expected.combined, proof, air_seed, &air_why)) {
        return Fail(
            why, "committed_feedback_air:" + air_why);
    }
    return true;
}

V5ShaProducedFeedbackComposition
BuildV5ShaProducedFeedbackComposition(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed)
{
    V5ShaProducedFeedbackComposition out;
    const V5SemanticMaterialization semantic =
        BuildV5SemanticMaterialization(composition);
    if (!semantic.valid ||
        semantic.cells.size() != kV5SemanticConsumerCells) {
        out.note =
            "stage3:v5_v6_bus:sha_feedback:semantic_boundary";
        return out;
    }
    out.public_boundary_commitment =
        semantic.public_boundary_commitment;
    out.program = BuildCommittedFeedbackProgram(semantic);
    if (!out.program.valid) {
        out.note = "stage3:v5_v6_bus:sha_feedback:program";
        return out;
    }
    const AirLambdaShaPrefix sha =
        BuildAirLambdaShaPrefix(composition, child_fs_seed);
    if (!sha.valid ||
        sha.packed.cs.n_rows != out.program.trace_rows ||
        sha.packed.columns.size() !=
            sha.packed.cs.n_columns) {
        out.note =
            "stage3:v5_v6_bus:sha_feedback:" + sha.note;
        return out;
    }

    std::vector<v6::PayloadCell> proof_cells;
    std::copy_if(
        out.program.payload_cells.begin(),
        out.program.payload_cells.end(),
        std::back_inserter(proof_cells),
        [](const v6::PayloadCell& cell) {
            return cell.origin == v6::WordOrigin::ProofDerived;
        });
    if (proof_cells.size() != semantic.cells.size()) {
        out.note =
            "stage3:v5_v6_bus:sha_feedback:payload_inventory";
        return out;
    }

    aq::AirConstraintSystem<Fp3> child = sha.packed.cs;
    std::vector<std::vector<Fp3>> child_columns =
        sha.packed.columns;
    const uint32_t export_base = child.n_columns;
    const uint32_t expected_base =
        export_base + v6::kRate;
    const uint32_t mask_base =
        expected_base + v6::kRate;
    const uint32_t digest_word_base =
        mask_base + v6::kRate;
    constexpr uint32_t kDigestWordsUsed = 6;
    constexpr uint32_t kDigestBitsUsed =
        kDigestWordsUsed * 32;
    const uint32_t digest_bit_base =
        digest_word_base + kDigestWordsUsed;
    const uint32_t challenge_output_base =
        digest_bit_base + kDigestBitsUsed;
    const uint32_t derived_mask_base =
        challenge_output_base + 3;
    child.n_columns =
        derived_mask_base + v6::kRate;
    child_columns.resize(
        child.n_columns,
        std::vector<Fp3>(child.n_rows, Fp3::Zero()));

    uint32_t derived_cells = 0;
    for (uint32_t index = 0;
         index < proof_cells.size(); ++index) {
        const auto& payload = proof_cells[index];
        if (payload.trace_row >= child.n_rows ||
            payload.rate_lane >= v6::kRate ||
            !gf::IsZero(
                child_columns[
                    mask_base + payload.rate_lane]
                    [payload.trace_row])) {
            out.note =
                "stage3:v5_v6_bus:sha_feedback:schedule_collision";
            return out;
        }
        const Fp3 value = Fp3::FromFp(
            semantic.cells[index].expected_v5_value);
        child_columns[
            export_base + payload.rate_lane]
            [payload.trace_row] = value;
        child_columns[
            expected_base + payload.rate_lane]
            [payload.trace_row] = value;
        child_columns[
            mask_base + payload.rate_lane]
            [payload.trace_row] = Fp3::One();
        if (semantic.cells[index].family ==
            ChallengeFeedbackFamily::AirQuotient) {
            child_columns[
                derived_mask_base + payload.rate_lane]
                [payload.trace_row] = Fp3::One();
            ++derived_cells;
        }
    }
    if (derived_cells != kV5V6RecursiveShaDerivationCells) {
        out.note =
            "stage3:v5_v6_bus:sha_feedback:derived_inventory";
        return out;
    }

    // SHA final words are big-endian 32-bit words.  The V5 legacy mapping
    // interprets digest bytes in 64-bit little-endian chunks.  Repeating the
    // exact bit witness and three outputs on all rows makes the producer
    // values locally available at both lanes' time-multiplexed payload rows.
    for (uint32_t word = 0; word < kDigestWordsUsed; ++word) {
        const Fp3 fixed_word = Fp3::FromFp(
            gf::FromU64(sha.digest_words[word]));
        std::vector<Fp3> fixed_values(
            child.n_rows, fixed_word);
        child.preprocessed.emplace_back(
            digest_word_base + word, fixed_values);
        child_columns[digest_word_base + word] =
            fixed_values;
        for (uint32_t bit = 0; bit < 32; ++bit) {
            const Fp3 value = Fp3::FromFp(gf::FromU64(
                (sha.digest_words[word] >> bit) & 1U));
            std::fill(
                child_columns[
                    digest_bit_base + word * 32 + bit]
                    .begin(),
                child_columns[
                    digest_bit_base + word * 32 + bit]
                    .end(),
                value);

            aq::AirConstraint<Fp3> boolean;
            boolean.name =
                "v5.feedback.sha_digest.bit_boolean";
            boolean.kind = aq::AirKind::kEverywhere;
            boolean.alg_degree = 2;
            const uint32_t column =
                digest_bit_base + word * 32 + bit;
            boolean.eval = [column](
                               const std::vector<Fp3>& row,
                               const std::vector<Fp3>&) {
                return gf::Mul(
                    row[column],
                    gf::Sub(row[column], Fp3::One()));
            };
            child.constraints.push_back(std::move(boolean));
        }

        aq::AirConstraint<Fp3> reconstruct;
        reconstruct.name =
            "v5.feedback.sha_digest.word_reconstruction";
        reconstruct.kind = aq::AirKind::kEverywhere;
        reconstruct.alg_degree = 1;
        reconstruct.eval =
            [digest_word_base, digest_bit_base, word](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 value = Fp3::Zero();
                Fp power = 1;
                for (uint32_t bit = 0; bit < 32; ++bit) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            Fp3::FromFp(power),
                            row[digest_bit_base +
                                word * 32 + bit]));
                    power = gf::Add(power, power);
                }
                return gf::Sub(
                    row[digest_word_base + word], value);
            };
        child.constraints.push_back(std::move(reconstruct));
    }

    const std::array<Fp, 3> expected_coordinates{
        composition.lane_pis[0].air_lambda.c0,
        composition.lane_pis[0].air_lambda.c1,
        composition.lane_pis[0].air_lambda.c2};
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        std::fill(
            child_columns[
                challenge_output_base + coordinate].begin(),
            child_columns[
                challenge_output_base + coordinate].end(),
            Fp3::FromFp(expected_coordinates[coordinate]));

        aq::AirConstraint<Fp3> convert;
        convert.name =
            "v5.feedback.sha_digest.to_fp3_coordinate";
        convert.kind = aq::AirKind::kEverywhere;
        convert.alg_degree = 1;
        convert.eval =
            [digest_bit_base, challenge_output_base,
             coordinate](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 value = Fp3::Zero();
                Fp power = 1;
                for (uint32_t byte = 0; byte < 8; ++byte) {
                    const uint32_t word =
                        2 * coordinate + byte / 4;
                    const uint32_t word_byte = byte % 4;
                    for (uint32_t bit = 0; bit < 8; ++bit) {
                        const uint32_t source_bit =
                            (3 - word_byte) * 8 + bit;
                        value = gf::Add(
                            value,
                            gf::Mul(
                                Fp3::FromFp(power),
                                row[digest_bit_base +
                                    word * 32 + source_bit]));
                        power = gf::Add(power, power);
                    }
                }
                return gf::Sub(
                    row[challenge_output_base + coordinate],
                    value);
            };
        child.constraints.push_back(std::move(convert));
    }

    for (uint32_t lane = 0; lane < v6::kRate; ++lane) {
        child.preprocessed.emplace_back(
            expected_base + lane,
            child_columns[expected_base + lane]);
        child.preprocessed.emplace_back(
            mask_base + lane,
            child_columns[mask_base + lane]);
        child.preprocessed.emplace_back(
            derived_mask_base + lane,
            child_columns[derived_mask_base + lane]);

        aq::AirConstraint<Fp3> expected_alias;
        expected_alias.name =
            "v5.feedback.sha_consumer.selected_alias";
        expected_alias.kind = aq::AirKind::kEverywhere;
        expected_alias.alg_degree = 2;
        expected_alias.eval =
            [export_base, expected_base, mask_base, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[mask_base + lane],
                    gf::Sub(
                        row[export_base + lane],
                        row[expected_base + lane]));
            };
        child.constraints.push_back(std::move(expected_alias));

        aq::AirConstraint<Fp3> padding;
        padding.name = "v5.feedback.sha_export.padding_zero";
        padding.kind = aq::AirKind::kEverywhere;
        padding.alg_degree = 2;
        padding.eval =
            [export_base, mask_base, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(), row[mask_base + lane]),
                    row[export_base + lane]);
            };
        child.constraints.push_back(std::move(padding));

        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            aq::AirConstraint<Fp3> derived_alias;
            derived_alias.name =
                "v5.feedback.sha_air_lambda.derived_alias";
            derived_alias.kind = aq::AirKind::kEverywhere;
            derived_alias.alg_degree = 2;
            derived_alias.eval =
                [export_base, derived_mask_base,
                 challenge_output_base, lane, coordinate](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    // Exactly one coordinate selector is active at a given
                    // payload cell. The fixed program places coordinate c on
                    // rate lane c after five fixed metadata words, so derive
                    // the coordinate from the canonical lane displacement.
                    const uint32_t expected_lane =
                        (7 + coordinate) % v6::kRate;
                    if (lane != expected_lane) return Fp3::Zero();
                    return gf::Mul(
                        row[derived_mask_base + lane],
                        gf::Sub(
                            row[export_base + lane],
                            row[challenge_output_base +
                                coordinate]));
                };
            child.constraints.push_back(
                std::move(derived_alias));
        }
    }

    v6::DirectAliasComposition alias;
    std::string why;
    if (!v6::BuildDirectAliasConstraintSystem(
            out.program, child, export_base, out.combined,
            &alias, &why)) {
        out.note =
            "stage3:v5_v6_bus:sha_feedback:compose:" + why;
        return out;
    }
    v6::Witness witness = v6::BuildDirectAliasWitness(
        out.program, child, child_columns, export_base);
    if (!witness.valid ||
        !witness.external_sources_owned_by_child_verifier) {
        out.note =
            "stage3:v5_v6_bus:sha_feedback:witness:" +
            witness.note;
        return out;
    }
    out.combined_columns = std::move(witness.columns);
    out.transcript_layout = alias.transcript;
    out.cells.reserve(semantic.cells.size());
    for (uint32_t index = 0;
         index < semantic.cells.size(); ++index) {
        const auto& source = semantic.cells[index];
        const auto& payload = proof_cells[index];
        out.cells.push_back({
            source.semantic_row,
            source.family,
            source.lane,
            source.item_index,
            source.coordinate,
            source.consumer,
            payload,
            export_base + payload.rate_lane,
            expected_base + payload.rate_lane,
            mask_base + payload.rate_lane,
            true,
            true,
            true,
            false,
            source.family ==
                ChallengeFeedbackFamily::AirQuotient});
    }

    HashWriter air_seed;
    air_seed <<
        "BTX_RC_STAGE3_V5_V6_SHA_PRODUCED_FEEDBACK_AIR_V1";
    air_seed << child_fs_seed;
    air_seed << out.public_boundary_commitment;
    air_seed << sha.packed.statement_commitment;
    air_seed << sha.packed.trace_commitment;
    air_seed << out.program.active_rows;
    air_seed << out.program.trace_rows;
    out.combined_air_seed = air_seed.GetHash();
    out.sha256d_compression_blocks =
        sha.real_compression_blocks;
    out.packed_sha_lanes = ha::kFixedProgramPackedLanes;
    out.trace_rows = out.combined.n_rows;
    out.sha_prefix_columns = sha.packed.cs.n_columns;
    out.export_base = export_base;
    out.digest_word_base = digest_word_base;
    out.digest_bit_base = digest_bit_base;
    out.challenge_output_base = challenge_output_base;
    out.derived_mask_base = derived_mask_base;
    out.combined_columns_count = out.combined.n_columns;
    out.combined_constraints =
        static_cast<uint32_t>(out.combined.constraints.size());
    out.combined_trace_cells =
        uint64_t{out.trace_rows} * out.combined_columns_count;
    out.committed_same_trace_feedback_alias_cells =
        static_cast<uint32_t>(out.cells.size());
    out.sha_air_derivation_cells = derived_cells;
    out.recursive_sha_derivation_cells = derived_cells;
    out.algebraic_v6_challenge_derivation_cells = 0;
    out.sha_compression_provenance_in_same_air = true;
    out.digest_to_fp3_in_same_air = true;
    out.under_recursive_column_cap =
        out.combined_columns_count < kStage3RecursiveColumnCap;
    out.production_authority_ready = false;
    const uint32_t violations = v6::CountViolations(
        out.combined, out.combined_columns);
    out.valid =
        violations == 0 &&
        !out.combined_air_seed.IsNull() &&
        out.committed_same_trace_feedback_alias_cells ==
            kV5SemanticConsumerCells &&
        out.recursive_sha_derivation_cells ==
            kV5V6RecursiveShaDerivationCells &&
        out.algebraic_v6_challenge_derivation_cells == 0 &&
        out.sha_compression_provenance_in_same_air &&
        out.digest_to_fp3_in_same_air &&
        out.under_recursive_column_cap &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:v5_v6_bus:sha_feedback:"
          "recursive_sha_derivation_6_of_304;"
          "committed_alias_304_of_304;"
          "algebraic_derivation_0_of_304"
        : "stage3:v5_v6_bus:sha_feedback:invalid;"
          "violations=" + std::to_string(violations);
    return out;
}

bool VerifyV5ShaProducedFeedbackComposition(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed,
    const uint256& public_boundary_commitment,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    const V5ShaProducedFeedbackComposition expected =
        BuildV5ShaProducedFeedbackComposition(
            composition, child_fs_seed);
    if (!expected.valid ||
        public_boundary_commitment.IsNull() ||
        public_boundary_commitment !=
            expected.public_boundary_commitment) {
        return Fail(why, "sha_feedback_public_boundary");
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            expected.combined, proof,
            expected.combined_air_seed, &air_why)) {
        return Fail(why, "sha_feedback_air:" + air_why);
    }
    return true;
}

namespace {

bool V5AirLambdaSplitRapBaseColumnsV1(
    const V5ShaProducedFeedbackComposition& sha,
    std::vector<uint32_t>& base,
    uint32_t& rdep)
{
    base.clear();
    rdep = 0;
    if (!sha.valid ||
        sha.sha_prefix_columns !=
            ha::kFixedProgramPackedProvenanceColumns ||
        sha.combined.n_columns <
            sha.sha_prefix_columns) {
        return false;
    }
    base.reserve(sha.combined.n_columns);
    for (uint32_t column = 0;
         column < sha.combined.n_columns; ++column) {
        bool challenge_dependent = false;
        if (column < sha.sha_prefix_columns) {
            const uint32_t local =
                column %
                ha::kFixedProgramProvenanceColumns;
            challenge_dependent =
                local >=
                    ha::kFixedProgramProvenanceBaseColumns;
        }
        if (challenge_dependent) {
            ++rdep;
        } else {
            base.push_back(column);
        }
    }
    return !base.empty() &&
        base.size() + rdep ==
            sha.combined.n_columns &&
        rdep ==
            ha::kFixedProgramPackedLanes *
                (ha::kFixedProgramProvenanceColumns -
                 ha::kFixedProgramProvenanceBaseColumns);
}

uint256 CommitV5AirLambdaSplitRapProofV1(
    const V5AirLambdaSplitRapProofV1& proof)
{
    if (proof.semantic_boundary_commitment.IsNull() ||
        proof.combined_air_seed.IsNull() ||
        proof.base_column_indices.empty()) {
        return {};
    }
    std::vector<unsigned char> encoded;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof.quotient, encoded) == 0 ||
        encoded.empty() ||
        encoded.size() >
            aq::kAirQuotientSplitRapRowsMaxProofBytesHard) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_AIR_LAMBDA_SPLIT_RAP_PROOF_V1";
    hash << proof.version;
    hash << proof.semantic_boundary_commitment;
    hash << proof.combined_air_seed;
    hash << proof.trace_columns;
    hash << proof.r0_columns;
    hash << proof.rdep_columns;
    hash << static_cast<uint32_t>(
        proof.base_column_indices.size());
    for (const uint32_t column :
         proof.base_column_indices) {
        hash << column;
    }
    hash << static_cast<uint64_t>(encoded.size());
    for (const unsigned char byte : encoded) {
        hash << byte;
    }
    return hash.GetHash();
}

} // namespace

V5AirLambdaSplitRapProofV1
ProveV5AirLambdaSplitRapV1(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed)
{
    V5AirLambdaSplitRapProofV1 out;
    const V5ShaProducedFeedbackComposition sha =
        BuildV5ShaProducedFeedbackComposition(
            composition, child_fs_seed);
    if (!sha.valid ||
        !V5AirLambdaSplitRapBaseColumnsV1(
            sha, out.base_column_indices,
            out.rdep_columns)) {
        out.note =
            "stage3:v5_v6_bus:air_lambda_split_rap:"
            "canonical_composition";
        return out;
    }
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            sha.combined, sha.combined_columns,
            out.base_column_indices,
            sha.combined_air_seed, {});
    if (!proved.ok || !proved.division_exact ||
        proved.proof.batch.groups.size() != 3 ||
        proved.proof.base_column_indices !=
            out.base_column_indices) {
        out.note =
            "stage3:v5_v6_bus:air_lambda_split_rap:"
            "prove:" + proved.note;
        return out;
    }
    out.semantic_boundary_commitment =
        sha.public_boundary_commitment;
    out.combined_air_seed = sha.combined_air_seed;
    out.trace_columns = sha.combined.n_columns;
    out.r0_columns =
        static_cast<uint32_t>(
            out.base_column_indices.size());
    out.locally_proved_cells =
        kV5TranscriptAirQuotientPendingCellsV1;
    out.normalized_recursive_cells = 0;
    out.quotient = proved.proof;
    out.proof_statement =
        CommitV5AirLambdaSplitRapProofV1(out);
    out.valid =
        !out.proof_statement.IsNull() &&
        out.r0_columns + out.rdep_columns ==
            out.trace_columns &&
        out.locally_proved_cells == 6 &&
        out.normalized_recursive_cells == 0;
    out.note = out.valid
        ? "stage3:v5_v6_bus:air_lambda_split_rap:"
          "multirow_v2_local_child_proved;"
          "six_outputs_local;normalized_recursive_0"
        : "stage3:v5_v6_bus:air_lambda_split_rap:invalid";
    return out;
}

bool VerifyV5AirLambdaSplitRapV1(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed,
    const V5AirLambdaSplitRapProofV1& proof,
    std::string* why)
{
    const V5ShaProducedFeedbackComposition sha =
        BuildV5ShaProducedFeedbackComposition(
            composition, child_fs_seed);
    std::vector<uint32_t> base;
    uint32_t rdep = 0;
    if (!proof.valid || !sha.valid ||
        !V5AirLambdaSplitRapBaseColumnsV1(
            sha, base, rdep) ||
        proof.semantic_boundary_commitment !=
            sha.public_boundary_commitment ||
        proof.combined_air_seed !=
            sha.combined_air_seed ||
        proof.trace_columns !=
            sha.combined.n_columns ||
        proof.r0_columns != base.size() ||
        proof.rdep_columns != rdep ||
        proof.base_column_indices != base ||
        proof.quotient.base_column_indices != base ||
        proof.locally_proved_cells !=
            kV5TranscriptAirQuotientPendingCellsV1 ||
        proof.normalized_recursive_cells != 0 ||
        proof.proof_statement !=
            CommitV5AirLambdaSplitRapProofV1(proof)) {
        return Fail(
            why, "air_lambda_split_rap:shape");
    }
    std::string air_why;
    if (!aq::AirQuotientVerifyRowsSplitRap(
            sha.combined, proof.quotient,
            base, sha.combined_air_seed,
            &air_why)) {
        return Fail(
            why,
            "air_lambda_split_rap:air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:v5_v6_bus:air_lambda_split_rap:"
            "public_only_multirow_v2_verified;"
            "six_outputs_local;normalized_recursive_0";
    }
    return true;
}

namespace {

uint256 V5AirLambdaArityEmptyCommitmentV1(
    const uint256& public_statement,
    const uint256& verifier_seed,
    uint32_t slot)
{
    if (public_statement.IsNull() ||
        verifier_seed.IsNull() ||
        slot == 0 ||
        slot >= kV5AirLambdaArityParentSlotsV1) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_AIR_LAMBDA_ARITY4_EMPTY_V1";
    hash << public_statement;
    hash << verifier_seed;
    hash << slot;
    return hash.GetHash();
}

std::array<Fp3, kV5AirLambdaArityParentOutputsV1>
V5AirLambdaArityOutputsV1(
    const SameTraceComposition& composition)
{
    std::array<
        Fp3, kV5AirLambdaArityParentOutputsV1> out{};
    if (composition.lane_pis.size() != 2) {
        return out;
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const Fp3 value =
            composition.lane_pis[lane].air_lambda;
        out[lane * 3 + 0] =
            Fp3::FromFp(value.c0);
        out[lane * 3 + 1] =
            Fp3::FromFp(value.c1);
        out[lane * 3 + 2] =
            Fp3::FromFp(value.c2);
    }
    return out;
}

bool V5AirLambdaArityOutputsEqualV1(
    const std::array<
        Fp3, kV5AirLambdaArityParentOutputsV1>& a,
    const std::array<
        Fp3, kV5AirLambdaArityParentOutputsV1>& b)
{
    for (uint32_t i = 0;
         i < kV5AirLambdaArityParentOutputsV1; ++i) {
        if (!gf::Eq(a[i], b[i])) {
            return false;
        }
    }
    return true;
}

uint256 CommitV5AirLambdaArityParentContractV1(
    const V5AirLambdaArityParentContractV1& contract,
    const uint256& proof_statement)
{
    if (contract.version != 1 ||
        contract.child_count != 1 ||
        contract.public_statement.IsNull() ||
        contract.verifier_seed.IsNull() ||
        proof_statement.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_AIR_LAMBDA_ARITY_PARENT_CONTRACT_V1";
    hash << contract.version;
    hash << contract.child_count;
    for (uint32_t width :
         contract.group_width) {
        hash << width;
    }
    for (uint32_t openings :
         contract.current_group_openings) {
        hash << openings;
    }
    for (uint32_t openings :
         contract.next_group_openings) {
        hash << openings;
    }
    for (const Fp3& output : contract.outputs) {
        hash << gf::Canonical(output.c0);
        hash << gf::Canonical(output.c1);
        hash << gf::Canonical(output.c2);
    }
    for (const uint256& child :
         contract.child_commitment) {
        hash << child;
    }
    hash << contract.public_statement;
    hash << contract.verifier_seed;
    hash << proof_statement;
    hash << contract.normalized_recursive_cells;
    hash << contract.codec_canonical;
    hash << contract.canonical_padding;
    hash << contract.verifier_api_pending;
    return hash.GetHash();
}

bool V5AirLambdaArityProofShapeV1(
    const V5AirLambdaSplitRapProofV1& proof,
    std::array<
        uint32_t, kV5AirLambdaArityParentGroupsV1>&
        group_width,
    std::array<
        uint32_t, kV5AirLambdaArityParentGroupsV1>&
        current_group_openings,
    std::array<
        uint32_t, kV5AirLambdaArityParentNextGroupsV1>&
        next_group_openings)
{
    const auto& batch = proof.quotient.batch;
    if (batch.groups.size() !=
            kV5AirLambdaArityParentGroupsV1 ||
        batch.groups[0].role !=
            Fri3AlgMultiRowGroupRole::MainTrace ||
        batch.groups[1].role !=
            Fri3AlgMultiRowGroupRole::AuxiliaryTrace ||
        batch.groups[2].role !=
            Fri3AlgMultiRowGroupRole::Quotient ||
        batch.groups[0].first_column != 0 ||
        batch.groups[0].column_count !=
            proof.r0_columns ||
        batch.groups[1].first_column !=
            proof.r0_columns ||
        batch.groups[1].column_count !=
            proof.rdep_columns ||
        batch.groups[2].first_column !=
            proof.trace_columns ||
        batch.groups[2].column_count != 1 ||
        batch.queries.empty() ||
        proof.quotient.next_trace_group_rows.size() !=
            batch.queries.size()) {
        return false;
    }
    for (uint32_t group = 0;
         group < kV5AirLambdaArityParentGroupsV1;
         ++group) {
        group_width[group] =
            batch.groups[group].column_count;
    }
    for (const auto& query : batch.queries) {
        if (query.group_rows.size() !=
                kV5AirLambdaArityParentGroupsV1) {
            return false;
        }
        for (uint32_t group = 0;
             group < kV5AirLambdaArityParentGroupsV1;
             ++group) {
            if (query.group_rows[group].values.size() !=
                    group_width[group]) {
                return false;
            }
            ++current_group_openings[group];
        }
    }
    for (const auto& query :
         proof.quotient.next_trace_group_rows) {
        if (query.size() !=
                kV5AirLambdaArityParentNextGroupsV1) {
            return false;
        }
        for (uint32_t group = 0;
             group <
                 kV5AirLambdaArityParentNextGroupsV1;
             ++group) {
            if (query[group].values.size() !=
                    group_width[group]) {
                return false;
            }
            ++next_group_openings[group];
        }
    }
    return true;
}

bool V5AirLambdaSplitRapCanonicalCodecV1(
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    std::vector<unsigned char> encoded;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof, encoded) == 0 ||
        encoded.empty()) {
        return false;
    }
    const auto decoded =
        aq::DeserializeAirQuotientSplitRapRowsProof(
            encoded);
    if (!decoded.has_value()) {
        return false;
    }
    std::vector<unsigned char> roundtrip;
    return
        aq::SerializeAirQuotientSplitRapRowsProof(
            *decoded, roundtrip) == encoded.size() &&
        roundtrip == encoded;
}

} // namespace

V5AirLambdaArityParentContractV1
BuildV5AirLambdaArityParentContractV1(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed,
    const V5AirLambdaSplitRapProofV1& proof)
{
    V5AirLambdaArityParentContractV1 out;
    std::string why;
    if (!VerifyV5AirLambdaSplitRapV1(
            composition, child_fs_seed, proof, &why) ||
        composition.lane_pis.size() != 2 ||
        !V5AirLambdaArityProofShapeV1(
            proof, out.group_width,
            out.current_group_openings,
            out.next_group_openings)) {
        out.note =
            "stage3:v5_v6_bus:air_lambda_arity_parent:"
            "child_shape:" + why;
        return out;
    }
    out.child_count = 1;
    out.public_statement =
        proof.semantic_boundary_commitment;
    out.verifier_seed =
        proof.combined_air_seed;
    out.outputs =
        V5AirLambdaArityOutputsV1(composition);
    out.child_commitment[0] =
        proof.proof_statement;
    out.canonical_padding = true;
    for (uint32_t slot = 1;
         slot < kV5AirLambdaArityParentSlotsV1;
         ++slot) {
        out.child_commitment[slot] =
            V5AirLambdaArityEmptyCommitmentV1(
                out.public_statement,
                out.verifier_seed, slot);
        if (out.child_commitment[slot].IsNull() ||
            out.child_commitment[slot] ==
                out.child_commitment[0]) {
            out.canonical_padding = false;
        }
        for (uint32_t earlier = 1;
             earlier < slot; ++earlier) {
            if (out.child_commitment[slot] ==
                out.child_commitment[earlier]) {
                out.canonical_padding = false;
            }
        }
    }
    out.codec_canonical =
        V5AirLambdaSplitRapCanonicalCodecV1(
            proof.quotient);
    out.normalized_recursive_cells = 0;
    out.verifier_api_pending = true;
    out.contract_commitment =
        CommitV5AirLambdaArityParentContractV1(
            out, proof.proof_statement);
    out.valid =
        out.child_count == 1 &&
        out.codec_canonical &&
        out.canonical_padding &&
        !out.contract_commitment.IsNull() &&
        out.normalized_recursive_cells == 0 &&
        out.verifier_api_pending;
    out.note = out.valid
        ? "stage3:v5_v6_bus:air_lambda_arity_parent:"
          "three_groups;current_and_next_openings;"
          "six_outputs;one_child;canonical_padding;"
          "verifier_api_pending;normalized_recursive_0"
        : "stage3:v5_v6_bus:air_lambda_arity_parent:"
          "invalid_contract";
    return out;
}

bool ValidateV5AirLambdaArityParentContractV1(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed,
    const V5AirLambdaSplitRapProofV1& proof,
    const V5AirLambdaArityParentContractV1& contract,
    std::string* why)
{
    std::array<
        uint32_t, kV5AirLambdaArityParentGroupsV1>
        widths{};
    std::array<
        uint32_t, kV5AirLambdaArityParentGroupsV1>
        current{};
    std::array<
        uint32_t, kV5AirLambdaArityParentNextGroupsV1>
        next{};
    if (!contract.valid ||
        contract.version != 1 ||
        contract.child_count != 1 ||
        contract.normalized_recursive_cells != 0 ||
        !contract.verifier_api_pending ||
        !contract.codec_canonical ||
        !contract.canonical_padding ||
        contract.public_statement !=
            proof.semantic_boundary_commitment ||
        contract.verifier_seed !=
            proof.combined_air_seed ||
        contract.child_commitment[0] !=
            proof.proof_statement ||
        !V5AirLambdaArityProofShapeV1(
            proof, widths, current, next) ||
        contract.group_width != widths ||
        contract.current_group_openings != current ||
        contract.next_group_openings != next ||
        !V5AirLambdaArityOutputsEqualV1(
            contract.outputs,
            V5AirLambdaArityOutputsV1(composition))) {
        return Fail(
            why, "air_lambda_arity_parent:shape");
    }
    for (uint32_t slot = 1;
         slot < kV5AirLambdaArityParentSlotsV1;
         ++slot) {
        if (contract.child_commitment[slot] !=
                V5AirLambdaArityEmptyCommitmentV1(
                    contract.public_statement,
                    contract.verifier_seed, slot)) {
            return Fail(
                why,
                "air_lambda_arity_parent:padding");
        }
    }
    if (contract.contract_commitment !=
            CommitV5AirLambdaArityParentContractV1(
                contract, proof.proof_statement) ||
        !V5AirLambdaSplitRapCanonicalCodecV1(
            proof.quotient)) {
        return Fail(
            why, "air_lambda_arity_parent:codec_commitment");
    }
    std::string proof_why;
    if (!VerifyV5AirLambdaSplitRapV1(
            composition, child_fs_seed,
            proof, &proof_why)) {
        return Fail(
            why,
            "air_lambda_arity_parent:child:" +
                proof_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:v5_v6_bus:air_lambda_arity_parent:"
            "contract_valid;verifier_api_pending;"
            "normalized_recursive_0";
    }
    return true;
}

V5FirstUniformVerticalShard
BuildV5FirstUniformVerticalShard(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed)
{
    V5FirstUniformVerticalShard out;
    const V5ShaProducerPlan plan =
        AssessV5ShaProducerPlan(
            composition, child, child_fs_seed);
    if (!plan.valid ||
        plan.uniform_shard_compression_blocks.empty() ||
        plan.uniform_shard_compression_blocks[0] != 63 ||
        plan.uniform_shard_consumer_cells[0] != 12) {
        out.note =
            "stage3:v5_v6_bus:first_uniform:"
            "canonical_plan";
        return out;
    }
    const auto transcript =
        BuildFri3AlgDualTranscriptWitness(
            child.batch.repeated, child_fs_seed);
    if (!transcript.valid) {
        out.note =
            "stage3:v5_v6_bus:first_uniform:transcript";
        return out;
    }
    const auto& proof = child.batch.repeated.lane[0];
    const auto& replay = transcript.lane[0];
    std::string why;
    auto append_hash =
        [&](const std::vector<uint8_t>& preimage,
            std::array<uint8_t, 32>& digest) {
            ha::ShaManifest manifest;
            if (!ha::BuildShaManifest(
                    preimage, ha::ShaMode::Double,
                    manifest, &why)) {
                return false;
            }
            std::vector<ha::FixedProgramBoundaryInstance>
                boundaries;
            if (!ha::BuildShaManifestBoundaryInstances(
                    manifest, boundaries, &why)) {
                return false;
            }
            out.boundaries.insert(
                out.boundaries.end(),
                boundaries.begin(), boundaries.end());
            digest = manifest.digest;
            return true;
        };

    std::vector<uint8_t> lane_seed_preimage;
    lane_seed_preimage.insert(
        lane_seed_preimage.end(),
        reinterpret_cast<const uint8_t*>(
            kRCFri3AlgDualDomainTag),
        reinterpret_cast<const uint8_t*>(
            kRCFri3AlgDualDomainTag) +
            sizeof(kRCFri3AlgDualDomainTag) - 1);
    AppendLE32Feedback(
        lane_seed_preimage, kRCFri3AlgDualProofVersion);
    static constexpr char kLaneLabel[] = "lane";
    lane_seed_preimage.insert(
        lane_seed_preimage.end(),
        reinterpret_cast<const uint8_t*>(kLaneLabel),
        reinterpret_cast<const uint8_t*>(kLaneLabel) +
            sizeof(kLaneLabel) - 1);
    AppendLE32Feedback(lane_seed_preimage, 0);
    lane_seed_preimage.insert(
        lane_seed_preimage.end(),
        child_fs_seed.begin(), child_fs_seed.end());
    AppendLE64Feedback(
        lane_seed_preimage, proof.pow_grind_nonce);
    std::array<uint8_t, 32> lane_seed_digest{};
    if (!append_hash(
            lane_seed_preimage, lane_seed_digest) ||
        !std::equal(
            lane_seed_digest.begin(),
            lane_seed_digest.end(),
            replay.lane_seed.begin())) {
        out.note =
            "stage3:v5_v6_bus:first_uniform:lane_seed";
        return out;
    }

    std::vector<uint8_t> fs;
    fs.insert(
        fs.end(),
        reinterpret_cast<const uint8_t*>(
            kRCFri3AlgDualLane0DomainTag),
        reinterpret_cast<const uint8_t*>(
            kRCFri3AlgDualLane0DomainTag) +
            sizeof(kRCFri3AlgDualLane0DomainTag) - 1);
    fs.insert(
        fs.end(), replay.lane_seed.begin(),
        replay.lane_seed.end());
    AppendLE64Feedback(fs, proof.pow_grind_nonce);
    AppendLE32Feedback(fs, proof.blowup);
    AppendLE32Feedback(fs, proof.n_coeffs);
    AppendLE32Feedback(
        fs, kRCFri3AlgDualLaneProofVersion);
    AppendLE32Feedback(
        fs, static_cast<uint32_t>(
                proof.column_len.size()));
    for (uint32_t length : proof.column_len) {
        AppendLE32Feedback(fs, length);
    }
    AppendAlgDigestFeedback(fs, proof.row_commit.root);

    std::vector<
        std::array<uint64_t, kRCFri3AlgDualUniformWords>>
        sampled_words;
    auto draw = [&](const char* label, uint32_t item,
                    Fp3& value) {
        std::array<uint64_t,
                   kRCFri3AlgDualUniformWords> words{};
        for (uint32_t block = 0;
             block <
                 kRCFri3AlgDualUniformHashBlocks;
             ++block) {
            std::vector<uint8_t> preimage = fs;
            preimage.insert(
                preimage.end(),
                reinterpret_cast<const uint8_t*>(
                    kRCFri3AlgDualUniformDrawDomainTag),
                reinterpret_cast<const uint8_t*>(
                    kRCFri3AlgDualUniformDrawDomainTag) +
                    sizeof(
                        kRCFri3AlgDualUniformDrawDomainTag) -
                    1);
            preimage.insert(
                preimage.end(),
                reinterpret_cast<const uint8_t*>(label),
                reinterpret_cast<const uint8_t*>(label) +
                    std::strlen(label));
            AppendLE32Feedback(preimage, item);
            AppendLE32Feedback(preimage, block);
            std::array<uint8_t, 32> digest{};
            if (!append_hash(preimage, digest)) return false;
            for (uint32_t word = 0; word < 4; ++word) {
                words[4 * block + word] =
                    ReadLE64Feedback(
                        digest.data() + 8 * word);
            }
        }
        const auto selected =
            Fri3AlgSelectUniformFp3Words(words);
        if (!selected.has_value()) return false;
        sampled_words.push_back(words);
        value = *selected;
        return true;
    };

    std::vector<Fp3> batch(proof.column_len.size());
    for (uint32_t column = 0;
         column < batch.size(); ++column) {
        if (!draw(
                "fra3_batch_coeff", column,
                batch[column])) {
            out.note =
                "stage3:v5_v6_bus:first_uniform:batch";
            return out;
        }
        out.ordered_outputs.push_back(
            Fp3::FromFp(batch[column].c0));
        out.ordered_outputs.push_back(
            Fp3::FromFp(batch[column].c1));
        out.ordered_outputs.push_back(
            Fp3::FromFp(batch[column].c2));
    }
    if (!EqFp3Vectors(
            batch, replay.batch_coefficients)) {
        out.note =
            "stage3:v5_v6_bus:first_uniform:batch_match";
        return out;
    }
    for (const Fp3& coefficient : batch) {
        AppendFp3Feedback(fs, coefficient);
    }
    std::array<Fp3, 4> candidates{};
    for (uint32_t candidate = 0;
         candidate < candidates.size(); ++candidate) {
        if (!draw(
                "fra3_z", candidate,
                candidates[candidate]) ||
            !gf::Eq(
                candidates[candidate],
                replay.ood_candidates[candidate])) {
            out.note =
                "stage3:v5_v6_bus:first_uniform:ood";
            return out;
        }
    }
    Fp3 z1{};
    Fp3 z2{};
    bool have_z1 = false;
    bool have_z2 = false;
    for (uint32_t candidate = 0;
         candidate < 2; ++candidate) {
        if (candidates[candidate].c1 == 0 &&
            candidates[candidate].c2 == 0) continue;
        z1 = candidates[candidate];
        have_z1 = true;
        break;
    }
    for (uint32_t candidate = 2;
         candidate < 4; ++candidate) {
        if ((candidates[candidate].c1 == 0 &&
             candidates[candidate].c2 == 0) ||
            gf::Eq(candidates[candidate], z1)) {
            continue;
        }
        z2 = candidates[candidate];
        have_z2 = true;
        break;
    }
    if (!have_z1 || !have_z2 ||
        !gf::Eq(z1, replay.selected_z1) ||
        !gf::Eq(z2, replay.selected_z2)) {
        out.note =
            "stage3:v5_v6_bus:first_uniform:ood_select";
        return out;
    }
    for (const Fp3& point : {z1, z2}) {
        out.ordered_outputs.push_back(
            Fp3::FromFp(point.c0));
        out.ordered_outputs.push_back(
            Fp3::FromFp(point.c1));
        out.ordered_outputs.push_back(
            Fp3::FromFp(point.c2));
    }
    out.compression_blocks =
        static_cast<uint32_t>(out.boundaries.size());
    out.consumer_cells =
        static_cast<uint32_t>(out.ordered_outputs.size());
    if (out.compression_blocks != 63 ||
        out.consumer_cells != 12) {
        out.note =
            "stage3:v5_v6_bus:first_uniform:inventory";
        return out;
    }
    HashWriter output_hash;
    output_hash <<
        "BTX_RC_STAGE3_V5_UNIFORM_SHARD0_OUTPUT_V1";
    output_hash << out.compression_blocks;
    output_hash << out.consumer_cells;
    for (const Fp3& value : out.ordered_outputs) {
        output_hash << gf::Canonical(value.c0);
        output_hash << gf::Canonical(value.c1);
        output_hash << gf::Canonical(value.c2);
    }
    out.ordered_output_commitment =
        output_hash.GetHash();
    HashWriter air_seed;
    air_seed <<
        "BTX_RC_STAGE3_V5_UNIFORM_SHARD0_VERTICAL_V1";
    air_seed << child_fs_seed;
    air_seed << out.ordered_output_commitment;
    out.vertical_air_seed = air_seed.GetHash();
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    out.sha_execution =
        ha::BuildFixedProgramVerticalProvenanceInstance(
            program, out.boundaries, out.vertical_air_seed);
    if (!out.sha_execution.valid) {
        out.note =
            "stage3:v5_v6_bus:first_uniform:vertical:" +
            out.sha_execution.note;
        return out;
    }
    if (sampled_words.size() != 6) {
        out.note =
            "stage3:v5_v6_bus:first_uniform:sampler_shape";
        return out;
    }

    // Append a compact verifier-reconstructed bounded sampler to the same
    // quotient statement. Each of the 48 candidate words is bit-decomposed;
    // accept = word < p is proved algebraically. Immutable first-three
    // selectors are recomputed from those exact words, and equality links
    // the selected values through six Fp3 draw outputs to the final 12-cell
    // V5 bus ordering (two batch coefficients and selected z1/z2).
    auto& cs = out.sha_execution.cs;
    auto& columns = out.sha_execution.columns;
    const uint32_t base = cs.n_columns;
    constexpr uint32_t LO = 0;
    constexpr uint32_t HI = 1;
    constexpr uint32_t BIT = 2;
    constexpr uint32_t HIGH_PREFIX = BIT + 64;
    constexpr uint32_t LOW_ZERO_PREFIX = HIGH_PREFIX + 32;
    constexpr uint32_t ACCEPT = LOW_ZERO_PREFIX + 32;
    constexpr uint32_t SELECT = ACCEPT + 1;
    constexpr uint32_t DRAW = SELECT + 3;
    constexpr uint32_t DRAW_OUTPUT = DRAW + 6;
    constexpr uint32_t FINAL_OUTPUT = DRAW_OUTPUT + 18;
    constexpr uint32_t OOD_WEIGHT = FINAL_OUTPUT + 12;
    constexpr uint32_t EXTRA_COLUMNS = OOD_WEIGHT + 4;
    out.sampler_final_output_base = base + FINAL_OUTPUT;
    cs.n_columns += EXTRA_COLUMNS;
    columns.resize(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    std::vector<std::vector<Fp3>> fixed(
        EXTRA_COLUMNS,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    std::array<std::array<uint32_t, 3>, 6>
        selected_indices{};
    for (uint32_t draw_index = 0;
         draw_index < sampled_words.size(); ++draw_index) {
        uint32_t accepted = 0;
        for (uint32_t word_index = 0;
             word_index <
                 kRCFri3AlgDualUniformWords;
             ++word_index) {
            const uint32_t row =
                8 * draw_index + word_index;
            const uint64_t word =
                sampled_words[draw_index][word_index];
            columns[base + LO][row] =
                Fp3::FromFp(
                    gf::FromU64(
                        static_cast<uint32_t>(word)));
            columns[base + HI][row] =
                Fp3::FromFp(
                    gf::FromU64(word >> 32));
            for (uint32_t bit = 0; bit < 64; ++bit) {
                columns[base + BIT + bit][row] =
                    Fp3::FromFp(
                        gf::FromU64((word >> bit) & 1U));
            }
            Fp3 high_prefix = Fp3::One();
            Fp3 low_zero_prefix = Fp3::One();
            for (uint32_t bit = 0; bit < 32; ++bit) {
                high_prefix = gf::Mul(
                    high_prefix,
                    columns[base + BIT + 32 + bit][row]);
                low_zero_prefix = gf::Mul(
                    low_zero_prefix,
                    gf::Sub(
                        Fp3::One(),
                        columns[base + BIT + bit][row]));
                columns[base + HIGH_PREFIX + bit][row] =
                    high_prefix;
                columns[
                    base + LOW_ZERO_PREFIX + bit][row] =
                    low_zero_prefix;
            }
            const bool accept = word < gf::kP;
            columns[base + ACCEPT][row] =
                Fp3::FromFp(gf::FromU64(accept));
            fixed[DRAW + draw_index][row] =
                Fp3::One();
            if (accept && accepted < 3) {
                fixed[SELECT + accepted][row] =
                    Fp3::One();
                selected_indices[draw_index][accepted] =
                    word_index;
                ++accepted;
            }
        }
        if (accepted != 3) {
            out.note =
                "stage3:v5_v6_bus:first_uniform:"
                "sampler_exhausted";
            return out;
        }
    }
    std::array<Fp3, 18> draw_outputs{};
    for (uint32_t draw_index = 0;
         draw_index < 6; ++draw_index) {
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            const uint64_t word =
                sampled_words[draw_index]
                    [selected_indices[draw_index][coordinate]];
            draw_outputs[3 * draw_index + coordinate] =
                Fp3::FromFp(word);
        }
    }
    for (uint32_t output = 0; output < 18; ++output) {
        std::fill(
            columns[base + DRAW_OUTPUT + output].begin(),
            columns[base + DRAW_OUTPUT + output].end(),
            draw_outputs[output]);
    }
    for (uint32_t output = 0; output < 12; ++output) {
        std::fill(
            columns[base + FINAL_OUTPUT + output].begin(),
            columns[base + FINAL_OUTPUT + output].end(),
            out.ordered_outputs[output]);
    }
    // z1 is the first valid of draws 2/3; z2 the first valid and distinct
    // of draws 4/5. These weights are canonical verifier preprocessing.
    const auto valid_ood = [&](uint32_t draw_index) {
        return !gf::IsZero(draw_outputs[3 * draw_index + 1]) ||
               !gf::IsZero(draw_outputs[3 * draw_index + 2]);
    };
    const uint32_t z1_draw =
        valid_ood(2) ? 2 : 3;
    const auto distinct_from_z1 = [&](uint32_t draw_index) {
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            if (!gf::Eq(
                    draw_outputs[3 * draw_index + coordinate],
                    draw_outputs[3 * z1_draw + coordinate])) {
                return true;
            }
        }
        return false;
    };
    const uint32_t z2_draw =
        valid_ood(4) && distinct_from_z1(4) ? 4 : 5;
    fixed[OOD_WEIGHT + z1_draw - 2].assign(
        cs.n_rows, Fp3::One());
    fixed[OOD_WEIGHT + 2 + z2_draw - 4].assign(
        cs.n_rows, Fp3::One());
    for (uint32_t offset = 0;
         offset < EXTRA_COLUMNS; ++offset) {
        if (offset >= SELECT && offset < DRAW_OUTPUT) {
            cs.preprocessed.emplace_back(
                base + offset, fixed[offset]);
            columns[base + offset] = fixed[offset];
        } else if (offset >= OOD_WEIGHT) {
            cs.preprocessed.emplace_back(
                base + offset, fixed[offset]);
            columns[base + offset] = fixed[offset];
        }
    }
    cs.preprocessed_pin_ood = true;
    const auto add = [&](const char* name, aq::AirKind kind,
                         uint32_t degree,
                         std::function<Fp3(
                             const std::vector<Fp3>&,
                             const std::vector<Fp3>&)> eval) {
        aq::AirConstraint<Fp3> constraint;
        constraint.name = name;
        constraint.kind = kind;
        constraint.alg_degree = degree;
        constraint.eval = std::move(eval);
        cs.constraints.push_back(std::move(constraint));
    };
    for (uint32_t bit = 0; bit < 64; ++bit) {
        add("stage3.v5.uniform.bit", aq::AirKind::kEverywhere,
            2, [base, bit](const auto& cur, const auto&) {
                const Fp3 b = cur[base + BIT + bit];
                return gf::Mul(b, gf::Sub(b, Fp3::One()));
            });
    }
    add("stage3.v5.uniform.lo_reconstruct",
        aq::AirKind::kEverywhere, 1,
        [base](const auto& cur, const auto&) {
            Fp3 sum = Fp3::Zero();
            Fp power = 1;
            for (uint32_t bit = 0; bit < 32; ++bit) {
                sum = gf::Add(
                    sum, gf::Mul(
                        Fp3::FromFp(power),
                        cur[base + BIT + bit]));
                power = gf::Add(power, power);
            }
            return gf::Sub(cur[base + LO], sum);
        });
    add("stage3.v5.uniform.hi_reconstruct",
        aq::AirKind::kEverywhere, 1,
        [base](const auto& cur, const auto&) {
            Fp3 sum = Fp3::Zero();
            Fp power = 1;
            for (uint32_t bit = 0; bit < 32; ++bit) {
                sum = gf::Add(
                    sum, gf::Mul(
                        Fp3::FromFp(power),
                        cur[base + BIT + 32 + bit]));
                power = gf::Add(power, power);
            }
            return gf::Sub(cur[base + HI], sum);
        });
    for (uint32_t bit = 0; bit < 32; ++bit) {
        add("stage3.v5.uniform.high_prefix",
            aq::AirKind::kEverywhere, 3,
            [base, bit](const auto& cur, const auto&) {
                const Fp3 previous = bit == 0
                    ? Fp3::One()
                    : cur[base + HIGH_PREFIX + bit - 1];
                Fp3 active = Fp3::Zero();
                for (uint32_t draw_index = 0;
                     draw_index < 6; ++draw_index) {
                    active = gf::Add(
                        active,
                        cur[base + DRAW + draw_index]);
                }
                return gf::Mul(
                    active,
                    gf::Sub(
                        cur[base + HIGH_PREFIX + bit],
                        gf::Mul(
                            previous,
                            cur[base + BIT + 32 + bit])));
            });
        add("stage3.v5.uniform.low_zero_prefix",
            aq::AirKind::kEverywhere, 3,
            [base, bit](const auto& cur, const auto&) {
                const Fp3 previous = bit == 0
                    ? Fp3::One()
                    : cur[
                        base + LOW_ZERO_PREFIX + bit - 1];
                Fp3 active = Fp3::Zero();
                for (uint32_t draw_index = 0;
                     draw_index < 6; ++draw_index) {
                    active = gf::Add(
                        active,
                        cur[base + DRAW + draw_index]);
                }
                return gf::Mul(
                    active,
                    gf::Sub(
                        cur[base + LOW_ZERO_PREFIX + bit],
                        gf::Mul(
                            previous,
                            gf::Sub(
                                Fp3::One(),
                                cur[base + BIT + bit]))));
            });
    }
    add("stage3.v5.uniform.accept_lt_p",
        aq::AirKind::kEverywhere, 3,
        [base](const auto& cur, const auto&) {
            const Fp3 high_all_one =
                cur[base + HIGH_PREFIX + 31];
            const Fp3 low_all_zero =
                cur[base + LOW_ZERO_PREFIX + 31];
            const Fp3 expected = gf::Sub(
                Fp3::One(),
                gf::Mul(
                    high_all_one,
                    gf::Sub(Fp3::One(), low_all_zero)));
            Fp3 active = Fp3::Zero();
            for (uint32_t draw_index = 0;
                 draw_index < 6; ++draw_index) {
                active = gf::Add(
                    active,
                    cur[base + DRAW + draw_index]);
            }
            return gf::Mul(
                active,
                gf::Sub(cur[base + ACCEPT], expected));
        });
    for (uint32_t draw_index = 0;
         draw_index < 6; ++draw_index) {
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            add("stage3.v5.uniform.selected_output",
                aq::AirKind::kEverywhere, 3,
                [base, draw_index, coordinate](
                    const auto& cur, const auto&) {
                    const Fp3 word = gf::Add(
                        cur[base + LO],
                        gf::Mul(
                            Fp3::FromFp(
                                gf::FromU64(
                                    UINT64_C(1) << 32)),
                            cur[base + HI]));
                    const Fp3 selector = gf::Mul(
                        cur[base + DRAW + draw_index],
                        cur[base + SELECT + coordinate]);
                    return gf::Mul(
                        selector,
                        gf::Sub(
                            cur[base + DRAW_OUTPUT +
                                3 * draw_index + coordinate],
                            word));
                });
        }
    }
    for (uint32_t output = 0; output < 30; ++output) {
        const uint32_t column =
            base + (output < 18
                ? DRAW_OUTPUT + output
                : FINAL_OUTPUT + output - 18);
        add("stage3.v5.uniform.output_constant",
            aq::AirKind::kTransition, 1,
            [column](const auto& cur, const auto& next) {
                return gf::Sub(next[column], cur[column]);
            });
    }
    for (uint32_t output = 0; output < 6; ++output) {
        add("stage3.v5.uniform.batch_final",
            aq::AirKind::kFirstRow, 1,
            [base, output](const auto& cur, const auto&) {
                return gf::Sub(
                    cur[base + FINAL_OUTPUT + output],
                    cur[base + DRAW_OUTPUT + output]);
            });
    }
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        add("stage3.v5.uniform.z1_select",
            aq::AirKind::kFirstRow, 2,
            [base, coordinate](const auto& cur, const auto&) {
                Fp3 selected = Fp3::Zero();
                for (uint32_t candidate = 0;
                     candidate < 2; ++candidate) {
                    selected = gf::Add(
                        selected,
                        gf::Mul(
                            cur[base + OOD_WEIGHT + candidate],
                            cur[base + DRAW_OUTPUT +
                                3 * (2 + candidate) +
                                coordinate]));
                }
                return gf::Sub(
                    cur[base + FINAL_OUTPUT + 6 + coordinate],
                    selected);
            });
        add("stage3.v5.uniform.z2_select",
            aq::AirKind::kFirstRow, 2,
            [base, coordinate](const auto& cur, const auto&) {
                Fp3 selected = Fp3::Zero();
                for (uint32_t candidate = 0;
                     candidate < 2; ++candidate) {
                    selected = gf::Add(
                        selected,
                        gf::Mul(
                            cur[base + OOD_WEIGHT + 2 + candidate],
                            cur[base + DRAW_OUTPUT +
                                3 * (4 + candidate) +
                                coordinate]));
                }
                return gf::Sub(
                    cur[base + FINAL_OUTPUT + 9 + coordinate],
                    selected);
            });
    }
    for (uint32_t output = 0; output < 12; ++output) {
        const Fp3 expected = out.ordered_outputs[output];
        add("stage3.v5.uniform.bus_output_equality",
            aq::AirKind::kFirstRow, 1,
            [base, output, expected](
                const auto& cur, const auto&) {
                return gf::Sub(
                    cur[base + FINAL_OUTPUT + output],
                    expected);
            });
    }
    out.sampler_selection_conversion_pending = false;
    out.output_root_equality_pending = false;
    // Full sampler/rejection/conversion and output-root equality are the next
    // proof layer. Until its quotient is produced these cells are executable
    // in the combined statement but not counted as proof-owned.
    out.proof_owned_sha_derivation_cells = 0;
    out.recursively_consumed_sha_derivation_cells = 0;
    out.valid = true;
    out.note =
        "stage3:v5_v6_bus:first_uniform:"
        "vertical_sha_complete_sampler_pending";
    return out;
}

namespace {

V5FirstUniformDrawWitnessPrefix
BuildV5UniformDrawWitnessPrefixImplV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    V5UniformDrawRelationV1 relation,
    uint32_t lane,
    uint32_t item)
{
    V5FirstUniformDrawWitnessPrefix out;
    out.relation = relation;
    out.lane = lane;
    out.batch_item = item;
    const bool is_batch =
        relation ==
        V5UniformDrawRelationV1::BatchCoefficient;
    const bool is_ood =
        relation ==
        V5UniformDrawRelationV1::OodCandidate;
    const bool is_deep =
        relation ==
        V5UniformDrawRelationV1::DeepWeight;
    const bool is_fold =
        relation ==
        V5UniformDrawRelationV1::FoldChallenge;
    const bool is_query =
        relation ==
        V5UniformDrawRelationV1::QueryIndex;
    if (!composition.valid || child_fs_seed.IsNull() ||
        lane >= 2 ||
        (!is_batch && !is_ood &&
         !is_deep && !is_fold && !is_query) ||
        (is_ood && item >= 4) ||
        ((is_batch || is_deep) && item >= 2) ||
        (is_query && item >=
             kRCFri3AlgDualQueriesPerLane)) {
        out.note =
            "stage3:v5_v6_bus:first_uniform_prefix:shape";
        return out;
    }
    const auto transcript =
        BuildFri3AlgDualTranscriptWitness(
            child.batch.repeated, child_fs_seed);
    if (!transcript.valid ||
        (is_batch &&
         item >= transcript.lane[lane]
                    .batch_coefficients.size()) ||
        (is_fold &&
         item >= transcript.lane[lane]
                    .fold_challenges.size()) ||
        (is_query &&
         item >= transcript.lane[lane]
                    .query_indices.size())) {
        out.note =
            "stage3:v5_v6_bus:first_uniform_prefix:transcript";
        return out;
    }
    const auto semantic =
        BuildV5SemanticMaterialization(composition);
    if (!semantic.valid) {
        out.note =
            "stage3:v5_v6_bus:first_uniform_prefix:semantic";
        return out;
    }
    const auto& proof = child.batch.repeated.lane[lane];
    const auto& replay = transcript.lane[lane];
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    std::string why;

    struct CallRange {
        uint32_t base{0};
        uint32_t first_blocks{0};
        std::vector<uint8_t> preimage;
        std::array<uint8_t, 32> digest{};
    };
    auto append_hash =
        [&](const std::vector<uint8_t>& preimage,
            CallRange& range) {
            ha::ShaManifest manifest;
            if (!ha::BuildShaManifest(
                    preimage, ha::ShaMode::Double,
                    manifest, &why)) {
                return false;
            }
            std::vector<ha::FixedProgramBoundaryInstance>
                boundaries;
            if (!ha::BuildShaManifestBoundaryInstances(
                    manifest, boundaries, &why) ||
                manifest.first.padded_blocks.empty() ||
                boundaries.size() !=
                    manifest.first.padded_blocks.size() + 1) {
                return false;
            }
            range.base =
                static_cast<uint32_t>(out.boundaries.size());
            range.first_blocks =
                static_cast<uint32_t>(
                    manifest.first.padded_blocks.size());
            range.preimage = preimage;
            range.digest = manifest.digest;
            out.boundaries.insert(
                out.boundaries.end(),
                boundaries.begin(), boundaries.end());
            for (uint32_t block = 0;
                 block < range.first_blocks; ++block) {
                const uint32_t target =
                    block + 1 < range.first_blocks
                    ? range.base + block + 1
                    : range.base + range.first_blocks;
                const uint32_t target_address =
                    block + 1 < range.first_blocks ? 17 : 1;
                for (uint32_t word = 0; word < 8; ++word) {
                    out.links.push_back({
                        .source_instance =
                            range.base + block,
                        .source_final_word = word,
                        .target_instance = target,
                        .target_external_address =
                            target_address + word,
                    });
                }
            }
            return true;
        };

    std::vector<uint8_t> lane_seed_preimage;
    lane_seed_preimage.insert(
        lane_seed_preimage.end(),
        reinterpret_cast<const uint8_t*>(
            kRCFri3AlgDualDomainTag),
        reinterpret_cast<const uint8_t*>(
            kRCFri3AlgDualDomainTag) +
            sizeof(kRCFri3AlgDualDomainTag) - 1);
    AppendLE32Feedback(
        lane_seed_preimage, kRCFri3AlgDualProofVersion);
    static constexpr char kLaneLabel[] = "lane";
    lane_seed_preimage.insert(
        lane_seed_preimage.end(),
        reinterpret_cast<const uint8_t*>(kLaneLabel),
        reinterpret_cast<const uint8_t*>(kLaneLabel) +
            sizeof(kLaneLabel) - 1);
    AppendLE32Feedback(lane_seed_preimage, lane);
    lane_seed_preimage.insert(
        lane_seed_preimage.end(),
        child_fs_seed.begin(), child_fs_seed.end());
    AppendLE64Feedback(
        lane_seed_preimage, proof.pow_grind_nonce);
    CallRange lane_seed_call;
    if (!append_hash(
            lane_seed_preimage, lane_seed_call) ||
        !std::equal(
            lane_seed_call.digest.begin(),
            lane_seed_call.digest.end(),
            replay.lane_seed.begin())) {
        out.note =
            "stage3:v5_v6_bus:first_uniform_prefix:lane_seed";
        return out;
    }

    std::vector<uint8_t> fs;
    const char* lane_domain = lane == 0
        ? kRCFri3AlgDualLane0DomainTag
        : kRCFri3AlgDualLane1DomainTag;
    fs.insert(
        fs.end(),
        reinterpret_cast<const uint8_t*>(lane_domain),
        reinterpret_cast<const uint8_t*>(lane_domain) +
            std::strlen(lane_domain));
    const uint32_t lane_seed_offset =
        static_cast<uint32_t>(fs.size());
    fs.insert(
        fs.end(), replay.lane_seed.begin(),
        replay.lane_seed.end());
    AppendLE64Feedback(fs, proof.pow_grind_nonce);
    AppendLE32Feedback(fs, proof.blowup);
    AppendLE32Feedback(fs, proof.n_coeffs);
    AppendLE32Feedback(
        fs, kRCFri3AlgDualLaneProofVersion);
    AppendLE32Feedback(
        fs, static_cast<uint32_t>(
                proof.column_len.size()));
    for (uint32_t length : proof.column_len) {
        AppendLE32Feedback(fs, length);
    }
    AppendAlgDigestFeedback(fs, proof.row_commit.root);
    if (!is_batch) {
        for (const Fp3& coefficient :
             replay.batch_coefficients) {
            AppendFp3Feedback(fs, coefficient);
        }
    }
    if (is_deep || is_fold || is_query) {
        AppendFp3Feedback(fs, replay.selected_z1);
        AppendFp3Feedback(fs, replay.selected_z2);
        for (uint32_t column = 0;
             column < proof.evals_z1.size(); ++column) {
            AppendFp3Feedback(fs, proof.evals_z1[column]);
            AppendFp3Feedback(fs, proof.evals_z2[column]);
        }
    }
    if (is_fold || is_query) {
        AppendFp3Feedback(fs, replay.w1);
        AppendFp3Feedback(fs, replay.w2);
    }
    if (is_fold) {
        for (uint32_t preceding = 0;
             preceding <= item; ++preceding) {
            if (preceding >= proof.fold_layers.size()) {
                out.note =
                    "stage3:v5_v6_bus:"
                    "first_uniform_prefix:fold_root";
                return out;
            }
            AppendAlgDigestFeedback(
                fs, proof.fold_layers[preceding].root);
            if (preceding < item) {
                AppendFp3Feedback(
                    fs,
                    replay.fold_challenges[preceding]);
            }
        }
    }
    if (is_query) {
        for (uint32_t fold = 0;
             fold < proof.fold_layers.size(); ++fold) {
            AppendAlgDigestFeedback(
                fs, proof.fold_layers[fold].root);
            if (fold < replay.fold_challenges.size()) {
                AppendFp3Feedback(
                    fs, replay.fold_challenges[fold]);
            }
        }
    }

    std::array<uint64_t, kRCFri3AlgDualUniformWords>
        sampled_words{};
    std::array<CallRange, 2> draw_calls;
    const uint32_t draw_call_count =
        is_query ? 1U
                 : kRCFri3AlgDualUniformHashBlocks;
    for (uint32_t block = 0;
         block < draw_call_count;
         ++block) {
        std::vector<uint8_t> preimage = fs;
        const char* draw_domain =
            is_query
            ? kRCFri3AlgDualIndexDrawDomainTag
            : kRCFri3AlgDualUniformDrawDomainTag;
        preimage.insert(
            preimage.end(),
            reinterpret_cast<const uint8_t*>(draw_domain),
            reinterpret_cast<const uint8_t*>(draw_domain) +
                std::strlen(draw_domain));
        const char* draw_label =
            is_batch
                ? "fra3_batch_coeff"
                : is_ood
                    ? "fra3_z"
                    : is_deep
                        ? "fra3_w"
                        : is_fold
                            ? "fra3_fold"
                            : "fra3_query";
        preimage.insert(
            preimage.end(),
            reinterpret_cast<const uint8_t*>(draw_label),
            reinterpret_cast<const uint8_t*>(draw_label) +
                std::strlen(draw_label));
        AppendLE32Feedback(preimage, item);
        if (!is_query) {
            AppendLE32Feedback(preimage, block);
        }
        if (!append_hash(preimage, draw_calls[block])) {
            out.note =
                "stage3:v5_v6_bus:first_uniform_prefix:draw_hash";
            return out;
        }
        if (!is_query) {
            for (uint32_t word = 0; word < 4; ++word) {
                sampled_words[4 * block + word] =
                    ReadLE64Feedback(
                        draw_calls[block].digest.data() +
                        8 * word);
            }
        }
    }
    std::optional<Fp3> selected;
    uint32_t query_index = 0;
    if (is_query) {
        uint32_t raw = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            raw |= uint32_t{
                draw_calls[0].digest[byte]} << (8 * byte);
        }
        if (proof.row_commit.n_leaves == 0 ||
            (proof.row_commit.n_leaves &
             (proof.row_commit.n_leaves - 1)) != 0) {
            out.note =
                "stage3:v5_v6_bus:first_uniform_prefix:"
                "query_domain";
            return out;
        }
        query_index =
            raw & (proof.row_commit.n_leaves - 1);
        selected =
            Fp3::FromFp(gf::FromU64(query_index));
    } else {
        selected =
            Fri3AlgSelectUniformFp3Words(sampled_words);
    }
    const Fp3 expected_draw =
        is_batch
            ? replay.batch_coefficients[item]
            : is_ood
                ? replay.ood_candidates[item]
                : is_deep
                    ? (item == 0
                           ? replay.w1
                           : replay.w2)
                    : is_fold
                        ? replay.fold_challenges[item]
                        : Fp3::FromFp(gf::FromU64(
                              replay.query_indices[item]));
    if (!selected.has_value() ||
        !gf::Eq(*selected, expected_draw)) {
        out.note =
            "stage3:v5_v6_bus:first_uniform_prefix:draw_match";
        return out;
    }
    out.draw_output = is_query
        ? std::array<Fp3, 3>{
              *selected, Fp3::Zero(), Fp3::Zero()}
        : std::array<Fp3, 3>{
              Fp3::FromFp(selected->c0),
              Fp3::FromFp(selected->c1),
              Fp3::FromFp(selected->c2)};
    out.compression_blocks =
        static_cast<uint32_t>(out.boundaries.size());
    if (out.compression_blocks > 63) {
        out.note =
            "stage3:v5_v6_bus:first_uniform_prefix:capacity";
        return out;
    }

    out.public_external_masks.assign(
        out.boundaries.size(),
        std::vector<uint8_t>(
            program.external_address_count, 1));
    for (const auto& link : out.links) {
        out.public_external_masks[
            link.target_instance]
            [link.target_external_address - 1] = 0;
    }

    struct MessageTarget {
        uint32_t instance{0};
        uint32_t address{0};
        uint32_t value{0};
        std::array<int16_t, 32> lane_seed_bit{};
    };
    std::vector<MessageTarget> message_targets;
    for (uint32_t call_index = 0;
         call_index < draw_call_count; ++call_index) {
        const auto& call = draw_calls[call_index];
        const uint32_t first_word =
            lane_seed_offset / 4;
        const uint32_t last_word =
            (lane_seed_offset + 31) / 4;
        for (uint32_t global_word = first_word;
             global_word <= last_word; ++global_word) {
            const uint32_t block = global_word / 16;
            if (block >= call.first_blocks) {
                out.note =
                    "stage3:v5_v6_bus:first_uniform_prefix:"
                    "message_word_range";
                return out;
            }
            MessageTarget target;
            target.instance = call.base + block;
            target.address = global_word % 16 + 1;
            target.value =
                out.boundaries[target.instance]
                    .external_values[target.address - 1];
            target.lane_seed_bit.fill(-1);
            for (uint32_t byte = 0; byte < 4; ++byte) {
                const uint32_t global_byte =
                    4 * global_word + byte;
                if (global_byte < lane_seed_offset ||
                    global_byte >= lane_seed_offset + 32) {
                    continue;
                }
                const uint32_t digest_byte =
                    global_byte - lane_seed_offset;
                const uint32_t source_word =
                    digest_byte / 4;
                const uint32_t source_byte =
                    digest_byte % 4;
                for (uint32_t bit = 0; bit < 8; ++bit) {
                    const uint32_t target_bit =
                        8 * (3 - byte) + bit;
                    const uint32_t source_bit =
                        32 * source_word +
                        8 * (3 - source_byte) + bit;
                    target.lane_seed_bit[target_bit] =
                        static_cast<int16_t>(source_bit);
                }
            }
            out.public_external_masks[target.instance]
                [target.address - 1] = 0;
            message_targets.push_back(target);
        }
    }
    out.digest_message_words =
        static_cast<uint32_t>(message_targets.size());
    out.exact_word_links =
        static_cast<uint32_t>(out.links.size());

    HashWriter seed_hash;
    seed_hash <<
        "BTX_RC_STAGE3_V5_UNIFORM_DRAW_PREFIX_AIR_V1";
    seed_hash << child_fs_seed;
    seed_hash << semantic.public_boundary_commitment;
    seed_hash << static_cast<uint8_t>(relation);
    seed_hash << lane;
    seed_hash << item;
    seed_hash << out.compression_blocks;
    seed_hash << out.exact_word_links;
    seed_hash << out.digest_message_words;
    const uint256 air_seed = seed_hash.GetHash();
    out.vertical_air_seed = air_seed;
    out.sha_execution =
        ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
            program, out.boundaries,
            out.public_external_masks, out.links, air_seed);
    if (!out.sha_execution.valid) {
        out.note =
            "stage3:v5_v6_bus:first_uniform_prefix:sha:" +
            out.sha_execution.note;
        return out;
    }

    auto& cs = out.sha_execution.cs;
    auto& columns = out.sha_execution.columns;
    const auto add =
        [&](const char* name, aq::AirKind kind,
            uint32_t degree,
            std::function<Fp3(
                const std::vector<Fp3>&,
                const std::vector<Fp3>&)> eval) {
            aq::AirConstraint<Fp3> constraint;
            constraint.name = name;
            constraint.kind = kind;
            constraint.alg_degree = degree;
            constraint.eval = std::move(eval);
            cs.constraints.push_back(std::move(constraint));
        };
    const auto add_columns = [&](uint32_t count) {
        const uint32_t base = cs.n_columns;
        cs.n_columns += count;
        columns.resize(
            cs.n_columns,
            std::vector<Fp3>(
                cs.n_rows, Fp3::Zero()));
        return base;
    };
    const auto two_power = [](uint32_t bit) {
        return Fp3::FromFp(
            gf::FromU64(UINT64_C(1) << bit));
    };

    struct SourceWord {
        uint32_t instance{0};
        uint32_t word{0};
    };
    std::vector<SourceWord> source_words;
    const uint32_t lane_digest_instance =
        lane_seed_call.base + lane_seed_call.first_blocks;
    for (uint32_t word = 0; word < 8; ++word) {
        source_words.push_back(
            {lane_digest_instance, word});
    }
    for (uint32_t call_index = 0;
         call_index < draw_call_count; ++call_index) {
        const auto& call = draw_calls[call_index];
        const uint32_t digest_instance =
            call.base + call.first_blocks;
        for (uint32_t word = 0; word < 8; ++word) {
            source_words.push_back(
                {digest_instance, word});
        }
    }
    const uint32_t source_word_base =
        add_columns(
            2 * static_cast<uint32_t>(
                    source_words.size()) + 256);
    const uint32_t source_selector_base =
        source_word_base +
        static_cast<uint32_t>(source_words.size());
    const uint32_t lane_seed_bit_base =
        source_selector_base +
        static_cast<uint32_t>(source_words.size());
    for (uint32_t index = 0;
         index < source_words.size(); ++index) {
        const auto& source = source_words[index];
        const uint32_t value =
            out.boundaries[source.instance]
                .final_words[source.word];
        std::fill(
            columns[source_word_base + index].begin(),
            columns[source_word_base + index].end(),
            Fp3::FromFp(gf::FromU64(value)));
        std::vector<Fp3> selector_column(
            cs.n_rows, Fp3::Zero());
        selector_column[
            out.sha_execution.final_output_rows[
                8 * source.instance + source.word]] =
            Fp3::One();
        cs.preprocessed.emplace_back(
            source_selector_base + index,
            selector_column);
        columns[source_selector_base + index] =
            std::move(selector_column);
        add("stage3.v5.prefix.source_final_export",
            aq::AirKind::kEverywhere, 2,
            [source_word_base, source_selector_base, index](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[source_selector_base + index],
                    gf::Sub(
                        cur[source_word_base + index],
                        cur[ha::ValueColumn(2)]));
            });
        add("stage3.v5.prefix.source_export_constant",
            aq::AirKind::kTransition, 1,
            [source_word_base, index](
                const auto& cur, const auto& next) {
                return gf::Sub(
                    next[source_word_base + index],
                    cur[source_word_base + index]);
            });
    }
    for (uint32_t word = 0; word < 8; ++word) {
        const uint32_t value =
            out.boundaries[lane_digest_instance]
                .final_words[word];
        for (uint32_t bit = 0; bit < 32; ++bit) {
            const uint32_t column =
                lane_seed_bit_base + 32 * word + bit;
            std::fill(
                columns[column].begin(),
                columns[column].end(),
                Fp3::FromFp(gf::FromU64(
                    (value >> bit) & 1U)));
            add("stage3.v5.prefix.lane_seed_bit_boolean",
                aq::AirKind::kEverywhere, 2,
                [column](const auto& cur, const auto&) {
                    return gf::Mul(
                        cur[column],
                        gf::Sub(cur[column], Fp3::One()));
                });
        }
        add("stage3.v5.prefix.lane_seed_word_reconstruct",
            aq::AirKind::kEverywhere, 1,
            [source_word_base, lane_seed_bit_base, word,
             two_power](const auto& cur, const auto&) {
                Fp3 sum = Fp3::Zero();
                for (uint32_t bit = 0; bit < 32; ++bit) {
                    sum = gf::Add(
                        sum,
                        gf::Mul(
                            two_power(bit),
                            cur[lane_seed_bit_base +
                                32 * word + bit]));
                }
                return gf::Sub(
                    cur[source_word_base + word], sum);
            });
    }

    const uint32_t message_base =
        add_columns(
            32 +
            static_cast<uint32_t>(
                message_targets.size()) + 3);
    const uint32_t message_selector_base =
        message_base + 32;
    const uint32_t message_input_mask_base =
        message_selector_base +
        static_cast<uint32_t>(
            message_targets.size());
    out.message_bit_base = message_base;
    std::vector<std::vector<Fp3>> message_selectors(
        message_targets.size(),
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    std::array<std::vector<Fp3>, 3> input_masks;
    for (auto& mask : input_masks) {
        mask.assign(cs.n_rows, Fp3::Zero());
    }
    for (uint32_t target_index = 0;
         target_index < message_targets.size();
         ++target_index) {
        const auto& target = message_targets[target_index];
        for (uint32_t row = 0;
             row < program.rows.size(); ++row) {
            for (uint32_t input = 0;
                 input < program.rows[row].input_count;
                 ++input) {
                if (program.rows[row].input_address[input] !=
                    target.address) {
                    continue;
                }
                const uint32_t trace_row =
                    1024 * target.instance + row;
                if (!gf::IsZero(
                        input_masks[input][trace_row])) {
                    out.note =
                        "stage3:v5_v6_bus:first_uniform_prefix:"
                        "message_collision";
                    return out;
                }
                message_selectors[target_index][trace_row] =
                    Fp3::One();
                input_masks[input][trace_row] = Fp3::One();
                for (uint32_t bit = 0; bit < 32; ++bit) {
                    columns[message_base + bit][trace_row] =
                        Fp3::FromFp(gf::FromU64(
                            (target.value >> bit) & 1U));
                }
            }
        }
        cs.preprocessed.emplace_back(
            message_selector_base + target_index,
            message_selectors[target_index]);
        columns[message_selector_base + target_index] =
            message_selectors[target_index];
        for (uint32_t bit = 0; bit < 32; ++bit) {
            const int16_t source_bit =
                target.lane_seed_bit[bit];
            const Fp3 fixed_bit =
                Fp3::FromFp(gf::FromU64(
                    (target.value >> bit) & 1U));
            add("stage3.v5.prefix.message_digest_bit_link",
                aq::AirKind::kEverywhere, 2,
                [message_base, message_selector_base,
                 lane_seed_bit_base, target_index, bit,
                 source_bit, fixed_bit](
                    const auto& cur, const auto&) {
                    const Fp3 expected =
                        source_bit >= 0
                        ? cur[lane_seed_bit_base +
                              static_cast<uint32_t>(
                                  source_bit)]
                        : fixed_bit;
                    return gf::Mul(
                        cur[message_selector_base +
                            target_index],
                        gf::Sub(
                            cur[message_base + bit],
                            expected));
                });
        }
    }
    for (uint32_t input = 0; input < 3; ++input) {
        cs.preprocessed.emplace_back(
            message_input_mask_base + input,
            input_masks[input]);
        columns[message_input_mask_base + input] =
            input_masks[input];
        add("stage3.v5.prefix.message_word_reconstruct",
            aq::AirKind::kEverywhere, 2,
            [message_base, message_input_mask_base,
             input, two_power](
                const auto& cur, const auto&) {
                Fp3 sum = Fp3::Zero();
                for (uint32_t bit = 0; bit < 32; ++bit) {
                    sum = gf::Add(
                        sum,
                        gf::Mul(
                            two_power(bit),
                            cur[message_base + bit]));
                }
                return gf::Mul(
                    cur[message_input_mask_base + input],
                    gf::Sub(
                        cur[ha::ValueColumn(input)], sum));
            });
    }
    for (uint32_t bit = 0; bit < 32; ++bit) {
        add("stage3.v5.prefix.message_bit_boolean",
            aq::AirKind::kEverywhere, 2,
            [message_base, bit](
                const auto& cur, const auto&) {
                const Fp3 value =
                    cur[message_base + bit];
                return gf::Mul(
                    value,
                    gf::Sub(value, Fp3::One()));
            });
    }

    if (is_query) {
        constexpr uint32_t QUERY_BITS = 0;
        constexpr uint32_t QUERY_OUTPUT = 32;
        constexpr uint32_t QUERY_COLUMNS = 33;
        const uint32_t query_base =
            add_columns(QUERY_COLUMNS);
        out.candidate_bit_base =
            query_base + QUERY_BITS;
        out.draw_output_base =
            query_base + QUERY_OUTPUT;
        uint32_t raw = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            raw |= uint32_t{
                draw_calls[0].digest[byte]} << (8 * byte);
        }
        for (uint32_t bit = 0; bit < 32; ++bit) {
            std::fill(
                columns[query_base + QUERY_BITS + bit]
                    .begin(),
                columns[query_base + QUERY_BITS + bit]
                    .end(),
                Fp3::FromFp(gf::FromU64(
                    (raw >> bit) & 1U)));
            add("stage3.v5.query.raw_bit_boolean",
                aq::AirKind::kEverywhere, 2,
                [query_base, bit](
                    const auto& cur, const auto&) {
                    const Fp3 value =
                        cur[query_base +
                            QUERY_BITS + bit];
                    return gf::Mul(
                        value,
                        gf::Sub(value, Fp3::One()));
                });
        }
        std::fill(
            columns[query_base + QUERY_OUTPUT].begin(),
            columns[query_base + QUERY_OUTPUT].end(),
            Fp3::FromFp(gf::FromU64(query_index)));
        add("stage3.v5.query.digest_word_byte_conversion",
            aq::AirKind::kEverywhere, 1,
            [query_base, source_word_base, two_power](
                const auto& cur, const auto&) {
                Fp3 reconstructed = Fp3::Zero();
                for (uint32_t byte = 0; byte < 4;
                     ++byte) {
                    for (uint32_t bit = 0; bit < 8;
                         ++bit) {
                        reconstructed = gf::Add(
                            reconstructed,
                            gf::Mul(
                                two_power(
                                    8 * (3 - byte) + bit),
                                cur[query_base +
                                    QUERY_BITS +
                                    8 * byte + bit]));
                    }
                }
                return gf::Sub(
                    cur[source_word_base + 8],
                    reconstructed);
            });
        uint32_t domain_bits = 0;
        for (uint32_t size =
                 proof.row_commit.n_leaves;
             size > 1; size >>= 1) {
            ++domain_bits;
        }
        add("stage3.v5.query.power_of_two_reduction",
            aq::AirKind::kEverywhere, 1,
            [query_base, domain_bits, two_power](
                const auto& cur, const auto&) {
                Fp3 reduced = Fp3::Zero();
                for (uint32_t bit = 0;
                     bit < domain_bits; ++bit) {
                    reduced = gf::Add(
                        reduced,
                        gf::Mul(
                            two_power(bit),
                            cur[query_base +
                                QUERY_BITS + bit]));
                }
                return gf::Sub(
                    cur[query_base + QUERY_OUTPUT],
                    reduced);
            });
        add("stage3.v5.query.output_constant",
            aq::AirKind::kTransition, 1,
            [query_base](
                const auto& cur, const auto& next) {
                return gf::Sub(
                    next[query_base + QUERY_OUTPUT],
                    cur[query_base + QUERY_OUTPUT]);
            });

        bool found = false;
        for (const auto& cell : semantic.cells) {
            if (cell.family !=
                    ChallengeFeedbackFamily::QueryIndex ||
                cell.lane != lane ||
                cell.item_index != item ||
                cell.coordinate != 0) {
                continue;
            }
            if (found ||
                !gf::Eq(
                    out.draw_output[0],
                    Fp3::FromFp(
                        cell.expected_v5_value))) {
                out.note =
                    "stage3:v5_v6_bus:"
                    "first_uniform_prefix:"
                    "query_v5_output_mismatch";
                return out;
            }
            found = true;
            out.v5_semantic_rows[0] =
                cell.semantic_row;
            const Fp3 expected =
                Fp3::FromFp(cell.expected_v5_value);
            add("stage3.v5.query.v5_consumer_equality",
                aq::AirKind::kFirstRow, 1,
                [query_base, expected](
                    const auto& cur, const auto&) {
                    return gf::Sub(
                        cur[query_base + QUERY_OUTPUT],
                        expected);
                });
        }
        if (!found) {
            out.note =
                "stage3:v5_v6_bus:first_uniform_prefix:"
                "query_v5_cell_missing";
            return out;
        }
        out.v5_semantic_cell_count = 1;

        HashWriter statement;
        statement <<
            "BTX_RC_STAGE3_V5_UNIFORM_DRAW_PREFIX_STATEMENT_V1";
        statement << out.sha_execution.public_statement;
        statement << semantic.public_boundary_commitment;
        statement << static_cast<uint8_t>(relation);
        statement << lane;
        statement << item;
        statement << proof.row_commit.n_leaves;
        statement << domain_bits;
        statement << lane_seed_offset;
        statement << out.compression_blocks;
        statement << out.exact_word_links;
        statement << out.digest_message_words;
        statement << out.v5_semantic_cell_count;
        statement << out.v5_semantic_rows[0];
        out.prefix_statement = statement.GetHash();
        out.trace_rows = cs.n_rows;
        out.trace_columns = cs.n_columns;
        out.constraints =
            static_cast<uint32_t>(
                cs.constraints.size());
        out.proof_owned_sha_derivation_cells = 0;
        out.recursively_consumed_sha_derivation_cells = 0;
        const uint32_t violations =
            v6::CountViolations(cs, columns);
        out.valid =
            violations == 0 &&
            !out.prefix_statement.IsNull() &&
            out.trace_columns <
                kStage3RecursiveColumnCap;
        out.note = out.valid
            ? "stage3:v5_v6_bus:"
              "query_prefix:sha_digest_bits_mask_v5_bound"
            : "stage3:v5_v6_bus:query_prefix:"
              "violations=" +
                  std::to_string(violations);
        return out;
    }

    constexpr uint32_t CANDIDATE_BITS = 0;
    constexpr uint32_t HIGH_PREFIX =
        CANDIDATE_BITS + 64;
    constexpr uint32_t LOW_ZERO_PREFIX =
        HIGH_PREFIX + 32;
    constexpr uint32_t ACCEPT =
        LOW_ZERO_PREFIX + 32;
    constexpr uint32_t WORD = ACCEPT + 1;
    constexpr uint32_t COUNT_STATE = WORD + 1;
    constexpr uint32_t SELECT = COUNT_STATE + 9;
    constexpr uint32_t OUTPUT = SELECT + 3;
    constexpr uint32_t CANDIDATE_SELECTOR =
        OUTPUT + 3;
    constexpr uint32_t CANDIDATE_ACTIVE =
        CANDIDATE_SELECTOR + 8;
    constexpr uint32_t TERMINAL =
        CANDIDATE_ACTIVE + 1;
    constexpr uint32_t SAMPLER_COLUMNS =
        TERMINAL + 1;
    const uint32_t sampler_base =
        add_columns(SAMPLER_COLUMNS);
    out.candidate_bit_base =
        sampler_base + CANDIDATE_BITS;
    out.accepted_count_base =
        sampler_base + COUNT_STATE;
    out.draw_output_base =
        sampler_base + OUTPUT;
    std::array<std::vector<Fp3>, 8>
        candidate_selectors;
    for (auto& selector : candidate_selectors) {
        selector.assign(cs.n_rows, Fp3::Zero());
    }
    std::vector<Fp3> candidate_active(
        cs.n_rows, Fp3::Zero());
    std::vector<Fp3> terminal(
        cs.n_rows, Fp3::Zero());
    std::array<uint8_t, 8> accepted{};
    std::array<uint32_t, 3> selected_index{};
    uint32_t accepted_count = 0;
    for (uint32_t candidate = 0;
         candidate < sampled_words.size(); ++candidate) {
        const uint64_t word = sampled_words[candidate];
        accepted[candidate] = word < gf::kP;
        candidate_selectors[candidate][candidate] =
            Fp3::One();
        candidate_active[candidate] = Fp3::One();
        for (uint32_t bit = 0; bit < 64; ++bit) {
            columns[sampler_base + CANDIDATE_BITS + bit]
                [candidate] =
                Fp3::FromFp(gf::FromU64(
                    (word >> bit) & 1U));
        }
        Fp3 high = Fp3::One();
        Fp3 low_zero = Fp3::One();
        for (uint32_t bit = 0; bit < 32; ++bit) {
            high = gf::Mul(
                high,
                columns[sampler_base +
                    CANDIDATE_BITS + 32 + bit]
                    [candidate]);
            low_zero = gf::Mul(
                low_zero,
                gf::Sub(
                    Fp3::One(),
                    columns[sampler_base +
                        CANDIDATE_BITS + bit]
                        [candidate]));
            columns[sampler_base + HIGH_PREFIX + bit]
                [candidate] = high;
            columns[
                sampler_base + LOW_ZERO_PREFIX + bit]
                [candidate] = low_zero;
        }
        columns[sampler_base + ACCEPT][candidate] =
            Fp3::FromFp(gf::FromU64(
                accepted[candidate]));
        columns[sampler_base + WORD][candidate] =
            Fp3::FromFp(gf::FromU64(word));
        if (accepted[candidate] &&
            accepted_count < 3) {
            selected_index[accepted_count] =
                candidate;
            columns[
                sampler_base + SELECT +
                accepted_count][candidate] =
                Fp3::One();
        }
        accepted_count += accepted[candidate];
    }
    if (accepted_count < 3) {
        out.note =
            "stage3:v5_v6_bus:first_uniform_prefix:"
            "sampler_exhausted";
        return out;
    }
    uint32_t running_count = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        if (row > 0 && row <= 8) {
            running_count += accepted[row - 1];
        }
        columns[
            sampler_base + COUNT_STATE +
            running_count][row] = Fp3::One();
    }
    terminal[8] = Fp3::One();
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        std::fill(
            columns[sampler_base + OUTPUT + coordinate]
                .begin(),
            columns[sampler_base + OUTPUT + coordinate]
                .end(),
            out.draw_output[coordinate]);
    }
    for (uint32_t candidate = 0;
         candidate < 8; ++candidate) {
        cs.preprocessed.emplace_back(
            sampler_base + CANDIDATE_SELECTOR +
                candidate,
            candidate_selectors[candidate]);
        columns[
            sampler_base + CANDIDATE_SELECTOR +
            candidate] =
            candidate_selectors[candidate];
    }
    cs.preprocessed.emplace_back(
        sampler_base + CANDIDATE_ACTIVE,
        candidate_active);
    columns[sampler_base + CANDIDATE_ACTIVE] =
        candidate_active;
    cs.preprocessed.emplace_back(
        sampler_base + TERMINAL, terminal);
    columns[sampler_base + TERMINAL] = terminal;
    cs.preprocessed_pin_ood = true;

    for (uint32_t bit = 0; bit < 64; ++bit) {
        add("stage3.v5.prefix.candidate_bit_boolean",
            aq::AirKind::kEverywhere, 2,
            [sampler_base, bit](
                const auto& cur, const auto&) {
                const Fp3 value =
                    cur[sampler_base +
                        CANDIDATE_BITS + bit];
                return gf::Mul(
                    value,
                    gf::Sub(value, Fp3::One()));
            });
    }
    add("stage3.v5.prefix.candidate_word_reconstruct",
        aq::AirKind::kEverywhere, 2,
        [sampler_base, two_power](
            const auto& cur, const auto&) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t bit = 0; bit < 64; ++bit) {
                sum = gf::Add(
                    sum,
                    gf::Mul(
                        two_power(bit),
                        cur[sampler_base +
                            CANDIDATE_BITS + bit]));
            }
            return gf::Sub(
                cur[sampler_base + WORD],
                gf::Mul(
                    cur[sampler_base + CANDIDATE_ACTIVE],
                    sum));
        });
    for (uint32_t bit = 0; bit < 32; ++bit) {
        add("stage3.v5.prefix.high_prefix",
            aq::AirKind::kEverywhere, 3,
            [sampler_base, bit](
                const auto& cur, const auto&) {
                const Fp3 previous = bit == 0
                    ? Fp3::One()
                    : cur[sampler_base +
                        HIGH_PREFIX + bit - 1];
                return gf::Mul(
                    cur[sampler_base + CANDIDATE_ACTIVE],
                    gf::Sub(
                        cur[sampler_base +
                            HIGH_PREFIX + bit],
                        gf::Mul(
                            previous,
                            cur[sampler_base +
                                CANDIDATE_BITS +
                                32 + bit])));
            });
        add("stage3.v5.prefix.low_zero_prefix",
            aq::AirKind::kEverywhere, 3,
            [sampler_base, bit](
                const auto& cur, const auto&) {
                const Fp3 previous = bit == 0
                    ? Fp3::One()
                    : cur[sampler_base +
                        LOW_ZERO_PREFIX + bit - 1];
                return gf::Mul(
                    cur[sampler_base + CANDIDATE_ACTIVE],
                    gf::Sub(
                        cur[sampler_base +
                            LOW_ZERO_PREFIX + bit],
                        gf::Mul(
                            previous,
                            gf::Sub(
                                Fp3::One(),
                                cur[sampler_base +
                                    CANDIDATE_BITS +
                                    bit]))));
            });
    }
    add("stage3.v5.prefix.accept_lt_p",
        aq::AirKind::kEverywhere, 3,
        [sampler_base](const auto& cur, const auto&) {
            const Fp3 expected = gf::Sub(
                Fp3::One(),
                gf::Mul(
                    cur[sampler_base + HIGH_PREFIX + 31],
                    gf::Sub(
                        Fp3::One(),
                        cur[sampler_base +
                            LOW_ZERO_PREFIX + 31])));
            return gf::Sub(
                cur[sampler_base + ACCEPT],
                gf::Mul(
                    cur[sampler_base + CANDIDATE_ACTIVE],
                    expected));
        });
    for (uint32_t candidate = 0;
         candidate < 8; ++candidate) {
        for (uint32_t half = 0; half < 2; ++half) {
            add("stage3.v5.prefix.digest_to_candidate",
                aq::AirKind::kEverywhere, 2,
                [sampler_base, source_word_base,
                 candidate, half, two_power](
                    const auto& cur, const auto&) {
                    Fp3 reconstructed = Fp3::Zero();
                    for (uint32_t byte = 0;
                         byte < 4; ++byte) {
                        for (uint32_t bit = 0;
                             bit < 8; ++bit) {
                            reconstructed = gf::Add(
                                reconstructed,
                                gf::Mul(
                                    two_power(
                                        8 * (3 - byte) +
                                        bit),
                                    cur[sampler_base +
                                        CANDIDATE_BITS +
                                        32 * half +
                                        8 * byte + bit]));
                        }
                    }
                    const uint32_t source =
                        8 + 8 * (candidate / 4) +
                        2 * (candidate % 4) + half;
                    return gf::Mul(
                        cur[sampler_base +
                            CANDIDATE_SELECTOR +
                            candidate],
                        gf::Sub(
                            cur[source_word_base + source],
                            reconstructed));
                });
        }
    }
    for (uint32_t state = 0; state < 9; ++state) {
        add("stage3.v5.prefix.count_state_boolean",
            aq::AirKind::kEverywhere, 2,
            [sampler_base, state](
                const auto& cur, const auto&) {
                const Fp3 value =
                    cur[sampler_base +
                        COUNT_STATE + state];
                return gf::Mul(
                    value,
                    gf::Sub(value, Fp3::One()));
            });
        add("stage3.v5.prefix.count_state_initial",
            aq::AirKind::kFirstRow, 1,
            [sampler_base, state](
                const auto& cur, const auto&) {
                return gf::Sub(
                    cur[sampler_base +
                        COUNT_STATE + state],
                    state == 0
                        ? Fp3::One()
                        : Fp3::Zero());
            });
        add("stage3.v5.prefix.count_transition",
            aq::AirKind::kTransition, 3,
            [sampler_base, state](
                const auto& cur, const auto& next) {
                const Fp3 accept =
                    cur[sampler_base + ACCEPT];
                Fp3 expected = gf::Mul(
                    cur[sampler_base +
                        COUNT_STATE + state],
                    gf::Sub(Fp3::One(), accept));
                if (state > 0) {
                    expected = gf::Add(
                        expected,
                        gf::Mul(
                            cur[sampler_base +
                                COUNT_STATE + state - 1],
                            accept));
                }
                return gf::Mul(
                    cur[sampler_base +
                        CANDIDATE_ACTIVE],
                    gf::Sub(
                        next[sampler_base +
                            COUNT_STATE + state],
                        expected));
            });
    }
    add("stage3.v5.prefix.count_state_one_hot",
        aq::AirKind::kEverywhere, 1,
        [sampler_base](const auto& cur, const auto&) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t state = 0; state < 9; ++state) {
                sum = gf::Add(
                    sum,
                    cur[sampler_base +
                        COUNT_STATE + state]);
            }
            return gf::Sub(sum, Fp3::One());
        });
    add("stage3.v5.prefix.at_least_three",
        aq::AirKind::kEverywhere, 2,
        [sampler_base](const auto& cur, const auto&) {
            Fp3 enough = Fp3::Zero();
            for (uint32_t state = 3; state < 9; ++state) {
                enough = gf::Add(
                    enough,
                    cur[sampler_base +
                        COUNT_STATE + state]);
            }
            return gf::Mul(
                cur[sampler_base + TERMINAL],
                gf::Sub(enough, Fp3::One()));
        });
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        add("stage3.v5.prefix.first_three_selector",
            aq::AirKind::kEverywhere, 2,
            [sampler_base, coordinate](
                const auto& cur, const auto&) {
                return gf::Sub(
                    cur[sampler_base +
                        SELECT + coordinate],
                    gf::Mul(
                        cur[sampler_base + ACCEPT],
                        cur[sampler_base +
                            COUNT_STATE + coordinate]));
            });
        add("stage3.v5.prefix.selected_draw_output",
            aq::AirKind::kEverywhere, 2,
            [sampler_base, coordinate](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[sampler_base +
                        SELECT + coordinate],
                    gf::Sub(
                        cur[sampler_base +
                            OUTPUT + coordinate],
                        cur[sampler_base + WORD]));
            });
        add("stage3.v5.prefix.draw_output_constant",
            aq::AirKind::kTransition, 1,
            [sampler_base, coordinate](
                const auto& cur, const auto& next) {
                return gf::Sub(
                    next[sampler_base +
                        OUTPUT + coordinate],
                    cur[sampler_base +
                        OUTPUT + coordinate]);
            });
    }

    if (!is_ood) {
        const ChallengeFeedbackFamily semantic_family =
            is_batch
            ? ChallengeFeedbackFamily::BatchCoefficient
            : is_deep
                ? ChallengeFeedbackFamily::DeepWeight
                : ChallengeFeedbackFamily::FoldChallenge;
        std::array<bool, 3> found_v5{};
        for (const auto& cell : semantic.cells) {
            if (cell.family != semantic_family ||
                cell.lane != lane ||
                cell.item_index != item ||
                cell.coordinate >= 3) {
                continue;
            }
            const uint32_t coordinate = cell.coordinate;
            if (found_v5[coordinate] ||
                !gf::Eq(
                    out.draw_output[coordinate],
                    Fp3::FromFp(
                        cell.expected_v5_value))) {
                out.note =
                    "stage3:v5_v6_bus:first_uniform_prefix:"
                    "v5_output_mismatch";
                return out;
            }
            found_v5[coordinate] = true;
            out.v5_semantic_rows[coordinate] =
                cell.semantic_row;
            const Fp3 expected =
                Fp3::FromFp(cell.expected_v5_value);
            add("stage3.v5.prefix.v5_consumer_equality",
                aq::AirKind::kFirstRow, 1,
                [sampler_base, coordinate, expected](
                    const auto& cur, const auto&) {
                    return gf::Sub(
                        cur[sampler_base +
                            OUTPUT + coordinate],
                        expected);
                });
        }
        if (!std::all_of(
                found_v5.begin(), found_v5.end(),
                [](bool found) { return found; })) {
            out.note =
                "stage3:v5_v6_bus:first_uniform_prefix:"
                "v5_cells_missing";
            return out;
        }
        out.v5_semantic_cell_count = 3;
    }

    HashWriter statement;
    statement <<
        "BTX_RC_STAGE3_V5_UNIFORM_DRAW_PREFIX_STATEMENT_V1";
    statement << out.sha_execution.public_statement;
    statement << semantic.public_boundary_commitment;
    statement << static_cast<uint8_t>(relation);
    statement << lane;
    statement << item;
    statement << lane_seed_offset;
    statement << out.compression_blocks;
    statement << out.exact_word_links;
    statement << out.digest_message_words;
    statement << out.v5_semantic_cell_count;
    for (uint32_t coordinate = 0;
         coordinate < out.v5_semantic_cell_count;
         ++coordinate) {
        statement << out.v5_semantic_rows[coordinate];
    }
    out.prefix_statement = statement.GetHash();
    out.trace_rows = cs.n_rows;
    out.trace_columns = cs.n_columns;
    out.constraints =
        static_cast<uint32_t>(cs.constraints.size());
    out.proof_owned_sha_derivation_cells = 0;
    out.recursively_consumed_sha_derivation_cells = 0;
    const uint32_t violations =
        v6::CountViolations(cs, columns);
    out.valid =
        violations == 0 &&
        !out.prefix_statement.IsNull() &&
        out.trace_columns < kStage3RecursiveColumnCap;
    out.note = out.valid
        ? "stage3:v5_v6_bus:first_uniform_prefix:"
          "witness_sha_chain_sampler_v5_bound"
        : "stage3:v5_v6_bus:first_uniform_prefix:"
          "violations=" + std::to_string(violations);
    return out;
}

} // namespace

V5FirstUniformDrawWitnessPrefix
BuildV5BatchCoefficientDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t batch_item)
{
    return BuildV5UniformDrawWitnessPrefixImplV1(
        composition, child, child_fs_seed,
        V5UniformDrawRelationV1::BatchCoefficient,
        lane, batch_item);
}

V5FirstUniformDrawWitnessPrefix
BuildV5OodCandidateDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t candidate)
{
    return BuildV5UniformDrawWitnessPrefixImplV1(
        composition, child, child_fs_seed,
        V5UniformDrawRelationV1::OodCandidate,
        lane, candidate);
}

V5FirstUniformDrawWitnessPrefix
BuildV5DeepWeightDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t item)
{
    return BuildV5UniformDrawWitnessPrefixImplV1(
        composition, child, child_fs_seed,
        V5UniformDrawRelationV1::DeepWeight,
        lane, item);
}

V5FirstUniformDrawWitnessPrefix
BuildV5FoldChallengeDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t fold)
{
    return BuildV5UniformDrawWitnessPrefixImplV1(
        composition, child, child_fs_seed,
        V5UniformDrawRelationV1::FoldChallenge,
        lane, fold);
}

V5FirstUniformDrawWitnessPrefix
BuildV5QueryIndexDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t query)
{
    return BuildV5UniformDrawWitnessPrefixImplV1(
        composition, child, child_fs_seed,
        V5UniformDrawRelationV1::QueryIndex,
        lane, query);
}

V5FirstUniformDrawWitnessPrefix
BuildV5FirstUniformDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed)
{
    return BuildV5BatchCoefficientDrawWitnessPrefix(
        composition, child, child_fs_seed, 0, 0);
}

namespace {

uint256 CommitV5FirstUniformSplitFriSchedule(
    const V5FirstUniformSplitFriPlan& plan)
{
    if (plan.prefix_statement.IsNull() ||
        plan.groups.size() != 3) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_FIRST_UNIFORM_SPLIT_RAP_V1";
    hash << plan.prefix_statement;
    hash << plan.trace_rows;
    hash << plan.trace_columns;
    hash << plan.n_coeffs;
    hash << plan.n_lde;
    hash << plan.query_count;
    hash << plan.quotient_virtual_column;
    hash << static_cast<uint32_t>(
        plan.groups.size());
    for (const auto& group : plan.groups) {
        hash << static_cast<uint8_t>(group.role);
        hash << group.first_flattened_column;
        hash << static_cast<uint32_t>(
            group.air_column_indices.size());
        for (uint32_t column :
             group.air_column_indices) {
            hash << column;
        }
    }
    return hash.GetHash();
}

} // namespace

V5FirstUniformSplitFriPlan
BuildV5FirstUniformSplitFriPlan(
    const V5FirstUniformDrawWitnessPrefix& prefix)
{
    V5FirstUniformSplitFriPlan out;
    if (!prefix.valid ||
        prefix.prefix_statement.IsNull() ||
        prefix.sha_execution.base_row_commitment.IsNull() ||
        prefix.sha_execution.base_column_indices.empty() ||
        !prefix.sha_execution.base_row_tree_cache ||
        prefix.sha_execution.cs.n_columns !=
            prefix.trace_columns) {
        out.note =
            "stage3:v5_v6_bus:split_fri_plan:prefix";
        return out;
    }
    out.prefix_statement =
        prefix.prefix_statement;
    out.trace_rows = prefix.trace_rows;
    out.trace_columns = prefix.trace_columns;
    out.n_coeffs = FriNextPow2(
        std::max(
            prefix.sha_execution.cs.n_rows,
            prefix.sha_execution.cs.QuotientLen()));
    out.n_lde =
        out.n_coeffs * kRCFriBlowup;
    out.query_count =
        kRCFri3AlgNumQueries;
    out.quotient_virtual_column =
        prefix.trace_columns;

    V5SplitFriGroupPlan r0;
    r0.role = V5SplitFriGroupRole::R0Base;
    r0.first_flattened_column = 0;
    r0.air_column_indices =
        prefix.sha_execution.base_column_indices;
    r0.row_commitment =
        prefix.sha_execution.base_row_commitment;

    std::vector<uint8_t> is_base(
        prefix.trace_columns, 0);
    for (uint32_t column :
         r0.air_column_indices) {
        if (column >= prefix.trace_columns ||
            is_base[column]) {
            out.note =
                "stage3:v5_v6_bus:split_fri_plan:r0";
            return out;
        }
        is_base[column] = 1;
    }
    V5SplitFriGroupPlan rdep;
    rdep.role = V5SplitFriGroupRole::Rdep;
    rdep.first_flattened_column =
        static_cast<uint32_t>(
            r0.air_column_indices.size());
    for (uint32_t column = 0;
         column < prefix.trace_columns; ++column) {
        if (!is_base[column]) {
            rdep.air_column_indices.push_back(column);
        }
    }
    V5SplitFriGroupPlan rq;
    rq.role = V5SplitFriGroupRole::Rq;
    rq.first_flattened_column =
        rdep.first_flattened_column +
        static_cast<uint32_t>(
            rdep.air_column_indices.size());
    rq.air_column_indices.push_back(
        out.quotient_virtual_column);
    out.groups = {
        std::move(r0),
        std::move(rdep),
        std::move(rq)};
    out.group_schedule_commitment =
        CommitV5FirstUniformSplitFriSchedule(out);

    out.r0_precedes_sha_challenges = true;
    out.rdep_precedes_constraint_batch_challenge =
        true;
    out.rq_precedes_fri_challenges = true;
    out.ordered_roots_absorbed_once = true;
    out.one_rlc_deep_fold_over_all_groups = true;
    out.shared_query_opens_all_groups = true;
    out.logical_columns_partitioned_once = true;
    // Reaching this point establishes the exact application prerequisites for
    // AirQuotientProveRowsSplitRap/AirQuotientVerifyRowsSplitRap: a retained,
    // correctly-sized R0 cache; a strict R0/Rdep complement; one Rq virtual
    // column; and the canonical Q192 shared-query schedule.
    out.backend_executable = true;
    out.global_soundness_accounted = false;
    out.proof_owned_sha_derivation_cells = 0;
    out.recursively_consumed_sha_derivation_cells =
        0;
    out.valid = true;
    out.note =
        "stage3:v5_v6_bus:split_fri_plan:"
        "exact_r0_rdep_rq_partition;"
        "multi_row_v2_backend_executable;"
        "global_soundness_pending";
    std::string why;
    if (!ValidateV5FirstUniformSplitFriPlan(
            prefix, out, &why)) {
        out.valid = false;
        out.note = why;
    }
    return out;
}

bool ValidateV5FirstUniformSplitFriPlan(
    const V5FirstUniformDrawWitnessPrefix& prefix,
    const V5FirstUniformSplitFriPlan& plan,
    std::string* why)
{
    const auto fail = [&](const char* detail) {
        if (why != nullptr) {
            *why =
                std::string{
                    "stage3:v5_v6_bus:"
                    "split_fri_plan:"} +
                detail;
        }
        return false;
    };
    if (!prefix.valid || !plan.valid ||
        plan.version != 1 ||
        plan.prefix_statement !=
            prefix.prefix_statement ||
        plan.trace_rows != prefix.trace_rows ||
        plan.trace_columns !=
            prefix.trace_columns ||
        plan.n_coeffs != FriNextPow2(
            std::max(
                prefix.sha_execution.cs.n_rows,
                prefix.sha_execution.cs.QuotientLen())) ||
        !prefix.sha_execution.base_row_tree_cache ||
        prefix.sha_execution.base_row_tree_cache
                ->n_coeffs != plan.n_coeffs ||
        plan.n_lde !=
            plan.n_coeffs * kRCFriBlowup ||
        plan.query_count !=
            kRCFri3AlgNumQueries ||
        plan.quotient_virtual_column !=
            prefix.trace_columns ||
        plan.groups.size() != 3 ||
        plan.group_schedule_commitment.IsNull() ||
        plan.group_schedule_commitment !=
            CommitV5FirstUniformSplitFriSchedule(
                plan)) {
        return fail("shape");
    }
    if (plan.groups[0].role !=
            V5SplitFriGroupRole::R0Base ||
        plan.groups[1].role !=
            V5SplitFriGroupRole::Rdep ||
        plan.groups[2].role !=
            V5SplitFriGroupRole::Rq ||
        plan.groups[0].first_flattened_column !=
            0 ||
        plan.groups[1].first_flattened_column !=
            plan.groups[0].air_column_indices.size() ||
        plan.groups[2].first_flattened_column !=
            plan.groups[1].first_flattened_column +
            plan.groups[1].air_column_indices.size()) {
        return fail("group_order");
    }
    if (plan.groups[0].air_column_indices !=
            prefix.sha_execution.base_column_indices ||
        plan.groups[0].row_commitment !=
            prefix.sha_execution.base_row_commitment ||
        plan.groups[0].row_commitment.IsNull() ||
        !plan.groups[1].row_commitment.IsNull() ||
        !plan.groups[2].row_commitment.IsNull() ||
        plan.groups[2].air_column_indices !=
            std::vector<uint32_t>{
                prefix.trace_columns}) {
        return fail("root_or_r0");
    }
    std::vector<uint8_t> seen(
        prefix.trace_columns + 1, 0);
    for (uint32_t group = 0;
         group < plan.groups.size(); ++group) {
        for (uint32_t column :
             plan.groups[group].air_column_indices) {
            if (column > prefix.trace_columns ||
                seen[column] ||
                (group < 2 &&
                 column == prefix.trace_columns) ||
                (group == 2 &&
                 column != prefix.trace_columns)) {
                return fail("overlap_or_range");
            }
            seen[column] = 1;
        }
    }
    if (!std::all_of(
            seen.begin(), seen.end(),
            [](uint8_t value) {
                return value == 1;
            })) {
        return fail("missing_column");
    }
    if (!plan.r0_precedes_sha_challenges ||
        !plan.rdep_precedes_constraint_batch_challenge ||
        !plan.rq_precedes_fri_challenges ||
        !plan.ordered_roots_absorbed_once ||
        !plan.one_rlc_deep_fold_over_all_groups ||
        !plan.shared_query_opens_all_groups ||
        !plan.logical_columns_partitioned_once) {
        return fail("transcript_order");
    }
    if (!plan.backend_executable ||
        plan.global_soundness_accounted ||
        plan.proof_owned_sha_derivation_cells != 0 ||
        plan.recursively_consumed_sha_derivation_cells !=
            0) {
        return fail("unearned_completion");
    }
    return true;
}

namespace {

uint256 V5FirstUniformSplitRapSeed(
    const V5FirstUniformDrawWitnessPrefix& prefix)
{
    if (!prefix.valid ||
        prefix.prefix_statement.IsNull() ||
        prefix.sha_execution.public_statement.IsNull() ||
        prefix.vertical_air_seed.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_FIRST_UNIFORM_SPLIT_RAP_PROOF_V1";
    hash << prefix.prefix_statement;
    hash << prefix.sha_execution.public_statement;
    hash << prefix.vertical_air_seed;
    hash << prefix.trace_rows;
    hash << prefix.trace_columns;
    hash << prefix.constraints;
    hash << prefix.compression_blocks;
    hash << prefix.exact_word_links;
    hash << prefix.digest_message_words;
    hash << static_cast<uint8_t>(prefix.relation);
    hash << prefix.lane;
    hash << prefix.batch_item;
    hash << prefix.v5_semantic_cell_count;
    for (uint32_t coordinate = 0;
         coordinate < prefix.v5_semantic_cell_count;
         ++coordinate) {
        hash << prefix.v5_semantic_rows[coordinate];
    }
    return hash.GetHash();
}

bool SamePublicCoreConstraintSchedule(
    const aq::AirConstraintSystem<Fp3>& public_core,
    const aq::AirConstraintSystem<Fp3>& full_prefix,
    std::string* why)
{
    if (public_core.n_rows !=
            full_prefix.n_rows ||
        public_core.n_columns >
            full_prefix.n_columns ||
        public_core.constraints.size() >
            full_prefix.constraints.size()) {
        return Fail(why, "split_rap_public_core_shape");
    }
    for (size_t constraint = 0;
         constraint <
             public_core.constraints.size();
         ++constraint) {
        const auto& expected =
            public_core.constraints[constraint];
        const auto& actual =
            full_prefix.constraints[constraint];
        if (std::string{expected.name} !=
                std::string{actual.name} ||
            expected.kind != actual.kind ||
            expected.alg_degree !=
                actual.alg_degree) {
            return Fail(
                why,
                "split_rap_public_core_constraint");
        }
    }
    for (const auto& prep : public_core.preprocessed) {
        const uint32_t column{prep.first};
        const auto& values{prep.second};
        const auto found =
            std::find_if(
                full_prefix.preprocessed.begin(),
                full_prefix.preprocessed.end(),
                [column](const auto& item) {
                    return item.first == column;
                });
        if (found ==
                full_prefix.preprocessed.end() ||
            found->second.size() !=
                values.size()) {
            return Fail(
                why,
                "split_rap_public_core_preprocessed");
        }
        for (size_t row = 0;
             row < values.size(); ++row) {
            if (!gf::Eq(
                    values[row],
                    found->second[row])) {
                return Fail(
                    why,
                    "split_rap_public_core_value");
            }
        }
    }
    return true;
}

} // namespace

V5FirstUniformSplitRapProveResult
ProveV5FirstUniformSplitRap(
    const V5FirstUniformDrawWitnessPrefix& prefix)
{
    V5FirstUniformSplitRapProveResult out;
    const auto fail =
        [&](const std::string& detail) {
            out.ok = false;
            out.note =
                "stage3:v5_v6_bus:"
                "first_uniform_split_rap_prove:" +
                detail;
            return out;
        };
    const auto plan =
        BuildV5FirstUniformSplitFriPlan(prefix);
    const uint256 proof_seed =
        V5FirstUniformSplitRapSeed(prefix);
    if (!prefix.valid || !plan.valid ||
        proof_seed.IsNull() ||
        prefix.vertical_air_seed.IsNull() ||
        !prefix.sha_execution
             .base_row_tree_cache ||
        !prefix.sha_execution
             .base_row_tree_cache->valid) {
        return fail("prefix_or_plan");
    }
    aq::AirQuotientTwoEpochBaseRowSession
        retained_r0;
    retained_r0.trace_rows =
        prefix.trace_rows;
    retained_r0.n_coeffs =
        plan.n_coeffs;
    retained_r0.base_column_indices =
        prefix.sha_execution
            .base_column_indices;
    retained_r0.base_row_commitment =
        prefix.sha_execution
            .base_row_commitment;
    retained_r0.row_tree_cache =
        prefix.sha_execution
            .base_row_tree_cache;
    retained_r0.valid = true;
    retained_r0.note =
        "v5_first_uniform_retained_r0";
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            prefix.sha_execution.cs,
            prefix.sha_execution.columns,
            prefix.sha_execution
                .base_column_indices,
            proof_seed, {}, &retained_r0);
    if (!proved.ok ||
        !proved.division_exact ||
        proved.proof.batch.groups.size() != 3) {
        return fail(
            "quotient:" + proved.note);
    }
    const uint256 proved_r0 =
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root);
    if (proved_r0 !=
            prefix.sha_execution
                .base_row_commitment) {
        return fail("r0_mismatch");
    }
    auto& proof = out.proof;
    proof.prefix_statement =
        prefix.prefix_statement;
    proof.sha_public_statement =
        prefix.sha_execution
            .public_statement;
    proof.vertical_air_seed =
        prefix.vertical_air_seed;
    proof.canonical_r0 = proved_r0;
    proof.proved_v5_exports =
        prefix.draw_output;
    proof.quotient = proved.proof;
    proof.proof_owned_v5_cells =
        prefix.v5_semantic_cell_count;
    proof.recursively_consumed_v5_cells = 0;
    proof.full_304_transcript = false;
    out.ok = true;
    out.note =
        "stage3:v5_v6_bus:"
        "first_uniform_split_rap_prove:"
        "draw_exports_proved;"
        "recursive_consumption_0;"
        "full_304_false";
    return out;
}

namespace {

bool VerifyV5UniformDrawSplitRapImplV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    V5UniformDrawRelationV1 relation,
    uint32_t lane,
    uint32_t item,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why)
{
    const auto fail =
        [&](const std::string& detail) {
            return Fail(
                why,
                "first_uniform_split_rap_verify:" +
                detail);
        };
    // Version-1 correctness integration: all inputs here are already-public
    // child proof/transcript values. The future descriptor-only constructor
    // removes the canonical witness allocation without changing this CS.
    V5FirstUniformDrawWitnessPrefix canonical;
    switch (relation) {
    case V5UniformDrawRelationV1::BatchCoefficient:
        canonical =
            BuildV5BatchCoefficientDrawWitnessPrefix(
                composition, child, child_fs_seed,
                lane, item);
        break;
    case V5UniformDrawRelationV1::OodCandidate:
        canonical =
            BuildV5OodCandidateDrawWitnessPrefix(
                composition, child, child_fs_seed,
                lane, item);
        break;
    case V5UniformDrawRelationV1::DeepWeight:
        canonical =
            BuildV5DeepWeightDrawWitnessPrefix(
                composition, child, child_fs_seed,
                lane, item);
        break;
    case V5UniformDrawRelationV1::FoldChallenge:
        canonical =
            BuildV5FoldChallengeDrawWitnessPrefix(
                composition, child, child_fs_seed,
                lane, item);
        break;
    case V5UniformDrawRelationV1::QueryIndex:
        canonical =
            BuildV5QueryIndexDrawWitnessPrefix(
                composition, child, child_fs_seed,
                lane, item);
        break;
    }
    const uint256 proof_seed =
        V5FirstUniformSplitRapSeed(
            canonical);
    if (proof.version != 1 ||
        !canonical.valid ||
        proof.proof_owned_v5_cells !=
            canonical.v5_semantic_cell_count ||
        proof.recursively_consumed_v5_cells != 0 ||
        proof.full_304_transcript ||
        proof.quotient.batch.groups.size() != 3 ||
        proof_seed.IsNull() ||
        proof.prefix_statement !=
            canonical.prefix_statement ||
        proof.sha_public_statement !=
            canonical.sha_execution
                .public_statement ||
        proof.vertical_air_seed !=
            canonical.vertical_air_seed ||
        proof.canonical_r0 !=
            canonical.sha_execution
                .base_row_commitment ||
        Fri3AlgDigestToUint256(
            proof.quotient.batch.groups[0]
                .row_commit.root) !=
            proof.canonical_r0) {
        return fail("canonical_public_statement");
    }

    // Explicitly discard all caller/private SHA words before rebuilding the
    // challenge-dependent core CS. Public-mask words remain unchanged.
    auto redacted =
        canonical.boundaries;
    for (uint32_t instance = 0;
         instance < redacted.size();
         ++instance) {
        std::fill(
            redacted[instance].final_words.begin(),
            redacted[instance].final_words.end(),
            0xdeadbeefU);
        for (uint32_t external = 0;
             external <
                 redacted[instance]
                     .external_values.size();
             ++external) {
            if (!canonical
                     .public_external_masks[
                         instance][external]) {
                redacted[instance]
                    .external_values[external] =
                    0xa5a5a5a5U;
            }
        }
    }
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::
                Sha256Compression);
    const auto public_core =
        ha::BuildFixedProgramVerticalWitnessBoundaryVerifierInstance(
            program, redacted,
            canonical.public_external_masks,
            canonical.links,
            canonical.vertical_air_seed,
            proof.canonical_r0);
    std::string core_why;
    if (!public_core.valid ||
        public_core.public_statement !=
            proof.sha_public_statement ||
        public_core.base_row_commitment !=
            proof.canonical_r0 ||
        public_core.base_column_indices !=
            canonical.sha_execution
                .base_column_indices ||
        CommitRCStage3CtlChallenges(
            public_core.challenges) !=
            CommitRCStage3CtlChallenges(
                canonical.sha_execution
                    .challenges) ||
        !SamePublicCoreConstraintSchedule(
            public_core.cs,
            canonical.sha_execution.cs,
            &core_why)) {
        return fail(
            "public_only_cs:" +
            public_core.note + ":" +
            core_why);
    }

    std::string air_why;
    if (!aq::AirQuotientVerifyRowsSplitRap(
            canonical.sha_execution.cs,
            proof.quotient,
            canonical.sha_execution
                .base_column_indices,
            proof_seed, &air_why)) {
        return fail("air:" + air_why);
    }
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        if (!gf::Eq(
                proof.proved_v5_exports[
                    coordinate],
                canonical.draw_output[
                    coordinate])) {
            return fail("v5_export");
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:v5_v6_bus:"
            "first_uniform_split_rap_verify:"
            "public_only_cs;"
            "three_v5_exports_proved;"
            "recursive_consumption_0;"
            "full_304_false";
    }
    return true;
}

} // namespace

bool VerifyV5BatchCoefficientDrawSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t batch_item,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why)
{
    return VerifyV5UniformDrawSplitRapImplV1(
        composition, child, child_fs_seed,
        V5UniformDrawRelationV1::BatchCoefficient,
        lane, batch_item, proof, why);
}

bool VerifyV5OodCandidateDrawSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t candidate,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why)
{
    return VerifyV5UniformDrawSplitRapImplV1(
        composition, child, child_fs_seed,
        V5UniformDrawRelationV1::OodCandidate,
        lane, candidate, proof, why);
}

bool VerifyV5DeepWeightDrawSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t item,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why)
{
    return VerifyV5UniformDrawSplitRapImplV1(
        composition, child, child_fs_seed,
        V5UniformDrawRelationV1::DeepWeight,
        lane, item, proof, why);
}

bool VerifyV5FoldChallengeDrawSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t fold,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why)
{
    return VerifyV5UniformDrawSplitRapImplV1(
        composition, child, child_fs_seed,
        V5UniformDrawRelationV1::FoldChallenge,
        lane, fold, proof, why);
}

bool VerifyV5QueryIndexDrawSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t query,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why)
{
    return VerifyV5UniformDrawSplitRapImplV1(
        composition, child, child_fs_seed,
        V5UniformDrawRelationV1::QueryIndex,
        lane, query, proof, why);
}

V5OodPointSelectorWitnessV1
BuildV5OodPointSelectorWitnessV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t point)
{
    V5OodPointSelectorWitnessV1 out;
    out.lane = lane;
    out.point = point;
    if (!composition.valid || child_fs_seed.IsNull() ||
        lane >= 2 || point >= 2) {
        out.note =
            "stage3:v5_v6_bus:ood_selector:shape";
        return out;
    }
    std::array<uint256, 4> candidate_statements{};
    for (uint32_t candidate = 0; candidate < 4;
         ++candidate) {
        const auto prefix =
            BuildV5OodCandidateDrawWitnessPrefix(
                composition, child, child_fs_seed,
                lane, candidate);
        if (!prefix.valid ||
            prefix.v5_semantic_cell_count != 0) {
            out.note =
                "stage3:v5_v6_bus:ood_selector:"
                "candidate_prefix";
            return out;
        }
        out.candidates[candidate] =
            prefix.draw_output;
        candidate_statements[candidate] =
            prefix.prefix_statement;
    }

    const auto is_extension_nonzero =
        [](const std::array<Fp3, 3>& value) {
            return !gf::IsZero(value[1]) ||
                   !gf::IsZero(value[2]);
        };
    uint32_t z1_candidate = UINT32_MAX;
    for (uint32_t candidate = 0; candidate < 2;
         ++candidate) {
        out.nonzero[candidate] =
            is_extension_nonzero(
                out.candidates[candidate]);
        if (z1_candidate == UINT32_MAX &&
            out.nonzero[candidate]) {
            z1_candidate = candidate;
        }
    }
    if (z1_candidate == UINT32_MAX) {
        out.note =
            "stage3:v5_v6_bus:ood_selector:"
            "z1_pool_exhausted";
        return out;
    }
    const auto& z1 = out.candidates[z1_candidate];
    uint32_t z2_candidate = UINT32_MAX;
    for (uint32_t candidate = 0; candidate < 4;
         ++candidate) {
        if (candidate >= 2) {
            out.nonzero[candidate] =
                is_extension_nonzero(
                    out.candidates[candidate]);
        }
        bool distinct = false;
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            distinct =
                distinct ||
                !gf::Eq(
                    out.candidates[candidate][coordinate],
                    z1[coordinate]);
        }
        out.distinct_from_z1[candidate] = distinct;
        if (candidate >= 2 &&
            z2_candidate == UINT32_MAX &&
            out.nonzero[candidate] && distinct) {
            z2_candidate = candidate;
        }
    }
    if (z2_candidate == UINT32_MAX) {
        out.note =
            "stage3:v5_v6_bus:ood_selector:"
            "z2_pool_exhausted";
        return out;
    }
    out.selected_candidate =
        point == 0 ? z1_candidate : z2_candidate;
    out.selected_output =
        out.candidates[out.selected_candidate];

    const auto semantic =
        BuildV5SemanticMaterialization(composition);
    if (!semantic.valid) {
        out.note =
            "stage3:v5_v6_bus:ood_selector:semantic";
        return out;
    }
    std::array<bool, 3> found{};
    for (const auto& cell : semantic.cells) {
        if (cell.family !=
                ChallengeFeedbackFamily::OodPoint ||
            cell.lane != lane ||
            cell.item_index != point ||
            cell.coordinate >= 3) {
            continue;
        }
        const uint32_t coordinate = cell.coordinate;
        if (found[coordinate] ||
            !gf::Eq(
                out.selected_output[coordinate],
                Fp3::FromFp(cell.expected_v5_value))) {
            out.note =
                "stage3:v5_v6_bus:ood_selector:"
                "semantic_mismatch";
            return out;
        }
        found[coordinate] = true;
        out.v5_semantic_rows[coordinate] =
            cell.semantic_row;
    }
    if (!std::all_of(
            found.begin(), found.end(),
            [](bool value) { return value; })) {
        out.note =
            "stage3:v5_v6_bus:ood_selector:"
            "semantic_rows";
        return out;
    }

    constexpr uint32_t N = 4;
    constexpr uint32_t CANDIDATE = 0;
    constexpr uint32_t C1_INVERSE = 3;
    constexpr uint32_t C1_NONZERO = 4;
    constexpr uint32_t C2_INVERSE = 5;
    constexpr uint32_t C2_NONZERO = 6;
    constexpr uint32_t EXT_NONZERO = 7;
    constexpr uint32_t DIFF_INVERSE = 8;
    constexpr uint32_t DIFF_NONZERO = 11;
    constexpr uint32_t DIFF_ANY01 = 14;
    constexpr uint32_t DISTINCT = 15;
    constexpr uint32_t VALID = 16;
    constexpr uint32_t HAVE_SELECTED = 17;
    constexpr uint32_t SELECTED = 18;
    constexpr uint32_t Z1_OUTPUT = 19;
    constexpr uint32_t Z2_OUTPUT = 22;
    constexpr uint32_t Z1_INDEX = 25;
    constexpr uint32_t Z2_INDEX = 26;
    constexpr uint32_t CANDIDATE_INDEX = 27;
    constexpr uint32_t GROUP_START = 28;
    constexpr uint32_t GROUP_FINAL = 29;
    constexpr uint32_t SECOND_POINT = 30;
    constexpr uint32_t Z1_ROW = 31;
    constexpr uint32_t Z2_ROW = 32;
    constexpr uint32_t W = 33;
    out.candidate_column_base = CANDIDATE;
    out.nonzero_column_base = C1_NONZERO;
    out.selector_column_base = SELECTED;
    out.selected_index_column =
        point == 0 ? Z1_INDEX : Z2_INDEX;
    out.selected_output_base =
        point == 0 ? Z1_OUTPUT : Z2_OUTPUT;
    out.cs.n_rows = N;
    out.cs.n_columns = W;
    out.columns.assign(
        W, std::vector<Fp3>(N, Fp3::Zero()));
    out.base_column_indices = {
        CANDIDATE, CANDIDATE + 1,
        CANDIDATE + 2};
    const auto bit = [](bool value) {
        return Fp3::FromFp(gf::FromU64(value));
    };
    const auto index_value = [](uint32_t value) {
        return Fp3::FromFp(gf::FromU64(value));
    };
    bool have_selected = false;
    for (uint32_t candidate = 0; candidate < 4;
         ++candidate) {
        if (candidate == 0 || candidate == 2) {
            have_selected = false;
        }
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            out.columns[CANDIDATE + coordinate]
                [candidate] =
                out.candidates[candidate][coordinate];
            const Fp3 difference = gf::Sub(
                out.candidates[candidate][coordinate],
                z1[coordinate]);
            const bool difference_nonzero =
                !gf::IsZero(difference);
            out.columns[
                DIFF_NONZERO + coordinate][candidate] =
                bit(difference_nonzero);
            out.columns[
                DIFF_INVERSE + coordinate][candidate] =
                difference_nonzero
                ? gf::Inv(difference)
                : Fp3::Zero();
        }
        const bool c1_nonzero =
            !gf::IsZero(out.candidates[candidate][1]);
        const bool c2_nonzero =
            !gf::IsZero(out.candidates[candidate][2]);
        out.columns[C1_NONZERO][candidate] =
            bit(c1_nonzero);
        out.columns[C2_NONZERO][candidate] =
            bit(c2_nonzero);
        out.columns[C1_INVERSE][candidate] =
            c1_nonzero
            ? gf::Inv(out.candidates[candidate][1])
            : Fp3::Zero();
        out.columns[C2_INVERSE][candidate] =
            c2_nonzero
            ? gf::Inv(out.candidates[candidate][2])
            : Fp3::Zero();
        out.columns[EXT_NONZERO][candidate] =
            bit(out.nonzero[candidate]);
        const bool diff_any01 =
            !gf::IsZero(
                out.columns[DIFF_NONZERO][candidate]) ||
            !gf::IsZero(
                out.columns[DIFF_NONZERO + 1][candidate]);
        out.columns[DIFF_ANY01][candidate] =
            bit(diff_any01);
        out.columns[DISTINCT][candidate] =
            bit(out.distinct_from_z1[candidate]);
        const bool valid =
            out.nonzero[candidate] &&
            (candidate < 2 ||
             out.distinct_from_z1[candidate]);
        const bool selected =
            valid && !have_selected;
        out.columns[VALID][candidate] = bit(valid);
        out.columns[HAVE_SELECTED][candidate] =
            bit(have_selected);
        out.columns[SELECTED][candidate] =
            bit(selected);
        have_selected = have_selected || selected;
        out.columns[CANDIDATE_INDEX][candidate] =
            index_value(candidate);
        out.columns[GROUP_START][candidate] =
            bit(candidate == 0 || candidate == 2);
        out.columns[GROUP_FINAL][candidate] =
            bit(candidate == 1 || candidate == 3);
        out.columns[SECOND_POINT][candidate] =
            bit(candidate >= 2);
        out.columns[Z1_ROW][candidate] =
            bit(candidate < 2);
        out.columns[Z2_ROW][candidate] =
            bit(candidate >= 2);
    }
    for (uint32_t row = 0; row < N; ++row) {
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            out.columns[Z1_OUTPUT + coordinate][row] =
                z1[coordinate];
            out.columns[Z2_OUTPUT + coordinate][row] =
                out.candidates[z2_candidate][coordinate];
        }
        out.columns[Z1_INDEX][row] =
            index_value(z1_candidate);
        out.columns[Z2_INDEX][row] =
            index_value(z2_candidate);
    }
    for (uint32_t column = CANDIDATE_INDEX;
         column <= Z2_ROW; ++column) {
        out.cs.preprocessed.emplace_back(
            column, out.columns[column]);
    }
    out.cs.preprocessed_pin_ood = true;
    const auto add =
        [&](const char* name, aq::AirKind kind,
            uint32_t degree,
            std::function<Fp3(
                const std::vector<Fp3>&,
                const std::vector<Fp3>&)> eval) {
            aq::AirConstraint<Fp3> constraint;
            constraint.name = name;
            constraint.kind = kind;
            constraint.alg_degree = degree;
            constraint.eval = std::move(eval);
            out.cs.constraints.push_back(
                std::move(constraint));
        };
    for (const uint32_t column :
         {C1_NONZERO, C2_NONZERO, EXT_NONZERO,
          DIFF_NONZERO, DIFF_NONZERO + 1,
          DIFF_NONZERO + 2, DIFF_ANY01, DISTINCT,
          VALID, HAVE_SELECTED, SELECTED}) {
        add("stage3.v5.ood.boolean",
            aq::AirKind::kEverywhere, 2,
            [column](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[column],
                    gf::Sub(cur[column], Fp3::One()));
            });
    }
    for (uint32_t coordinate = 0;
         coordinate < 2; ++coordinate) {
        const uint32_t value =
            CANDIDATE + 1 + coordinate;
        const uint32_t inverse =
            coordinate == 0 ? C1_INVERSE : C2_INVERSE;
        const uint32_t nonzero =
            coordinate == 0 ? C1_NONZERO : C2_NONZERO;
        add("stage3.v5.ood.ext_zero_branch",
            aq::AirKind::kEverywhere, 2,
            [value, nonzero](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[value],
                    gf::Sub(Fp3::One(), cur[nonzero]));
            });
        add("stage3.v5.ood.ext_inverse",
            aq::AirKind::kEverywhere, 2,
            [value, inverse, nonzero](
                const auto& cur, const auto&) {
                return gf::Sub(
                    gf::Mul(cur[value], cur[inverse]),
                    cur[nonzero]);
            });
    }
    add("stage3.v5.ood.has_extension_coordinate",
        aq::AirKind::kEverywhere, 2,
        [](const auto& cur, const auto&) {
            const Fp3 expected = gf::Sub(
                gf::Add(
                    cur[C1_NONZERO],
                    cur[C2_NONZERO]),
                gf::Mul(
                    cur[C1_NONZERO],
                    cur[C2_NONZERO]));
            return gf::Sub(
                cur[EXT_NONZERO], expected);
        });
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        add("stage3.v5.ood.diff_zero_branch",
            aq::AirKind::kEverywhere, 2,
            [coordinate](const auto& cur, const auto&) {
                const Fp3 difference = gf::Sub(
                    cur[CANDIDATE + coordinate],
                    cur[Z1_OUTPUT + coordinate]);
                return gf::Mul(
                    difference,
                    gf::Sub(
                        Fp3::One(),
                        cur[DIFF_NONZERO + coordinate]));
            });
        add("stage3.v5.ood.diff_inverse",
            aq::AirKind::kEverywhere, 2,
            [coordinate](const auto& cur, const auto&) {
                const Fp3 difference = gf::Sub(
                    cur[CANDIDATE + coordinate],
                    cur[Z1_OUTPUT + coordinate]);
                return gf::Sub(
                    gf::Mul(
                        difference,
                        cur[DIFF_INVERSE + coordinate]),
                    cur[DIFF_NONZERO + coordinate]);
            });
    }
    add("stage3.v5.ood.diff_any01",
        aq::AirKind::kEverywhere, 2,
        [](const auto& cur, const auto&) {
            const Fp3 expected = gf::Sub(
                gf::Add(
                    cur[DIFF_NONZERO],
                    cur[DIFF_NONZERO + 1]),
                gf::Mul(
                    cur[DIFF_NONZERO],
                    cur[DIFF_NONZERO + 1]));
            return gf::Sub(cur[DIFF_ANY01], expected);
        });
    add("stage3.v5.ood.distinct_from_z1",
        aq::AirKind::kEverywhere, 2,
        [](const auto& cur, const auto&) {
            const Fp3 expected = gf::Sub(
                gf::Add(
                    cur[DIFF_ANY01],
                    cur[DIFF_NONZERO + 2]),
                gf::Mul(
                    cur[DIFF_ANY01],
                    cur[DIFF_NONZERO + 2]));
            return gf::Sub(cur[DISTINCT], expected);
        });
    add("stage3.v5.ood.valid",
        aq::AirKind::kEverywhere, 3,
        [](const auto& cur, const auto&) {
            const Fp3 expected = gf::Mul(
                cur[EXT_NONZERO],
                gf::Sub(
                    Fp3::One(),
                    gf::Mul(
                        cur[SECOND_POINT],
                        gf::Sub(
                            Fp3::One(),
                            cur[DISTINCT]))));
            return gf::Sub(cur[VALID], expected);
        });
    add("stage3.v5.ood.first_valid",
        aq::AirKind::kEverywhere, 2,
        [](const auto& cur, const auto&) {
            return gf::Sub(
                cur[SELECTED],
                gf::Mul(
                    cur[VALID],
                    gf::Sub(
                        Fp3::One(),
                        cur[HAVE_SELECTED])));
        });
    add("stage3.v5.ood.group_reset",
        aq::AirKind::kEverywhere, 2,
        [](const auto& cur, const auto&) {
            return gf::Mul(
                cur[GROUP_START],
                cur[HAVE_SELECTED]);
        });
    add("stage3.v5.ood.have_transition",
        aq::AirKind::kTransition, 2,
        [](const auto& cur, const auto& next) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    next[GROUP_START]),
                gf::Sub(
                    next[HAVE_SELECTED],
                    gf::Add(
                        cur[HAVE_SELECTED],
                        cur[SELECTED])));
        });
    add("stage3.v5.ood.pool_not_exhausted",
        aq::AirKind::kEverywhere, 1,
        [](const auto& cur, const auto&) {
            return gf::Mul(
                cur[GROUP_FINAL],
                gf::Sub(
                    gf::Add(
                        cur[HAVE_SELECTED],
                        cur[SELECTED]),
                    Fp3::One()));
        });
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        add("stage3.v5.ood.bind_selected_z1",
            aq::AirKind::kEverywhere, 3,
            [coordinate](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[Z1_ROW],
                    gf::Mul(
                        cur[SELECTED],
                        gf::Sub(
                            cur[Z1_OUTPUT + coordinate],
                            cur[CANDIDATE + coordinate])));
            });
        add("stage3.v5.ood.bind_selected_z2",
            aq::AirKind::kEverywhere, 3,
            [coordinate](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[Z2_ROW],
                    gf::Mul(
                        cur[SELECTED],
                        gf::Sub(
                            cur[Z2_OUTPUT + coordinate],
                            cur[CANDIDATE + coordinate])));
            });
        for (const uint32_t output :
             {Z1_OUTPUT + coordinate,
              Z2_OUTPUT + coordinate}) {
            add("stage3.v5.ood.output_constant",
                aq::AirKind::kTransition, 1,
                [output](
                    const auto& cur, const auto& next) {
                    return gf::Sub(
                        next[output], cur[output]);
                });
        }
    }
    add("stage3.v5.ood.bind_selected_z1_index",
        aq::AirKind::kEverywhere, 3,
        [](const auto& cur, const auto&) {
            return gf::Mul(
                cur[Z1_ROW],
                gf::Mul(
                    cur[SELECTED],
                    gf::Sub(
                        cur[Z1_INDEX],
                        cur[CANDIDATE_INDEX])));
        });
    add("stage3.v5.ood.bind_selected_z2_index",
        aq::AirKind::kEverywhere, 3,
        [](const auto& cur, const auto&) {
            return gf::Mul(
                cur[Z2_ROW],
                gf::Mul(
                    cur[SELECTED],
                    gf::Sub(
                        cur[Z2_INDEX],
                        cur[CANDIDATE_INDEX])));
        });
    for (const uint32_t index : {Z1_INDEX, Z2_INDEX}) {
        add("stage3.v5.ood.index_constant",
            aq::AirKind::kTransition, 1,
            [index](const auto& cur, const auto& next) {
                return gf::Sub(next[index], cur[index]);
            });
    }
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        const uint32_t output =
            (point == 0 ? Z1_OUTPUT : Z2_OUTPUT) +
            coordinate;
        const Fp3 expected =
            out.selected_output[coordinate];
        add("stage3.v5.ood.v5_consumer_equality",
            aq::AirKind::kFirstRow, 1,
            [output, expected](
                const auto& cur, const auto&) {
                return gf::Sub(cur[output], expected);
            });
    }
    HashWriter seed;
    seed <<
        "BTX_RC_STAGE3_V5_OOD_SELECTOR_AIR_V1";
    seed << child_fs_seed;
    seed << semantic.public_boundary_commitment;
    seed << lane;
    seed << point;
    for (const uint256& statement :
         candidate_statements) {
        seed << statement;
    }
    out.vertical_air_seed = seed.GetHash();
    std::string r0_why;
    out.canonical_r0 =
        aq::AirQuotientTwoEpochBaseRowCommitment(
            out.cs, out.columns,
            out.base_column_indices, &r0_why);
    if (out.canonical_r0.IsNull()) {
        out.note =
            "stage3:v5_v6_bus:ood_selector:r0:" +
            r0_why;
        return out;
    }
    HashWriter statement;
    statement <<
        "BTX_RC_STAGE3_V5_OOD_SELECTOR_STATEMENT_V1";
    statement << out.vertical_air_seed;
    statement << out.canonical_r0;
    statement << lane;
    statement << point;
    statement << out.selected_candidate;
    for (const auto& candidate : out.candidates) {
        for (const Fp3& coordinate : candidate) {
            statement << gf::Canonical(coordinate.c0);
            statement << gf::Canonical(coordinate.c1);
            statement << gf::Canonical(coordinate.c2);
        }
    }
    for (uint32_t row : out.v5_semantic_rows) {
        statement << row;
    }
    out.selector_statement = statement.GetHash();
    const uint32_t violations =
        v6::CountViolations(out.cs, out.columns);
    out.valid =
        violations == 0 &&
        !out.vertical_air_seed.IsNull() &&
        !out.canonical_r0.IsNull() &&
        !out.selector_statement.IsNull();
    out.note = out.valid
        ? "stage3:v5_v6_bus:ood_selector:"
          "four_candidates;first_valid_exact;"
          "v5_rows_3;recursive_0;authority_false"
        : "stage3:v5_v6_bus:ood_selector:"
          "violations=" + std::to_string(violations);
    return out;
}

namespace {

uint256 V5OodPointProofSeedV1(
    const V5OodPointSelectorWitnessV1& selector)
{
    if (!selector.valid ||
        selector.selector_statement.IsNull() ||
        selector.vertical_air_seed.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_OOD_POINT_SPLIT_RAP_SEED_V1";
    hash << selector.selector_statement;
    hash << selector.vertical_air_seed;
    hash << selector.lane;
    hash << selector.point;
    hash << selector.selected_candidate;
    for (uint32_t row :
         selector.v5_semantic_rows) {
        hash << row;
    }
    return hash.GetHash();
}

uint256 CommitV5OodPointProofV1(
    const V5OodPointSplitRapProofV1& proof)
{
    if (proof.lane >= 2 || proof.point >= 2 ||
        proof.selected_candidate >= 4 ||
        proof.candidate_proofs.size() != 4 ||
        proof.selector_quotient.batch.groups.size() != 3) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_OOD_POINT_SPLIT_RAP_PROOF_V1";
    hash << proof.version;
    hash << proof.lane;
    hash << proof.point;
    hash << proof.selected_candidate;
    for (uint32_t candidate = 0; candidate < 4;
         ++candidate) {
        hash << proof.candidate_proofs[candidate]
                    .prefix_statement;
        hash << proof.candidate_proofs[candidate]
                    .canonical_r0;
        for (const Fp3& coordinate :
             proof.proved_candidates[candidate]) {
            hash << gf::Canonical(coordinate.c0);
            hash << gf::Canonical(coordinate.c1);
            hash << gf::Canonical(coordinate.c2);
        }
    }
    for (const auto& group :
         proof.selector_quotient.batch.groups) {
        hash << Fri3AlgDigestToUint256(
            group.row_commit.root);
    }
    for (const Fp3& coordinate :
         proof.proved_v5_exports) {
        hash << gf::Canonical(coordinate.c0);
        hash << gf::Canonical(coordinate.c1);
        hash << gf::Canonical(coordinate.c2);
    }
    hash << proof.proof_owned_v5_cells;
    hash << proof.recursively_consumed_v5_cells;
    hash << proof.full_304_transcript;
    return hash.GetHash();
}

} // namespace

V5OodPointSplitRapProveResultV1
ProveV5OodPointSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t point)
{
    V5OodPointSplitRapProveResultV1 out;
    auto& proof = out.proof;
    proof.lane = lane;
    proof.point = point;
    const auto selector =
        BuildV5OodPointSelectorWitnessV1(
            composition, child, child_fs_seed,
            lane, point);
    if (!selector.valid) {
        out.note =
            "stage3:v5_v6_bus:ood_prove:selector:" +
            selector.note;
        return out;
    }
    for (uint32_t candidate = 0; candidate < 4;
         ++candidate) {
        auto prefix =
            BuildV5OodCandidateDrawWitnessPrefix(
                composition, child, child_fs_seed,
                lane, candidate);
        const auto proved =
            ProveV5FirstUniformSplitRap(prefix);
        if (!prefix.valid || !proved.ok ||
            proved.proof.proof_owned_v5_cells != 0) {
            out.note =
                "stage3:v5_v6_bus:ood_prove:"
                "candidate_" +
                std::to_string(candidate) + ":" +
                proved.note;
            return out;
        }
        proof.candidate_proofs[candidate] =
            proved.proof;
        proof.proved_candidates[candidate] =
            prefix.draw_output;
    }
    const uint256 selector_seed =
        V5OodPointProofSeedV1(selector);
    const auto selector_proved =
        aq::AirQuotientProveRowsSplitRap(
            selector.cs, selector.columns,
            selector.base_column_indices,
            selector_seed, {});
    if (!selector_proved.ok ||
        !selector_proved.division_exact ||
        selector_proved.proof.batch.groups.size() != 3 ||
        Fri3AlgDigestToUint256(
            selector_proved.proof.batch.groups[0]
                .row_commit.root) !=
            selector.canonical_r0) {
        out.note =
            "stage3:v5_v6_bus:ood_prove:"
            "selector_quotient:" +
            selector_proved.note;
        return out;
    }
    proof.selected_candidate =
        selector.selected_candidate;
    proof.proved_v5_exports =
        selector.selected_output;
    proof.selector_quotient =
        selector_proved.proof;
    proof.proof_owned_v5_cells = 3;
    proof.recursively_consumed_v5_cells = 0;
    proof.full_304_transcript = false;
    proof.proof_statement =
        CommitV5OodPointProofV1(proof);
    out.ok = !proof.proof_statement.IsNull();
    out.note = out.ok
        ? "stage3:v5_v6_bus:ood_prove:"
          "four_candidate_sha_uniform_and_selector_proved;"
          "v5_cells_3;recursive_0;authority_false"
        : "stage3:v5_v6_bus:ood_prove:statement";
    return out;
}

bool VerifyV5OodPointSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t point,
    const V5OodPointSplitRapProofV1& proof,
    std::string* why)
{
    const auto fail = [&](const std::string& detail) {
        return Fail(
            why, "ood_split_rap_verify:" + detail);
    };
    if (proof.version != 1 ||
        proof.lane != lane || proof.point != point ||
        lane >= 2 || point >= 2 ||
        proof.selected_candidate >= 4 ||
        proof.proof_owned_v5_cells != 3 ||
        proof.recursively_consumed_v5_cells != 0 ||
        proof.full_304_transcript ||
        proof.selector_quotient.batch.groups.size() != 3 ||
        proof.proof_statement.IsNull()) {
        return fail("shape");
    }
    const auto selector =
        BuildV5OodPointSelectorWitnessV1(
            composition, child, child_fs_seed,
            lane, point);
    if (!selector.valid ||
        proof.selected_candidate !=
            selector.selected_candidate) {
        return fail("canonical_selector");
    }
    for (uint32_t candidate = 0; candidate < 4;
         ++candidate) {
        std::string candidate_why;
        if (!VerifyV5OodCandidateDrawSplitRap(
                composition, child, child_fs_seed,
                lane, candidate,
                proof.candidate_proofs[candidate],
                &candidate_why)) {
            return fail(
                "candidate_" +
                std::to_string(candidate) + ":" +
                candidate_why);
        }
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            if (!gf::Eq(
                    proof.proved_candidates[candidate]
                        [coordinate],
                    selector.candidates[candidate]
                        [coordinate]) ||
                !gf::Eq(
                    proof.candidate_proofs[candidate]
                        .proved_v5_exports[coordinate],
                    selector.candidates[candidate]
                        [coordinate])) {
                return fail("candidate_export");
            }
        }
    }
    const uint256 selector_seed =
        V5OodPointProofSeedV1(selector);
    std::string selector_why;
    if (Fri3AlgDigestToUint256(
            proof.selector_quotient.batch.groups[0]
                .row_commit.root) !=
            selector.canonical_r0 ||
        !aq::AirQuotientVerifyRowsSplitRap(
            selector.cs, proof.selector_quotient,
            selector.base_column_indices,
            selector_seed, &selector_why)) {
        return fail("selector_air:" + selector_why);
    }
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        if (!gf::Eq(
                proof.proved_v5_exports[coordinate],
                selector.selected_output[coordinate])) {
            return fail("v5_export");
        }
    }
    if (proof.proof_statement !=
            CommitV5OodPointProofV1(proof)) {
        return fail("proof_statement");
    }
    if (why != nullptr) {
        *why =
            "stage3:v5_v6_bus:ood_verify:"
            "four_candidate_sha_uniform;"
            "first_valid_nonzero_distinct;"
            "three_v5_cells_proved;"
            "recursive_0;authority_false";
    }
    return true;
}

bool VerifyV5FirstUniformSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why)
{
    return VerifyV5BatchCoefficientDrawSplitRap(
        composition, child, child_fs_seed,
        0, 0, proof, why);
}

V5ShaProducerPlan AssessV5ShaProducerPlan(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed)
{
    V5ShaProducerPlan out;
    if (!composition.valid ||
        composition.lane_pis.size() != 2 ||
        child_fs_seed.IsNull()) {
        out.note =
            "stage3:v5_v6_bus:sha_plan:shape";
        return out;
    }
    const auto transcript =
        BuildFri3AlgDualTranscriptWitness(
            child.batch.repeated, child_fs_seed);
    if (!transcript.valid) {
        out.note =
            "stage3:v5_v6_bus:sha_plan:transcript:" +
            transcript.note;
        return out;
    }

    uint32_t uniform_blocks = 0;
    uint32_t query_blocks = 0;
    bool uniform_match = true;
    bool query_match = true;
    // (compression blocks, V5 consumer cells). Units are deliberately typed
    // at the dependency boundary: lane seed, one batch draw, the complete
    // four-candidate OOD selector, both DEEP weights, or one fold draw.
    std::vector<std::pair<uint32_t, uint32_t>> uniform_units;
    std::vector<std::pair<uint32_t, uint32_t>> query_units;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const auto& proof = child.batch.repeated.lane[lane];
        const auto& replay = transcript.lane[lane];
        const auto& pi = composition.lane_pis[lane];
        const char* lane_domain = lane == 0
            ? kRCFri3AlgDualLane0DomainTag
            : kRCFri3AlgDualLane1DomainTag;

        // The replayed child must be the child already normalized into this
        // parent.  Otherwise a self-consistent, unrelated proof could pass
        // the native transcript replay while never driving the composition's
        // 304 consumer cells.
        const auto trace_root =
            Fri3AlgDigestFromUint256(child.trace_commit);
        std::vector<uint32_t> query_indices;
        query_indices.reserve(proof.queries.size());
        for (const auto& query : proof.queries) {
            query_indices.push_back(query.index);
        }
        bool normalized_child_match =
            trace_root.has_value() &&
            pi.row_commit_root == proof.row_commit.root &&
            pi.rt_root == *trace_root &&
            pi.child_w + 1 == proof.column_len.size() &&
            pi.child_n_coeffs == proof.n_coeffs &&
            pi.child_n_lde == proof.row_commit.n_leaves &&
            pi.n_folds + 1 == proof.fold_layers.size() &&
            pi.fold_roots.size() == pi.n_folds &&
            gf::Eq(pi.fri_lambda, proof.lambda) &&
            gf::Eq(pi.z1, proof.z1) &&
            gf::Eq(pi.z2, proof.z2) &&
            gf::Eq(pi.w1, proof.w1) &&
            gf::Eq(pi.w2, proof.w2) &&
            gf::Eq(pi.final_value, proof.final_value) &&
            pi.column_len == proof.column_len &&
            EqFp3Vectors(pi.evals_z1, proof.evals_z1) &&
            EqFp3Vectors(pi.evals_z2, proof.evals_z2) &&
            EqFp3Vectors(
                pi.fold_challenges, proof.fold_challenges) &&
            EqFp3Vectors(
                pi.fri_batch_coefficients,
                replay.batch_coefficients) &&
            pi.query_index == query_indices;
        for (uint32_t fold = 0;
             normalized_child_match &&
             fold < pi.n_folds;
             ++fold) {
            normalized_child_match =
                pi.fold_roots[fold] ==
                proof.fold_layers[fold].root;
        }
        if (!normalized_child_match) {
            out.note =
                "stage3:v5_v6_bus:sha_plan:"
                "normalized_child_mismatch";
            return out;
        }

        std::vector<uint8_t> lane_seed_preimage;
        lane_seed_preimage.insert(
            lane_seed_preimage.end(),
            reinterpret_cast<const uint8_t*>(
                kRCFri3AlgDualDomainTag),
            reinterpret_cast<const uint8_t*>(
                kRCFri3AlgDualDomainTag) +
                sizeof(kRCFri3AlgDualDomainTag) - 1);
        AppendLE32Feedback(
            lane_seed_preimage, kRCFri3AlgDualProofVersion);
        static constexpr char kLaneLabel[] = "lane";
        lane_seed_preimage.insert(
            lane_seed_preimage.end(),
            reinterpret_cast<const uint8_t*>(kLaneLabel),
            reinterpret_cast<const uint8_t*>(kLaneLabel) +
                sizeof(kLaneLabel) - 1);
        AppendLE32Feedback(lane_seed_preimage, lane);
        lane_seed_preimage.insert(
            lane_seed_preimage.end(),
            child_fs_seed.begin(), child_fs_seed.end());
        AppendLE64Feedback(
            lane_seed_preimage, proof.pow_grind_nonce);
        std::array<uint8_t, 32> lane_seed_digest{};
        const uint32_t lane_seed_block_base = uniform_blocks;
        if (!BuildCountedSha256d(
                lane_seed_preimage, lane_seed_digest,
                uniform_blocks) ||
            !std::equal(
                lane_seed_digest.begin(), lane_seed_digest.end(),
                replay.lane_seed.begin())) {
            out.note =
                "stage3:v5_v6_bus:sha_plan:lane_seed";
            return out;
        }
        uniform_units.emplace_back(
            uniform_blocks - lane_seed_block_base, 0);
        out.uniform_sha256d_compression_blocks_per_call.push_back(
            uniform_blocks - lane_seed_block_base);
        ++out.lane_seed_sha256d_calls;

        std::vector<uint8_t> fs;
        fs.insert(
            fs.end(),
            reinterpret_cast<const uint8_t*>(lane_domain),
            reinterpret_cast<const uint8_t*>(lane_domain) +
                std::strlen(lane_domain));
        fs.insert(fs.end(), replay.lane_seed.begin(),
                  replay.lane_seed.end());
        AppendLE64Feedback(fs, proof.pow_grind_nonce);
        AppendLE32Feedback(fs, proof.blowup);
        AppendLE32Feedback(fs, proof.n_coeffs);
        AppendLE32Feedback(
            fs, kRCFri3AlgDualLaneProofVersion);
        AppendLE32Feedback(
            fs, static_cast<uint32_t>(
                    proof.column_len.size()));
        for (uint32_t length : proof.column_len) {
            AppendLE32Feedback(fs, length);
        }
        AppendAlgDigestFeedback(fs, proof.row_commit.root);

        auto draw_uniform =
            [&](const char* label, uint32_t item,
                Fp3& value) {
                std::array<uint64_t,
                           kRCFri3AlgDualUniformWords> words{};
                for (uint32_t block = 0;
                     block <
                     kRCFri3AlgDualUniformHashBlocks;
                     ++block) {
                    std::vector<uint8_t> preimage = fs;
                    preimage.insert(
                        preimage.end(),
                        reinterpret_cast<const uint8_t*>(
                            kRCFri3AlgDualUniformDrawDomainTag),
                        reinterpret_cast<const uint8_t*>(
                            kRCFri3AlgDualUniformDrawDomainTag) +
                            sizeof(
                                kRCFri3AlgDualUniformDrawDomainTag) -
                            1);
                    preimage.insert(
                        preimage.end(),
                        reinterpret_cast<const uint8_t*>(label),
                        reinterpret_cast<const uint8_t*>(label) +
                            std::strlen(label));
                    AppendLE32Feedback(preimage, item);
                    AppendLE32Feedback(preimage, block);
                    std::array<uint8_t, 32> digest{};
                    const uint32_t call_block_base =
                        uniform_blocks;
                    if (!BuildCountedSha256d(
                            preimage, digest,
                            uniform_blocks)) {
                        return false;
                    }
                    out
                        .uniform_sha256d_compression_blocks_per_call
                        .push_back(
                            uniform_blocks - call_block_base);
                    ++out.uniform_fp3_sha256d_calls;
                    for (uint32_t word = 0; word < 4;
                         ++word) {
                        words[4 * block + word] =
                            ReadLE64Feedback(
                                digest.data() + 8 * word);
                    }
                }
                const auto selected =
                    Fri3AlgSelectUniformFp3Words(words);
                if (!selected.has_value()) return false;
                value = *selected;
                ++out.uniform_fp3_draws;
                return true;
            };

        std::vector<Fp3> batch(
            proof.column_len.size());
        for (uint32_t column = 0;
             column < batch.size(); ++column) {
            const uint32_t block_base = uniform_blocks;
            if (!draw_uniform(
                    "fra3_batch_coeff", column,
                    batch[column])) {
                out.note =
                    "stage3:v5_v6_bus:sha_plan:batch_draw";
                return out;
            }
            uniform_units.emplace_back(
                uniform_blocks - block_base, 3);
        }
        uniform_match =
            uniform_match &&
            EqFp3Vectors(batch, replay.batch_coefficients);
        for (const Fp3& coefficient : batch) {
            AppendFp3Feedback(fs, coefficient);
        }

        const uint32_t ood_block_base = uniform_blocks;
        std::array<Fp3, 4> candidates{};
        for (uint32_t candidate = 0;
             candidate < candidates.size(); ++candidate) {
            if (!draw_uniform(
                    "fra3_z", candidate,
                    candidates[candidate])) {
                out.note =
                    "stage3:v5_v6_bus:sha_plan:ood_draw";
                return out;
            }
            uniform_match =
                uniform_match &&
                gf::Eq(
                    candidates[candidate],
                    replay.ood_candidates[candidate]);
        }
        Fp3 z1{};
        Fp3 z2{};
        bool have_z1 = false;
        bool have_z2 = false;
        for (uint32_t candidate = 0;
             candidate < 2; ++candidate) {
            if (candidates[candidate].c1 == 0 &&
                candidates[candidate].c2 == 0) {
                continue;
            }
            z1 = candidates[candidate];
            have_z1 = true;
            break;
        }
        for (uint32_t candidate = 2;
             candidate < 4; ++candidate) {
            if ((candidates[candidate].c1 == 0 &&
                 candidates[candidate].c2 == 0) ||
                gf::Eq(candidates[candidate], z1)) {
                continue;
            }
            z2 = candidates[candidate];
            have_z2 = true;
            break;
        }
        if (!have_z1 || !have_z2) {
            out.note =
                "stage3:v5_v6_bus:sha_plan:ood_selection";
            return out;
        }
        uniform_units.emplace_back(
            uniform_blocks - ood_block_base, 6);
        uniform_match =
            uniform_match &&
            gf::Eq(z1, replay.selected_z1) &&
            gf::Eq(z2, replay.selected_z2);
        AppendFp3Feedback(fs, z1);
        AppendFp3Feedback(fs, z2);
        for (uint32_t column = 0;
             column < proof.evals_z1.size(); ++column) {
            AppendFp3Feedback(fs, proof.evals_z1[column]);
            AppendFp3Feedback(fs, proof.evals_z2[column]);
        }

        Fp3 w1{};
        Fp3 w2{};
        const uint32_t deep_block_base = uniform_blocks;
        if (!draw_uniform("fra3_w", 0, w1) ||
            !draw_uniform("fra3_w", 1, w2)) {
            out.note =
                "stage3:v5_v6_bus:sha_plan:deep_draw";
            return out;
        }
        uniform_units.emplace_back(
            uniform_blocks - deep_block_base, 6);
        uniform_match =
            uniform_match &&
            gf::Eq(w1, replay.w1) &&
            gf::Eq(w2, replay.w2);
        AppendFp3Feedback(fs, w1);
        AppendFp3Feedback(fs, w2);

        std::vector<Fp3> folds;
        for (uint32_t fold = 0;
             fold < proof.fold_layers.size(); ++fold) {
            AppendAlgDigestFeedback(
                fs, proof.fold_layers[fold].root);
            if (fold + 1 < proof.fold_layers.size()) {
                Fp3 challenge{};
                const uint32_t fold_block_base =
                    uniform_blocks;
                if (!draw_uniform(
                        "fra3_fold", fold, challenge)) {
                    out.note =
                        "stage3:v5_v6_bus:sha_plan:fold_draw";
                    return out;
                }
                folds.push_back(challenge);
                uniform_units.emplace_back(
                    uniform_blocks - fold_block_base, 3);
            }
        }
        uniform_match =
            uniform_match &&
            EqFp3Vectors(folds, replay.fold_challenges);

        for (uint32_t query = 0;
             query < kRCFri3AlgDualQueriesPerLane;
             ++query) {
            std::vector<uint8_t> preimage = fs;
            preimage.insert(
                preimage.end(),
                reinterpret_cast<const uint8_t*>(
                    kRCFri3AlgDualIndexDrawDomainTag),
                reinterpret_cast<const uint8_t*>(
                    kRCFri3AlgDualIndexDrawDomainTag) +
                    sizeof(kRCFri3AlgDualIndexDrawDomainTag) -
                    1);
            static constexpr char kQueryLabel[] =
                "fra3_query";
            preimage.insert(
                preimage.end(),
                reinterpret_cast<const uint8_t*>(
                    kQueryLabel),
                reinterpret_cast<const uint8_t*>(
                    kQueryLabel) +
                    sizeof(kQueryLabel) - 1);
            AppendLE32Feedback(preimage, query);
            std::array<uint8_t, 32> digest{};
            const uint32_t query_block_base = query_blocks;
            if (!BuildCountedSha256d(
                    preimage, digest, query_blocks)) {
                out.note =
                    "stage3:v5_v6_bus:sha_plan:query_hash";
                return out;
            }
            query_units.emplace_back(
                query_blocks - query_block_base, 1);
            out.query_sha256d_compression_blocks_per_call
                .push_back(
                    query_blocks - query_block_base);
            ++out.query_index_sha256d_calls;
            uint32_t raw = 0;
            for (uint32_t byte = 0; byte < 4; ++byte) {
                raw |= uint32_t{digest[byte]} << (8 * byte);
            }
            const uint32_t index =
                raw & (proof.row_commit.n_leaves - 1);
            query_match =
                query_match &&
                query < replay.query_indices.size() &&
                index == replay.query_indices[query];
        }
    }

    out.uniform_sha_compression_blocks = uniform_blocks;
    out.query_sha_compression_blocks = query_blocks;
    out.uniform_consumer_cells = 42;
    out.query_consumer_cells = 256;
    constexpr uint32_t kFixedFeedbackAndConversionColumns =
        713 + 201;
    out.packed_provenance_instance_capacity =
        (kStage3RecursiveColumnCap -
         kFixedFeedbackAndConversionColumns) /
        ha::kFixedProgramProvenanceColumns;
    const auto build_typed_shards =
        [&](const std::vector<std::pair<uint32_t, uint32_t>>& units,
            uint32_t expected_blocks, uint32_t expected_cells,
            std::vector<uint32_t>& shard_blocks,
            std::vector<uint32_t>& shard_cells) {
            uint32_t typed_blocks = 0;
            uint32_t typed_cells = 0;
            for (const auto& [blocks, cells] : units) {
                if (blocks == 0 ||
                    blocks >
                        out.packed_provenance_instance_capacity) {
                    return false;
                }
                if (typed_blocks != 0 &&
                    typed_blocks + blocks >
                        out.packed_provenance_instance_capacity) {
                    shard_blocks.push_back(typed_blocks);
                    shard_cells.push_back(typed_cells);
                    typed_blocks = 0;
                    typed_cells = 0;
                }
                typed_blocks += blocks;
                typed_cells += cells;
            }
            if (typed_blocks != 0) {
                shard_blocks.push_back(typed_blocks);
                shard_cells.push_back(typed_cells);
            }
            return
                std::accumulate(
                    shard_blocks.begin(), shard_blocks.end(),
                    uint32_t{0}) == expected_blocks &&
                std::accumulate(
                    shard_cells.begin(), shard_cells.end(),
                    uint32_t{0}) == expected_cells;
        };
    out.uniform_shards_preserve_typed_draws =
        build_typed_shards(
            uniform_units, uniform_blocks, 42,
            out.uniform_shard_compression_blocks,
            out.uniform_shard_consumer_cells);
    out.query_shards_preserve_typed_draws =
        build_typed_shards(
            query_units, query_blocks, 256,
            out.query_shard_compression_blocks,
            out.query_shard_consumer_cells);
    const auto shards = [&](uint32_t blocks) {
        return (blocks +
                out.packed_provenance_instance_capacity - 1) /
               out.packed_provenance_instance_capacity;
    };
    out.uniform_minimum_parent_shards =
        shards(out.uniform_sha_compression_blocks);
    out.query_minimum_parent_shards =
        shards(out.query_sha_compression_blocks);
    out.currently_recursive_sha_cells =
        kV5V6RecursiveShaDerivationCells;
    out.proof_owned_sha_derivation_cells = 0;
    out.recursively_consumed_sha_derivation_cells =
        kV5V6RecursiveShaDerivationCells;
    out.pending_uniform_cells = 42;
    out.pending_query_cells = 256;
    out.all_preimages_replayed = true;
    out.all_uniform_outputs_match = uniform_match;
    out.all_query_outputs_match = query_match;
    out.uniform_fits_one_parent =
        out.uniform_sha_compression_blocks <=
            out.packed_provenance_instance_capacity;
    out.query_fits_one_parent =
        out.query_sha_compression_blocks <=
            out.packed_provenance_instance_capacity;
    out.valid =
        out.lane_seed_sha256d_calls == 2 &&
        out.uniform_fp3_draws == 18 &&
        out.uniform_fp3_sha256d_calls == 36 &&
        out.query_index_sha256d_calls == 256 &&
        out.uniform_sha256d_compression_blocks_per_call
                .size() == 38 &&
        out.query_sha256d_compression_blocks_per_call
                .size() == 256 &&
        std::accumulate(
            out.uniform_sha256d_compression_blocks_per_call
                .begin(),
            out.uniform_sha256d_compression_blocks_per_call
                .end(),
            uint32_t{0}) == uniform_blocks &&
        std::accumulate(
            out.query_sha256d_compression_blocks_per_call
                .begin(),
            out.query_sha256d_compression_blocks_per_call
                .end(),
            uint32_t{0}) == query_blocks &&
        out.uniform_consumer_cells == 42 &&
        out.query_consumer_cells == 256 &&
        out.packed_provenance_instance_capacity != 0 &&
        out.uniform_shards_preserve_typed_draws &&
        out.query_shards_preserve_typed_draws &&
        out.all_preimages_replayed &&
        out.all_uniform_outputs_match &&
        out.all_query_outputs_match;
    out.note = out.valid
        ? "stage3:v5_v6_bus:sha_plan:exact_replay;"
          "uniform_and_query_require_recursive_sha_shards"
        : "stage3:v5_v6_bus:sha_plan:mismatch";
    return out;
}

namespace {

uint256 CommitV5FullTranscriptWitnessShardPlan(
    const V5FullTranscriptWitnessShardPlan& plan)
{
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_FULL_TRANSCRIPT_WITNESS_SHARD_PLAN_V1";
    hash << plan.sha256d_calls;
    hash << plan.prequery_sha256d_calls;
    hash << plan.query_sha256d_calls;
    hash << plan.parent_shards;
    hash << plan.vertical_leaf_proofs;
    hash << plan.mapped_consumer_cells;
    hash << static_cast<uint32_t>(plan.calls.size());
    for (const auto& call : plan.calls) {
        hash << call.ordinal;
        hash << static_cast<uint8_t>(call.kind);
        hash << call.lane;
        hash << call.item;
        hash << call.hash_block;
        hash << call.compression_blocks;
        hash << call.parent_shard;
        hash << call.leaf_in_parent;
        hash << call.dependency_lane_seed_call;
    }
    hash << static_cast<uint32_t>(plan.consumers.size());
    for (const auto& consumer : plan.consumers) {
        hash << consumer.semantic_row;
        hash << static_cast<uint8_t>(consumer.family);
        hash << consumer.lane;
        hash << consumer.item_index;
        hash << consumer.coordinate;
        hash << static_cast<uint8_t>(consumer.consumer);
        hash << consumer.parent_shard;
        hash << consumer.source_call_count;
        for (uint32_t source :
             consumer.source_call_ordinals) {
            hash << source;
        }
        hash << consumer.dependency_lane_seed_call;
    }
    hash << static_cast<uint32_t>(plan.fanout_links.size());
    for (const auto& link : plan.fanout_links) {
        hash << link.link_id;
        hash << link.source_call_ordinal;
        hash << link.source_word;
        hash << link.target_count;
        hash << static_cast<uint32_t>(
            link.target_call_ordinals.size());
        for (uint32_t target :
             link.target_call_ordinals) {
            hash << target;
        }
    }
    hash << static_cast<uint32_t>(plan.shards.size());
    for (const auto& shard : plan.shards) {
        hash << shard.parent_shard;
        hash << shard.compression_blocks;
        hash << shard.consumer_cells;
        hash << shard.leaf_count;
        hash << static_cast<uint32_t>(
            shard.call_ordinals.size());
        for (uint32_t call : shard.call_ordinals) {
            hash << call;
        }
        hash << static_cast<uint32_t>(
            shard.consumer_semantic_rows.size());
        for (uint32_t row :
             shard.consumer_semantic_rows) {
            hash << row;
        }
        hash << shard.public_schedule_statement;
    }
    return hash.GetHash();
}

uint256 CommitV5TranscriptUnificationCanaryV1(
    const V5TranscriptUnificationCanaryV1& canary)
{
    if (canary.source_plan_statement.IsNull() ||
        canary.families.size() != 6) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_TRANSCRIPT_UNIFICATION_CANARY_V1";
    hash << canary.version;
    hash << canary.source_plan_statement;
    hash << canary.sha256d_calls;
    hash << canary.direct_sha256d_calls;
    hash << canary.dependency_sha256d_calls;
    hash << canary.sha256d_compression_blocks;
    hash << canary.direct_sha256d_compression_blocks;
    hash << canary.dependency_sha256d_compression_blocks;
    hash << canary.semantic_cells;
    hash << canary.locally_executable_cells;
    hash << canary.proof_owned_cells;
    hash << canary.recursively_consumed_cells;
    hash << canary.pending_cells;
    hash << canary.direct_v6_to_v5_feedback_cells;
    hash << canary.trace_rows;
    hash << canary.trace_columns;
    for (const auto& family : canary.families) {
        hash << static_cast<uint8_t>(family.family);
        hash << family.semantic_cells;
        hash << family.direct_sha256d_calls;
        hash << family.direct_sha256d_compression_blocks;
        hash << family.locally_executable_cells;
        hash << family.proof_owned_cells;
        hash << family.recursively_consumed_cells;
        hash << family.pending_cells;
    }
    return hash.GetHash();
}

void BuildV5TranscriptUnificationPublicCsV1(
    aq::AirConstraintSystem<Fp3>& cs)
{
    cs.n_rows = kV5TranscriptUnificationRowsV1;
    cs.n_columns = kV5TranscriptUnificationColumns;
    cs.preprocessed_pin_ood = true;

    const auto boolean_constraint =
        [&](const char* name, uint32_t column) {
            aq::AirConstraint<Fp3> constraint;
            constraint.name = name;
            constraint.kind = aq::AirKind::kEverywhere;
            constraint.alg_degree = 2;
            constraint.eval = [column](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[column],
                    gf::Sub(row[column], Fp3::One()));
            };
            cs.constraints.push_back(std::move(constraint));
        };
    boolean_constraint(
        "v5.transcript_unification.active_boolean",
        kV5TranscriptUnificationActive);
    boolean_constraint(
        "v5.transcript_unification.local_boolean",
        kV5TranscriptUnificationLocallyExecutable);
    boolean_constraint(
        "v5.transcript_unification.proof_owned_boolean",
        kV5TranscriptUnificationProofOwned);
    boolean_constraint(
        "v5.transcript_unification.recursive_boolean",
        kV5TranscriptUnificationRecursivelyConsumed);
    boolean_constraint(
        "v5.transcript_unification.pending_boolean",
        kV5TranscriptUnificationPending);

    aq::AirConstraint<Fp3> ownership_partition;
    ownership_partition.name =
        "v5.transcript_unification.ownership_partition";
    ownership_partition.kind = aq::AirKind::kEverywhere;
    ownership_partition.alg_degree = 2;
    ownership_partition.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kV5TranscriptUnificationActive],
            gf::Sub(
                gf::Add(
                    row[kV5TranscriptUnificationProofOwned],
                    row[kV5TranscriptUnificationPending]),
                Fp3::One()));
    };
    cs.constraints.push_back(std::move(ownership_partition));

    aq::AirConstraint<Fp3> recursive_requires_proof;
    recursive_requires_proof.name =
        "v5.transcript_unification.recursive_requires_proof";
    recursive_requires_proof.kind = aq::AirKind::kEverywhere;
    recursive_requires_proof.alg_degree = 2;
    recursive_requires_proof.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kV5TranscriptUnificationRecursivelyConsumed],
            gf::Sub(
                Fp3::One(),
                row[kV5TranscriptUnificationProofOwned]));
    };
    cs.constraints.push_back(
        std::move(recursive_requires_proof));

    for (uint32_t column =
             kV5TranscriptUnificationFamily;
         column < kV5TranscriptUnificationColumns;
         ++column) {
        aq::AirConstraint<Fp3> padding;
        padding.name =
            "v5.transcript_unification.padding_zero";
        padding.kind = aq::AirKind::kEverywhere;
        padding.alg_degree = 2;
        padding.eval = [column](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    row[kV5TranscriptUnificationActive]),
                row[column]);
        };
        cs.constraints.push_back(std::move(padding));
    }
}

bool ValidateV5TranscriptConsumerSourceV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5TranscriptConsumerSource& consumer)
{
    std::array<uint32_t, 8> expected_sources{};
    uint32_t expected_source_count = 0;
    uint32_t expected_dependency = UINT32_MAX;
    if (consumer.family ==
        ChallengeFeedbackFamily::AirQuotient) {
        expected_source_count = 1;
        expected_sources[0] = consumer.lane;
    } else if (consumer.family ==
               ChallengeFeedbackFamily::QueryIndex) {
        expected_source_count = 1;
        expected_sources[0] =
            40 + 128 * consumer.lane + consumer.item_index;
        expected_dependency = 2 + 19 * consumer.lane;
    } else {
        uint32_t draw = 0;
        uint32_t draw_count = 1;
        switch (consumer.family) {
        case ChallengeFeedbackFamily::BatchCoefficient:
            draw = consumer.item_index;
            break;
        case ChallengeFeedbackFamily::OodPoint:
            draw = 2;
            draw_count =
                consumer.item_index == 0 ? 2 : 4;
            break;
        case ChallengeFeedbackFamily::DeepWeight:
            draw = 6 + consumer.item_index;
            break;
        case ChallengeFeedbackFamily::FoldChallenge:
            draw = 8 + consumer.item_index;
            break;
        default:
            return false;
        }
        if (draw >= 9 || draw + draw_count > 9) {
            return false;
        }
        const uint32_t lane_base = 2 + 19 * consumer.lane;
        for (uint32_t candidate = 0;
             candidate < draw_count; ++candidate) {
            for (uint32_t block = 0; block < 2; ++block) {
                expected_sources[expected_source_count++] =
                    lane_base + 1 +
                    2 * (draw + candidate) + block;
            }
        }
        expected_dependency = lane_base;
    }
    if (consumer.source_call_count !=
            expected_source_count ||
        consumer.dependency_lane_seed_call !=
            expected_dependency) {
        return false;
    }
    for (uint32_t source = 0;
         source < expected_source_count; ++source) {
        const uint32_t ordinal =
            consumer.source_call_ordinals[source];
        if (ordinal != expected_sources[source] ||
            ordinal >= plan.calls.size() ||
            plan.calls[ordinal].lane != consumer.lane) {
            return false;
        }
        const auto expected_kind =
            consumer.family ==
                    ChallengeFeedbackFamily::AirQuotient
                ? V5TranscriptShaCallKind::AirQuotient
                : consumer.family ==
                          ChallengeFeedbackFamily::QueryIndex
                      ? V5TranscriptShaCallKind::QueryIndex
                      : V5TranscriptShaCallKind::UniformDigest;
        if (plan.calls[ordinal].kind != expected_kind) {
            return false;
        }
    }
    if (expected_dependency != UINT32_MAX &&
        (expected_dependency >= plan.calls.size() ||
         plan.calls[expected_dependency].kind !=
             V5TranscriptShaCallKind::LaneSeed ||
         plan.calls[expected_dependency].lane != consumer.lane)) {
        return false;
    }
    return true;
}

bool EqualFp3Vector(
    const std::vector<Fp3>& lhs,
    const std::vector<Fp3>& rhs)
{
    if (lhs.size() != rhs.size()) return false;
    for (uint32_t index = 0; index < lhs.size(); ++index) {
        if (!gf::Eq(lhs[index], rhs[index])) return false;
    }
    return true;
}

bool EqualFp3Columns(
    const std::vector<std::vector<Fp3>>& lhs,
    const std::vector<std::vector<Fp3>>& rhs)
{
    if (lhs.size() != rhs.size()) return false;
    for (uint32_t column = 0; column < lhs.size(); ++column) {
        if (!EqualFp3Vector(lhs[column], rhs[column])) return false;
    }
    return true;
}

bool EqualFp3Preprocessed(
    const std::vector<
        std::pair<uint32_t, std::vector<Fp3>>>& lhs,
    const std::vector<
        std::pair<uint32_t, std::vector<Fp3>>>& rhs)
{
    if (lhs.size() != rhs.size()) return false;
    for (uint32_t index = 0; index < lhs.size(); ++index) {
        if (lhs[index].first != rhs[index].first ||
            !EqualFp3Vector(
                lhs[index].second, rhs[index].second)) {
            return false;
        }
    }
    return true;
}

} // namespace

bool ValidateV5FullTranscriptWitnessShardPlan(
    const V5FullTranscriptWitnessShardPlan& plan,
    std::string* why)
{
    if (!plan.valid ||
        plan.sha256d_calls != 296 ||
        plan.prequery_sha256d_calls != 40 ||
        plan.query_sha256d_calls != 256 ||
        plan.parent_shards != 30 ||
        plan.vertical_leaf_proofs != 57 ||
        plan.mapped_consumer_cells !=
            kV5SemanticConsumerCells ||
        plan.calls.size() != plan.sha256d_calls ||
        plan.consumers.size() !=
            kV5SemanticConsumerCells ||
        plan.fanout_links.size() != 16 ||
        plan.shards.size() != plan.parent_shards ||
        !plan.exact_304_source_mapping ||
        !plan.fanout_safe_unique_link_ids ||
        !plan.public_only_schedule_reconstruction ||
        plan.public_only_proof_verifier_reconstruction ||
        plan.proof_owned_sha_derivation_cells != 0 ||
        plan.recursively_consumed_sha_derivation_cells != 0) {
        return Fail(why, "full_shard_plan_shape");
    }
    std::vector<uint8_t> call_seen(
        plan.calls.size(), 0);
    std::array<uint32_t, 4> kind_counts{};
    for (uint32_t ordinal = 0;
         ordinal < plan.calls.size(); ++ordinal) {
        const auto& call = plan.calls[ordinal];
        const uint32_t kind =
            static_cast<uint32_t>(call.kind);
        if (call.ordinal != ordinal ||
            kind == 0 || kind > kind_counts.size() ||
            call.lane >= 2 ||
            call.compression_blocks == 0 ||
            call.compression_blocks > 63 ||
            call.parent_shard >= plan.shards.size() ||
            call.leaf_in_parent >=
                plan.shards[call.parent_shard].leaf_count) {
            return Fail(why, "full_shard_plan_call");
        }
        ++kind_counts[kind - 1];
    }
    if (kind_counts[0] != 2 ||
        kind_counts[1] != 2 ||
        kind_counts[2] != 36 ||
        kind_counts[3] != 256) {
        return Fail(why, "full_shard_plan_call_inventory");
    }
    uint32_t leaf_count = 0;
    uint32_t shard_cells = 0;
    for (uint32_t shard_index = 0;
         shard_index < plan.shards.size();
         ++shard_index) {
        const auto& shard = plan.shards[shard_index];
        if (shard.parent_shard != shard_index ||
            shard.leaf_count == 0 ||
            shard.public_schedule_statement.IsNull() ||
            shard.proof.version != 1 ||
            shard.proof.parent_shard != shard_index ||
            shard.proof.public_schedule_statement !=
                shard.public_schedule_statement ||
            shard.proof.proof_owned_cells != 0 ||
            shard.proof.recursively_consumed_cells != 0 ||
            shard.proof.aggregate_present ||
            !shard.proof.leaf_proofs.empty() ||
            !shard.proof.claimed_outputs.empty()) {
            return Fail(why, "full_shard_plan_container");
        }
        uint32_t blocks = 0;
        for (uint32_t ordinal : shard.call_ordinals) {
            if (ordinal >= plan.calls.size() ||
                call_seen[ordinal] ||
                plan.calls[ordinal].parent_shard !=
                    shard_index) {
                return Fail(why, "full_shard_plan_call_cover");
            }
            call_seen[ordinal] = 1;
            blocks +=
                plan.calls[ordinal].compression_blocks;
        }
        if (blocks != shard.compression_blocks ||
            shard.consumer_cells !=
                shard.consumer_semantic_rows.size()) {
            return Fail(why, "full_shard_plan_shard_totals");
        }
        leaf_count += shard.leaf_count;
        shard_cells += shard.consumer_cells;
    }
    if (std::find(
            call_seen.begin(), call_seen.end(), 0) !=
            call_seen.end() ||
        leaf_count != plan.vertical_leaf_proofs ||
        shard_cells != kV5SemanticConsumerCells) {
        return Fail(why, "full_shard_plan_cover");
    }

    std::array<uint8_t, kV5SemanticConsumerCells>
        semantic_seen{};
    for (const auto& consumer : plan.consumers) {
        if (consumer.semantic_row >= semantic_seen.size() ||
            semantic_seen[consumer.semantic_row] ||
            consumer.lane >= 2 ||
            consumer.coordinate >= 3 ||
            consumer.parent_shard >= plan.shards.size() ||
            consumer.source_call_count == 0 ||
            consumer.source_call_count >
                consumer.source_call_ordinals.size()) {
            return Fail(why, "full_shard_plan_consumer");
        }
        semantic_seen[consumer.semantic_row] = 1;
        for (uint32_t source_index = 0;
             source_index < consumer.source_call_count;
             ++source_index) {
            const uint32_t source =
                consumer.source_call_ordinals[source_index];
            if (source >= plan.calls.size() ||
                plan.calls[source].parent_shard !=
                    consumer.parent_shard) {
                return Fail(
                    why, "full_shard_plan_consumer_source");
            }
        }
        if (consumer.family !=
                ChallengeFeedbackFamily::AirQuotient &&
            consumer.dependency_lane_seed_call >=
                plan.calls.size()) {
            return Fail(
                why, "full_shard_plan_consumer_dependency");
        }
    }
    if (std::find(
            semantic_seen.begin(), semantic_seen.end(), 0) !=
            semantic_seen.end()) {
        return Fail(why, "full_shard_plan_semantic_cover");
    }

    for (uint32_t index = 0;
         index < plan.fanout_links.size(); ++index) {
        const auto& link = plan.fanout_links[index];
        if (link.link_id == 0 ||
            link.link_id >= gf::kP ||
            link.source_call_ordinal >= plan.calls.size() ||
            plan.calls[link.source_call_ordinal].kind !=
                V5TranscriptShaCallKind::LaneSeed ||
            link.source_word >= 8 ||
            link.target_count != 146 ||
            link.target_call_ordinals.size() !=
                link.target_count) {
            return Fail(why, "full_shard_plan_fanout");
        }
        std::vector<uint32_t> targets =
            link.target_call_ordinals;
        std::sort(targets.begin(), targets.end());
        if (std::adjacent_find(
                targets.begin(), targets.end()) !=
                targets.end()) {
            return Fail(why, "full_shard_plan_fanout_target");
        }
        for (uint32_t prior = 0; prior < index; ++prior) {
            if (plan.fanout_links[prior].link_id ==
                link.link_id) {
                return Fail(why, "full_shard_plan_link_id");
            }
        }
    }
    if (plan.public_plan_statement.IsNull() ||
        plan.public_plan_statement !=
            CommitV5FullTranscriptWitnessShardPlan(plan)) {
        return Fail(why, "full_shard_plan_commitment");
    }
    return true;
}

V5TranscriptUnificationCanaryV1
BuildV5TranscriptUnificationCanaryV1(
    const V5FullTranscriptWitnessShardPlan& plan)
{
    V5TranscriptUnificationCanaryV1 out;
    std::string plan_why;
    if (!ValidateV5FullTranscriptWitnessShardPlan(
            plan, &plan_why)) {
        out.note =
            "stage3:v5_v6_bus:transcript_unification:"
            "invalid_plan:" +
            plan_why;
        return out;
    }

    out.source_plan_statement = plan.public_plan_statement;
    out.sha256d_calls = plan.sha256d_calls;
    out.semantic_cells = plan.mapped_consumer_cells;
    out.trace_rows = kV5TranscriptUnificationRowsV1;
    out.trace_columns = kV5TranscriptUnificationColumns;
    out.public_columns.assign(
        out.trace_columns,
        std::vector<Fp3>(out.trace_rows, Fp3::Zero()));

    std::array<std::vector<uint8_t>, 6> family_call_seen;
    for (auto& seen : family_call_seen) {
        seen.assign(plan.calls.size(), 0);
    }
    std::vector<uint8_t> direct_call_seen(
        plan.calls.size(), 0);
    std::vector<uint8_t> dependency_call_seen(
        plan.calls.size(), 0);
    for (uint32_t family = 0;
         family < out.families.size(); ++family) {
        out.families[family].family =
            static_cast<ChallengeFeedbackFamily>(family + 1);
    }

    for (const auto& call : plan.calls) {
        out.sha256d_compression_blocks +=
            call.compression_blocks;
    }
    for (const auto& consumer : plan.consumers) {
        if (!ValidateV5TranscriptConsumerSourceV1(
                plan, consumer)) {
            out.note =
                "stage3:v5_v6_bus:transcript_unification:"
                "noncanonical_source_mapping";
            return out;
        }
        const uint32_t family_index =
            static_cast<uint32_t>(consumer.family) - 1;
        if (family_index >= out.families.size() ||
            consumer.semantic_row >= out.trace_rows) {
            out.note =
                "stage3:v5_v6_bus:transcript_unification:"
                "consumer_shape";
            return out;
        }
        auto& coverage = out.families[family_index];
        ++coverage.semantic_cells;

        bool locally_executable =
            consumer.family ==
                ChallengeFeedbackFamily::AirQuotient;
        for (uint32_t source_index = 0;
             source_index < consumer.source_call_count;
             ++source_index) {
            const uint32_t ordinal =
                consumer.source_call_ordinals[source_index];
            if (ordinal >= plan.calls.size()) {
                out.note =
                    "stage3:v5_v6_bus:"
                    "transcript_unification:source";
                return out;
            }
            locally_executable =
                locally_executable &&
                plan.calls[ordinal].kind ==
                    V5TranscriptShaCallKind::AirQuotient;
            if (!family_call_seen[family_index][ordinal]) {
                family_call_seen[family_index][ordinal] = 1;
                ++coverage.direct_sha256d_calls;
                coverage.direct_sha256d_compression_blocks +=
                    plan.calls[ordinal].compression_blocks;
            }
            if (!direct_call_seen[ordinal]) {
                direct_call_seen[ordinal] = 1;
                ++out.direct_sha256d_calls;
                out.direct_sha256d_compression_blocks +=
                    plan.calls[ordinal].compression_blocks;
            }
        }
        if (consumer.dependency_lane_seed_call != UINT32_MAX) {
            const uint32_t dependency =
                consumer.dependency_lane_seed_call;
            if (dependency >= plan.calls.size() ||
                plan.calls[dependency].kind !=
                    V5TranscriptShaCallKind::LaneSeed) {
                out.note =
                    "stage3:v5_v6_bus:"
                    "transcript_unification:dependency";
                return out;
            }
            if (!dependency_call_seen[dependency]) {
                dependency_call_seen[dependency] = 1;
                ++out.dependency_sha256d_calls;
                out.dependency_sha256d_compression_blocks +=
                    plan.calls[dependency].compression_blocks;
            }
        }

        if (locally_executable) {
            ++coverage.locally_executable_cells;
            ++out.locally_executable_cells;
        }
        // The validated V1 plan rejects every unearned proof counter.
        // Local SHA execution is deliberately not promoted to proof ownership.
        ++coverage.pending_cells;
        ++out.pending_cells;

        const uint32_t row = consumer.semantic_row;
        auto& columns = out.public_columns;
        columns[kV5TranscriptUnificationActive][row] =
            Fp3::One();
        columns[kV5TranscriptUnificationFamily][row] =
            Fp3::FromFp(gf::FromU64(
                static_cast<uint8_t>(consumer.family)));
        columns[kV5TranscriptUnificationLane][row] =
            Fp3::FromFp(gf::FromU64(consumer.lane));
        columns[kV5TranscriptUnificationItem][row] =
            Fp3::FromFp(gf::FromU64(
                consumer.item_index));
        columns[kV5TranscriptUnificationCoordinate][row] =
            Fp3::FromFp(gf::FromU64(
                consumer.coordinate));
        columns[kV5TranscriptUnificationConsumer][row] =
            Fp3::FromFp(gf::FromU64(
                static_cast<uint8_t>(consumer.consumer)));
        columns[kV5TranscriptUnificationSourceCallCount][row] =
            Fp3::FromFp(gf::FromU64(
                consumer.source_call_count));
        columns[kV5TranscriptUnificationParentShard][row] =
            Fp3::FromFp(gf::FromU64(
                consumer.parent_shard));
        columns[
            kV5TranscriptUnificationLocallyExecutable][row] =
            locally_executable ? Fp3::One() : Fp3::Zero();
        columns[kV5TranscriptUnificationPending][row] =
            Fp3::One();
    }

    for (uint32_t ordinal = 0;
         ordinal < plan.calls.size(); ++ordinal) {
        if (direct_call_seen[ordinal] &&
            dependency_call_seen[ordinal]) {
            out.note =
                "stage3:v5_v6_bus:transcript_unification:"
                "direct_dependency_overlap";
            return out;
        }
    }
    out.proof_owned_cells =
        plan.proof_owned_sha_derivation_cells;
    out.recursively_consumed_cells =
        plan.recursively_consumed_sha_derivation_cells;
    out.direct_v6_to_v5_feedback_cells = 0;
    out.exact_sha256d_call_inventory =
        out.sha256d_calls == 296 &&
        out.direct_sha256d_calls == 294 &&
        out.dependency_sha256d_calls == 2 &&
        out.direct_sha256d_calls +
                out.dependency_sha256d_calls ==
            out.sha256d_calls;
    out.exact_semantic_cell_inventory =
        out.semantic_cells == kV5SemanticConsumerCells &&
        out.pending_cells == out.semantic_cells;
    out.v5_sha256d_xof_schedule_selected = true;
    out.incompatible_v6_alghash_feedback_rejected = true;
    out.full_sha256d_execution_proved = false;
    out.complete_xof_selection_proved = false;
    out.public_proof_verifier_reconstructible = false;
    out.recursive_consumption_complete = false;
    out.production_authority_ready = false;

    BuildV5TranscriptUnificationPublicCsV1(
        out.public_constraint_system);
    for (uint32_t column = 0;
         column < out.public_columns.size(); ++column) {
        out.public_constraint_system.preprocessed.emplace_back(
            column, out.public_columns[column]);
    }
    out.public_schedule_cs_satisfied =
        v6::CountViolations(
            out.public_constraint_system,
            out.public_columns) == 0;
    out.public_schedule_cs_reconstructible = true;
    out.public_schedule_statement =
        CommitV5TranscriptUnificationCanaryV1(out);
    out.valid =
        out.version == 1 &&
        !out.source_plan_statement.IsNull() &&
        !out.public_schedule_statement.IsNull() &&
        out.exact_sha256d_call_inventory &&
        out.exact_semantic_cell_inventory &&
        out.public_schedule_cs_reconstructible &&
        out.public_schedule_cs_satisfied &&
        out.locally_executable_cells == 6 &&
        out.proof_owned_cells == 0 &&
        out.recursively_consumed_cells == 0 &&
        !out.full_sha256d_execution_proved &&
        !out.complete_xof_selection_proved &&
        !out.public_proof_verifier_reconstructible &&
        !out.recursive_consumption_complete &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:v5_v6_bus:transcript_unification:"
          "296_calls;304_cells;public_schedule_only;"
          "proof_owned_0;recursive_consumed_0;authority_false"
        : "stage3:v5_v6_bus:transcript_unification:invalid";
    return out;
}

bool ReconstructV5TranscriptUnificationPublicConstraintSystemV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const uint256& expected_public_schedule_statement,
    aq::AirConstraintSystem<Fp3>& constraint_system,
    std::vector<std::vector<Fp3>>& public_columns,
    std::string* why)
{
    constraint_system = {};
    public_columns.clear();
    if (expected_public_schedule_statement.IsNull()) {
        return Fail(
            why,
            "transcript_unification:null_public_statement");
    }
    const V5TranscriptUnificationCanaryV1 canonical =
        BuildV5TranscriptUnificationCanaryV1(plan);
    if (!canonical.valid ||
        canonical.public_schedule_statement !=
            expected_public_schedule_statement) {
        return Fail(
            why,
            "transcript_unification:public_statement");
    }
    constraint_system = canonical.public_constraint_system;
    public_columns = canonical.public_columns;
    if (v6::CountViolations(
            constraint_system, public_columns) != 0) {
        constraint_system = {};
        public_columns.clear();
        return Fail(
            why,
            "transcript_unification:public_cs");
    }
    return true;
}

bool ValidateV5TranscriptUnificationCanaryV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5TranscriptUnificationCanaryV1& canary,
    std::string* why)
{
    const V5TranscriptUnificationCanaryV1 canonical =
        BuildV5TranscriptUnificationCanaryV1(plan);
    if (!canonical.valid || !canary.valid ||
        canary.version != canonical.version ||
        canary.source_plan_statement !=
            canonical.source_plan_statement ||
        canary.public_schedule_statement !=
            canonical.public_schedule_statement ||
        canary.sha256d_calls != canonical.sha256d_calls ||
        canary.direct_sha256d_calls !=
            canonical.direct_sha256d_calls ||
        canary.dependency_sha256d_calls !=
            canonical.dependency_sha256d_calls ||
        canary.sha256d_compression_blocks !=
            canonical.sha256d_compression_blocks ||
        canary.direct_sha256d_compression_blocks !=
            canonical.direct_sha256d_compression_blocks ||
        canary.dependency_sha256d_compression_blocks !=
            canonical.dependency_sha256d_compression_blocks ||
        canary.semantic_cells != canonical.semantic_cells ||
        canary.locally_executable_cells !=
            canonical.locally_executable_cells ||
        canary.proof_owned_cells !=
            canonical.proof_owned_cells ||
        canary.recursively_consumed_cells !=
            canonical.recursively_consumed_cells ||
        canary.pending_cells != canonical.pending_cells ||
        canary.direct_v6_to_v5_feedback_cells != 0 ||
        canary.trace_rows != canonical.trace_rows ||
        canary.trace_columns != canonical.trace_columns ||
        canary.families != canonical.families ||
        !canary.exact_sha256d_call_inventory ||
        !canary.exact_semantic_cell_inventory ||
        !canary.v5_sha256d_xof_schedule_selected ||
        !canary.incompatible_v6_alghash_feedback_rejected ||
        !canary.public_schedule_cs_reconstructible ||
        !canary.public_schedule_cs_satisfied ||
        canary.full_sha256d_execution_proved ||
        canary.complete_xof_selection_proved ||
        canary.public_proof_verifier_reconstructible ||
        canary.recursive_consumption_complete ||
        canary.production_authority_ready ||
        !EqualFp3Columns(
            canary.public_columns,
            canonical.public_columns)) {
        return Fail(why, "transcript_unification:canary");
    }
    if (canary.public_constraint_system.n_rows !=
            canonical.public_constraint_system.n_rows ||
        canary.public_constraint_system.n_columns !=
            canonical.public_constraint_system.n_columns ||
        !EqualFp3Preprocessed(
            canary.public_constraint_system.preprocessed,
            canonical.public_constraint_system.preprocessed) ||
        canary.public_constraint_system.constraints.size() !=
            canonical.public_constraint_system.constraints.size()) {
        return Fail(why, "transcript_unification:canary_cs");
    }
    for (uint32_t constraint = 0;
         constraint <
             canary.public_constraint_system.constraints.size();
         ++constraint) {
        const auto& actual =
            canary.public_constraint_system
                .constraints[constraint];
        const auto& expected =
            canonical.public_constraint_system
                .constraints[constraint];
        if (actual.name == nullptr ||
            expected.name == nullptr ||
            std::strcmp(actual.name, expected.name) != 0 ||
            actual.kind != expected.kind ||
            actual.alg_degree != expected.alg_degree) {
            return Fail(
                why, "transcript_unification:constraint");
        }
    }
    aq::AirConstraintSystem<Fp3> reconstructed;
    std::vector<std::vector<Fp3>> reconstructed_columns;
    if (!ReconstructV5TranscriptUnificationPublicConstraintSystemV1(
            plan, canary.public_schedule_statement,
            reconstructed, reconstructed_columns, why) ||
        !EqualFp3Columns(
            reconstructed_columns, canary.public_columns) ||
        v6::CountViolations(
            reconstructed, reconstructed_columns) != 0) {
        return Fail(
            why, "transcript_unification:reconstruction");
    }
    return true;
}

V5FullTranscriptWitnessShardPlan
BuildV5FullTranscriptWitnessShardPlan(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed)
{
    V5FullTranscriptWitnessShardPlan out;
    const V5ShaProducerPlan inventory =
        AssessV5ShaProducerPlan(
            composition, child, child_fs_seed);
    const V5SemanticMaterialization semantic =
        BuildV5SemanticMaterialization(composition);
    if (!inventory.valid || !semantic.valid ||
        inventory.uniform_sha256d_compression_blocks_per_call
                .size() != 38 ||
        inventory.query_sha256d_compression_blocks_per_call
                .size() != 256) {
        out.note =
            "stage3:v5_v6_bus:full_shard_plan:inventory";
        return out;
    }
    out.shards.resize(30);
    for (uint32_t shard = 0;
         shard < out.shards.size(); ++shard) {
        out.shards[shard].parent_shard = shard;
        out.shards[shard].proof.parent_shard = shard;
    }
    const auto append_call =
        [&](V5TranscriptShaCallKind kind, uint32_t lane,
            uint32_t item, uint32_t hash_block,
            uint32_t blocks, uint32_t shard) {
            V5TranscriptShaCall call;
            call.ordinal =
                static_cast<uint32_t>(out.calls.size());
            call.kind = kind;
            call.lane = lane;
            call.item = item;
            call.hash_block = hash_block;
            call.compression_blocks = blocks;
            call.parent_shard = shard;
            if (kind == V5TranscriptShaCallKind::UniformDigest ||
                kind == V5TranscriptShaCallKind::QueryIndex) {
                call.dependency_lane_seed_call =
                    2 + 19 * lane;
            }
            out.shards[shard].call_ordinals.push_back(
                call.ordinal);
            out.shards[shard].compression_blocks += blocks;
            out.calls.push_back(call);
        };

    // The already-executed air-lambda SHA256d path has three compression
    // instances per lane and owns the first six consumer cells.
    append_call(
        V5TranscriptShaCallKind::AirQuotient,
        0, 0, 0, 3, 0);
    append_call(
        V5TranscriptShaCallKind::AirQuotient,
        1, 0, 0, 3, 0);

    uint32_t uniform_shard = 1;
    uint32_t uniform_in_shard = 0;
    for (uint32_t local = 0; local < 38; ++local) {
        const uint32_t blocks =
            inventory
                .uniform_sha256d_compression_blocks_per_call
                [local];
        while (uniform_shard <= 3 &&
               uniform_in_shard == inventory
                   .uniform_shard_compression_blocks
                   [uniform_shard - 1]) {
            ++uniform_shard;
            uniform_in_shard = 0;
        }
        if (uniform_shard > 3 ||
            uniform_in_shard + blocks >
                inventory.uniform_shard_compression_blocks
                    [uniform_shard - 1]) {
            out.note =
                "stage3:v5_v6_bus:full_shard_plan:"
                "uniform_partition";
            return out;
        }
        const uint32_t lane = local >= 19;
        const uint32_t lane_local = local - 19 * lane;
        if (lane_local == 0) {
            append_call(
                V5TranscriptShaCallKind::LaneSeed,
                lane, 0, 0, blocks, uniform_shard);
        } else {
            const uint32_t digest_call = lane_local - 1;
            append_call(
                V5TranscriptShaCallKind::UniformDigest,
                lane, digest_call / 2,
                digest_call % 2, blocks,
                uniform_shard);
        }
        uniform_in_shard += blocks;
    }

    uint32_t query_shard = 4;
    uint32_t query_in_shard = 0;
    for (uint32_t local = 0; local < 256; ++local) {
        const uint32_t blocks =
            inventory
                .query_sha256d_compression_blocks_per_call
                [local];
        while (query_shard < 30 &&
               query_in_shard == inventory
                   .query_shard_compression_blocks
                   [query_shard - 4]) {
            ++query_shard;
            query_in_shard = 0;
        }
        if (query_shard >= 30 ||
            query_in_shard + blocks >
                inventory.query_shard_compression_blocks
                    [query_shard - 4]) {
            out.note =
                "stage3:v5_v6_bus:full_shard_plan:"
                "query_partition";
            return out;
        }
        const uint32_t lane = local / 128;
        append_call(
            V5TranscriptShaCallKind::QueryIndex,
            lane, local % 128, 0, blocks,
            query_shard);
        query_in_shard += blocks;
    }

    // Split every parent into dependency-preserving vertical leaves of at
    // most 63 compression instances. No SHA256d call is ever split.
    for (auto& shard : out.shards) {
        uint32_t leaf = 0;
        uint32_t leaf_blocks = 0;
        for (uint32_t ordinal : shard.call_ordinals) {
            auto& call = out.calls[ordinal];
            if (leaf_blocks != 0 &&
                leaf_blocks + call.compression_blocks > 63) {
                ++leaf;
                leaf_blocks = 0;
            }
            call.leaf_in_parent = leaf;
            leaf_blocks += call.compression_blocks;
        }
        shard.leaf_count =
            shard.call_ordinals.empty() ? 0 : leaf + 1;
        out.vertical_leaf_proofs += shard.leaf_count;
    }

    const auto uniform_sources =
        [&](const V5SemanticConsumerCell& cell,
            std::array<uint32_t, 8>& sources,
            uint32_t& count) {
            uint32_t draw = 0;
            uint32_t draw_count = 1;
            switch (cell.family) {
            case ChallengeFeedbackFamily::BatchCoefficient:
                draw = cell.item_index;
                break;
            case ChallengeFeedbackFamily::OodPoint:
                draw = 2;
                draw_count =
                    cell.item_index == 0 ? 2 : 4;
                break;
            case ChallengeFeedbackFamily::DeepWeight:
                draw = 6 + cell.item_index;
                break;
            case ChallengeFeedbackFamily::FoldChallenge:
                draw = 8 + cell.item_index;
                break;
            default:
                return false;
            }
            if (draw >= 9 ||
                draw + draw_count > 9) {
                return false;
            }
            count = 0;
            const uint32_t lane_base =
                2 + 19 * cell.lane;
            for (uint32_t candidate = 0;
                 candidate < draw_count; ++candidate) {
                for (uint32_t block = 0; block < 2; ++block) {
                    sources[count++] =
                        lane_base + 1 +
                        2 * (draw + candidate) + block;
                }
            }
            return true;
        };
    for (const auto& cell : semantic.cells) {
        V5TranscriptConsumerSource mapped;
        mapped.semantic_row = cell.semantic_row;
        mapped.family = cell.family;
        mapped.lane = cell.lane;
        mapped.item_index = cell.item_index;
        mapped.coordinate = cell.coordinate;
        mapped.consumer = cell.consumer;
        if (cell.family ==
            ChallengeFeedbackFamily::AirQuotient) {
            mapped.source_call_count = 1;
            mapped.source_call_ordinals[0] = cell.lane;
        } else if (cell.family ==
                   ChallengeFeedbackFamily::QueryIndex) {
            mapped.source_call_count = 1;
            mapped.source_call_ordinals[0] =
                40 + 128 * cell.lane + cell.item_index;
            mapped.dependency_lane_seed_call =
                2 + 19 * cell.lane;
        } else if (!uniform_sources(
                       cell, mapped.source_call_ordinals,
                       mapped.source_call_count)) {
            out.note =
                "stage3:v5_v6_bus:full_shard_plan:"
                "consumer_family";
            return out;
        } else {
            mapped.dependency_lane_seed_call =
                2 + 19 * cell.lane;
        }
        mapped.parent_shard =
            out.calls[mapped.source_call_ordinals[0]]
                .parent_shard;
        for (uint32_t source = 1;
             source < mapped.source_call_count; ++source) {
            if (out.calls[
                    mapped.source_call_ordinals[source]]
                    .parent_shard != mapped.parent_shard) {
                out.note =
                    "stage3:v5_v6_bus:full_shard_plan:"
                    "typed_draw_split";
                return out;
            }
        }
        out.shards[mapped.parent_shard]
            .consumer_semantic_rows.push_back(
                mapped.semantic_row);
        ++out.shards[mapped.parent_shard].consumer_cells;
        out.consumers.push_back(mapped);
    }

    // One ID per lane-seed digest word is reused at every bit-sliced target.
    // A single source multiplicity therefore balances all 146 target calls
    // without overwriting source metadata.
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t lane_seed_call = 2 + 19 * lane;
        std::vector<uint32_t> targets;
        for (uint32_t call = lane_seed_call + 1;
             call < lane_seed_call + 19; ++call) {
            targets.push_back(call);
        }
        for (uint32_t query = 0; query < 128; ++query) {
            targets.push_back(40 + 128 * lane + query);
        }
        for (uint32_t word = 0; word < 8; ++word) {
            V5TranscriptFanoutLink link;
            link.link_id =
                UINT64_C(0x5653460000000000) +
                (uint64_t{lane} << 16) + word + 1;
            link.source_call_ordinal = lane_seed_call;
            link.source_word = word;
            link.target_count =
                static_cast<uint32_t>(targets.size());
            link.target_call_ordinals = targets;
            out.fanout_links.push_back(std::move(link));
        }
    }

    for (auto& shard : out.shards) {
        HashWriter statement;
        statement <<
            "BTX_RC_STAGE3_V5_TRANSCRIPT_WITNESS_PARENT_SHARD_V1";
        statement << semantic.public_boundary_commitment;
        statement << child_fs_seed;
        statement << shard.parent_shard;
        statement << shard.compression_blocks;
        statement << shard.consumer_cells;
        statement << shard.leaf_count;
        for (uint32_t call : shard.call_ordinals) {
            statement << call;
            statement <<
                out.calls[call].compression_blocks;
            statement << static_cast<uint8_t>(
                out.calls[call].kind);
        }
        for (uint32_t row :
             shard.consumer_semantic_rows) {
            statement << row;
        }
        shard.public_schedule_statement =
            statement.GetHash();
        shard.proof.public_schedule_statement =
            shard.public_schedule_statement;
    }
    out.sha256d_calls =
        static_cast<uint32_t>(out.calls.size());
    out.prequery_sha256d_calls = 40;
    out.query_sha256d_calls = 256;
    out.parent_shards =
        static_cast<uint32_t>(out.shards.size());
    out.mapped_consumer_cells =
        static_cast<uint32_t>(out.consumers.size());
    out.proof_owned_sha_derivation_cells = 0;
    out.recursively_consumed_sha_derivation_cells = 0;
    out.exact_304_source_mapping =
        out.mapped_consumer_cells ==
            kV5SemanticConsumerCells;
    out.fanout_safe_unique_link_ids =
        out.fanout_links.size() == 16;
    out.public_only_schedule_reconstruction = true;
    out.public_only_proof_verifier_reconstruction =
        false;
    out.valid = true;
    out.public_plan_statement =
        CommitV5FullTranscriptWitnessShardPlan(out);
    std::string validate_why;
    if (!ValidateV5FullTranscriptWitnessShardPlan(
            out, &validate_why)) {
        out.valid = false;
        out.note = validate_why;
        return out;
    }
    out.note =
        "stage3:v5_v6_bus:full_shard_plan:"
        "304_sources_mapped;30_parents;57_vertical_leaves;"
        "proof_owned_0;recursive_consumed_0";
    return out;
}

namespace {

constexpr uint32_t kV5TranscriptAttachmentMagicV1 =
    0x31545056U; // "VPT1"
constexpr uint32_t kV5OodAttachmentProofMagicV1 =
    0x31444f56U; // "VOD1"
constexpr uint32_t kV5QueryLeafAttachmentProofMagicV1 =
    0x31515156U; // "VQQ1"

size_t V5TranscriptProofMaxBytesV1(
    V5TranscriptLeafProofKindV1 kind)
{
    if (kind ==
            V5TranscriptLeafProofKindV1::
                QueryIndexLeafSplitRap) {
        return kV5TranscriptQueryLeafProofMaxBytesV1;
    }
    return kind ==
            V5TranscriptLeafProofKindV1::
                OodPointSplitRap
        ? kV5TranscriptOodProofMaxBytesV1
        : kV5TranscriptLeafProofMaxBytesV1;
}

uint256 CommitV5TranscriptLeafScheduleV1(
    const uint256& source_plan_statement,
    const V5TranscriptLeafScheduleV1& leaf)
{
    if (source_plan_statement.IsNull() ||
        leaf.call_ordinals.empty()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_TRANSCRIPT_LEAF_SCHEDULE_V1";
    hash << source_plan_statement;
    hash << leaf.leaf_ordinal;
    hash << leaf.parent_shard;
    hash << leaf.leaf_in_parent;
    hash << leaf.compression_blocks;
    hash << leaf.consumer_source_edges;
    hash << static_cast<uint32_t>(
        leaf.call_ordinals.size());
    for (uint32_t call : leaf.call_ordinals) hash << call;
    hash << static_cast<uint32_t>(
        leaf.consumer_semantic_rows.size());
    for (uint32_t row :
         leaf.consumer_semantic_rows) {
        hash << row;
    }
    return hash.GetHash();
}

uint256 CommitV5TranscriptAttachmentScheduleV1(
    const V5TranscriptProofAttachmentBundleV1& bundle)
{
    if (bundle.source_plan_statement.IsNull() ||
        bundle.leaves.size() !=
            kV5TranscriptVerticalLeafCountV1 ||
        bundle.consumers.size() !=
            kV5SemanticConsumerCells) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_TRANSCRIPT_ATTACHMENT_SCHEDULE_V1";
    hash << bundle.version;
    hash << bundle.source_plan_statement;
    hash << bundle.vertical_leaves;
    hash << bundle.sha256d_calls;
    hash << bundle.semantic_cells;
    hash << bundle.lane_seed_fanouts;
    hash << static_cast<uint32_t>(bundle.leaves.size());
    for (const auto& leaf : bundle.leaves) {
        hash << leaf.schedule_statement;
    }
    hash << static_cast<uint32_t>(
        bundle.consumers.size());
    for (const auto& consumer : bundle.consumers) {
        hash << consumer.semantic_row;
        hash << static_cast<uint8_t>(consumer.family);
        hash << consumer.lane;
        hash << consumer.item_index;
        hash << consumer.coordinate;
        hash << static_cast<uint8_t>(consumer.consumer);
        hash << consumer.source_call_count;
        for (uint32_t source :
             consumer.source_call_ordinals) {
            hash << source;
        }
        for (uint32_t leaf :
             consumer.source_leaf_ordinals) {
            hash << leaf;
        }
        hash << consumer.dependency_lane_seed_call;
        hash << consumer.dependency_lane_seed_leaf;
    }
    for (const auto& fanout : bundle.fanouts) {
        hash << fanout.lane;
        hash << fanout.source_call_ordinal;
        hash << fanout.source_leaf_ordinal;
        for (uint64_t link_id :
             fanout.word_link_ids) {
            hash << link_id;
        }
        hash << static_cast<uint32_t>(
            fanout.target_call_ordinals.size());
        for (uint32_t call :
             fanout.target_call_ordinals) {
            hash << call;
        }
        hash << static_cast<uint32_t>(
            fanout.target_leaf_ordinals.size());
        for (uint32_t leaf :
             fanout.target_leaf_ordinals) {
            hash << leaf;
        }
    }
    return hash.GetHash();
}

uint256 CommitV5TranscriptLeafProofAttachmentV1(
    const uint256& public_schedule_statement,
    const V5TranscriptLeafProofAttachmentV1& proof)
{
    if (public_schedule_statement.IsNull() ||
        proof.proof_bytes.empty() ||
        proof.proof_bytes.size() >
            V5TranscriptProofMaxBytesV1(proof.kind) ||
        proof.proof_owned_semantic_rows.empty()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_TRANSCRIPT_LEAF_PROOF_ATTACHMENT_V1";
    hash << proof.version;
    hash << public_schedule_statement;
    hash << proof.leaf_ordinal;
    hash << static_cast<uint8_t>(proof.kind);
    hash << proof.lane;
    hash << proof.batch_item;
    hash << static_cast<uint32_t>(
        proof.proof_owned_semantic_rows.size());
    for (uint32_t row :
         proof.proof_owned_semantic_rows) {
        hash << row;
    }
    hash << static_cast<uint64_t>(proof.proof_bytes.size());
    for (unsigned char byte : proof.proof_bytes) {
        hash << byte;
    }
    hash << proof.recursively_consumed_cells;
    return hash.GetHash();
}

uint256 CommitV5TranscriptProofAttachmentBundleV1(
    const V5TranscriptProofAttachmentBundleV1& bundle)
{
    if (bundle.public_schedule_statement.IsNull()) return {};
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_TRANSCRIPT_PROOF_ATTACHMENT_BUNDLE_V1";
    hash << bundle.version;
    hash << bundle.source_plan_statement;
    hash << bundle.public_schedule_statement;
    hash << bundle.proof_attached_leaves;
    hash << bundle.proof_owned_cells;
    hash << bundle.algebraically_bound_output_cells;
    hash << bundle.recursively_consumed_cells;
    hash << bundle.pending_cells;
    hash << bundle.encoded_proof_bytes;
    hash << static_cast<uint32_t>(bundle.proofs.size());
    for (const auto& proof : bundle.proofs) {
        hash << proof.proof_statement;
    }
    return hash.GetHash();
}

std::vector<uint32_t> BatchCoefficientAttachmentRowsV1(
    const V5TranscriptProofAttachmentBundleV1& bundle,
    uint32_t lane,
    uint32_t batch_item)
{
    std::vector<uint32_t> rows;
    for (const auto& consumer : bundle.consumers) {
        if (consumer.family ==
                ChallengeFeedbackFamily::BatchCoefficient &&
            consumer.lane == lane &&
            consumer.item_index == batch_item) {
            rows.push_back(consumer.semantic_row);
        }
    }
    std::sort(rows.begin(), rows.end());
    return rows;
}

std::optional<uint32_t> BatchCoefficientAttachmentLeafV1(
    const V5TranscriptProofAttachmentBundleV1& bundle,
    uint32_t lane,
    uint32_t batch_item)
{
    const std::vector<uint32_t> rows =
        BatchCoefficientAttachmentRowsV1(
            bundle, lane, batch_item);
    if (rows.size() != 3) return std::nullopt;
    std::optional<uint32_t> leaf;
    for (uint32_t row : rows) {
        if (row >= bundle.consumers.size() ||
            bundle.consumers[row].semantic_row != row) {
            return std::nullopt;
        }
        const auto& consumer = bundle.consumers[row];
        for (uint32_t source = 0;
             source < consumer.source_call_count;
             ++source) {
            const uint32_t source_leaf =
                consumer.source_leaf_ordinals[source];
            if (!leaf.has_value()) leaf = source_leaf;
            if (*leaf != source_leaf) return std::nullopt;
        }
        if (consumer.dependency_lane_seed_call == UINT32_MAX ||
            consumer.dependency_lane_seed_leaf != *leaf) {
            return std::nullopt;
        }
    }
    if (!leaf.has_value() ||
        *leaf >= bundle.leaves.size()) {
        return std::nullopt;
    }
    const auto& calls =
        bundle.leaves[*leaf].call_ordinals;
    const uint32_t lane_base = 2 + 19 * lane;
    const std::array<uint32_t, 3> required{
        lane_base,
        lane_base + 1 + 2 * batch_item,
        lane_base + 2 + 2 * batch_item};
    for (uint32_t call : required) {
        if (std::find(calls.begin(), calls.end(), call) ==
            calls.end()) {
            return std::nullopt;
        }
    }
    return leaf;
}

std::vector<uint32_t> OodPointAttachmentRowsV1(
    const V5TranscriptProofAttachmentBundleV1& bundle,
    uint32_t lane,
    uint32_t point)
{
    std::vector<uint32_t> rows;
    for (const auto& consumer : bundle.consumers) {
        if (consumer.family ==
                ChallengeFeedbackFamily::OodPoint &&
            consumer.lane == lane &&
            consumer.item_index == point) {
            rows.push_back(consumer.semantic_row);
        }
    }
    std::sort(rows.begin(), rows.end());
    return rows;
}

std::optional<uint32_t> OodPointAttachmentLeafV1(
    const V5TranscriptProofAttachmentBundleV1& bundle,
    uint32_t lane,
    uint32_t point)
{
    const auto rows =
        OodPointAttachmentRowsV1(bundle, lane, point);
    if (rows.size() != 3 || lane >= 2 || point >= 2) {
        return std::nullopt;
    }
    std::optional<uint32_t> leaf;
    for (uint32_t row : rows) {
        if (row >= bundle.consumers.size() ||
            bundle.consumers[row].semantic_row != row) {
            return std::nullopt;
        }
        const auto& consumer = bundle.consumers[row];
        for (uint32_t source = 0;
             source < consumer.source_call_count;
             ++source) {
            const uint32_t source_leaf =
                consumer.source_leaf_ordinals[source];
            if (!leaf.has_value()) leaf = source_leaf;
            if (*leaf != source_leaf) return std::nullopt;
        }
        if (consumer.dependency_lane_seed_call == UINT32_MAX ||
            consumer.dependency_lane_seed_leaf != *leaf) {
            return std::nullopt;
        }
    }
    if (!leaf.has_value() ||
        *leaf >= bundle.leaves.size()) {
        return std::nullopt;
    }
    const auto& calls =
        bundle.leaves[*leaf].call_ordinals;
    const uint32_t lane_base = 2 + 19 * lane;
    // Both points use the complete selector: candidate 2/3 validity depends
    // on the selected result of candidates 0/1.
    for (uint32_t call = lane_base + 5;
         call <= lane_base + 12; ++call) {
        if (std::find(calls.begin(), calls.end(), call) ==
            calls.end()) {
            return std::nullopt;
        }
    }
    if (std::find(calls.begin(), calls.end(), lane_base) ==
        calls.end()) {
        return std::nullopt;
    }
    return leaf;
}

std::vector<uint32_t> SingleUniformAttachmentRowsV1(
    const V5TranscriptProofAttachmentBundleV1& bundle,
    ChallengeFeedbackFamily family,
    uint32_t lane,
    uint32_t item)
{
    std::vector<uint32_t> rows;
    for (const auto& consumer : bundle.consumers) {
        if (consumer.family == family &&
            consumer.lane == lane &&
            consumer.item_index == item) {
            rows.push_back(consumer.semantic_row);
        }
    }
    std::sort(rows.begin(), rows.end());
    return rows;
}

std::optional<uint32_t> SingleUniformAttachmentLeafV1(
    const V5TranscriptProofAttachmentBundleV1& bundle,
    ChallengeFeedbackFamily family,
    uint32_t lane,
    uint32_t item)
{
    if (lane >= 2 ||
        (family != ChallengeFeedbackFamily::DeepWeight &&
         family !=
             ChallengeFeedbackFamily::FoldChallenge)) {
        return std::nullopt;
    }
    const auto rows =
        SingleUniformAttachmentRowsV1(
            bundle, family, lane, item);
    if (rows.size() != 3) return std::nullopt;
    std::optional<uint32_t> source_leaf;
    for (uint32_t row : rows) {
        if (row >= bundle.consumers.size() ||
            bundle.consumers[row].semantic_row != row) {
            return std::nullopt;
        }
        const auto& consumer = bundle.consumers[row];
        if (consumer.source_call_count != 2 ||
            consumer.dependency_lane_seed_call ==
                UINT32_MAX ||
            consumer.dependency_lane_seed_leaf >=
                bundle.leaves.size()) {
            return std::nullopt;
        }
        for (uint32_t source = 0; source < 2; ++source) {
            const uint32_t leaf =
                consumer.source_leaf_ordinals[source];
            if (!source_leaf.has_value()) {
                source_leaf = leaf;
            }
            if (*source_leaf != leaf) {
                return std::nullopt;
            }
        }
    }
    if (!source_leaf.has_value() ||
        *source_leaf >= bundle.leaves.size()) {
        return std::nullopt;
    }
    const uint32_t draw =
        family == ChallengeFeedbackFamily::DeepWeight
        ? 6 + item
        : 8 + item;
    if (draw >= 9) return std::nullopt;
    const uint32_t lane_base = 2 + 19 * lane;
    const auto& calls =
        bundle.leaves[*source_leaf].call_ordinals;
    for (uint32_t block = 0; block < 2; ++block) {
        const uint32_t call =
            lane_base + 1 + 2 * draw + block;
        if (std::find(
                calls.begin(), calls.end(), call) ==
            calls.end()) {
            return std::nullopt;
        }
    }
    return source_leaf;
}

std::vector<uint32_t> QueryLeafAttachmentRowsV1(
    const V5TranscriptProofAttachmentBundleV1& bundle,
    uint32_t leaf_ordinal,
    uint32_t lane,
    uint32_t first_query)
{
    std::vector<
        std::pair<uint32_t, uint32_t>> query_rows;
    for (const auto& consumer : bundle.consumers) {
        if (consumer.family !=
                ChallengeFeedbackFamily::QueryIndex ||
            consumer.lane != lane ||
            consumer.coordinate != 0 ||
            consumer.source_call_count != 1 ||
            consumer.source_leaf_ordinals[0] !=
                leaf_ordinal) {
            continue;
        }
        query_rows.emplace_back(
            consumer.item_index,
            consumer.semantic_row);
    }
    std::sort(query_rows.begin(), query_rows.end());
    if (query_rows.empty() ||
        query_rows.size() >
            kV5QueryIndexLeafMaxQueriesV1 ||
        query_rows.front().first != first_query) {
        return {};
    }
    std::vector<uint32_t> rows;
    rows.reserve(query_rows.size());
    for (uint32_t index = 0;
         index < query_rows.size(); ++index) {
        if (query_rows[index].first !=
            first_query + index) {
            return {};
        }
        rows.push_back(query_rows[index].second);
    }
    std::sort(rows.begin(), rows.end());
    return rows;
}

void RefreshV5TranscriptAttachmentProofCountersV1(
    V5TranscriptProofAttachmentBundleV1& bundle)
{
    bundle.proof_attached_leaves = 0;
    bundle.proof_owned_cells = 0;
    bundle.algebraically_bound_output_cells = 0;
    bundle.recursively_consumed_cells = 0;
    bundle.encoded_proof_bytes = 0;
    std::vector<uint32_t> attached_leaves;
    for (const auto& proof : bundle.proofs) {
        if (std::find(
                attached_leaves.begin(),
                attached_leaves.end(),
                proof.leaf_ordinal) ==
            attached_leaves.end()) {
            attached_leaves.push_back(proof.leaf_ordinal);
            ++bundle.proof_attached_leaves;
        }
        bundle.proof_owned_cells +=
            static_cast<uint32_t>(
                proof.proof_owned_semantic_rows.size());
        bundle.algebraically_bound_output_cells +=
            static_cast<uint32_t>(
                proof.proof_owned_semantic_rows.size());
        bundle.recursively_consumed_cells +=
            proof.recursively_consumed_cells;
        bundle.encoded_proof_bytes +=
            proof.proof_bytes.size();
    }
    bundle.pending_cells =
        bundle.proof_owned_cells <= bundle.semantic_cells
        ? bundle.semantic_cells - bundle.proof_owned_cells
        : 0;
    bundle.attached_proofs_publicly_verified =
        !bundle.proofs.empty();
    bundle.all_57_leaf_proofs_attached =
        bundle.proof_attached_leaves ==
            kV5TranscriptVerticalLeafCountV1;
    bundle.recursive_consumption_complete = false;
    bundle.production_authority_ready = false;
    bundle.bundle_statement =
        CommitV5TranscriptProofAttachmentBundleV1(bundle);
}

bool SameV5TranscriptAttachmentScheduleV1(
    const V5TranscriptProofAttachmentBundleV1& actual,
    const V5TranscriptProofAttachmentBundleV1& expected)
{
    return
        actual.version == expected.version &&
        actual.source_plan_statement ==
            expected.source_plan_statement &&
        actual.public_schedule_statement ==
            expected.public_schedule_statement &&
        actual.vertical_leaves == expected.vertical_leaves &&
        actual.sha256d_calls == expected.sha256d_calls &&
        actual.semantic_cells == expected.semantic_cells &&
        actual.lane_seed_fanouts ==
            expected.lane_seed_fanouts &&
        actual.exact_leaf_call_partition &&
        actual.exact_consumer_source_binding &&
        actual.exact_lane_seed_fanouts &&
        actual.leaves == expected.leaves &&
        actual.consumers == expected.consumers &&
        actual.fanouts == expected.fanouts;
}

bool CanonicalSplitRapProofBytesV1(
    const std::vector<unsigned char>& bytes,
    aq::AirQuotientSplitRapRowsProof* decoded = nullptr)
{
    if (bytes.empty() ||
        bytes.size() > kV5TranscriptLeafProofMaxBytesV1) {
        return false;
    }
    const auto proof =
        aq::DeserializeAirQuotientSplitRapRowsProof(bytes);
    if (!proof.has_value()) return false;
    std::vector<unsigned char> canonical;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            *proof, canonical) != bytes.size() ||
        canonical != bytes) {
        return false;
    }
    if (decoded != nullptr) *decoded = *proof;
    return true;
}

struct DecodedV5OodAttachmentProofV1 {
    uint32_t lane{0};
    uint32_t point{0};
    uint32_t selected_candidate{0};
    uint256 proof_statement{};
    std::array<aq::AirQuotientSplitRapRowsProof, 4>
        candidate_quotients{};
    aq::AirQuotientSplitRapRowsProof selector_quotient;
};

bool SerializeV5OodAttachmentProofV1(
    const V5OodPointSplitRapProofV1& proof,
    std::vector<unsigned char>& out);

std::optional<DecodedV5OodAttachmentProofV1>
DeserializeV5OodAttachmentProofV1(
    const std::vector<unsigned char>& bytes);

struct DecodedV5QueryLeafAttachmentProofV1 {
    uint32_t leaf_ordinal{0};
    uint32_t lane{0};
    uint32_t first_query{0};
    uint256 proof_statement{};
    std::vector<aq::AirQuotientSplitRapRowsProof>
        query_quotients;
};

bool SerializeV5QueryLeafAttachmentProofV1(
    const V5QueryIndexLeafSplitRapProofV1& proof,
    std::vector<unsigned char>& out);

std::optional<DecodedV5QueryLeafAttachmentProofV1>
DeserializeV5QueryLeafAttachmentProofV1(
    const std::vector<unsigned char>& bytes);

bool ValidateV5TranscriptAttachmentShapeV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why)
{
    const auto canonical =
        BuildV5TranscriptProofAttachmentBundleV1(plan);
    if (!canonical.valid || !bundle.valid ||
        !SameV5TranscriptAttachmentScheduleV1(
            bundle, canonical) ||
        bundle.proofs.size() >
            kV5TranscriptVerticalLeafCountV1) {
        return Fail(
            why, "transcript_attachment:schedule");
    }
    uint64_t encoded_bytes = 0;
    uint32_t owned_cells = 0;
    std::array<uint8_t, kV5SemanticConsumerCells>
        owned_rows{};
    uint32_t previous_key = 0;
    std::vector<uint32_t> attached_leaves;
    for (uint32_t index = 0;
         index < bundle.proofs.size(); ++index) {
        const auto& proof = bundle.proofs[index];
        const bool is_batch =
            proof.kind ==
            V5TranscriptLeafProofKindV1::
                BatchCoefficientSplitRap;
        const bool is_ood =
            proof.kind ==
            V5TranscriptLeafProofKindV1::
                OodPointSplitRap;
        const bool is_deep =
            proof.kind ==
            V5TranscriptLeafProofKindV1::
                DeepWeightSplitRap;
        const bool is_fold =
            proof.kind ==
            V5TranscriptLeafProofKindV1::
                FoldChallengeSplitRap;
        const bool is_query =
            proof.kind ==
            V5TranscriptLeafProofKindV1::
                QueryIndexLeafSplitRap;
        const auto decoded_ood =
            is_ood
            ? DeserializeV5OodAttachmentProofV1(
                  proof.proof_bytes)
            : std::optional<
                  DecodedV5OodAttachmentProofV1>{};
        const auto decoded_query =
            is_query
            ? DeserializeV5QueryLeafAttachmentProofV1(
                  proof.proof_bytes)
            : std::optional<
                  DecodedV5QueryLeafAttachmentProofV1>{};
        const std::vector<uint32_t> expected_rows =
            is_batch
            ? BatchCoefficientAttachmentRowsV1(
                  canonical, proof.lane,
                  proof.batch_item)
            : is_ood
                ? OodPointAttachmentRowsV1(
                      canonical, proof.lane,
                      proof.batch_item)
                : is_deep
                    ? SingleUniformAttachmentRowsV1(
                          canonical,
                          ChallengeFeedbackFamily::
                              DeepWeight,
                          proof.lane, proof.batch_item)
                    : is_fold
                        ? SingleUniformAttachmentRowsV1(
                              canonical,
                              ChallengeFeedbackFamily::
                                  FoldChallenge,
                              proof.lane,
                              proof.batch_item)
                        : is_query
                            ? QueryLeafAttachmentRowsV1(
                                  canonical,
                                  proof.leaf_ordinal,
                                  proof.lane,
                                  proof.batch_item)
                            : std::vector<uint32_t>{};
        const auto expected_leaf =
            is_batch
            ? BatchCoefficientAttachmentLeafV1(
                  canonical, proof.lane,
                  proof.batch_item)
            : is_ood
                ? OodPointAttachmentLeafV1(
                      canonical, proof.lane,
                      proof.batch_item)
                : is_deep
                    ? SingleUniformAttachmentLeafV1(
                          canonical,
                          ChallengeFeedbackFamily::
                              DeepWeight,
                          proof.lane, proof.batch_item)
                    : is_fold
                        ? SingleUniformAttachmentLeafV1(
                              canonical,
                              ChallengeFeedbackFamily::
                                  FoldChallenge,
                              proof.lane,
                              proof.batch_item)
                        : is_query &&
                                  !expected_rows.empty()
                            ? std::optional<uint32_t>{
                                  proof.leaf_ordinal}
                            : std::optional<uint32_t>{};
        const uint32_t key =
            is_query
            ? 14U + proof.leaf_ordinal
            : is_fold
                ? 12U + proof.lane
                : (is_ood ? 4U
                          : is_deep ? 8U : 0U) +
                      2 * proof.lane +
                      proof.batch_item;
        if (proof.version != 1 ||
            (!is_batch && !is_ood &&
             !is_deep && !is_fold && !is_query) ||
            proof.lane >= 2 ||
            proof.batch_item >=
                (is_query ? 128U
                          : is_fold ? 1U : 2U) ||
            (!is_query && expected_rows.size() != 3) ||
            expected_rows.empty() ||
            !expected_leaf.has_value() ||
            proof.leaf_ordinal >= bundle.leaves.size() ||
            (index != 0 &&
             key <= previous_key) ||
            proof.leaf_ordinal != *expected_leaf ||
            proof.proof_owned_semantic_rows !=
                expected_rows ||
            proof.recursively_consumed_cells != 0 ||
            (is_ood &&
             (!decoded_ood.has_value() ||
              decoded_ood->lane != proof.lane ||
              decoded_ood->point != proof.batch_item)) ||
            (is_query &&
             (!decoded_query.has_value() ||
              decoded_query->leaf_ordinal !=
                  proof.leaf_ordinal ||
              decoded_query->lane != proof.lane ||
              decoded_query->first_query !=
                  proof.batch_item ||
              decoded_query->query_quotients.size() !=
                  expected_rows.size())) ||
            proof.proof_statement.IsNull() ||
            proof.proof_statement !=
                CommitV5TranscriptLeafProofAttachmentV1(
                    bundle.public_schedule_statement,
                    proof) ||
            ((is_batch || is_deep || is_fold)
                 ? !CanonicalSplitRapProofBytesV1(
                       proof.proof_bytes)
                 : is_ood
                     ? !decoded_ood.has_value()
                     : !decoded_query.has_value())) {
            return Fail(
                why, "transcript_attachment:proof_shape");
        }
        previous_key = key;
        if (std::find(
                attached_leaves.begin(),
                attached_leaves.end(),
                proof.leaf_ordinal) ==
            attached_leaves.end()) {
            attached_leaves.push_back(proof.leaf_ordinal);
        }
        if (proof.proof_bytes.size() >
                kV5TranscriptAttachmentBundleMaxBytesV1 -
                    encoded_bytes) {
            return Fail(
                why, "transcript_attachment:proof_bytes");
        }
        encoded_bytes += proof.proof_bytes.size();
        for (uint32_t row :
             proof.proof_owned_semantic_rows) {
            if (row >= owned_rows.size() ||
                owned_rows[row]) {
                return Fail(
                    why,
                    "transcript_attachment:proof_row");
            }
            owned_rows[row] = 1;
            ++owned_cells;
        }
    }
    if (bundle.proofs.size() >
            kV5TranscriptLocalProofAttachmentCountV1 ||
        bundle.proof_attached_leaves !=
            attached_leaves.size() ||
        bundle.proof_owned_cells != owned_cells ||
        owned_cells >
            kV5TranscriptWithQueryProofOwnedCellsV1 ||
        bundle.algebraically_bound_output_cells !=
            owned_cells ||
        bundle.recursively_consumed_cells != 0 ||
        bundle.pending_cells !=
            kV5SemanticConsumerCells - owned_cells ||
        bundle.encoded_proof_bytes != encoded_bytes ||
        bundle.all_57_leaf_proofs_attached ||
        bundle.recursive_consumption_complete ||
        bundle.production_authority_ready ||
        bundle.bundle_statement.IsNull() ||
        bundle.bundle_statement !=
            CommitV5TranscriptProofAttachmentBundleV1(
                bundle)) {
        return Fail(
            why, "transcript_attachment:counters");
    }
    return true;
}

void AppendU32Attachment(
    std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t byte = 0; byte < 4; ++byte) {
        out.push_back(
            static_cast<unsigned char>(
                value >> (8 * byte)));
    }
}

bool ReadU32Attachment(
    const unsigned char*& cursor,
    const unsigned char* end,
    uint32_t& value)
{
    if (static_cast<size_t>(end - cursor) < 4) return false;
    value = 0;
    for (uint32_t byte = 0; byte < 4; ++byte) {
        value |=
            uint32_t{cursor[byte]} << (8 * byte);
    }
    cursor += 4;
    return true;
}

void AppendUint256Attachment(
    std::vector<unsigned char>& out,
    const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

bool ReadUint256Attachment(
    const unsigned char*& cursor,
    const unsigned char* end,
    uint256& value)
{
    if (static_cast<size_t>(end - cursor) < value.size()) {
        return false;
    }
    std::copy(cursor, cursor + value.size(), value.begin());
    cursor += value.size();
    return true;
}

bool SerializeV5OodAttachmentProofV1(
    const V5OodPointSplitRapProofV1& proof,
    std::vector<unsigned char>& out)
{
    out.clear();
    if (proof.version != 1 || proof.lane >= 2 ||
        proof.point >= 2 ||
        proof.selected_candidate >= 4 ||
        proof.proof_statement.IsNull() ||
        proof.proof_owned_v5_cells != 3 ||
        proof.recursively_consumed_v5_cells != 0 ||
        proof.full_304_transcript) {
        return false;
    }
    std::array<std::vector<unsigned char>, 5> nested;
    for (uint32_t candidate = 0; candidate < 4;
         ++candidate) {
        if (aq::SerializeAirQuotientSplitRapRowsProof(
                proof.candidate_proofs[candidate].quotient,
                nested[candidate]) == 0 ||
            nested[candidate].size() >
                kV5TranscriptLeafProofMaxBytesV1) {
            return false;
        }
    }
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof.selector_quotient, nested[4]) == 0 ||
        nested[4].size() >
            kV5TranscriptLeafProofMaxBytesV1) {
        return false;
    }
    uint64_t exact_size =
        4 + 4 + 4 + 4 + 4 + 32;
    for (const auto& bytes : nested) {
        exact_size += 4 + bytes.size();
    }
    if (exact_size > kV5TranscriptOodProofMaxBytesV1 ||
        exact_size > std::numeric_limits<size_t>::max()) {
        return false;
    }
    out.reserve(static_cast<size_t>(exact_size));
    AppendU32Attachment(
        out, kV5OodAttachmentProofMagicV1);
    AppendU32Attachment(out, proof.version);
    AppendU32Attachment(out, proof.lane);
    AppendU32Attachment(out, proof.point);
    AppendU32Attachment(
        out, proof.selected_candidate);
    AppendUint256Attachment(
        out, proof.proof_statement);
    for (const auto& bytes : nested) {
        AppendU32Attachment(
            out, static_cast<uint32_t>(bytes.size()));
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out.size() == exact_size;
}

std::optional<DecodedV5OodAttachmentProofV1>
DeserializeV5OodAttachmentProofV1(
    const std::vector<unsigned char>& bytes)
{
    if (bytes.empty() ||
        bytes.size() > kV5TranscriptOodProofMaxBytesV1) {
        return std::nullopt;
    }
    const unsigned char* cursor = bytes.data();
    const unsigned char* end = bytes.data() + bytes.size();
    uint32_t magic = 0;
    uint32_t version = 0;
    DecodedV5OodAttachmentProofV1 out;
    if (!ReadU32Attachment(cursor, end, magic) ||
        magic != kV5OodAttachmentProofMagicV1 ||
        !ReadU32Attachment(cursor, end, version) ||
        version != 1 ||
        !ReadU32Attachment(cursor, end, out.lane) ||
        out.lane >= 2 ||
        !ReadU32Attachment(cursor, end, out.point) ||
        out.point >= 2 ||
        !ReadU32Attachment(
            cursor, end, out.selected_candidate) ||
        out.selected_candidate >= 4 ||
        !ReadUint256Attachment(
            cursor, end, out.proof_statement) ||
        out.proof_statement.IsNull()) {
        return std::nullopt;
    }
    for (uint32_t nested = 0; nested < 5; ++nested) {
        uint32_t length = 0;
        if (!ReadU32Attachment(cursor, end, length) ||
            length == 0 ||
            length > kV5TranscriptLeafProofMaxBytesV1 ||
            length > static_cast<size_t>(end - cursor)) {
            return std::nullopt;
        }
        std::vector<unsigned char> proof_bytes(
            cursor, cursor + length);
        cursor += length;
        if (!CanonicalSplitRapProofBytesV1(
                proof_bytes)) {
            return std::nullopt;
        }
        const auto proof =
            aq::DeserializeAirQuotientSplitRapRowsProof(
                proof_bytes);
        if (!proof.has_value()) return std::nullopt;
        if (nested < 4) {
            out.candidate_quotients[nested] = *proof;
        } else {
            out.selector_quotient = *proof;
        }
    }
    if (cursor != end) return std::nullopt;

    // Re-encode the syntax-only envelope to reject alternate encodings.
    std::vector<unsigned char> canonical;
    AppendU32Attachment(
        canonical, kV5OodAttachmentProofMagicV1);
    AppendU32Attachment(canonical, version);
    AppendU32Attachment(canonical, out.lane);
    AppendU32Attachment(canonical, out.point);
    AppendU32Attachment(
        canonical, out.selected_candidate);
    AppendUint256Attachment(
        canonical, out.proof_statement);
    for (uint32_t nested = 0; nested < 5; ++nested) {
        std::vector<unsigned char> proof_bytes;
        const auto& proof = nested < 4
            ? out.candidate_quotients[nested]
            : out.selector_quotient;
        if (aq::SerializeAirQuotientSplitRapRowsProof(
                proof, proof_bytes) == 0) {
            return std::nullopt;
        }
        AppendU32Attachment(
            canonical,
            static_cast<uint32_t>(proof_bytes.size()));
        canonical.insert(
            canonical.end(),
            proof_bytes.begin(), proof_bytes.end());
    }
    if (canonical != bytes) return std::nullopt;
    return out;
}

bool SerializeV5QueryLeafAttachmentProofV1(
    const V5QueryIndexLeafSplitRapProofV1& proof,
    std::vector<unsigned char>& out)
{
    out.clear();
    if (proof.version != 1 ||
        proof.lane >= 2 ||
        proof.first_query >= 128 ||
        proof.query_proofs.empty() ||
        proof.query_proofs.size() >
            kV5QueryIndexLeafMaxQueriesV1 ||
        proof.queries.size() !=
            proof.query_proofs.size() ||
        proof.proved_indices.size() !=
            proof.query_proofs.size() ||
        proof.v5_semantic_rows.size() !=
            proof.query_proofs.size() ||
        proof.proof_owned_v5_cells !=
            proof.query_proofs.size() ||
        proof.recursively_consumed_v5_cells != 0 ||
        proof.full_304_transcript ||
        proof.proof_statement.IsNull()) {
        return false;
    }
    std::vector<std::vector<unsigned char>> nested(
        proof.query_proofs.size());
    uint64_t exact_size =
        4 + 4 + 4 + 4 + 4 + 4 + 32;
    for (uint32_t index = 0;
         index < proof.query_proofs.size(); ++index) {
        if (aq::SerializeAirQuotientSplitRapRowsProof(
                proof.query_proofs[index].quotient,
                nested[index]) == 0 ||
            nested[index].size() >
                kV5TranscriptLeafProofMaxBytesV1) {
            return false;
        }
        exact_size += 4 + nested[index].size();
    }
    if (exact_size >
            kV5TranscriptQueryLeafProofMaxBytesV1 ||
        exact_size > std::numeric_limits<size_t>::max()) {
        return false;
    }
    out.reserve(static_cast<size_t>(exact_size));
    AppendU32Attachment(
        out, kV5QueryLeafAttachmentProofMagicV1);
    AppendU32Attachment(out, proof.version);
    AppendU32Attachment(out, proof.leaf_ordinal);
    AppendU32Attachment(out, proof.lane);
    AppendU32Attachment(out, proof.first_query);
    AppendU32Attachment(
        out, static_cast<uint32_t>(nested.size()));
    AppendUint256Attachment(
        out, proof.proof_statement);
    for (const auto& bytes : nested) {
        AppendU32Attachment(
            out, static_cast<uint32_t>(bytes.size()));
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out.size() == exact_size;
}

std::optional<DecodedV5QueryLeafAttachmentProofV1>
DeserializeV5QueryLeafAttachmentProofV1(
    const std::vector<unsigned char>& bytes)
{
    if (bytes.empty() ||
        bytes.size() >
            kV5TranscriptQueryLeafProofMaxBytesV1) {
        return std::nullopt;
    }
    const unsigned char* cursor = bytes.data();
    const unsigned char* end = bytes.data() + bytes.size();
    uint32_t magic = 0;
    uint32_t version = 0;
    uint32_t count = 0;
    DecodedV5QueryLeafAttachmentProofV1 out;
    if (!ReadU32Attachment(cursor, end, magic) ||
        magic != kV5QueryLeafAttachmentProofMagicV1 ||
        !ReadU32Attachment(cursor, end, version) ||
        version != 1 ||
        !ReadU32Attachment(
            cursor, end, out.leaf_ordinal) ||
        !ReadU32Attachment(cursor, end, out.lane) ||
        out.lane >= 2 ||
        !ReadU32Attachment(
            cursor, end, out.first_query) ||
        out.first_query >= 128 ||
        !ReadU32Attachment(cursor, end, count) ||
        count == 0 ||
        count > kV5QueryIndexLeafMaxQueriesV1 ||
        !ReadUint256Attachment(
            cursor, end, out.proof_statement) ||
        out.proof_statement.IsNull()) {
        return std::nullopt;
    }
    out.query_quotients.reserve(count);
    std::vector<std::vector<unsigned char>> nested;
    nested.reserve(count);
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t length = 0;
        if (!ReadU32Attachment(cursor, end, length) ||
            length == 0 ||
            length > kV5TranscriptLeafProofMaxBytesV1 ||
            length > static_cast<size_t>(end - cursor)) {
            return std::nullopt;
        }
        nested.emplace_back(cursor, cursor + length);
        cursor += length;
        if (!CanonicalSplitRapProofBytesV1(
                nested.back())) {
            return std::nullopt;
        }
        const auto quotient =
            aq::DeserializeAirQuotientSplitRapRowsProof(
                nested.back());
        if (!quotient.has_value()) return std::nullopt;
        out.query_quotients.push_back(*quotient);
    }
    if (cursor != end) return std::nullopt;
    std::vector<unsigned char> canonical;
    AppendU32Attachment(
        canonical, kV5QueryLeafAttachmentProofMagicV1);
    AppendU32Attachment(canonical, version);
    AppendU32Attachment(canonical, out.leaf_ordinal);
    AppendU32Attachment(canonical, out.lane);
    AppendU32Attachment(canonical, out.first_query);
    AppendU32Attachment(canonical, count);
    AppendUint256Attachment(
        canonical, out.proof_statement);
    for (const auto& proof_bytes : nested) {
        AppendU32Attachment(
            canonical,
            static_cast<uint32_t>(proof_bytes.size()));
        canonical.insert(
            canonical.end(),
            proof_bytes.begin(), proof_bytes.end());
    }
    if (canonical != bytes) return std::nullopt;
    return out;
}

} // namespace

V5TranscriptProofAttachmentBundleV1
BuildV5TranscriptProofAttachmentBundleV1(
    const V5FullTranscriptWitnessShardPlan& plan)
{
    V5TranscriptProofAttachmentBundleV1 out;
    std::string plan_why;
    if (!ValidateV5FullTranscriptWitnessShardPlan(
            plan, &plan_why)) {
        out.note =
            "stage3:v5_v6_bus:transcript_attachment:"
            "plan:" +
            plan_why;
        return out;
    }
    out.source_plan_statement = plan.public_plan_statement;
    out.vertical_leaves = plan.vertical_leaf_proofs;
    out.sha256d_calls = plan.sha256d_calls;
    out.semantic_cells = plan.mapped_consumer_cells;
    out.lane_seed_fanouts =
        kV5TranscriptLaneSeedFanoutCountV1;

    std::vector<uint32_t> call_to_leaf(
        plan.calls.size(), UINT32_MAX);
    for (uint32_t parent = 0;
         parent < plan.shards.size(); ++parent) {
        for (uint32_t local_leaf = 0;
             local_leaf <
                 plan.shards[parent].leaf_count;
             ++local_leaf) {
            V5TranscriptLeafScheduleV1 leaf;
            leaf.leaf_ordinal =
                static_cast<uint32_t>(out.leaves.size());
            leaf.parent_shard = parent;
            leaf.leaf_in_parent = local_leaf;
            for (uint32_t call :
                 plan.shards[parent].call_ordinals) {
                if (plan.calls[call].leaf_in_parent !=
                    local_leaf) {
                    continue;
                }
                if (call >= call_to_leaf.size() ||
                    call_to_leaf[call] != UINT32_MAX) {
                    out.note =
                        "stage3:v5_v6_bus:"
                        "transcript_attachment:call_overlap";
                    return out;
                }
                call_to_leaf[call] = leaf.leaf_ordinal;
                leaf.call_ordinals.push_back(call);
                leaf.compression_blocks +=
                    plan.calls[call].compression_blocks;
            }
            if (leaf.call_ordinals.empty() ||
                leaf.compression_blocks == 0 ||
                leaf.compression_blocks >
                    ha::kFixedProgramVerticalSemanticInstances) {
                out.note =
                    "stage3:v5_v6_bus:"
                    "transcript_attachment:leaf_shape";
                return out;
            }
            out.leaves.push_back(std::move(leaf));
        }
    }
    if (out.leaves.size() !=
            kV5TranscriptVerticalLeafCountV1 ||
        std::find(
            call_to_leaf.begin(),
            call_to_leaf.end(), UINT32_MAX) !=
            call_to_leaf.end()) {
        out.note =
            "stage3:v5_v6_bus:"
            "transcript_attachment:leaf_partition";
        return out;
    }

    out.consumers.resize(kV5SemanticConsumerCells);
    std::array<uint8_t, kV5SemanticConsumerCells>
        consumer_seen{};
    for (const auto& source : plan.consumers) {
        if (source.semantic_row >= out.consumers.size() ||
            consumer_seen[source.semantic_row]) {
            out.note =
                "stage3:v5_v6_bus:"
                "transcript_attachment:consumer_order";
            return out;
        }
        consumer_seen[source.semantic_row] = 1;
        V5TranscriptConsumerLeafBindingV1 binding;
        binding.semantic_row = source.semantic_row;
        binding.family = source.family;
        binding.lane = source.lane;
        binding.item_index = source.item_index;
        binding.coordinate = source.coordinate;
        binding.consumer = source.consumer;
        binding.source_call_count =
            source.source_call_count;
        binding.source_call_ordinals =
            source.source_call_ordinals;
        binding.dependency_lane_seed_call =
            source.dependency_lane_seed_call;
        for (uint32_t source_index = 0;
             source_index < source.source_call_count;
             ++source_index) {
            const uint32_t call =
                source.source_call_ordinals[source_index];
            if (call >= call_to_leaf.size()) {
                out.note =
                    "stage3:v5_v6_bus:"
                    "transcript_attachment:consumer_call";
                return out;
            }
            const uint32_t leaf = call_to_leaf[call];
            binding.source_leaf_ordinals[source_index] =
                leaf;
            ++out.leaves[leaf].consumer_source_edges;
            auto& rows =
                out.leaves[leaf].consumer_semantic_rows;
            if (std::find(
                    rows.begin(), rows.end(),
                    source.semantic_row) == rows.end()) {
                rows.push_back(source.semantic_row);
            }
        }
        for (uint32_t source_index =
                 source.source_call_count;
             source_index <
                 binding.source_leaf_ordinals.size();
             ++source_index) {
            binding.source_leaf_ordinals[source_index] =
                UINT32_MAX;
        }
        if (source.dependency_lane_seed_call != UINT32_MAX) {
            if (source.dependency_lane_seed_call >=
                call_to_leaf.size()) {
                out.note =
                    "stage3:v5_v6_bus:"
                    "transcript_attachment:dependency_call";
                return out;
            }
            binding.dependency_lane_seed_leaf =
                call_to_leaf[
                    source.dependency_lane_seed_call];
        }
        out.consumers[source.semantic_row] = binding;
    }
    if (std::find(
            consumer_seen.begin(), consumer_seen.end(), 0) !=
            consumer_seen.end()) {
        out.note =
            "stage3:v5_v6_bus:"
            "transcript_attachment:consumer_cover";
        return out;
    }
    for (auto& leaf : out.leaves) {
        std::sort(
            leaf.consumer_semantic_rows.begin(),
            leaf.consumer_semantic_rows.end());
        leaf.schedule_statement =
            CommitV5TranscriptLeafScheduleV1(
                out.source_plan_statement, leaf);
        if (leaf.schedule_statement.IsNull()) {
            out.note =
                "stage3:v5_v6_bus:"
                "transcript_attachment:leaf_statement";
            return out;
        }
    }

    for (uint32_t lane = 0;
         lane < out.fanouts.size(); ++lane) {
        auto& fanout = out.fanouts[lane];
        fanout.lane = lane;
        fanout.source_call_ordinal = 2 + 19 * lane;
        fanout.source_leaf_ordinal =
            call_to_leaf[fanout.source_call_ordinal];
        for (uint32_t target =
                 fanout.source_call_ordinal + 1;
             target <
                 fanout.source_call_ordinal + 19;
             ++target) {
            fanout.target_call_ordinals.push_back(target);
        }
        for (uint32_t query = 0;
             query < 128; ++query) {
            fanout.target_call_ordinals.push_back(
                40 + 128 * lane + query);
        }
        for (uint32_t call :
             fanout.target_call_ordinals) {
            fanout.target_leaf_ordinals.push_back(
                call_to_leaf[call]);
        }
        if (fanout.target_call_ordinals.size() != 146) {
            out.note =
                "stage3:v5_v6_bus:"
                "transcript_attachment:fanout_targets";
            return out;
        }
        for (uint32_t word = 0; word < 8; ++word) {
            const auto found = std::find_if(
                plan.fanout_links.begin(),
                plan.fanout_links.end(),
                [&](const V5TranscriptFanoutLink& link) {
                    return link.source_call_ordinal ==
                               fanout.source_call_ordinal &&
                           link.source_word == word;
                });
            if (found == plan.fanout_links.end() ||
                found->target_call_ordinals !=
                    fanout.target_call_ordinals) {
                out.note =
                    "stage3:v5_v6_bus:"
                    "transcript_attachment:fanout_link";
                return out;
            }
            fanout.word_link_ids[word] = found->link_id;
        }
    }

    out.exact_leaf_call_partition = true;
    out.exact_consumer_source_binding = true;
    out.exact_lane_seed_fanouts = true;
    out.public_schedule_statement =
        CommitV5TranscriptAttachmentScheduleV1(out);
    RefreshV5TranscriptAttachmentProofCountersV1(out);
    out.valid =
        out.version == 1 &&
        !out.public_schedule_statement.IsNull() &&
        !out.bundle_statement.IsNull() &&
        out.vertical_leaves ==
            kV5TranscriptVerticalLeafCountV1 &&
        out.sha256d_calls ==
            kV5TranscriptShaCallCountV1 &&
        out.semantic_cells ==
            kV5SemanticConsumerCells &&
        out.lane_seed_fanouts ==
            kV5TranscriptLaneSeedFanoutCountV1 &&
        out.proof_owned_cells == 0 &&
        out.recursively_consumed_cells == 0 &&
        out.pending_cells ==
            kV5SemanticConsumerCells &&
        !out.attached_proofs_publicly_verified &&
        !out.all_57_leaf_proofs_attached &&
        !out.recursive_consumption_complete &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:v5_v6_bus:transcript_attachment:"
          "57_leaves;296_calls;304_consumers;2_fanouts;"
          "proof_owned_0;recursive_consumed_0;authority_false"
        : "stage3:v5_v6_bus:"
          "transcript_attachment:invalid";
    return out;
}

namespace {

struct V5QueryLeafDescriptorV1 {
    bool valid{false};
    uint32_t leaf_ordinal{0};
    uint32_t lane{0};
    uint32_t first_query{0};
    std::vector<uint32_t> queries;
    std::vector<uint32_t> semantic_rows;
};

V5QueryLeafDescriptorV1 BuildV5QueryLeafDescriptorV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t leaf_ordinal)
{
    V5QueryLeafDescriptorV1 out;
    out.leaf_ordinal = leaf_ordinal;
    const auto bundle =
        BuildV5TranscriptProofAttachmentBundleV1(plan);
    if (!bundle.valid ||
        leaf_ordinal >= bundle.leaves.size()) {
        return out;
    }
    const auto& leaf = bundle.leaves[leaf_ordinal];
    for (uint32_t call_ordinal : leaf.call_ordinals) {
        if (call_ordinal >= plan.calls.size()) return out;
        const auto& call = plan.calls[call_ordinal];
        if (call.kind !=
                V5TranscriptShaCallKind::QueryIndex) {
            if (!out.queries.empty()) return out;
            continue;
        }
        if (out.queries.empty()) {
            out.lane = call.lane;
            out.first_query = call.item;
        }
        if (call.lane != out.lane ||
            call.item !=
                out.first_query + out.queries.size()) {
            return out;
        }
        out.queries.push_back(call.item);
        const auto consumer = std::find_if(
            plan.consumers.begin(),
            plan.consumers.end(),
            [&](const auto& item) {
                return item.family ==
                           ChallengeFeedbackFamily::
                               QueryIndex &&
                       item.lane == call.lane &&
                       item.item_index == call.item &&
                       item.coordinate == 0 &&
                       item.source_call_count == 1 &&
                       item.source_call_ordinals[0] ==
                           call_ordinal;
            });
        if (consumer == plan.consumers.end()) return out;
        out.semantic_rows.push_back(
            consumer->semantic_row);
    }
    if (out.queries.empty() ||
        out.queries.size() >
            kV5QueryIndexLeafMaxQueriesV1 ||
        out.semantic_rows.size() != out.queries.size()) {
        return out;
    }
    out.valid = true;
    return out;
}

uint256 CommitV5QueryIndexLeafProofV1(
    const V5QueryIndexLeafSplitRapProofV1& proof)
{
    if (proof.version != 1 ||
        proof.lane >= 2 ||
        proof.queries.empty() ||
        proof.queries.size() >
            kV5QueryIndexLeafMaxQueriesV1 ||
        proof.proved_indices.size() !=
            proof.queries.size() ||
        proof.v5_semantic_rows.size() !=
            proof.queries.size() ||
        proof.query_proofs.size() !=
            proof.queries.size()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_QUERY_INDEX_LEAF_SPLIT_RAP_V1";
    hash << proof.version;
    hash << proof.leaf_ordinal;
    hash << proof.lane;
    hash << proof.first_query;
    hash << static_cast<uint32_t>(proof.queries.size());
    for (uint32_t index = 0;
         index < proof.queries.size(); ++index) {
        hash << proof.queries[index];
        hash << proof.proved_indices[index];
        hash << proof.v5_semantic_rows[index];
        hash << proof.query_proofs[index].prefix_statement;
        hash << proof.query_proofs[index].canonical_r0;
    }
    hash << proof.proof_owned_v5_cells;
    hash << proof.recursively_consumed_v5_cells;
    hash << proof.full_304_transcript;
    return hash.GetHash();
}

} // namespace

V5QueryIndexLeafSplitRapProveResultV1
ProveV5QueryIndexLeafSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t leaf_ordinal)
{
    V5QueryIndexLeafSplitRapProveResultV1 out;
    const auto descriptor =
        BuildV5QueryLeafDescriptorV1(
            plan, leaf_ordinal);
    if (!descriptor.valid) {
        out.note =
            "stage3:v5_v6_bus:query_leaf_prove:"
            "descriptor";
        return out;
    }
    auto& proof = out.proof;
    proof.leaf_ordinal = leaf_ordinal;
    proof.lane = descriptor.lane;
    proof.first_query = descriptor.first_query;
    proof.queries = descriptor.queries;
    proof.v5_semantic_rows =
        descriptor.semantic_rows;
    proof.proved_indices.reserve(
        descriptor.queries.size());
    proof.query_proofs.reserve(
        descriptor.queries.size());
    for (uint32_t query : descriptor.queries) {
        auto prefix =
            BuildV5QueryIndexDrawWitnessPrefix(
                composition, child, child_fs_seed,
                descriptor.lane, query);
        const auto proved =
            ProveV5FirstUniformSplitRap(prefix);
        if (!prefix.valid || !proved.ok ||
            proved.proof.proof_owned_v5_cells != 1) {
            out.note =
                "stage3:v5_v6_bus:query_leaf_prove:"
                "query_" + std::to_string(query) +
                ":" + proved.note;
            return out;
        }
        proof.proved_indices.push_back(
            static_cast<uint32_t>(
                gf::Canonical(
                    prefix.draw_output[0].c0)));
        proof.query_proofs.push_back(proved.proof);
    }
    proof.proof_owned_v5_cells =
        static_cast<uint32_t>(proof.queries.size());
    proof.recursively_consumed_v5_cells = 0;
    proof.full_304_transcript = false;
    proof.proof_statement =
        CommitV5QueryIndexLeafProofV1(proof);
    out.ok = !proof.proof_statement.IsNull();
    out.note = out.ok
        ? "stage3:v5_v6_bus:query_leaf_prove:"
          "exact_sha_digest_bits_mask;"
          "recursive_0;authority_false"
        : "stage3:v5_v6_bus:query_leaf_prove:"
          "statement";
    return out;
}

bool VerifyV5QueryIndexLeafSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t leaf_ordinal,
    const V5QueryIndexLeafSplitRapProofV1& proof,
    std::string* why)
{
    const auto fail = [&](const std::string& detail) {
        return Fail(
            why, "query_leaf_split_rap_verify:" + detail);
    };
    const auto descriptor =
        BuildV5QueryLeafDescriptorV1(
            plan, leaf_ordinal);
    if (!descriptor.valid ||
        proof.version != 1 ||
        proof.leaf_ordinal != leaf_ordinal ||
        proof.lane != descriptor.lane ||
        proof.first_query != descriptor.first_query ||
        proof.queries != descriptor.queries ||
        proof.v5_semantic_rows !=
            descriptor.semantic_rows ||
        proof.proved_indices.size() !=
            descriptor.queries.size() ||
        proof.query_proofs.size() !=
            descriptor.queries.size() ||
        proof.proof_owned_v5_cells !=
            descriptor.queries.size() ||
        proof.recursively_consumed_v5_cells != 0 ||
        proof.full_304_transcript ||
        proof.proof_statement.IsNull()) {
        return fail("shape");
    }
    for (uint32_t index = 0;
         index < descriptor.queries.size(); ++index) {
        const uint32_t query =
            descriptor.queries[index];
        std::string query_why;
        if (!VerifyV5QueryIndexDrawSplitRap(
                composition, child, child_fs_seed,
                descriptor.lane, query,
                proof.query_proofs[index],
                &query_why)) {
            return fail(
                "query_" + std::to_string(query) +
                ":" + query_why);
        }
        const Fp expected =
            gf::FromU64(proof.proved_indices[index]);
        if (!gf::Eq(
                proof.query_proofs[index]
                    .proved_v5_exports[0],
                Fp3::FromFp(expected))) {
            return fail("index_export");
        }
    }
    if (proof.proof_statement !=
            CommitV5QueryIndexLeafProofV1(proof)) {
        return fail("statement");
    }
    if (why != nullptr) {
        *why =
            "stage3:v5_v6_bus:query_leaf_verify:"
            "exact_sha_digest_bits_mask;"
            "earned_rows_only;recursive_0;"
            "authority_false";
    }
    return true;
}

bool VerifyV5TranscriptProofAttachmentBundleV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why)
{
    const auto current_public_plan =
        BuildV5FullTranscriptWitnessShardPlan(
            composition, child, child_fs_seed);
    if (!current_public_plan.valid ||
        current_public_plan.public_plan_statement !=
            plan.public_plan_statement) {
        return Fail(
            why,
            "transcript_attachment:committed_child_plan");
    }
    if (!ValidateV5TranscriptAttachmentShapeV1(
            plan, bundle, why)) {
        return false;
    }
    if (!composition.valid ||
        child_fs_seed.IsNull()) {
        return Fail(
            why, "transcript_attachment:public_inputs");
    }
    if (!bundle.proofs.empty()) {
        for (const auto& attachment : bundle.proofs) {
            if (attachment.kind ==
                    V5TranscriptLeafProofKindV1::
                        QueryIndexLeafSplitRap) {
                const auto descriptor =
                    BuildV5QueryLeafDescriptorV1(
                        plan, attachment.leaf_ordinal);
                const auto decoded =
                    DeserializeV5QueryLeafAttachmentProofV1(
                        attachment.proof_bytes);
                std::vector<uint32_t> expected_rows =
                    descriptor.semantic_rows;
                std::sort(
                    expected_rows.begin(),
                    expected_rows.end());
                if (!descriptor.valid ||
                    !decoded.has_value() ||
                    decoded->leaf_ordinal !=
                        attachment.leaf_ordinal ||
                    decoded->lane != attachment.lane ||
                    decoded->first_query !=
                        attachment.batch_item ||
                    decoded->query_quotients.size() !=
                        descriptor.queries.size() ||
                    attachment.proof_owned_semantic_rows !=
                        expected_rows) {
                    return Fail(
                        why,
                        "transcript_attachment:"
                        "query_leaf_codec");
                }
                V5QueryIndexLeafSplitRapProofV1 proof;
                proof.leaf_ordinal =
                    attachment.leaf_ordinal;
                proof.lane = descriptor.lane;
                proof.first_query =
                    descriptor.first_query;
                proof.proof_statement =
                    decoded->proof_statement;
                proof.queries = descriptor.queries;
                proof.v5_semantic_rows =
                    descriptor.semantic_rows;
                proof.proof_owned_v5_cells =
                    static_cast<uint32_t>(
                        descriptor.queries.size());
                proof.recursively_consumed_v5_cells = 0;
                proof.full_304_transcript = false;
                for (uint32_t index = 0;
                     index < descriptor.queries.size();
                     ++index) {
                    const uint32_t query =
                        descriptor.queries[index];
                    const auto prefix =
                        BuildV5QueryIndexDrawWitnessPrefix(
                            composition, child,
                            child_fs_seed,
                            descriptor.lane, query);
                    if (!prefix.valid) {
                        return Fail(
                            why,
                            "transcript_attachment:"
                            "query_prefix");
                    }
                    proof.proved_indices.push_back(
                        static_cast<uint32_t>(
                            gf::Canonical(
                                prefix.draw_output[0].c0)));
                    V5FirstUniformSplitRapProof query_proof;
                    query_proof.prefix_statement =
                        prefix.prefix_statement;
                    query_proof.sha_public_statement =
                        prefix.sha_execution
                            .public_statement;
                    query_proof.vertical_air_seed =
                        prefix.vertical_air_seed;
                    query_proof.canonical_r0 =
                        prefix.sha_execution
                            .base_row_commitment;
                    query_proof.proved_v5_exports =
                        prefix.draw_output;
                    query_proof.quotient =
                        decoded->query_quotients[index];
                    query_proof.proof_owned_v5_cells = 1;
                    query_proof
                        .recursively_consumed_v5_cells = 0;
                    query_proof.full_304_transcript = false;
                    proof.query_proofs.push_back(
                        std::move(query_proof));
                }
                std::string proof_why;
                if (!VerifyV5QueryIndexLeafSplitRapV1(
                        composition, child, child_fs_seed,
                        plan, attachment.leaf_ordinal,
                        proof, &proof_why)) {
                    return Fail(
                        why,
                        "transcript_attachment:"
                        "query_leaf_proof:" + proof_why);
                }
                continue;
            }
            if (attachment.kind ==
                    V5TranscriptLeafProofKindV1::
                        OodPointSplitRap) {
                const auto selector =
                    BuildV5OodPointSelectorWitnessV1(
                        composition, child, child_fs_seed,
                        attachment.lane,
                        attachment.batch_item);
                const auto decoded =
                    DeserializeV5OodAttachmentProofV1(
                        attachment.proof_bytes);
                std::vector<uint32_t> selector_rows{
                    selector.v5_semantic_rows.begin(),
                    selector.v5_semantic_rows.end()};
                std::sort(
                    selector_rows.begin(),
                    selector_rows.end());
                if (!selector.valid ||
                    !decoded.has_value() ||
                    decoded->lane != attachment.lane ||
                    decoded->point !=
                        attachment.batch_item ||
                    attachment.proof_owned_semantic_rows !=
                        selector_rows) {
                    return Fail(
                        why,
                        "transcript_attachment:"
                        "ood_proof_codec");
                }
                V5OodPointSplitRapProofV1 proof;
                proof.lane = decoded->lane;
                proof.point = decoded->point;
                proof.selected_candidate =
                    decoded->selected_candidate;
                proof.proof_statement =
                    decoded->proof_statement;
                proof.proved_candidates =
                    selector.candidates;
                proof.proved_v5_exports =
                    selector.selected_output;
                for (uint32_t candidate = 0;
                     candidate < 4; ++candidate) {
                    const auto prefix =
                        BuildV5OodCandidateDrawWitnessPrefix(
                            composition, child,
                            child_fs_seed,
                            attachment.lane, candidate);
                    if (!prefix.valid) {
                        return Fail(
                            why,
                            "transcript_attachment:"
                            "ood_candidate_prefix");
                    }
                    auto& candidate_proof =
                        proof.candidate_proofs[candidate];
                    candidate_proof.prefix_statement =
                        prefix.prefix_statement;
                    candidate_proof.sha_public_statement =
                        prefix.sha_execution
                            .public_statement;
                    candidate_proof.vertical_air_seed =
                        prefix.vertical_air_seed;
                    candidate_proof.canonical_r0 =
                        prefix.sha_execution
                            .base_row_commitment;
                    candidate_proof.proved_v5_exports =
                        prefix.draw_output;
                    candidate_proof.quotient =
                        decoded
                            ->candidate_quotients[candidate];
                    candidate_proof.proof_owned_v5_cells = 0;
                    candidate_proof
                        .recursively_consumed_v5_cells = 0;
                    candidate_proof.full_304_transcript =
                        false;
                }
                proof.selector_quotient =
                    decoded->selector_quotient;
                proof.proof_owned_v5_cells = 3;
                proof.recursively_consumed_v5_cells = 0;
                proof.full_304_transcript = false;
                std::string proof_why;
                if (!VerifyV5OodPointSplitRapV1(
                        composition, child, child_fs_seed,
                        attachment.lane,
                        attachment.batch_item,
                        proof, &proof_why)) {
                    return Fail(
                        why,
                        "transcript_attachment:"
                        "ood_proof:" + proof_why);
                }
                continue;
            }
            const bool is_deep =
                attachment.kind ==
                V5TranscriptLeafProofKindV1::
                    DeepWeightSplitRap;
            const bool is_fold =
                attachment.kind ==
                V5TranscriptLeafProofKindV1::
                    FoldChallengeSplitRap;
            const auto prefix =
                is_deep
                ? BuildV5DeepWeightDrawWitnessPrefix(
                      composition, child, child_fs_seed,
                      attachment.lane,
                      attachment.batch_item)
                : is_fold
                    ? BuildV5FoldChallengeDrawWitnessPrefix(
                          composition, child,
                          child_fs_seed,
                          attachment.lane,
                          attachment.batch_item)
                    : BuildV5BatchCoefficientDrawWitnessPrefix(
                          composition, child,
                          child_fs_seed,
                          attachment.lane,
                          attachment.batch_item);
            if (!prefix.valid) {
                return Fail(
                    why,
                    "transcript_attachment:prefix:" +
                        prefix.note);
            }
            std::vector<uint32_t> prefix_rows{
                prefix.v5_semantic_rows.begin(),
                prefix.v5_semantic_rows.end()};
            std::sort(
                prefix_rows.begin(), prefix_rows.end());
            aq::AirQuotientSplitRapRowsProof quotient;
            if (attachment.proof_owned_semantic_rows !=
                    prefix_rows ||
                !CanonicalSplitRapProofBytesV1(
                    attachment.proof_bytes, &quotient)) {
                return Fail(
                    why,
                    "transcript_attachment:proof_codec");
            }
            V5FirstUniformSplitRapProof proof;
            proof.prefix_statement =
                prefix.prefix_statement;
            proof.sha_public_statement =
                prefix.sha_execution.public_statement;
            proof.vertical_air_seed =
                prefix.vertical_air_seed;
            proof.canonical_r0 =
                prefix.sha_execution.base_row_commitment;
            proof.proved_v5_exports =
                prefix.draw_output;
            proof.quotient = std::move(quotient);
            proof.proof_owned_v5_cells = 3;
            proof.recursively_consumed_v5_cells = 0;
            proof.full_304_transcript = false;
            std::string proof_why;
            const bool proof_ok =
                is_deep
                ? VerifyV5DeepWeightDrawSplitRap(
                      composition, child, child_fs_seed,
                      attachment.lane,
                      attachment.batch_item,
                      proof, &proof_why)
                : is_fold
                    ? VerifyV5FoldChallengeDrawSplitRap(
                          composition, child,
                          child_fs_seed,
                          attachment.lane,
                          attachment.batch_item,
                          proof, &proof_why)
                    : VerifyV5BatchCoefficientDrawSplitRap(
                          composition, child,
                          child_fs_seed,
                          attachment.lane,
                          attachment.batch_item,
                          proof, &proof_why);
            if (!proof_ok) {
                return Fail(
                    why,
                    "transcript_attachment:proof:" +
                        proof_why);
            }
        }
    }
    if (why != nullptr) {
        *why =
            bundle.proofs.empty()
            ? "stage3:v5_v6_bus:transcript_attachment:"
              "canonical_schedule;proof_owned_0;"
              "recursive_consumed_0;authority_false"
            : "stage3:v5_v6_bus:transcript_attachment:"
              "uniform_and_ood_public_proofs_verified;"
              "earned_cells_only;recursive_consumed_0;"
              "authority_false";
    }
    return true;
}

bool AttachV5BatchCoefficientDrawSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t lane,
    uint32_t batch_item,
    const V5FirstUniformSplitRapProof& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why)
{
    if (bundle.proofs.size() >=
            kV5TranscriptLocalProofAttachmentCountV1 ||
        lane >= 2 ||
        batch_item >= 2 ||
        std::any_of(
            bundle.proofs.begin(), bundle.proofs.end(),
            [lane, batch_item](
                const V5TranscriptLeafProofAttachmentV1&
                    attached) {
                return attached.kind ==
                           V5TranscriptLeafProofKindV1::
                               BatchCoefficientSplitRap &&
                       attached.lane == lane &&
                       attached.batch_item == batch_item;
            }) ||
        !VerifyV5TranscriptProofAttachmentBundleV1(
            composition, child, child_fs_seed,
            plan, bundle, why)) {
        return Fail(
            why,
            "transcript_attachment:attach_base");
    }
    std::string proof_why;
    if (!VerifyV5BatchCoefficientDrawSplitRap(
            composition, child, child_fs_seed,
            lane, batch_item, proof, &proof_why)) {
        return Fail(
            why,
            "transcript_attachment:attach_proof:" +
                proof_why);
    }
    std::vector<unsigned char> proof_bytes;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof.quotient, proof_bytes) == 0 ||
        proof_bytes.size() >
            kV5TranscriptLeafProofMaxBytesV1) {
        return Fail(
            why, "transcript_attachment:attach_codec");
    }
    const auto prefix =
        BuildV5BatchCoefficientDrawWitnessPrefix(
            composition, child, child_fs_seed,
            lane, batch_item);
    const auto leaf =
        BatchCoefficientAttachmentLeafV1(
            bundle, lane, batch_item);
    if (!prefix.valid || !leaf.has_value()) {
        return Fail(
            why, "transcript_attachment:attach_mapping");
    }
    V5TranscriptLeafProofAttachmentV1 attachment;
    attachment.leaf_ordinal = *leaf;
    attachment.kind =
        V5TranscriptLeafProofKindV1::
            BatchCoefficientSplitRap;
    attachment.lane = lane;
    attachment.batch_item = batch_item;
    attachment.proof_owned_semantic_rows.assign(
        prefix.v5_semantic_rows.begin(),
        prefix.v5_semantic_rows.end());
    std::sort(
        attachment.proof_owned_semantic_rows.begin(),
        attachment.proof_owned_semantic_rows.end());
    attachment.proof_bytes = std::move(proof_bytes);
    attachment.recursively_consumed_cells = 0;
    attachment.proof_statement =
        CommitV5TranscriptLeafProofAttachmentV1(
            bundle.public_schedule_statement,
            attachment);
    if (attachment.proof_statement.IsNull()) {
        return Fail(
            why,
            "transcript_attachment:attach_statement");
    }
    auto candidate = bundle;
    candidate.proofs.push_back(std::move(attachment));
    std::sort(
        candidate.proofs.begin(),
        candidate.proofs.end(),
        [](const auto& lhs, const auto& rhs) {
            return std::tie(
                       lhs.kind, lhs.lane,
                       lhs.batch_item) <
                   std::tie(
                       rhs.kind, rhs.lane,
                       rhs.batch_item);
        });
    RefreshV5TranscriptAttachmentProofCountersV1(candidate);
    candidate.valid = true;
    candidate.note =
        "stage3:v5_v6_bus:transcript_attachment:"
        "batch_draw_attached;earned_cells_only;"
        "recursive_consumed_0;authority_false";
    if (!VerifyV5TranscriptProofAttachmentBundleV1(
            composition, child, child_fs_seed,
            plan, candidate, why)) {
        return false;
    }
    bundle = std::move(candidate);
    return true;
}

bool AttachV5FirstUniformSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5FirstUniformSplitRapProof& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why)
{
    return AttachV5BatchCoefficientDrawSplitRapV1(
        composition, child, child_fs_seed,
        plan, 0, 0, proof, bundle, why);
}

bool AttachV5OodPointSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t lane,
    uint32_t point,
    const V5OodPointSplitRapProofV1& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why)
{
    if (bundle.proofs.size() >=
            kV5TranscriptLocalProofAttachmentCountV1 ||
        lane >= 2 || point >= 2 ||
        std::any_of(
            bundle.proofs.begin(), bundle.proofs.end(),
            [lane, point](const auto& attached) {
                return attached.kind ==
                           V5TranscriptLeafProofKindV1::
                               OodPointSplitRap &&
                       attached.lane == lane &&
                       attached.batch_item == point;
            }) ||
        !VerifyV5TranscriptProofAttachmentBundleV1(
            composition, child, child_fs_seed,
            plan, bundle, why)) {
        return Fail(
            why, "transcript_attachment:ood_attach_base");
    }
    std::string proof_why;
    if (!VerifyV5OodPointSplitRapV1(
            composition, child, child_fs_seed,
            lane, point, proof, &proof_why)) {
        return Fail(
            why,
            "transcript_attachment:ood_attach_proof:" +
                proof_why);
    }
    std::vector<unsigned char> proof_bytes;
    if (!SerializeV5OodAttachmentProofV1(
            proof, proof_bytes)) {
        return Fail(
            why, "transcript_attachment:ood_attach_codec");
    }
    const auto selector =
        BuildV5OodPointSelectorWitnessV1(
            composition, child, child_fs_seed,
            lane, point);
    const auto leaf =
        OodPointAttachmentLeafV1(
            bundle, lane, point);
    if (!selector.valid || !leaf.has_value()) {
        return Fail(
            why,
            "transcript_attachment:ood_attach_mapping");
    }
    V5TranscriptLeafProofAttachmentV1 attachment;
    attachment.leaf_ordinal = *leaf;
    attachment.kind =
        V5TranscriptLeafProofKindV1::
            OodPointSplitRap;
    attachment.lane = lane;
    attachment.batch_item = point;
    attachment.proof_owned_semantic_rows.assign(
        selector.v5_semantic_rows.begin(),
        selector.v5_semantic_rows.end());
    std::sort(
        attachment.proof_owned_semantic_rows.begin(),
        attachment.proof_owned_semantic_rows.end());
    attachment.proof_bytes = std::move(proof_bytes);
    attachment.recursively_consumed_cells = 0;
    attachment.proof_statement =
        CommitV5TranscriptLeafProofAttachmentV1(
            bundle.public_schedule_statement,
            attachment);
    if (attachment.proof_statement.IsNull()) {
        return Fail(
            why,
            "transcript_attachment:ood_attach_statement");
    }
    auto candidate = bundle;
    candidate.proofs.push_back(std::move(attachment));
    std::sort(
        candidate.proofs.begin(),
        candidate.proofs.end(),
        [](const auto& lhs, const auto& rhs) {
            return std::tie(
                       lhs.kind, lhs.lane,
                       lhs.batch_item) <
                   std::tie(
                       rhs.kind, rhs.lane,
                       rhs.batch_item);
        });
    RefreshV5TranscriptAttachmentProofCountersV1(candidate);
    candidate.valid = true;
    candidate.note =
        "stage3:v5_v6_bus:transcript_attachment:"
        "ood_point_attached;earned_cells_only;"
        "recursive_consumed_0;authority_false";
    if (!VerifyV5TranscriptProofAttachmentBundleV1(
            composition, child, child_fs_seed,
            plan, candidate, why)) {
        return false;
    }
    bundle = std::move(candidate);
    return true;
}

namespace {

bool AttachV5SingleUniformSplitRapImplV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    ChallengeFeedbackFamily family,
    V5TranscriptLeafProofKindV1 kind,
    uint32_t lane,
    uint32_t item,
    const V5FirstUniformSplitRapProof& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why)
{
    const bool is_deep =
        family == ChallengeFeedbackFamily::DeepWeight &&
        kind ==
            V5TranscriptLeafProofKindV1::
                DeepWeightSplitRap;
    const bool is_fold =
        family ==
            ChallengeFeedbackFamily::FoldChallenge &&
        kind ==
            V5TranscriptLeafProofKindV1::
                FoldChallengeSplitRap;
    if ((!is_deep && !is_fold) ||
        bundle.proofs.size() >=
            kV5TranscriptLocalProofAttachmentCountV1 ||
        lane >= 2 || item >= (is_fold ? 1U : 2U) ||
        std::any_of(
            bundle.proofs.begin(), bundle.proofs.end(),
            [kind, lane, item](const auto& attached) {
                return attached.kind == kind &&
                       attached.lane == lane &&
                       attached.batch_item == item;
            }) ||
        !VerifyV5TranscriptProofAttachmentBundleV1(
            composition, child, child_fs_seed,
            plan, bundle, why)) {
        return Fail(
            why,
            "transcript_attachment:"
            "single_uniform_attach_base");
    }
    std::string proof_why;
    const bool verified =
        is_deep
        ? VerifyV5DeepWeightDrawSplitRap(
              composition, child, child_fs_seed,
              lane, item, proof, &proof_why)
        : VerifyV5FoldChallengeDrawSplitRap(
              composition, child, child_fs_seed,
              lane, item, proof, &proof_why);
    if (!verified) {
        return Fail(
            why,
            "transcript_attachment:"
            "single_uniform_attach_proof:" +
                proof_why);
    }
    std::vector<unsigned char> proof_bytes;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof.quotient, proof_bytes) == 0 ||
        proof_bytes.size() >
            kV5TranscriptLeafProofMaxBytesV1) {
        return Fail(
            why,
            "transcript_attachment:"
            "single_uniform_attach_codec");
    }
    const auto prefix =
        is_deep
        ? BuildV5DeepWeightDrawWitnessPrefix(
              composition, child, child_fs_seed,
              lane, item)
        : BuildV5FoldChallengeDrawWitnessPrefix(
              composition, child, child_fs_seed,
              lane, item);
    const auto leaf =
        SingleUniformAttachmentLeafV1(
            bundle, family, lane, item);
    if (!prefix.valid || !leaf.has_value()) {
        return Fail(
            why,
            "transcript_attachment:"
            "single_uniform_attach_mapping");
    }
    V5TranscriptLeafProofAttachmentV1 attachment;
    attachment.leaf_ordinal = *leaf;
    attachment.kind = kind;
    attachment.lane = lane;
    attachment.batch_item = item;
    attachment.proof_owned_semantic_rows.assign(
        prefix.v5_semantic_rows.begin(),
        prefix.v5_semantic_rows.end());
    std::sort(
        attachment.proof_owned_semantic_rows.begin(),
        attachment.proof_owned_semantic_rows.end());
    attachment.proof_bytes = std::move(proof_bytes);
    attachment.recursively_consumed_cells = 0;
    attachment.proof_statement =
        CommitV5TranscriptLeafProofAttachmentV1(
            bundle.public_schedule_statement,
            attachment);
    if (attachment.proof_statement.IsNull()) {
        return Fail(
            why,
            "transcript_attachment:"
            "single_uniform_attach_statement");
    }
    auto candidate = bundle;
    candidate.proofs.push_back(std::move(attachment));
    std::sort(
        candidate.proofs.begin(),
        candidate.proofs.end(),
        [](const auto& lhs, const auto& rhs) {
            return std::tie(
                       lhs.kind, lhs.lane,
                       lhs.batch_item) <
                   std::tie(
                       rhs.kind, rhs.lane,
                       rhs.batch_item);
        });
    RefreshV5TranscriptAttachmentProofCountersV1(candidate);
    candidate.valid = true;
    candidate.note =
        "stage3:v5_v6_bus:transcript_attachment:"
        "single_uniform_attached;earned_cells_only;"
        "recursive_consumed_0;authority_false";
    if (!VerifyV5TranscriptProofAttachmentBundleV1(
            composition, child, child_fs_seed,
            plan, candidate, why)) {
        return false;
    }
    bundle = std::move(candidate);
    return true;
}

} // namespace

bool AttachV5DeepWeightSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t lane,
    uint32_t item,
    const V5FirstUniformSplitRapProof& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why)
{
    return AttachV5SingleUniformSplitRapImplV1(
        composition, child, child_fs_seed, plan,
        ChallengeFeedbackFamily::DeepWeight,
        V5TranscriptLeafProofKindV1::
            DeepWeightSplitRap,
        lane, item, proof, bundle, why);
}

bool AttachV5FoldChallengeSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t lane,
    uint32_t fold,
    const V5FirstUniformSplitRapProof& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why)
{
    return AttachV5SingleUniformSplitRapImplV1(
        composition, child, child_fs_seed, plan,
        ChallengeFeedbackFamily::FoldChallenge,
        V5TranscriptLeafProofKindV1::
            FoldChallengeSplitRap,
        lane, fold, proof, bundle, why);
}

bool AttachV5QueryIndexLeafSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5QueryIndexLeafSplitRapProofV1& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why)
{
    const auto descriptor =
        BuildV5QueryLeafDescriptorV1(
            plan, proof.leaf_ordinal);
    if (!descriptor.valid ||
        bundle.proofs.size() >=
            kV5TranscriptLocalProofAttachmentCountV1 ||
        std::any_of(
            bundle.proofs.begin(), bundle.proofs.end(),
            [&](const auto& attached) {
                return attached.kind ==
                           V5TranscriptLeafProofKindV1::
                               QueryIndexLeafSplitRap &&
                       attached.leaf_ordinal ==
                           proof.leaf_ordinal;
            }) ||
        !VerifyV5TranscriptProofAttachmentBundleV1(
            composition, child, child_fs_seed,
            plan, bundle, why)) {
        return Fail(
            why,
            "transcript_attachment:"
            "query_leaf_attach_base");
    }
    std::string proof_why;
    if (!VerifyV5QueryIndexLeafSplitRapV1(
            composition, child, child_fs_seed,
            plan, proof.leaf_ordinal,
            proof, &proof_why)) {
        return Fail(
            why,
            "transcript_attachment:"
            "query_leaf_attach_proof:" + proof_why);
    }
    std::vector<unsigned char> proof_bytes;
    if (!SerializeV5QueryLeafAttachmentProofV1(
            proof, proof_bytes)) {
        return Fail(
            why,
            "transcript_attachment:"
            "query_leaf_attach_codec");
    }
    V5TranscriptLeafProofAttachmentV1 attachment;
    attachment.leaf_ordinal = proof.leaf_ordinal;
    attachment.kind =
        V5TranscriptLeafProofKindV1::
            QueryIndexLeafSplitRap;
    attachment.lane = descriptor.lane;
    attachment.batch_item =
        descriptor.first_query;
    attachment.proof_owned_semantic_rows =
        descriptor.semantic_rows;
    std::sort(
        attachment.proof_owned_semantic_rows.begin(),
        attachment.proof_owned_semantic_rows.end());
    attachment.proof_bytes = std::move(proof_bytes);
    attachment.recursively_consumed_cells = 0;
    attachment.proof_statement =
        CommitV5TranscriptLeafProofAttachmentV1(
            bundle.public_schedule_statement,
            attachment);
    if (attachment.proof_statement.IsNull()) {
        return Fail(
            why,
            "transcript_attachment:"
            "query_leaf_attach_statement");
    }
    auto candidate = bundle;
    candidate.proofs.push_back(std::move(attachment));
    std::sort(
        candidate.proofs.begin(),
        candidate.proofs.end(),
        [](const auto& lhs, const auto& rhs) {
            return std::tie(
                       lhs.kind, lhs.lane,
                       lhs.batch_item) <
                   std::tie(
                       rhs.kind, rhs.lane,
                       rhs.batch_item);
        });
    RefreshV5TranscriptAttachmentProofCountersV1(candidate);
    candidate.valid = true;
    candidate.note =
        "stage3:v5_v6_bus:transcript_attachment:"
        "query_leaf_attached;earned_cells_only;"
        "recursive_consumed_0;authority_false";
    if (!VerifyV5TranscriptProofAttachmentBundleV1(
            composition, child, child_fs_seed,
            plan, candidate, why)) {
        return false;
    }
    bundle = std::move(candidate);
    return true;
}

size_t SerializeV5TranscriptProofAttachmentBundleV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5TranscriptProofAttachmentBundleV1& bundle,
    std::vector<unsigned char>& out)
{
    out.clear();
    std::string shape_why;
    if (!ValidateV5TranscriptAttachmentShapeV1(
            plan, bundle, &shape_why)) {
        return 0;
    }
    uint64_t exact_size =
        4 + 4 + 32 + 32 + 4 + 32;
    for (const auto& proof : bundle.proofs) {
        exact_size +=
            4 + 4 + 4 + 4 + 4 + 32 + 4 +
            uint64_t{
                proof.proof_owned_semantic_rows.size()} *
                4 +
            4 + proof.proof_bytes.size();
    }
    if (exact_size >
            kV5TranscriptAttachmentBundleMaxBytesV1 ||
        exact_size > std::numeric_limits<size_t>::max()) {
        return 0;
    }
    out.reserve(static_cast<size_t>(exact_size));
    AppendU32Attachment(
        out, kV5TranscriptAttachmentMagicV1);
    AppendU32Attachment(out, bundle.version);
    AppendUint256Attachment(
        out, bundle.source_plan_statement);
    AppendUint256Attachment(
        out, bundle.public_schedule_statement);
    AppendU32Attachment(
        out, static_cast<uint32_t>(bundle.proofs.size()));
    for (const auto& proof : bundle.proofs) {
        AppendU32Attachment(out, proof.version);
        AppendU32Attachment(out, proof.leaf_ordinal);
        AppendU32Attachment(
            out, static_cast<uint32_t>(proof.kind));
        AppendU32Attachment(out, proof.lane);
        AppendU32Attachment(out, proof.batch_item);
        AppendUint256Attachment(
            out, proof.proof_statement);
        AppendU32Attachment(
            out,
            static_cast<uint32_t>(
                proof.proof_owned_semantic_rows.size()));
        for (uint32_t row :
             proof.proof_owned_semantic_rows) {
            AppendU32Attachment(out, row);
        }
        AppendU32Attachment(
            out,
            static_cast<uint32_t>(
                proof.proof_bytes.size()));
        out.insert(
            out.end(),
            proof.proof_bytes.begin(),
            proof.proof_bytes.end());
    }
    AppendUint256Attachment(out, bundle.bundle_statement);
    if (out.size() != exact_size) {
        out.clear();
        return 0;
    }
    return out.size();
}

std::optional<V5TranscriptProofAttachmentBundleV1>
DeserializeV5TranscriptProofAttachmentBundleV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const std::vector<unsigned char>& in)
{
    if (in.empty() ||
        in.size() >
            kV5TranscriptAttachmentBundleMaxBytesV1) {
        return std::nullopt;
    }
    const unsigned char* cursor = in.data();
    const unsigned char* end = in.data() + in.size();
    uint32_t magic = 0;
    uint32_t version = 0;
    uint256 source_plan_statement;
    uint256 public_schedule_statement;
    uint32_t proof_count = 0;
    if (!ReadU32Attachment(cursor, end, magic) ||
        magic != kV5TranscriptAttachmentMagicV1 ||
        !ReadU32Attachment(cursor, end, version) ||
        version != 1 ||
        !ReadUint256Attachment(
            cursor, end, source_plan_statement) ||
        !ReadUint256Attachment(
            cursor, end, public_schedule_statement) ||
        !ReadU32Attachment(cursor, end, proof_count) ||
        proof_count >
            kV5TranscriptLocalProofAttachmentCountV1) {
        return std::nullopt;
    }
    auto out =
        BuildV5TranscriptProofAttachmentBundleV1(plan);
    if (!out.valid ||
        source_plan_statement !=
            out.source_plan_statement ||
        public_schedule_statement !=
            out.public_schedule_statement) {
        return std::nullopt;
    }
    out.proofs.clear();
    out.proofs.reserve(proof_count);
    for (uint32_t index = 0;
         index < proof_count; ++index) {
        V5TranscriptLeafProofAttachmentV1 proof;
        uint32_t proof_version = 0;
        uint32_t kind = 0;
        uint32_t row_count = 0;
        uint32_t proof_bytes = 0;
        if (!ReadU32Attachment(
                cursor, end, proof_version) ||
            proof_version != 1 ||
            !ReadU32Attachment(
                cursor, end, proof.leaf_ordinal) ||
            !ReadU32Attachment(cursor, end, kind) ||
            (kind != static_cast<uint32_t>(
                         V5TranscriptLeafProofKindV1::
                             BatchCoefficientSplitRap) &&
             kind != static_cast<uint32_t>(
                         V5TranscriptLeafProofKindV1::
                             OodPointSplitRap) &&
             kind != static_cast<uint32_t>(
                         V5TranscriptLeafProofKindV1::
                             DeepWeightSplitRap) &&
             kind != static_cast<uint32_t>(
                         V5TranscriptLeafProofKindV1::
                             FoldChallengeSplitRap) &&
             kind != static_cast<uint32_t>(
                         V5TranscriptLeafProofKindV1::
                             QueryIndexLeafSplitRap)) ||
            !ReadU32Attachment(
                cursor, end, proof.lane) ||
            !ReadU32Attachment(
                cursor, end, proof.batch_item) ||
            !ReadUint256Attachment(
                cursor, end, proof.proof_statement) ||
            !ReadU32Attachment(cursor, end, row_count) ||
            row_count == 0 ||
            row_count > kV5SemanticConsumerCells ||
            static_cast<size_t>(end - cursor) <
                uint64_t{row_count} * 4) {
            return std::nullopt;
        }
        proof.version =
            static_cast<uint16_t>(proof_version);
        proof.kind =
            static_cast<V5TranscriptLeafProofKindV1>(kind);
        proof.proof_owned_semantic_rows.resize(row_count);
        for (uint32_t& row :
             proof.proof_owned_semantic_rows) {
            if (!ReadU32Attachment(cursor, end, row)) {
                return std::nullopt;
            }
        }
        if (!ReadU32Attachment(
                cursor, end, proof_bytes) ||
            proof_bytes == 0 ||
            proof_bytes > V5TranscriptProofMaxBytesV1(
                              proof.kind) ||
            proof_bytes >
                static_cast<size_t>(end - cursor)) {
            return std::nullopt;
        }
        proof.proof_bytes.assign(
            cursor, cursor + proof_bytes);
        cursor += proof_bytes;
        proof.recursively_consumed_cells = 0;
        out.proofs.push_back(std::move(proof));
    }
    uint256 bundle_statement;
    if (!ReadUint256Attachment(
            cursor, end, bundle_statement) ||
        cursor != end) {
        return std::nullopt;
    }
    RefreshV5TranscriptAttachmentProofCountersV1(out);
    // Decoding establishes canonical syntax and schedule shape only. The
    // caller must run VerifyV5TranscriptProofAttachmentBundleV1 before
    // treating any attachment as publicly verified.
    out.attached_proofs_publicly_verified = false;
    out.valid = true;
    out.note =
        out.proofs.empty()
        ? "stage3:v5_v6_bus:transcript_attachment:"
          "codec_schedule_only"
        : "stage3:v5_v6_bus:transcript_attachment:"
          "codec_proofs_require_public_verification";
    std::string shape_why;
    if (bundle_statement != out.bundle_statement ||
        !ValidateV5TranscriptAttachmentShapeV1(
            plan, out, &shape_why)) {
        return std::nullopt;
    }
    std::vector<unsigned char> canonical;
    if (SerializeV5TranscriptProofAttachmentBundleV1(
            plan, out, canonical) != in.size() ||
        canonical != in) {
        return std::nullopt;
    }
    return out;
}

namespace {

inline constexpr uint32_t kV5UnifiedShaAirProofMagicV1 =
    0x31514156u; // 'VAQ1'

void AppendU64Unified(
    std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t byte = 0; byte < 8; ++byte) {
        out.push_back(
            static_cast<unsigned char>(
                value >> (8 * byte)));
    }
}

bool ReadU64Unified(
    const unsigned char*& cursor,
    const unsigned char* end,
    uint64_t& value)
{
    if (static_cast<size_t>(end - cursor) < 8) return false;
    value = 0;
    for (uint32_t byte = 0; byte < 8; ++byte) {
        value |= uint64_t{cursor[byte]} << (8 * byte);
    }
    cursor += 8;
    return true;
}

void AppendFp3Unified(
    std::vector<unsigned char>& out, const Fp3& value)
{
    AppendU64Unified(out, gf::Canonical(value.c0));
    AppendU64Unified(out, gf::Canonical(value.c1));
    AppendU64Unified(out, gf::Canonical(value.c2));
}

bool ReadFp3Unified(
    const unsigned char*& cursor,
    const unsigned char* end,
    Fp3& value)
{
    uint64_t c0 = 0;
    uint64_t c1 = 0;
    uint64_t c2 = 0;
    if (!ReadU64Unified(cursor, end, c0) ||
        !ReadU64Unified(cursor, end, c1) ||
        !ReadU64Unified(cursor, end, c2) ||
        c0 >= gf::kP || c1 >= gf::kP || c2 >= gf::kP) {
        return false;
    }
    value = {c0, c1, c2};
    return true;
}

bool SerializeV5UnifiedAirProofV1(
    const aq::AirQuotientProof<Fp3>& proof,
    std::vector<unsigned char>& out)
{
    out.clear();
    std::vector<unsigned char> batch;
    if (SerializeFri3BatchProof(proof.batch, batch) == 0 ||
        batch.empty() ||
        batch.size() > kRCFriMaxProofBytesHard ||
        proof.next_openings.size() >
            kRCFriMaxQueriesHard) {
        return false;
    }
    uint64_t exact_size =
        4 + 4 + 4 + batch.size() + 32 + 4;
    for (const auto& paths : proof.next_openings) {
        if (paths.size() > kRCFriBatchMaxColumns) {
            return false;
        }
        exact_size += 4;
        for (const auto& path : paths) {
            if (path.siblings.size() >
                kRCFriMaxFoldLayersHard) {
                return false;
            }
            exact_size +=
                4 + 24 + 4 +
                uint64_t{path.siblings.size()} * 32;
        }
    }
    if (exact_size >
            kV5UnifiedShaAirProofMaxBytesV1 ||
        exact_size >
            std::numeric_limits<size_t>::max()) {
        return false;
    }
    out.reserve(static_cast<size_t>(exact_size));
    AppendU32Attachment(
        out, kV5UnifiedShaAirProofMagicV1);
    AppendU32Attachment(out, 1);
    AppendU32Attachment(
        out, static_cast<uint32_t>(batch.size()));
    out.insert(out.end(), batch.begin(), batch.end());
    AppendUint256Attachment(out, proof.trace_commit);
    AppendU32Attachment(
        out,
        static_cast<uint32_t>(
            proof.next_openings.size()));
    for (const auto& paths : proof.next_openings) {
        AppendU32Attachment(
            out, static_cast<uint32_t>(paths.size()));
        for (const auto& path : paths) {
            AppendU32Attachment(out, path.index);
            AppendFp3Unified(out, path.leaf);
            AppendU32Attachment(
                out,
                static_cast<uint32_t>(
                    path.siblings.size()));
            for (const uint256& sibling : path.siblings) {
                AppendUint256Attachment(out, sibling);
            }
        }
    }
    if (out.size() != exact_size) {
        out.clear();
        return false;
    }
    return true;
}

std::optional<aq::AirQuotientProof<Fp3>>
DeserializeV5UnifiedAirProofV1(
    const std::vector<unsigned char>& in)
{
    if (in.empty() ||
        in.size() > kV5UnifiedShaAirProofMaxBytesV1) {
        return std::nullopt;
    }
    const unsigned char* cursor = in.data();
    const unsigned char* end = in.data() + in.size();
    uint32_t magic = 0;
    uint32_t version = 0;
    uint32_t batch_size = 0;
    if (!ReadU32Attachment(cursor, end, magic) ||
        magic != kV5UnifiedShaAirProofMagicV1 ||
        !ReadU32Attachment(cursor, end, version) ||
        version != 1 ||
        !ReadU32Attachment(cursor, end, batch_size) ||
        batch_size == 0 ||
        batch_size > kRCFriMaxProofBytesHard ||
        batch_size >
            static_cast<size_t>(end - cursor)) {
        return std::nullopt;
    }
    std::vector<unsigned char> batch_bytes(
        cursor, cursor + batch_size);
    cursor += batch_size;
    const auto batch =
        DeserializeFri3BatchProof(batch_bytes);
    if (!batch.has_value()) return std::nullopt;
    std::vector<unsigned char> canonical_batch;
    if (SerializeFri3BatchProof(
            *batch, canonical_batch) !=
            batch_bytes.size() ||
        canonical_batch != batch_bytes) {
        return std::nullopt;
    }

    aq::AirQuotientProof<Fp3> out;
    out.batch = *batch;
    uint32_t query_count = 0;
    if (!ReadUint256Attachment(
            cursor, end, out.trace_commit) ||
        !ReadU32Attachment(
            cursor, end, query_count) ||
        query_count > kRCFriMaxQueriesHard) {
        return std::nullopt;
    }
    out.next_openings.resize(query_count);
    for (auto& paths : out.next_openings) {
        uint32_t path_count = 0;
        if (!ReadU32Attachment(
                cursor, end, path_count) ||
            path_count > kRCFriBatchMaxColumns) {
            return std::nullopt;
        }
        paths.resize(path_count);
        for (auto& path : paths) {
            uint32_t sibling_count = 0;
            if (!ReadU32Attachment(
                    cursor, end, path.index) ||
                !ReadFp3Unified(
                    cursor, end, path.leaf) ||
                !ReadU32Attachment(
                    cursor, end, sibling_count) ||
                sibling_count >
                    kRCFriMaxFoldLayersHard ||
                uint64_t{sibling_count} * 32 >
                    static_cast<size_t>(
                        end - cursor)) {
                return std::nullopt;
            }
            path.siblings.resize(sibling_count);
            for (uint256& sibling : path.siblings) {
                if (!ReadUint256Attachment(
                        cursor, end, sibling)) {
                    return std::nullopt;
                }
            }
        }
    }
    if (cursor != end) return std::nullopt;
    std::vector<unsigned char> canonical;
    if (!SerializeV5UnifiedAirProofV1(
            out, canonical) ||
        canonical != in) {
        return std::nullopt;
    }
    return out;
}

uint256 CommitV5UnifiedShaReceiptV1(
    const V5UnifiedShaReceiptV1& receipt)
{
    if (receipt.source_plan_statement.IsNull() ||
        receipt.public_schedule_statement.IsNull() ||
        receipt.semantic_boundary_commitment.IsNull() ||
        receipt.airq_combined_air_seed.IsNull() ||
        receipt.attachment_bundle_bytes.empty() ||
        receipt.airq_proof_bytes.empty() ||
        receipt.attachment_bundle_bytes.size() >
            kV5UnifiedShaAttachmentMaxBytesV1 ||
        receipt.airq_proof_bytes.size() >
            kV5UnifiedShaAirProofMaxBytesV1) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V5_UNIFIED_SHA_RECEIPT_V1";
    hash << receipt.version;
    hash << receipt.source_plan_statement;
    hash << receipt.public_schedule_statement;
    hash << receipt.semantic_boundary_commitment;
    hash << receipt.airq_combined_air_seed;
    hash << static_cast<uint64_t>(
        receipt.attachment_bundle_bytes.size());
    for (const unsigned char byte :
         receipt.attachment_bundle_bytes) {
        hash << byte;
    }
    hash << static_cast<uint64_t>(
        receipt.airq_proof_bytes.size());
    for (const unsigned char byte :
         receipt.airq_proof_bytes) {
        hash << byte;
    }
    return hash.GetHash();
}

bool ExactV5UnifiedCoverageV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5TranscriptProofAttachmentBundleV1& attachments)
{
    if (plan.consumers.size() !=
            kV5SemanticConsumerCells ||
        attachments.proof_owned_cells !=
            kV5TranscriptWithQueryProofOwnedCellsV1 ||
        attachments.pending_cells !=
            kV5TranscriptAirQuotientPendingCellsV1) {
        return false;
    }
    std::array<uint8_t, kV5SemanticConsumerCells> covered{};
    for (const auto& proof : attachments.proofs) {
        for (const uint32_t row :
             proof.proof_owned_semantic_rows) {
            if (row >= covered.size() || covered[row]) {
                return false;
            }
            covered[row] = 1;
        }
    }
    uint32_t airq = 0;
    for (const auto& consumer : plan.consumers) {
        if (consumer.semantic_row >= covered.size()) {
            return false;
        }
        const bool is_airq =
            consumer.family ==
                ChallengeFeedbackFamily::AirQuotient;
        if (is_airq) {
            ++airq;
            if (covered[consumer.semantic_row]) {
                return false;
            }
        } else if (!covered[consumer.semantic_row]) {
            return false;
        }
    }
    return airq ==
        kV5TranscriptAirQuotientPendingCellsV1;
}

bool SameV5UnifiedReceiptSummaryV1(
    const V5UnifiedShaReceiptV1& lhs,
    const V5UnifiedShaReceiptV1& rhs)
{
    return
        lhs.version == rhs.version &&
        lhs.source_plan_statement ==
            rhs.source_plan_statement &&
        lhs.public_schedule_statement ==
            rhs.public_schedule_statement &&
        lhs.semantic_boundary_commitment ==
            rhs.semantic_boundary_commitment &&
        lhs.airq_combined_air_seed ==
            rhs.airq_combined_air_seed &&
        lhs.receipt_commitment ==
            rhs.receipt_commitment &&
        lhs.semantic_cells == rhs.semantic_cells &&
        lhs.split_rap_local_cells ==
            rhs.split_rap_local_cells &&
        lhs.same_parent_sha_cells ==
            rhs.same_parent_sha_cells &&
        lhs.proof_owned_local_cells ==
            rhs.proof_owned_local_cells &&
        lhs.normalized_recursive_cells ==
            rhs.normalized_recursive_cells &&
        lhs.direct_v6_feedback_cells ==
            rhs.direct_v6_feedback_cells &&
        lhs.pending_normalized_recursive_cells ==
            rhs.pending_normalized_recursive_cells &&
        lhs.encoded_attachment_bytes ==
            rhs.encoded_attachment_bytes &&
        lhs.encoded_airq_proof_bytes ==
            rhs.encoded_airq_proof_bytes &&
        lhs.exact_disjoint_304_coverage ==
            rhs.exact_disjoint_304_coverage &&
        lhs.nested_codecs_canonical ==
            rhs.nested_codecs_canonical &&
        lhs.normalized_recursive_consumption_complete ==
            rhs.normalized_recursive_consumption_complete &&
        lhs.v6_challenges_drive_v5_equations ==
            rhs.v6_challenges_drive_v5_equations &&
        lhs.production_authority_ready ==
            rhs.production_authority_ready &&
        lhs.attachment_bundle_bytes ==
            rhs.attachment_bundle_bytes &&
        lhs.airq_proof_bytes == rhs.airq_proof_bytes;
}

} // namespace

V5UnifiedShaReceiptV1 BuildV5UnifiedShaReceiptV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5TranscriptProofAttachmentBundleV1& attachments,
    const aq::AirQuotientProof<Fp3>& airq_sha_proof)
{
    V5UnifiedShaReceiptV1 out;
    std::string why;
    const V5FullTranscriptWitnessShardPlan canonical_plan =
        BuildV5FullTranscriptWitnessShardPlan(
            composition, child, child_fs_seed);
    if (!canonical_plan.valid ||
        canonical_plan.public_plan_statement !=
            plan.public_plan_statement ||
        !VerifyV5TranscriptProofAttachmentBundleV1(
            composition, child, child_fs_seed,
            plan, attachments, &why) ||
        !ExactV5UnifiedCoverageV1(plan, attachments)) {
        out.note =
            "stage3:v5_v6_bus:unified_sha_receipt:"
            "attachment:" + why;
        return out;
    }
    const V5ShaProducedFeedbackComposition sha =
        BuildV5ShaProducedFeedbackComposition(
            composition, child_fs_seed);
    if (!sha.valid ||
        sha.recursive_sha_derivation_cells !=
            kV5TranscriptAirQuotientPendingCellsV1 ||
        !VerifyV5ShaProducedFeedbackComposition(
            composition, child_fs_seed,
            sha.public_boundary_commitment,
            airq_sha_proof, &why)) {
        out.note =
            "stage3:v5_v6_bus:unified_sha_receipt:"
            "airq:" + why;
        return out;
    }
    uint32_t exact_airq_cells = 0;
    for (const auto& cell : sha.cells) {
        if (cell.recursive_sha_derivation) {
            if (cell.family !=
                    ChallengeFeedbackFamily::AirQuotient ||
                !cell.v5_consumer_equality ||
                !cell.same_trace_alias) {
                out.note =
                    "stage3:v5_v6_bus:unified_sha_receipt:"
                    "airq_cell_mapping";
                return out;
            }
            ++exact_airq_cells;
        }
    }
    if (exact_airq_cells !=
        kV5TranscriptAirQuotientPendingCellsV1) {
        out.note =
            "stage3:v5_v6_bus:unified_sha_receipt:"
            "airq_cell_count";
        return out;
    }

    if (attachments.encoded_proof_bytes >
            kV5UnifiedShaAttachmentMaxBytesV1 ||
        SerializeV5TranscriptProofAttachmentBundleV1(
            plan, attachments,
            out.attachment_bundle_bytes) == 0 ||
        out.attachment_bundle_bytes.size() >
            kV5UnifiedShaAttachmentMaxBytesV1 ||
        !SerializeV5UnifiedAirProofV1(
            airq_sha_proof, out.airq_proof_bytes)) {
        out.note =
            "stage3:v5_v6_bus:unified_sha_receipt:"
            "nested_codec";
        return out;
    }
    const auto decoded_attachments =
        DeserializeV5TranscriptProofAttachmentBundleV1(
            plan, out.attachment_bundle_bytes);
    const auto decoded_airq =
        DeserializeV5UnifiedAirProofV1(
            out.airq_proof_bytes);
    if (!decoded_attachments.has_value() ||
        !decoded_airq.has_value()) {
        out.note =
            "stage3:v5_v6_bus:unified_sha_receipt:"
            "nested_roundtrip";
        return out;
    }

    out.source_plan_statement =
        plan.public_plan_statement;
    out.public_schedule_statement =
        attachments.public_schedule_statement;
    out.semantic_boundary_commitment =
        sha.public_boundary_commitment;
    out.airq_combined_air_seed =
        sha.combined_air_seed;
    out.semantic_cells = kV5SemanticConsumerCells;
    out.split_rap_local_cells =
        attachments.proof_owned_cells;
    out.same_parent_sha_cells = exact_airq_cells;
    out.proof_owned_local_cells =
        out.split_rap_local_cells +
        out.same_parent_sha_cells;
    // "Same parent" is not inherited as normalized recursion.
    out.normalized_recursive_cells = 0;
    out.direct_v6_feedback_cells = 0;
    out.pending_normalized_recursive_cells =
        kV5SemanticConsumerCells;
    out.encoded_attachment_bytes =
        out.attachment_bundle_bytes.size();
    out.encoded_airq_proof_bytes =
        out.airq_proof_bytes.size();
    out.one_child_seed_and_plan = true;
    out.exact_disjoint_304_coverage = true;
    out.nested_codecs_canonical = true;
    out.attached_proofs_publicly_verified = true;
    out.airq_sha_proof_publicly_verified = true;
    out.complete_local_sha_transcript_proof =
        out.proof_owned_local_cells ==
            kV5SemanticConsumerCells;
    out.normalized_recursive_consumption_complete = false;
    out.v6_challenges_drive_v5_equations = false;
    out.production_authority_ready = false;
    out.receipt_commitment =
        CommitV5UnifiedShaReceiptV1(out);
    out.valid =
        !out.receipt_commitment.IsNull() &&
        out.split_rap_local_cells ==
            kV5TranscriptWithQueryProofOwnedCellsV1 &&
        out.same_parent_sha_cells ==
            kV5TranscriptAirQuotientPendingCellsV1 &&
        out.proof_owned_local_cells ==
            kV5SemanticConsumerCells &&
        out.normalized_recursive_cells == 0 &&
        out.direct_v6_feedback_cells == 0 &&
        out.pending_normalized_recursive_cells ==
            kV5SemanticConsumerCells &&
        out.complete_local_sha_transcript_proof &&
        !out.normalized_recursive_consumption_complete &&
        !out.v6_challenges_drive_v5_equations &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:v5_v6_bus:unified_sha_receipt:"
          "local_proof_owned_304_of_304;"
          "split_rap_298;same_parent_sha_6;"
          "normalized_recursive_0;direct_v6_0;"
          "authority_false"
        : "stage3:v5_v6_bus:unified_sha_receipt:invalid";
    return out;
}

bool VerifyV5UnifiedShaReceiptV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5UnifiedShaReceiptV1& receipt,
    std::string* why)
{
    if (!receipt.valid ||
        receipt.attachment_bundle_bytes.empty() ||
        receipt.airq_proof_bytes.empty() ||
        receipt.encoded_attachment_bytes !=
            receipt.attachment_bundle_bytes.size() ||
        receipt.encoded_airq_proof_bytes !=
            receipt.airq_proof_bytes.size() ||
        receipt.receipt_commitment !=
            CommitV5UnifiedShaReceiptV1(receipt)) {
        return Fail(why, "unified_sha_receipt:shape");
    }
    const auto attachments =
        DeserializeV5TranscriptProofAttachmentBundleV1(
            plan, receipt.attachment_bundle_bytes);
    const auto airq =
        DeserializeV5UnifiedAirProofV1(
            receipt.airq_proof_bytes);
    if (!attachments.has_value() ||
        !airq.has_value()) {
        return Fail(why, "unified_sha_receipt:codec");
    }
    const V5UnifiedShaReceiptV1 expected =
        BuildV5UnifiedShaReceiptV1(
            composition, child, child_fs_seed,
            plan, *attachments, *airq);
    if (!expected.valid ||
        !SameV5UnifiedReceiptSummaryV1(
            receipt, expected)) {
        return Fail(
            why, "unified_sha_receipt:public_verify");
    }
    if (why != nullptr) {
        *why =
            "stage3:v5_v6_bus:unified_sha_receipt:"
            "canonical_nested_codecs;exact_disjoint_304;"
            "local_proof_complete;"
            "normalized_recursive_0;direct_v6_0;"
            "authority_false";
    }
    return true;
}

size_t SerializeV5UnifiedShaReceiptV1(
    const V5UnifiedShaReceiptV1& receipt,
    std::vector<unsigned char>& out)
{
    out.clear();
    if (!receipt.valid ||
        receipt.version != 1 ||
        receipt.receipt_commitment !=
            CommitV5UnifiedShaReceiptV1(receipt) ||
        receipt.encoded_attachment_bytes !=
            receipt.attachment_bundle_bytes.size() ||
        receipt.encoded_airq_proof_bytes !=
            receipt.airq_proof_bytes.size()) {
        return 0;
    }
    const uint64_t exact_size =
        4 + 4 + 4 * 32 + 4 +
        receipt.attachment_bundle_bytes.size() +
        4 + receipt.airq_proof_bytes.size() + 32;
    if (exact_size > kV5UnifiedShaReceiptMaxBytesV1 ||
        exact_size >
            std::numeric_limits<size_t>::max() ||
        receipt.attachment_bundle_bytes.size() >
            std::numeric_limits<uint32_t>::max() ||
        receipt.airq_proof_bytes.size() >
            std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    out.reserve(static_cast<size_t>(exact_size));
    AppendU32Attachment(out, kV5UnifiedShaReceiptMagicV1);
    AppendU32Attachment(out, receipt.version);
    AppendUint256Attachment(
        out, receipt.source_plan_statement);
    AppendUint256Attachment(
        out, receipt.public_schedule_statement);
    AppendUint256Attachment(
        out, receipt.semantic_boundary_commitment);
    AppendUint256Attachment(
        out, receipt.airq_combined_air_seed);
    AppendU32Attachment(
        out,
        static_cast<uint32_t>(
            receipt.attachment_bundle_bytes.size()));
    out.insert(
        out.end(),
        receipt.attachment_bundle_bytes.begin(),
        receipt.attachment_bundle_bytes.end());
    AppendU32Attachment(
        out,
        static_cast<uint32_t>(
            receipt.airq_proof_bytes.size()));
    out.insert(
        out.end(),
        receipt.airq_proof_bytes.begin(),
        receipt.airq_proof_bytes.end());
    AppendUint256Attachment(
        out, receipt.receipt_commitment);
    if (out.size() != exact_size) {
        out.clear();
        return 0;
    }
    return out.size();
}

std::optional<V5UnifiedShaReceiptV1>
DeserializeV5UnifiedShaReceiptV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const std::vector<unsigned char>& in)
{
    if (in.empty() ||
        in.size() > kV5UnifiedShaReceiptMaxBytesV1) {
        return std::nullopt;
    }
    const unsigned char* cursor = in.data();
    const unsigned char* end = in.data() + in.size();
    uint32_t magic = 0;
    uint32_t version = 0;
    uint32_t attachment_size = 0;
    uint32_t airq_size = 0;
    V5UnifiedShaReceiptV1 out;
    if (!ReadU32Attachment(cursor, end, magic) ||
        magic != kV5UnifiedShaReceiptMagicV1 ||
        !ReadU32Attachment(cursor, end, version) ||
        version != 1 ||
        !ReadUint256Attachment(
            cursor, end, out.source_plan_statement) ||
        !ReadUint256Attachment(
            cursor, end, out.public_schedule_statement) ||
        !ReadUint256Attachment(
            cursor, end,
            out.semantic_boundary_commitment) ||
        !ReadUint256Attachment(
            cursor, end, out.airq_combined_air_seed) ||
        !ReadU32Attachment(
            cursor, end, attachment_size) ||
        attachment_size == 0 ||
        attachment_size >
            kV5UnifiedShaAttachmentMaxBytesV1 ||
        attachment_size >
            static_cast<size_t>(end - cursor)) {
        return std::nullopt;
    }
    out.version = static_cast<uint16_t>(version);
    out.attachment_bundle_bytes.assign(
        cursor, cursor + attachment_size);
    cursor += attachment_size;
    if (!ReadU32Attachment(cursor, end, airq_size) ||
        airq_size == 0 ||
        airq_size > kV5UnifiedShaAirProofMaxBytesV1 ||
        airq_size >
            static_cast<size_t>(end - cursor)) {
        return std::nullopt;
    }
    out.airq_proof_bytes.assign(
        cursor, cursor + airq_size);
    cursor += airq_size;
    if (!ReadUint256Attachment(
            cursor, end, out.receipt_commitment) ||
        cursor != end) {
        return std::nullopt;
    }
    const auto attachments =
        DeserializeV5TranscriptProofAttachmentBundleV1(
            plan, out.attachment_bundle_bytes);
    if (!attachments.has_value() ||
        !DeserializeV5UnifiedAirProofV1(
            out.airq_proof_bytes).has_value() ||
        out.source_plan_statement !=
            plan.public_plan_statement ||
        out.public_schedule_statement !=
            attachments->public_schedule_statement ||
        !ExactV5UnifiedCoverageV1(
            plan, *attachments)) {
        return std::nullopt;
    }
    out.semantic_cells = kV5SemanticConsumerCells;
    out.split_rap_local_cells =
        attachments->proof_owned_cells;
    out.same_parent_sha_cells =
        kV5TranscriptAirQuotientPendingCellsV1;
    out.proof_owned_local_cells =
        out.split_rap_local_cells +
        out.same_parent_sha_cells;
    out.normalized_recursive_cells = 0;
    out.direct_v6_feedback_cells = 0;
    out.pending_normalized_recursive_cells =
        kV5SemanticConsumerCells;
    out.encoded_attachment_bytes = attachment_size;
    out.encoded_airq_proof_bytes = airq_size;
    // Codec decoding establishes syntax/coverage, not public proof validity.
    out.one_child_seed_and_plan = false;
    out.exact_disjoint_304_coverage = true;
    out.nested_codecs_canonical = true;
    out.attached_proofs_publicly_verified = false;
    out.airq_sha_proof_publicly_verified = false;
    out.complete_local_sha_transcript_proof = false;
    out.normalized_recursive_consumption_complete = false;
    out.v6_challenges_drive_v5_equations = false;
    out.production_authority_ready = false;
    out.valid = true;
    out.note =
        "stage3:v5_v6_bus:unified_sha_receipt:"
        "codec_canonical;public_verification_required;"
        "normalized_recursive_0;authority_false";
    if (out.receipt_commitment !=
        CommitV5UnifiedShaReceiptV1(out)) {
        return std::nullopt;
    }
    // Re-encode without trusting non-wire summary flags.
    std::vector<unsigned char> canonical;
    const bool saved_valid = out.valid;
    out.valid = true;
    if (SerializeV5UnifiedShaReceiptV1(
            out, canonical) != in.size() ||
        canonical != in) {
        return std::nullopt;
    }
    out.valid = saved_valid;
    return out;
}

namespace {

uint256 CommitV6ShaCompatibilityOutputsV1(
    const std::vector<V6ShaCompatibilityCellV1>& cells)
{
    if (cells.size() != kV5SemanticConsumerCells) return {};
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V6_SHA_COMPATIBILITY_OUTPUTS_V1";
    hash << uint16_t{1};
    hash << static_cast<uint32_t>(cells.size());
    for (uint32_t ordinal = 0;
         ordinal < cells.size(); ++ordinal) {
        const auto& cell = cells[ordinal];
        const auto expected_consumer =
            ExpectedConsumerForFamily(cell.family);
        if (cell.ordinal != ordinal ||
            cell.lane >= 2 ||
            cell.coordinate >= 3 ||
            !expected_consumer.has_value() ||
            cell.consumer != *expected_consumer ||
            cell.receipt_output !=
                cell.normalized_v5_input) {
            return {};
        }
        hash << cell.ordinal;
        hash << static_cast<uint8_t>(cell.family);
        hash << cell.lane;
        hash << cell.item_index;
        hash << cell.coordinate;
        hash << static_cast<uint8_t>(cell.consumer);
        hash << gf::Canonical(cell.receipt_output);
    }
    return hash.GetHash();
}

uint256 CommitV6ShaCompatibilityStatementV1(
    const V6ShaCompatibilityModeV1& mode)
{
    if (mode.version != 1 ||
        mode.challenge_source_domain !=
            V6ChallengeSourceDomainV1::
                UnifiedV5ShaReceipt ||
        mode.child_fs_seed.IsNull() ||
        mode.source_plan_statement.IsNull() ||
        mode.public_schedule_statement.IsNull() ||
        mode.semantic_boundary_commitment.IsNull() ||
        mode.unified_receipt_commitment.IsNull() ||
        mode.ordered_output_commitment.IsNull() ||
        mode.ordered_output_commitment !=
            CommitV6ShaCompatibilityOutputsV1(
                mode.cells)) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V6_SHA_COMPATIBILITY_STATEMENT_V1";
    hash << mode.version;
    hash << static_cast<uint8_t>(
        mode.challenge_source_domain);
    hash << mode.child_fs_seed;
    hash << mode.source_plan_statement;
    hash << mode.public_schedule_statement;
    hash << mode.semantic_boundary_commitment;
    hash << mode.unified_receipt_commitment;
    hash << mode.ordered_output_commitment;
    hash << kV5SemanticConsumerCells;
    hash << kV5SemanticConsumerRows;
    hash << kV6ShaCompatibilityColumns;
    return hash.GetHash();
}

bool SameV6ShaCompatibilitySummaryV1(
    const V6ShaCompatibilityModeV1& lhs,
    const V6ShaCompatibilityModeV1& rhs)
{
    return
        lhs.version == rhs.version &&
        lhs.valid == rhs.valid &&
        lhs.challenge_source_domain ==
            rhs.challenge_source_domain &&
        lhs.child_fs_seed == rhs.child_fs_seed &&
        lhs.source_plan_statement ==
            rhs.source_plan_statement &&
        lhs.public_schedule_statement ==
            rhs.public_schedule_statement &&
        lhs.semantic_boundary_commitment ==
            rhs.semantic_boundary_commitment &&
        lhs.unified_receipt_commitment ==
            rhs.unified_receipt_commitment &&
        lhs.ordered_output_commitment ==
            rhs.ordered_output_commitment &&
        lhs.compatibility_statement ==
            rhs.compatibility_statement &&
        lhs.semantic_cells == rhs.semantic_cells &&
        lhs.local_direct_feedback_cells ==
            rhs.local_direct_feedback_cells &&
        lhs.normalized_recursive_cells ==
            rhs.normalized_recursive_cells &&
        lhs.pending_normalized_recursive_cells ==
            rhs.pending_normalized_recursive_cells &&
        lhs.trace_rows == rhs.trace_rows &&
        lhs.trace_columns == rhs.trace_columns &&
        lhs.unified_receipt_publicly_verified ==
            rhs.unified_receipt_publicly_verified &&
        lhs.exact_schedule_and_order ==
            rhs.exact_schedule_and_order &&
        lhs.exact_statement_equality ==
            rhs.exact_statement_equality &&
        lhs.exact_seed_equality ==
            rhs.exact_seed_equality &&
        lhs.receipt_outputs_drive_normalized_v5_equations ==
            rhs.receipt_outputs_drive_normalized_v5_equations &&
        lhs.legacy_alghash_semantics_unchanged ==
            rhs.legacy_alghash_semantics_unchanged &&
        lhs.alghash_domain_substitution_rejected ==
            rhs.alghash_domain_substitution_rejected &&
        lhs.normalized_recursive_consumption_complete ==
            rhs.normalized_recursive_consumption_complete &&
        lhs.production_authority_ready ==
            rhs.production_authority_ready &&
        lhs.cells == rhs.cells &&
        EqFp3Matrices(
            lhs.witness_columns, rhs.witness_columns) &&
        SameNormalizedFeedbackConstraintShape(
            lhs.constraint_system, rhs.constraint_system);
}

} // namespace

V6ShaCompatibilityModeV1 BuildV6ShaCompatibilityModeV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5UnifiedShaReceiptV1& receipt,
    V6ChallengeSourceDomainV1 source_domain)
{
    V6ShaCompatibilityModeV1 out;
    out.challenge_source_domain = source_domain;
    out.legacy_alghash_semantics_unchanged = true;
    out.alghash_domain_substitution_rejected = true;
    if (source_domain !=
        V6ChallengeSourceDomainV1::UnifiedV5ShaReceipt) {
        out.note =
            "stage3:v5_v6_bus:v6_sha_compatibility:"
            "alghash_domain_substitution_rejected";
        return out;
    }

    std::string why;
    const V5FullTranscriptWitnessShardPlan canonical_plan =
        BuildV5FullTranscriptWitnessShardPlan(
            composition, child, child_fs_seed);
    const V5TranscriptUnificationCanaryV1 canary =
        BuildV5TranscriptUnificationCanaryV1(plan);
    const V5SemanticMaterialization semantic =
        BuildV5SemanticMaterialization(composition);
    if (child_fs_seed.IsNull() ||
        !canonical_plan.valid ||
        canonical_plan.public_plan_statement !=
            plan.public_plan_statement ||
        !canary.valid ||
        !semantic.valid ||
        plan.consumers.size() !=
            kV5SemanticConsumerCells ||
        semantic.cells.size() !=
            kV5SemanticConsumerCells ||
        receipt.source_plan_statement !=
            plan.public_plan_statement ||
        receipt.public_schedule_statement !=
            canary.public_schedule_statement ||
        receipt.semantic_boundary_commitment !=
            semantic.public_boundary_commitment ||
        !VerifyV5UnifiedShaReceiptV1(
            composition, child, child_fs_seed,
            plan, receipt, &why)) {
        out.note =
            "stage3:v5_v6_bus:v6_sha_compatibility:"
            "receipt_or_public_statement:" + why;
        return out;
    }

    out.cells.reserve(kV5SemanticConsumerCells);
    out.witness_columns.assign(
        kV6ShaCompatibilityColumns,
        std::vector<Fp3>(
            kV5SemanticConsumerRows, Fp3::Zero()));
    for (uint32_t ordinal = 0;
         ordinal < kV5SemanticConsumerCells;
         ++ordinal) {
        const auto& source = plan.consumers[ordinal];
        const auto& target = semantic.cells[ordinal];
        if (source.semantic_row != ordinal ||
            target.semantic_row != ordinal ||
            source.family != target.family ||
            source.lane != target.lane ||
            source.item_index != target.item_index ||
            source.coordinate != target.coordinate ||
            source.consumer != target.consumer) {
            out.note =
                "stage3:v5_v6_bus:v6_sha_compatibility:"
                "schedule_or_order";
            return out;
        }

        V6ShaCompatibilityCellV1 cell;
        cell.ordinal = ordinal;
        cell.family = target.family;
        cell.lane = target.lane;
        cell.item_index = target.item_index;
        cell.coordinate = target.coordinate;
        cell.consumer = target.consumer;
        // Public verification of the unified receipt proves that its exact
        // typed output at this row is the normalized-V5 boundary value.
        cell.receipt_output =
            gf::Canonical(target.expected_v5_value);
        cell.normalized_v5_input = cell.receipt_output;
        out.cells.push_back(cell);

        auto& columns = out.witness_columns;
        columns[kV6ShaCompatibilityActive][ordinal] =
            Fp3::One();
        columns[kV6ShaCompatibilityFamily][ordinal] =
            Fp3::FromFp(gf::FromU64(
                static_cast<uint8_t>(cell.family)));
        columns[kV6ShaCompatibilityLane][ordinal] =
            Fp3::FromFp(gf::FromU64(cell.lane));
        columns[kV6ShaCompatibilityItem][ordinal] =
            Fp3::FromFp(gf::FromU64(cell.item_index));
        columns[kV6ShaCompatibilityCoordinate][ordinal] =
            Fp3::FromFp(gf::FromU64(cell.coordinate));
        columns[kV6ShaCompatibilityConsumer][ordinal] =
            Fp3::FromFp(gf::FromU64(
                static_cast<uint8_t>(cell.consumer)));
        columns[kV6ShaCompatibilityExpected][ordinal] =
            Fp3::FromFp(cell.receipt_output);
        columns[kV6ShaCompatibilityReceiptOutput][ordinal] =
            Fp3::FromFp(cell.receipt_output);
        columns[kV6ShaCompatibilityNormalizedInput][ordinal] =
            Fp3::FromFp(cell.normalized_v5_input);
    }

    auto& cs = out.constraint_system;
    cs.n_rows = kV5SemanticConsumerRows;
    cs.n_columns = kV6ShaCompatibilityColumns;
    cs.preprocessed_pin_ood = true;
    for (uint32_t column = kV6ShaCompatibilityActive;
         column <= kV6ShaCompatibilityExpected;
         ++column) {
        cs.preprocessed.emplace_back(
            column, out.witness_columns[column]);
    }

    aq::AirConstraint<Fp3> active_boolean;
    active_boolean.name =
        "v6_sha_compatibility.active_boolean";
    active_boolean.kind = aq::AirKind::kEverywhere;
    active_boolean.alg_degree = 2;
    active_boolean.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kV6ShaCompatibilityActive],
            gf::Sub(
                row[kV6ShaCompatibilityActive],
                Fp3::One()));
    };
    cs.constraints.push_back(std::move(active_boolean));

    aq::AirConstraint<Fp3> receipt_output;
    receipt_output.name =
        "v6_sha_compatibility.receipt_output_equality";
    receipt_output.kind = aq::AirKind::kEverywhere;
    receipt_output.alg_degree = 2;
    receipt_output.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kV6ShaCompatibilityActive],
            gf::Sub(
                row[kV6ShaCompatibilityReceiptOutput],
                row[kV6ShaCompatibilityExpected]));
    };
    cs.constraints.push_back(std::move(receipt_output));

    aq::AirConstraint<Fp3> normalized_input;
    normalized_input.name =
        "v6_sha_compatibility.normalized_v5_input_equality";
    normalized_input.kind = aq::AirKind::kEverywhere;
    normalized_input.alg_degree = 2;
    normalized_input.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kV6ShaCompatibilityActive],
            gf::Sub(
                row[kV6ShaCompatibilityNormalizedInput],
                row[kV6ShaCompatibilityReceiptOutput]));
    };
    cs.constraints.push_back(std::move(normalized_input));

    for (uint32_t witness :
         std::array<uint32_t, 2>{
             kV6ShaCompatibilityReceiptOutput,
             kV6ShaCompatibilityNormalizedInput}) {
        aq::AirConstraint<Fp3> padding_zero;
        padding_zero.name =
            "v6_sha_compatibility.padding_zero";
        padding_zero.kind = aq::AirKind::kEverywhere;
        padding_zero.alg_degree = 2;
        padding_zero.eval = [witness](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    row[kV6ShaCompatibilityActive]),
                row[witness]);
        };
        cs.constraints.push_back(std::move(padding_zero));
    }

    out.child_fs_seed = child_fs_seed;
    out.source_plan_statement =
        plan.public_plan_statement;
    out.public_schedule_statement =
        canary.public_schedule_statement;
    out.semantic_boundary_commitment =
        semantic.public_boundary_commitment;
    out.unified_receipt_commitment =
        receipt.receipt_commitment;
    out.ordered_output_commitment =
        CommitV6ShaCompatibilityOutputsV1(out.cells);
    out.semantic_cells = out.cells.size();
    out.local_direct_feedback_cells =
        kV5SemanticConsumerCells;
    // These local equalities become recursive ownership only after the
    // normalized parent executes every receipt-child verifier in AIR.
    out.normalized_recursive_cells = 0;
    out.pending_normalized_recursive_cells =
        kV5SemanticConsumerCells;
    out.trace_rows = cs.n_rows;
    out.trace_columns = cs.n_columns;
    out.unified_receipt_publicly_verified = true;
    out.exact_schedule_and_order = true;
    out.exact_statement_equality = true;
    out.exact_seed_equality = true;
    out.receipt_outputs_drive_normalized_v5_equations = true;
    out.normalized_recursive_consumption_complete = false;
    out.production_authority_ready = false;
    out.compatibility_statement =
        CommitV6ShaCompatibilityStatementV1(out);
    out.valid =
        !out.ordered_output_commitment.IsNull() &&
        !out.compatibility_statement.IsNull() &&
        out.semantic_cells ==
            kV5SemanticConsumerCells &&
        out.local_direct_feedback_cells ==
            kV5SemanticConsumerCells &&
        out.normalized_recursive_cells == 0 &&
        out.pending_normalized_recursive_cells ==
            kV5SemanticConsumerCells &&
        v6::CountViolations(
            cs, out.witness_columns) == 0 &&
        !out.normalized_recursive_consumption_complete &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:v5_v6_bus:v6_sha_compatibility:"
          "v5_sha_receipt_source;local_direct_304_of_304;"
          "normalized_recursive_0_of_304;"
          "alghash_substitution_rejected;authority_false"
        : "stage3:v5_v6_bus:v6_sha_compatibility:invalid";
    return out;
}

bool VerifyV6ShaCompatibilityModeV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5UnifiedShaReceiptV1& receipt,
    const V6ShaCompatibilityModeV1& compatibility,
    std::string* why)
{
    if (!compatibility.valid ||
        compatibility.version != 1 ||
        compatibility.challenge_source_domain !=
            V6ChallengeSourceDomainV1::
                UnifiedV5ShaReceipt) {
        return Fail(
            why,
            "v6_sha_compatibility:"
            "alghash_domain_substitution_or_shape");
    }
    const V6ShaCompatibilityModeV1 expected =
        BuildV6ShaCompatibilityModeV1(
            composition, child, child_fs_seed,
            plan, receipt,
            V6ChallengeSourceDomainV1::
                UnifiedV5ShaReceipt);
    if (!expected.valid ||
        compatibility.compatibility_statement !=
            CommitV6ShaCompatibilityStatementV1(
                compatibility) ||
        !SameV6ShaCompatibilitySummaryV1(
            compatibility, expected)) {
        return Fail(
            why,
            "v6_sha_compatibility:"
            "schedule_statement_seed_or_value");
    }
    if (compatibility.local_direct_feedback_cells !=
            kV5SemanticConsumerCells ||
        compatibility.normalized_recursive_cells != 0 ||
        compatibility.pending_normalized_recursive_cells !=
            kV5SemanticConsumerCells ||
        compatibility.normalized_recursive_consumption_complete ||
        compatibility.production_authority_ready ||
        v6::CountViolations(
            compatibility.constraint_system,
            compatibility.witness_columns) != 0) {
        return Fail(
            why,
            "v6_sha_compatibility:ownership_or_air");
    }
    if (why != nullptr) {
        *why =
            "stage3:v5_v6_bus:v6_sha_compatibility:"
            "local_direct_304;normalized_recursive_0;"
            "exact_schedule_statement_seed;"
            "alghash_substitution_rejected;"
            "authority_false";
    }
    return true;
}

V5UnifiedShaRecursivePlanV1
BuildV5UnifiedShaRecursivePlanV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5UnifiedShaReceiptV1& receipt,
    const V5AirLambdaSplitRapProofV1& airq_split_rap)
{
    V5UnifiedShaRecursivePlanV1 out;
    std::string why;
    if (!VerifyV5UnifiedShaReceiptV1(
            composition, child, child_fs_seed,
            plan, receipt, &why) ||
        !VerifyV5AirLambdaSplitRapV1(
            composition, child_fs_seed,
            airq_split_rap, &why) ||
        airq_split_rap.semantic_boundary_commitment !=
            receipt.semantic_boundary_commitment) {
        out.note =
            "stage3:v5_v6_bus:unified_recursive_plan:"
            "local_proof:" + why;
        return out;
    }
    const auto attachments =
        DeserializeV5TranscriptProofAttachmentBundleV1(
            plan, receipt.attachment_bundle_bytes);
    if (!attachments.has_value() ||
        attachments->proof_attached_leaves !=
            kV5TranscriptVerticalLeafCountV1 ||
        !attachments->all_57_leaf_proofs_attached) {
        out.note =
            "stage3:v5_v6_bus:unified_recursive_plan:"
            "complete_leaf_attachments";
        return out;
    }
    std::vector<unsigned char> airq_bytes;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            airq_split_rap.quotient,
            airq_bytes) == 0 ||
        airq_bytes.empty() ||
        airq_bytes.size() >
            aq::kAirQuotientSplitRapRowsMaxProofBytesHard) {
        out.note =
            "stage3:v5_v6_bus:unified_recursive_plan:"
            "airq_codec";
        return out;
    }

    out.receipt_commitment =
        receipt.receipt_commitment;
    out.airq_split_rap_statement =
        airq_split_rap.proof_statement;
    out.transcript_leaf_children =
        kV5TranscriptVerticalLeafCountV1;
    out.airq_children = 1;
    out.total_leaf_children =
        out.transcript_leaf_children +
        out.airq_children;
    std::vector<uint256> previous_commitments;
    previous_commitments.reserve(
        out.total_leaf_children);
    for (uint32_t leaf = 0;
         leaf < out.transcript_leaf_children; ++leaf) {
        if (leaf >= attachments->leaves.size()) {
            out.note =
                "stage3:v5_v6_bus:unified_recursive_plan:"
                "leaf_statement";
            return out;
        }
        HashWriter leaf_hash;
        leaf_hash <<
            "BTX_RC_STAGE3_V5_UNIFIED_SHA_RECURSIVE_LEAF_V1";
        leaf_hash << out.receipt_commitment;
        leaf_hash << leaf;
        leaf_hash <<
            attachments->leaves[leaf].schedule_statement;
        uint32_t proof_count = 0;
        for (const auto& proof : attachments->proofs) {
            if (proof.leaf_ordinal == leaf) ++proof_count;
        }
        if (proof_count == 0) {
            out.note =
                "stage3:v5_v6_bus:unified_recursive_plan:"
                "leaf_proof_omission";
            return out;
        }
        leaf_hash << proof_count;
        for (const auto& proof : attachments->proofs) {
            if (proof.leaf_ordinal == leaf) {
                leaf_hash << proof.proof_statement;
            }
        }
        previous_commitments.push_back(
            leaf_hash.GetHash());
    }
    previous_commitments.push_back(
        out.airq_split_rap_statement);
    uint32_t previous = out.total_leaf_children;
    uint32_t level = 0;
    while (previous > 1) {
        const uint32_t parents =
            (previous + 3) / 4;
        std::vector<uint256> next_commitments;
        next_commitments.reserve(parents);
        for (uint32_t parent = 0;
             parent < parents; ++parent) {
            V5UnifiedShaArityFourNodeV1 node;
            node.level = level;
            node.ordinal = parent;
            const uint32_t first = 4 * parent;
            node.child_count =
                std::min<uint32_t>(
                    4, previous - first);
            for (uint32_t child_index = 0;
                 child_index < 4; ++child_index) {
                if (child_index < node.child_count) {
                    node.child_active[child_index] = 1;
                    node.child_ordinal[child_index] =
                        first + child_index;
                    node.child_commitment[child_index] =
                        previous_commitments[
                            first + child_index];
                } else {
                    node.child_active[child_index] = 0;
                    node.child_ordinal[child_index] =
                        UINT32_MAX;
                    HashWriter empty_hash;
                    empty_hash <<
                        "BTX_RC_STAGE3_V5_UNIFIED_SHA_EMPTY_CHILD_V1";
                    empty_hash << out.receipt_commitment;
                    empty_hash << level;
                    empty_hash << parent;
                    empty_hash << child_index;
                    node.child_commitment[child_index] =
                        empty_hash.GetHash();
                }
            }
            HashWriter node_hash;
            node_hash <<
                "BTX_RC_STAGE3_V5_UNIFIED_SHA_ARITY4_NODE_V1";
            node_hash << out.receipt_commitment;
            node_hash << level;
            node_hash << parent;
            node_hash << node.child_count;
            for (uint32_t child_index = 0;
                 child_index < 4; ++child_index) {
                node_hash <<
                    node.child_active[child_index];
                node_hash <<
                    node.child_commitment[child_index];
            }
            node.node_commitment =
                node_hash.GetHash();
            if (node.node_commitment.IsNull()) {
                out.note =
                    "stage3:v5_v6_bus:unified_recursive_plan:"
                    "node_commitment";
                return out;
            }
            next_commitments.push_back(
                node.node_commitment);
            out.nodes.push_back(node);
        }
        ++level;
        previous = parents;
        previous_commitments =
            std::move(next_commitments);
    }
    if (previous_commitments.size() != 1 ||
        previous_commitments[0].IsNull()) {
        out.note =
            "stage3:v5_v6_bus:unified_recursive_plan:"
            "root_commitment";
        return out;
    }
    out.recursive_schedule_commitment =
        previous_commitments[0];
    out.aggregation_levels = level;
    out.aggregation_parent_nodes =
        static_cast<uint32_t>(out.nodes.size());
    out.locally_proof_owned_cells =
        kV5SemanticConsumerCells;
    out.normalized_recursive_cells = 0;
    out.pending_normalized_recursive_cells =
        kV5SemanticConsumerCells;
    out.exact_arity_four_schedule =
        out.total_leaf_children == 58 &&
        out.aggregation_levels == 3 &&
        out.aggregation_parent_nodes == 20 &&
        !out.nodes.empty() &&
        out.nodes.back().child_count == 4;
    out.canonical_empty_children_domain_bound =
        std::all_of(
            out.nodes.begin(), out.nodes.end(),
            [](const auto& node) {
                for (uint32_t slot = 0;
                     slot < 4; ++slot) {
                    if (slot < node.child_count) {
                        if (!node.child_active[slot] ||
                            node.child_ordinal[slot] ==
                                UINT32_MAX ||
                            node.child_commitment[slot]
                                .IsNull()) {
                            return false;
                        }
                    } else if (
                        node.child_active[slot] ||
                        node.child_ordinal[slot] !=
                            UINT32_MAX ||
                        node.child_commitment[slot]
                            .IsNull()) {
                        return false;
                    }
                }
                return !node.node_commitment.IsNull();
            });
    out.all_child_codecs_durable =
        receipt.nested_codecs_canonical &&
        !receipt.attachment_bundle_bytes.empty() &&
        !receipt.airq_proof_bytes.empty() &&
        !airq_bytes.empty();
    out.airq_split_rap_locally_verified = true;
    out.parent_verifier_air_executable = false;
    out.production_authority_ready = false;
    out.residuals = {
        "normalized_parent_decode_and_field_map_for_all_58_children",
        "in_parent_split_rap_multirow_v2_fiat_shamir_and_opening_verifier",
        "six_air_lambda_and_298_leaf_output_equality_links_to_v5_equations",
    };
    out.valid =
        !out.receipt_commitment.IsNull() &&
        !out.airq_split_rap_statement.IsNull() &&
        !out.recursive_schedule_commitment.IsNull() &&
        out.exact_arity_four_schedule &&
        out.canonical_empty_children_domain_bound &&
        out.all_child_codecs_durable &&
        out.airq_split_rap_locally_verified &&
        out.locally_proof_owned_cells == 304 &&
        out.normalized_recursive_cells == 0 &&
        out.pending_normalized_recursive_cells == 304 &&
        !out.parent_verifier_air_executable &&
        !out.production_authority_ready &&
        out.residuals.size() == 3;
    out.note = out.valid
        ? "stage3:v5_v6_bus:unified_recursive_plan:"
          "58_children;arity4_levels_3;parents_20;"
          "airq_split_rap_local;"
          "normalized_recursive_0_of_304;"
          "parent_verifier_residual_explicit"
        : "stage3:v5_v6_bus:unified_recursive_plan:invalid";
    return out;
}

v6::Program BuildProgramFromV5LanePublicInputs(
    const std::vector<ar::ChildPublicInputs>& lane_pis,
    const std::array<uint8_t, 32>& public_statement_sha256d,
    TranscriptScope scope,
    std::string* why)
{
    if (lane_pis.size() != 2 ||
        !SameLaneShape(lane_pis[0], lane_pis[1])) {
        Fail(why, "ordered_lane_shape");
        return {};
    }
    if (scope == TranscriptScope::MasterBinding) {
        v6::Program program = v6::BuildMasterBindingProgram(
            MasterInput(lane_pis, public_statement_sha256d));
        if (!program.valid) Fail(why, program.note);
        return program;
    }
    if (scope != TranscriptScope::FullTranscript) {
        Fail(why, "unknown_scope");
        return {};
    }
    v6::FullTranscriptInput input;
    if (!BuildFullInput(
            lane_pis, public_statement_sha256d, input, why)) {
        return {};
    }
    v6::Program program = v6::BuildFullTranscriptProgram(input);
    if (!program.valid) Fail(why, program.note);
    return program;
}

SameTraceComposition BuildSameTraceComposition(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const std::array<uint8_t, 32>& public_statement_sha256d,
    TranscriptScope scope,
    const ar::VerifierAirFamilies& families)
{
    SameTraceComposition out;
    out.scope = scope;
    const auto begin = std::chrono::steady_clock::now();
    ar::DualV5AggregateWitness v5 =
        ar::BuildDualV5AggregateWitness(
            child_cs, {child}, child_fs_seed, families);
    if (!v5.ok) {
        out.note = "stage3:v5_v6_bus:v5:" + v5.note;
        return out;
    }
    out.native_v5_verified = true;
    out.finite_v5_transcript_replayed_on_host = true;
    out.lane_pis = v5.normalized.pis;
    std::string why;
    out.program = BuildProgramFromV5LanePublicInputs(
        out.lane_pis, public_statement_sha256d, scope, &why);
    if (!out.program.valid) {
        out.note = why;
        return out;
    }

    const uint32_t aligned_rows =
        std::max(v5.normalized.cs.n_rows, out.program.trace_rows);
    out.program = v6::PadProgramToTraceRows(
        out.program, aligned_rows);
    if (!out.program.valid) {
        out.note = out.program.note;
        return out;
    }
    out.original_v5_rows = v5.normalized.cs.n_rows;
    out.original_v5_columns = v5.normalized.cs.n_columns;
    out.aligned_rows = aligned_rows;
    out.proof_derived_payload_cells =
        ProofDerivedCells(out.program);
    const auto outputs =
        DescribeOutputs(out.lane_pis, scope, families);

    if (!LiftAndPublish(
            v5.normalized.cs, &v5.normalized.columns,
            out.program, outputs, out.normalized_v5,
            &out.normalized_v5_columns, out.export_base,
            out.selector_base, &out.payload_mappings, &why)) {
        out.note = why;
        return out;
    }
    out.row_root_payload_cells_directly_aliased =
        static_cast<uint32_t>(std::count_if(
            outputs.begin(), outputs.end(),
            [](const auto& output) {
                return output.kind ==
                    ar::VerifierAirTranscriptOutputKind::RowRoot;
            }));
    out.transcript_payload_cells_directly_aliased =
        static_cast<uint32_t>(outputs.size());
    out.selector_columns =
        static_cast<uint32_t>(outputs.size());

    v6::DirectAliasComposition alias;
    if (!v6::BuildDirectAliasConstraintSystem(
            out.program, out.normalized_v5, out.export_base,
            out.combined, &alias, &why)) {
        out.note = why;
        return out;
    }
    v6::Witness combined_witness = v6::BuildDirectAliasWitness(
        out.program, out.normalized_v5,
        out.normalized_v5_columns, out.export_base);
    if (!combined_witness.valid ||
        !combined_witness.external_sources_owned_by_child_verifier) {
        out.note = combined_witness.note;
        return out;
    }
    out.combined_columns = std::move(combined_witness.columns);
    out.transcript_layout = alias.transcript;
    out.combined_columns_count = out.combined.n_columns;
    out.combined_constraints =
        static_cast<uint32_t>(out.combined.constraints.size());
    out.witness_build_micros = MicrosSince(begin);

    const auto scan = std::chrono::steady_clock::now();
    const uint32_t violations =
        v6::CountViolations(out.combined, out.combined_columns);
    out.constraint_scan_micros = MicrosSince(scan);
    if (violations != 0) {
        out.note =
            "stage3:v5_v6_bus:combined_violations=" +
            std::to_string(violations);
        return out;
    }

    const bool every_payload_mapped =
        out.payload_mappings.size() ==
            out.proof_derived_payload_cells &&
        std::all_of(
            out.payload_mappings.begin(),
            out.payload_mappings.end(),
            [](const PayloadMapping& mapping) {
                return mapping.source_is_v5_witness_column &&
                       mapping.equation_consumer_present &&
                       mapping.same_trace_constrained;
            });
    out.export_bus_constrained_in_air = every_payload_mapped;
    out.literal_v6_alias =
        alias.direct_alias &&
        alias.transcript.external_source_base == out.export_base;
    out.v6_challenges_drive_v5_equations = false;
    out.sha_public_boundary_in_air = false;
    out.production_authority_ready = false;
    out.valid = out.literal_v6_alias &&
                every_payload_mapped;
    out.note = out.valid
        ? "stage3:v5_v6_bus:all_proof_payloads_same_trace_mapped;"
          "v6_to_v5_challenge_feedback_and_sha_boundary_open"
        : "stage3:v5_v6_bus:payload_mapping_incomplete";
    return out;
}

Shape MeasureSameTraceComposition(
    const std::vector<ar::ChildPublicInputs>& lane_pis,
    const std::array<uint8_t, 32>& public_statement_sha256d,
    TranscriptScope scope,
    const ar::VerifierAirFamilies& families)
{
    Shape out;
    std::string why;
    v6::Program program = BuildProgramFromV5LanePublicInputs(
        lane_pis, public_statement_sha256d, scope, &why);
    if (!program.valid) {
        out.note = why;
        return out;
    }
    const aq::AirConstraintSystem<Fp3> v5 =
        ar::BuildVerifierAIRPinned(2, lane_pis, families);
    out.v5_rows = v5.n_rows;
    out.v6_rows = program.trace_rows;
    out.aligned_rows = std::max(out.v5_rows, out.v6_rows);
    program = v6::PadProgramToTraceRows(
        program, out.aligned_rows);
    if (!program.valid) {
        out.note = program.note;
        return out;
    }
    out.v5_columns = v5.n_columns;
    out.v5_constraints =
        static_cast<uint32_t>(v5.constraints.size());
    out.proof_derived_payload_cells =
        ProofDerivedCells(program);

    aq::AirConstraintSystem<Fp3> lifted;
    uint32_t export_base = 0;
    uint32_t selector_base = 0;
    const auto outputs =
        DescribeOutputs(lane_pis, scope, families);
    if (!LiftAndPublish(
            v5, nullptr, program, outputs,
            lifted, nullptr, export_base, selector_base,
            nullptr, &why)) {
        out.note = why;
        return out;
    }
    out.row_root_payload_cells_directly_aliased =
        static_cast<uint32_t>(std::count_if(
            outputs.begin(), outputs.end(),
            [](const auto& output) {
                return output.kind ==
                    ar::VerifierAirTranscriptOutputKind::RowRoot;
            }));
    out.transcript_payload_cells_directly_aliased =
        static_cast<uint32_t>(outputs.size());
    out.selector_columns =
        static_cast<uint32_t>(outputs.size());
    out.export_and_selector_columns =
        v6::kRate + out.selector_columns;
    aq::AirConstraintSystem<Fp3> combined;
    v6::DirectAliasComposition alias;
    if (!v6::BuildDirectAliasConstraintSystem(
            program, lifted, export_base,
            combined, &alias, &why)) {
        out.note = why;
        return out;
    }
    out.combined_columns = combined.n_columns;
    out.combined_constraints =
        static_cast<uint32_t>(combined.constraints.size());
    out.combined_cells =
        static_cast<uint64_t>(combined.n_columns) *
        combined.n_rows;
    out.valid = alias.valid;
    out.note = out.valid
        ? "stage3:v5_v6_bus:exact_shape"
        : alias.note;
    return out;
}

} // namespace matmul::v4::rc::stage3_v5_v6_bus
