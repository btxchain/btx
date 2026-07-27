// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_recursive_consumption.h>

#include <hash.h>

#include <algorithm>
#include <chrono>
#include <limits>

namespace matmul::v4::rc::recursive_consumption {
namespace {

namespace gf = gkr_field;
namespace ah = alg_hash;

constexpr char V6_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_RECURSIVE_CONSUMPTION_V6_SEED_V1";
constexpr char V6_PROGRAM_DOMAIN[] =
    "BTX_RC_STAGE3_RECURSIVE_CONSUMPTION_V6_PROGRAM_V1";
constexpr char V6_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_RECURSIVE_CONSUMPTION_V6_PROOF_V1";
constexpr char PARENT_DOMAIN[] =
    "BTX_RC_STAGE3_RECURSIVE_CONSUMPTION_PARENT_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:recursive_consumption:" + detail;
    }
    return false;
}

uint64_t MicrosSince(const std::chrono::steady_clock::time_point& start)
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start)
            .count());
}

ar::VerifierAirFamilies BindingOnlyFamilies()
{
    ar::VerifierAirFamilies out;
    out.row_merkle = false;
    out.fold = false;
    out.deep = false;
    out.per_point = false;
    out.next_row = false;
    out.trace_binding = false;
    return out;
}

ar::VerifierAirFamilies FamiliesForWork(
    const scheduler::ParentWorkItem&)
{
    // Even one logical dual-V5 child produces an ~8k-column parent whose
    // mandatory Q128 full-row openings exceed the 16 MiB per-lane codec cap.
    // The 2-child column screen is therefore not an executable proof profile.
    return BindingOnlyFamilies();
}

bool AllVcsFamiliesEnabled(const ar::VerifierAirFamilies& families)
{
    return families.row_merkle && families.fold &&
           families.deep && families.per_point &&
           families.next_row && families.trace_binding;
}

bool ValidateSupportedSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const scheduler::ProductionAggregationSchedule& schedule,
    std::string* why)
{
    if (schedule.version ==
            scheduler::kBinaryV1AggregationScheduleVersion &&
        schedule.arity ==
            scheduler::kBinaryV1AggregationScheduleArity) {
        return scheduler::ValidateBinaryV1AggregationSchedule(
            manifest, schedule, why);
    }
    return scheduler::ValidateProductionAggregationSchedule(
        manifest, schedule, why);
}

void AppendU64(std::vector<v6::Word>& words,
               uint64_t value,
               v6::WordOrigin origin)
{
    words.push_back({gf::FromU64(value & UINT64_C(0xffffffff)), origin});
    words.push_back({gf::FromU64(value >> 32), origin});
}

void AppendUint256(std::vector<v6::Word>& words,
                   const uint256& value,
                   v6::WordOrigin origin)
{
    for (uint32_t limb = 0; limb < 8; ++limb) {
        const size_t offset = static_cast<size_t>(limb) * 4;
        const uint32_t word =
            static_cast<uint32_t>(value.begin()[offset]) |
            (static_cast<uint32_t>(value.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(value.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(value.begin()[offset + 3]) << 24);
        words.push_back({gf::FromU64(word), origin});
    }
}

v6::Program BuildBindingProgram(
    const scheduler::ParentWorkItem& work,
    const std::vector<ar::DualV5RecursiveChildPin>& pins)
{
    std::vector<v6::Frame> frames;
    v6::Frame statement;
    statement.kind = v6::FrameKind::MasterStatement;
    statement.lane = 0;
    statement.index = 0;
    statement.payload.push_back(
        {gf::FromU64(kRecursiveConsumptionVersion),
         v6::WordOrigin::PublicStatement});
    statement.payload.push_back(
        {gf::FromU64(static_cast<uint16_t>(work.role)),
         v6::WordOrigin::PublicStatement});
    statement.payload.push_back(
        {gf::FromU64(work.level), v6::WordOrigin::PublicStatement});
    statement.payload.push_back(
        {gf::FromU64(work.child_count), v6::WordOrigin::PublicStatement});
    AppendU64(statement.payload, work.parent_ordinal,
              v6::WordOrigin::PublicStatement);
    AppendU64(statement.payload, work.parent_index,
              v6::WordOrigin::PublicStatement);
    AppendU64(statement.payload, work.parent_site,
              v6::WordOrigin::PublicStatement);
    AppendU64(statement.payload, work.first_child_site,
              v6::WordOrigin::PublicStatement);
    AppendUint256(statement.payload, work.schedule_commitment,
                  v6::WordOrigin::PublicStatement);
    AppendUint256(statement.payload, work.seed,
                  v6::WordOrigin::PublicStatement);
    frames.push_back(std::move(statement));

    for (uint32_t child = 0; child < pins.size(); ++child) {
        const auto& pin = pins[child];
        v6::Frame frame;
        frame.kind = v6::FrameKind::AbsorbCommitment;
        frame.lane = static_cast<uint16_t>(child);
        frame.index = child;
        AppendU64(frame.payload, work.first_child_site + child,
                  v6::WordOrigin::PublicStatement);
        AppendUint256(frame.payload, pin.air_proof_commitment,
                      v6::WordOrigin::ProofDerived);
        AppendUint256(frame.payload, pin.transcript_commitment,
                      v6::WordOrigin::ProofDerived);
        AppendUint256(frame.payload, pin.master_statement_binding,
                      v6::WordOrigin::ProofDerived);
        for (const uint256& binding : pin.lane_child_binding) {
            AppendUint256(frame.payload, binding,
                          v6::WordOrigin::ProofDerived);
        }
        for (const uint256& root : pin.lane_row_root) {
            AppendUint256(frame.payload, root,
                          v6::WordOrigin::ProofDerived);
        }
        frames.push_back(std::move(frame));
    }
    return v6::BuildProgram(frames);
}

struct ExportFixture {
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
};

ExportFixture BuildExportFixture(const v6::Program& program)
{
    ExportFixture out;
    if (!program.valid || program.trace_rows == 0) return out;
    out.cs.n_rows = program.trace_rows;
    out.cs.n_columns = 2 * v6::kRate;
    out.cs.preprocessed_pin_ood = true;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(out.cs.n_rows, gf::Fp3::Zero()));

    for (uint32_t lane = 0; lane < v6::kRate; ++lane) {
        std::vector<gf::Fp3> expected(
            out.cs.n_rows, gf::Fp3::Zero());
        for (uint32_t row = 0; row < program.trace_rows; ++row) {
            if (program.rows[row].proof_mask[lane] != 0) {
                expected[row] =
                    gf::Fp3::FromFp(program.rows[row].source[lane]);
            }
        }
        out.cs.preprocessed.emplace_back(v6::kRate + lane, expected);
        out.columns[lane] = expected;
        out.columns[v6::kRate + lane] = expected;

        aq::AirConstraint<gf::Fp3> boundary;
        boundary.name =
            "stage3.recursive_consumption.v5_export_public_pin";
        boundary.kind = aq::AirKind::kEverywhere;
        boundary.alg_degree = 1;
        boundary.eval = [lane](
                            const std::vector<gf::Fp3>& cur,
                            const std::vector<gf::Fp3>&) {
            return gf::Sub(cur[lane], cur[v6::kRate + lane]);
        };
        out.cs.constraints.push_back(std::move(boundary));
    }
    return out;
}

void HashFp3(HashWriter& hash, const gf::Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

void HashDigest(HashWriter& hash, const ah::Digest& digest)
{
    for (const gf::Fp value : digest) hash << gf::Canonical(value);
}

uint256 CommitProgram(const v6::Program& program)
{
    if (!program.valid) return {};
    HashWriter hash;
    hash << V6_PROGRAM_DOMAIN;
    hash << program.active_rows;
    hash << program.trace_rows;
    hash << program.query_domain_bits;
    hash << static_cast<uint32_t>(program.frames.size());
    for (const auto& frame : program.frames) {
        hash << static_cast<uint16_t>(frame.kind);
        hash << frame.lane;
        hash << frame.index;
        hash << static_cast<uint32_t>(frame.payload.size());
        for (const auto& word : frame.payload) {
            hash << gf::Canonical(word.value);
            hash << static_cast<uint8_t>(word.origin);
        }
    }
    return hash.GetHash();
}

uint256 CommitV6Proof(const V6BindingProof& proof)
{
    std::vector<unsigned char> batch;
    if (SerializeFri3AlgBatchProof(proof.batch, batch) != batch.size() ||
        batch.empty()) {
        return {};
    }
    HashWriter hash;
    hash << V6_PROOF_DOMAIN;
    hash << static_cast<uint32_t>(batch.size());
    for (const unsigned char byte : batch) hash << byte;
    hash << proof.trace_commit;
    hash << static_cast<uint32_t>(proof.next_openings.size());
    for (const auto& paths : proof.next_openings) {
        hash << static_cast<uint32_t>(paths.size());
        for (const auto& path : paths) {
            hash << path.index;
            hash << static_cast<uint32_t>(path.values.size());
            for (const gf::Fp3& value : path.values) HashFp3(hash, value);
            hash << static_cast<uint32_t>(path.siblings.size());
            for (const ah::Digest& sibling : path.siblings) {
                HashDigest(hash, sibling);
            }
        }
    }
    return hash.GetHash();
}

uint256 DeriveV6Seed(
    const scheduler::ParentWorkItem& work,
    const uint256& normalized_parent_commitment,
    const uint256& child_statement_commitment,
    const uint256& program_commitment)
{
    if (work.seed.IsNull() || normalized_parent_commitment.IsNull() ||
        child_statement_commitment.IsNull() ||
        program_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << V6_SEED_DOMAIN;
    hash << work.seed;
    hash << work.parent_ordinal;
    hash << static_cast<uint16_t>(work.role);
    hash << work.level;
    hash << work.parent_site;
    hash << work.first_child_site;
    hash << work.child_count;
    hash << normalized_parent_commitment;
    hash << child_statement_commitment;
    hash << program_commitment;
    return hash.GetHash();
}

uint256 CommitParentOutput(
    const scheduler::ParentWorkItem& work,
    const uint256& normalized_parent_commitment,
    const uint256& child_statement_commitment,
    const uint256& program_commitment,
    const uint256& v6_proof_commitment)
{
    if (work.seed.IsNull() || normalized_parent_commitment.IsNull() ||
        child_statement_commitment.IsNull() ||
        program_commitment.IsNull() || v6_proof_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PARENT_DOMAIN;
    hash << kRecursiveConsumptionVersion;
    hash << work.seed;
    hash << work.schedule_commitment;
    hash << work.parent_ordinal;
    hash << static_cast<uint16_t>(work.role);
    hash << work.level;
    hash << work.parent_index;
    hash << work.parent_site;
    hash << work.first_child_site;
    hash << work.child_count;
    hash << normalized_parent_commitment;
    hash << child_statement_commitment;
    hash << program_commitment;
    hash << v6_proof_commitment;
    return hash.GetHash();
}

bool RebuildCombinedV6(
    const v6::Program& program,
    aq::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>* columns,
    std::string* why)
{
    const ExportFixture exports = BuildExportFixture(program);
    if (exports.cs.n_rows == 0) return Fail(why, "empty_v6_export");
    v6::DirectAliasComposition composition;
    if (!v6::BuildDirectAliasConstraintSystem(
            program, exports.cs, 0, cs, &composition, why)) {
        return false;
    }
    if (!composition.valid || !composition.same_trace ||
        !composition.direct_alias) {
        return Fail(why, "v6_direct_alias_not_closed");
    }
    if (columns != nullptr) {
        v6::Witness witness = v6::BuildDirectAliasWitness(
            program, exports.cs, exports.columns, 0);
        if (!witness.valid ||
            !witness.external_sources_owned_by_child_verifier ||
            v6::CountViolations(cs, witness.columns) != 0) {
            return Fail(why, "v6_direct_alias_witness");
        }
        *columns = std::move(witness.columns);
    }
    return true;
}

} // namespace

FullWideVcsPreflight AssessFullWideVcsPreflight(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::vector<ar::DualAlgAirProof>& source_children,
    const uint256& child_fs_seed)
{
    FullWideVcsPreflight out;
    out.logical_children =
        static_cast<uint32_t>(source_children.size());
    if (source_children.empty() ||
        source_children.size() >
            kFullWideLogicalChildCap) {
        out.note =
            "stage3:recursive_consumption:wide_preflight_child_count";
        return out;
    }
    const ar::DualV5AggregateWitness witness =
        ar::BuildDualV5AggregateWitness(
            child_cs, source_children, child_fs_seed, {});
    if (!witness.ok ||
        witness.normalized_violations != 0) {
        out.note =
            "stage3:recursive_consumption:wide_preflight:" +
            witness.note;
        return out;
    }
    out.normalized_lanes = static_cast<uint32_t>(
        witness.normalized.pis.size());
    out.parent_rows = witness.normalized.cs.n_rows;
    out.parent_columns = witness.normalized.cs.n_columns;
    out.parent_constraints = static_cast<uint32_t>(
        witness.normalized.cs.constraints.size());

    constexpr uint64_t FP3_BYTES = 3 * sizeof(uint64_t);
    const uint64_t opened_columns =
        uint64_t{out.parent_columns} + 1;
    if (opened_columns >
        std::numeric_limits<uint64_t>::max() /
            kRCFri3AlgDualQueriesPerLane /
            FP3_BYTES) {
        out.note =
            "stage3:recursive_consumption:wide_preflight_overflow";
        return out;
    }
    out.minimum_query_value_bytes_per_lane =
        uint64_t{kRCFri3AlgDualQueriesPerLane} *
        opened_columns * FP3_BYTES;
    out.codec_bytes_per_lane = kRCFriMaxProofBytesHard;
    out.backend_columns_supported =
        out.parent_columns <= kRCFri3AlgBatchMaxColumns;
    out.proof_codec_supported =
        out.minimum_query_value_bytes_per_lane <=
        out.codec_bytes_per_lane;
    // The wide layout grows with the child width; passing the parent back as
    // a child is not a shape fixed point even if its first level fits.
    out.self_similar_shape = false;
    out.executable =
        out.backend_columns_supported &&
        out.proof_codec_supported &&
        out.self_similar_shape;
    out.valid = true;
    out.note = out.proof_codec_supported
        ? "stage3:recursive_consumption:wide_preflight_"
          "self_similarity_open"
        : "stage3:recursive_consumption:wide_preflight_"
          "codec_bound_exceeded_before_proving";
    return out;
}

RecursiveParentArtifact BuildRecursiveParentArtifact(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const scheduler::ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed,
    uint64_t parent_ordinal,
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::vector<ar::DualAlgAirProof>& source_children,
    const uint256& child_fs_seed)
{
    RecursiveParentArtifact out;
    out.child_fs_seed = child_fs_seed;
    out.source_children = source_children;
    std::string why;
    if (!ValidateSupportedSchedule(manifest, schedule, &why)) {
        out.note = why;
        return out;
    }
    const auto work = scheduler::ProductionAggregationParentWorkItem(
        schedule, unified_root_seed, parent_ordinal, &why);
    if (!work.has_value()) {
        out.note = why;
        return out;
    }
    out.claimed_work = *work;
    if (source_children.size() != work->child_count) {
        out.note = "stage3:recursive_consumption:child_count";
        return out;
    }

    const ar::VerifierAirFamilies families = FamiliesForWork(*work);
    out.full_vcs_families = AllVcsFamiliesEnabled(families);
    const auto parent_start = std::chrono::steady_clock::now();
    ar::DualV5AggregateResult parent =
        ar::ProveAggregateDualV5Checked(
            child_cs, source_children, child_fs_seed,
            work->seed, families);
    out.parent_prove_micros = MicrosSince(parent_start);
    if (!parent.ok || !parent.witness_satisfies) {
        out.note = "stage3:recursive_consumption:parent:" + parent.note;
        return out;
    }
    if (parent.all_vcs_families_enabled !=
        out.full_vcs_families) {
        out.note =
            "stage3:recursive_consumption:parent_family_profile";
        return out;
    }
    out.normalized_parent_rows = parent.measurement.n_rows;
    out.normalized_parent_columns = parent.measurement.n_columns;
    out.normalized_parent_constraints =
        parent.measurement.n_constraints;
    {
        std::vector<unsigned char> encoded;
        out.normalized_parent_batch_bytes =
            SerializeFri3AlgDualBatchProof(
                parent.proof.batch.repeated, encoded);
        if (out.normalized_parent_batch_bytes != encoded.size()) {
            out.note =
                "stage3:recursive_consumption:parent_batch_codec";
            return out;
        }
    }
    const auto parent_verify_start =
        std::chrono::steady_clock::now();
    if (!ar::VerifyAggregateDualV5Diagnostic(
            parent.proof, parent.lane_pis, parent.child_pins,
            work->seed, families, &why)) {
        out.note = "stage3:recursive_consumption:parent_verify:" + why;
        return out;
    }
    out.normalized_parent_verify_micros =
        MicrosSince(parent_verify_start);
    out.normalized_parent = parent.proof;

    const v6::Program program =
        BuildBindingProgram(*work, parent.child_pins);
    if (!program.valid) {
        out.note = "stage3:recursive_consumption:v6_program:" +
                   program.note;
        return out;
    }
    aq::AirConstraintSystem<gf::Fp3> combined;
    std::vector<std::vector<gf::Fp3>> columns;
    if (!RebuildCombinedV6(program, combined, &columns, &why)) {
        out.note = why;
        return out;
    }
    out.v6_rows = combined.n_rows;
    out.v6_columns = combined.n_columns;
    out.v6_constraints =
        static_cast<uint32_t>(combined.constraints.size());
    const uint256 normalized_parent_commitment =
        ar::ComputeDualV5AirProofCommitment(parent.proof);
    const uint256 program_commitment = CommitProgram(program);
    const uint256 v6_seed = DeriveV6Seed(
        *work, normalized_parent_commitment,
        parent.child_statement_commitment, program_commitment);
    if (v6_seed.IsNull()) {
        out.note = "stage3:recursive_consumption:null_v6_seed";
        return out;
    }

    const auto v6_start = std::chrono::steady_clock::now();
    auto proved = aq::AirQuotientProve<
        gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
        combined, columns, v6_seed, {});
    out.v6_prove_micros = MicrosSince(v6_start);
    if (!proved.ok || !proved.division_exact) {
        out.note = "stage3:recursive_consumption:v6_prove:" +
                   proved.note;
        return out;
    }
    out.v6_binding_proof = std::move(proved.proof);
    {
        std::vector<unsigned char> encoded;
        out.v6_batch_bytes = SerializeFri3AlgBatchProof(
            out.v6_binding_proof.batch, encoded);
        if (out.v6_batch_bytes != encoded.size()) {
            out.note =
                "stage3:recursive_consumption:v6_batch_codec";
            return out;
        }
    }
    const auto v6_verify_start =
        std::chrono::steady_clock::now();
    if (!aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            combined, out.v6_binding_proof, v6_seed, &why)) {
        out.note = "stage3:recursive_consumption:v6_verify:" + why;
        return out;
    }
    out.v6_verify_micros = MicrosSince(v6_verify_start);

    const uint256 v6_proof_commitment =
        CommitV6Proof(out.v6_binding_proof);
    out.receipt.work_seed = work->seed;
    out.receipt.parent_commitment = CommitParentOutput(
        *work, normalized_parent_commitment,
        parent.child_statement_commitment, program_commitment,
        v6_proof_commitment);
    out.receipt.binding =
        scheduler::CommitProductionAggregationReceipt(
            *work, out.receipt.parent_commitment);
    if (out.receipt.parent_commitment.IsNull() ||
        out.receipt.binding.IsNull()) {
        out.note = "stage3:recursive_consumption:null_receipt";
        return out;
    }

    const auto verify_start = std::chrono::steady_clock::now();
    if (!VerifyRecursiveParentArtifact(
            manifest, schedule, unified_root_seed, child_cs,
            out, &why, &out.verify_micros)) {
        out.note = "stage3:recursive_consumption:self_verify:" + why;
        return out;
    }
    if (out.verify_micros == 0) {
        out.verify_micros = MicrosSince(verify_start);
    }
    out.valid = true;
    out.note = out.full_vcs_families
        ? "stage3:recursive_consumption:full_wide_vcs_v5_v6_receipt_ok_"
          "arity4_vertical_fixedpoint_and_fs_feedback_pending"
        : "stage3:recursive_consumption:bounded_v5_v6_receipt_ok_"
          "production_full_family_and_native_export_pending";
    return out;
}

bool VerifyRecursiveParentArtifact(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const scheduler::ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed,
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const RecursiveParentArtifact& artifact,
    std::string* why,
    uint64_t* verify_micros)
{
    const auto start = std::chrono::steady_clock::now();
    auto finish = [&](bool value) {
        if (verify_micros != nullptr) *verify_micros = MicrosSince(start);
        return value;
    };
    if (artifact.version != kRecursiveConsumptionVersion) {
        return finish(Fail(why, "version"));
    }
    if (!ValidateSupportedSchedule(manifest, schedule, why)) {
        return finish(false);
    }
    const auto expected_work =
        scheduler::ProductionAggregationParentWorkItem(
            schedule, unified_root_seed,
            artifact.claimed_work.parent_ordinal, why);
    if (!expected_work.has_value()) return finish(false);
    if (artifact.claimed_work != *expected_work) {
        return finish(Fail(why, "noncanonical_work"));
    }
    if (artifact.source_children.size() !=
            expected_work->child_count ||
        artifact.source_children.empty() ||
        artifact.child_fs_seed.IsNull()) {
        return finish(Fail(why, "source_child_shape"));
    }

    const ar::VerifierAirFamilies families =
        FamiliesForWork(*expected_work);
    if (artifact.full_vcs_families !=
        AllVcsFamiliesEnabled(families)) {
        return finish(Fail(why, "family_profile"));
    }
    ar::DualV5AggregateWitness derived =
        ar::BuildDualV5AggregateWitness(
            child_cs, artifact.source_children,
            artifact.child_fs_seed, families);
    if (!derived.ok) {
        return finish(Fail(why, "source_child:" + derived.note));
    }
    std::string proof_why;
    if (!ar::VerifyAggregateDualV5Diagnostic(
            artifact.normalized_parent,
            derived.normalized.pis, derived.child_pins,
            expected_work->seed, families, &proof_why)) {
        return finish(Fail(why, "normalized_parent:" + proof_why));
    }

    const v6::Program program =
        BuildBindingProgram(*expected_work, derived.child_pins);
    if (!program.valid) {
        return finish(Fail(why, "v6_program:" + program.note));
    }
    aq::AirConstraintSystem<gf::Fp3> combined;
    if (!RebuildCombinedV6(
            program, combined, nullptr, &proof_why)) {
        return finish(Fail(why, "v6_combined:" + proof_why));
    }
    const uint256 normalized_parent_commitment =
        ar::ComputeDualV5AirProofCommitment(
            artifact.normalized_parent);
    const uint256 program_commitment = CommitProgram(program);
    const uint256 v6_seed = DeriveV6Seed(
        *expected_work, normalized_parent_commitment,
        derived.child_statement_commitment, program_commitment);
    if (!aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            combined, artifact.v6_binding_proof,
            v6_seed, &proof_why)) {
        return finish(Fail(why, "v6_proof:" + proof_why));
    }

    const uint256 parent_commitment = CommitParentOutput(
        *expected_work, normalized_parent_commitment,
        derived.child_statement_commitment, program_commitment,
        CommitV6Proof(artifact.v6_binding_proof));
    const uint256 receipt_binding =
        scheduler::CommitProductionAggregationReceipt(
            *expected_work, parent_commitment);
    if (parent_commitment.IsNull() || receipt_binding.IsNull() ||
        artifact.receipt.work_seed != expected_work->seed ||
        artifact.receipt.parent_commitment != parent_commitment ||
        artifact.receipt.binding != receipt_binding) {
        return finish(Fail(why, "receipt_binding"));
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_consumption:ok_bounded_"
            "production_authority_false";
    }
    return finish(true);
}

} // namespace matmul::v4::rc::recursive_consumption
