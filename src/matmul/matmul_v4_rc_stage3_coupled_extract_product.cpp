// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_extract_product.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_gkr_wiring.h>
#include <matmul/matmul_v4_rc_extract.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ga = gkr_air;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
namespace lt = matmul::v4::lt;
using gf::Fp3;

constexpr uint32_t MX_BLOCK_LANE = 0x4D58424CU;
constexpr uint32_t GOLDEN = 0x9E3779B9U;
constexpr char SCALE_TAG[] = "BTX_MATEXPAND_MXSCALE_V44LT";
constexpr char TILE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_EXTRACT_TILE_V1";
constexpr char PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_EXTRACT_PRODUCT_V1";
constexpr char SAMPLER_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_EXTRACT_SAMPLER_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:coupled_extract_product:" + detail;
    }
    return false;
}

bool IsCoupledStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Coupled ||
           statement.statement == RCStage3StatementKind::Composed;
}

uint64_t StateCells(const RCStage3CoupledShape& shape)
{
    return uint64_t{shape.lobes} * shape.rows_per_lobe *
           shape.lobe_width;
}

uint256 ExtractPrf(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    uint32_t barrier)
{
    const auto& tags =
        RCCoupDomainTagsForVersion(shape.transcript_version);
    std::vector<uint8_t> bytes;
    const size_t tag_len = std::strlen(tags.extract);
    bytes.insert(
        bytes.end(),
        reinterpret_cast<const uint8_t*>(tags.extract),
        reinterpret_cast<const uint8_t*>(tags.extract) + tag_len);
    bytes.insert(
        bytes.end(), statement.public_inputs.sigma.begin(),
        statement.public_inputs.sigma.end());
    for (uint32_t value : {barrier, uint32_t{0}}) {
        for (uint32_t i = 0; i < 4; ++i) {
            bytes.push_back(
                static_cast<uint8_t>(value >> (8 * i)));
        }
    }
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(digest);
    return lt::DeriveMatExpandPrfKey(
        uint256{Span<const unsigned char>{
            digest, sizeof(digest)}});
}

std::vector<uint8_t> ScalePreimage(
    const uint256& prf, uint32_t row, uint32_t block)
{
    std::vector<uint8_t> out(
        SCALE_TAG, SCALE_TAG + sizeof(SCALE_TAG) - 1);
    out.insert(out.end(), prf.begin(), prf.end());
    for (uint32_t value : {row, block}) {
        for (uint32_t i = 0; i < 4; ++i) {
            out.push_back(
                static_cast<uint8_t>(value >> (8 * i)));
        }
    }
    return out;
}

uint256 SamplerSeed(
    const uint256& statement_commitment,
    const uint256& shape_commitment,
    uint64_t instance)
{
    HashWriter hash;
    hash << SAMPLER_SEED_DOMAIN;
    hash << statement_commitment;
    hash << shape_commitment;
    hash << instance;
    return hash.GetHash();
}

bool DeriveCoupledSamplerChallenges(
    const uint256& fs_seed,
    uint64_t instance,
    uint32_t n_rows,
    uint32_t n_coeffs,
    const std::vector<uint256>& base_roots,
    Fp3& gamma,
    Fp3& alpha)
{
    if (fs_seed.IsNull() ||
        base_roots.size() != aq::kRcSamplerBaseCols) {
        return false;
    }
    HashWriter epoch;
    epoch << std::string{
        "BTX_RC_STAGE3_COUPLED_EXTRACT_SAMPLER_EPOCH1_V1"};
    epoch << fs_seed;
    epoch << instance;
    epoch << n_rows;
    epoch << n_coeffs;
    for (const auto& root : base_roots) {
        if (root.IsNull()) return false;
        epoch << root;
    }
    const uint256 epoch_seed = epoch.GetHash();
    gamma = WiringChallengeFp3(
        epoch_seed, "coupled_extract_gamma", instance, 0);
    alpha = WiringChallengeFp3(
        epoch_seed, "coupled_extract_alpha", instance, 0);
    return !gf::IsZero(gamma) && !gf::IsZero(alpha);
}

Fp3 U(uint64_t value);

aq::RcSamplerBuild<Fp3> BuildCoupledSampler(
    const ga::TileWitness& witness,
    const ga::TableTM& tm,
    const uint256& fs_seed,
    uint64_t instance)
{
    aq::RcSamplerBuild<Fp3> out;
    const uint32_t n_rows = ga::kAirSlotBudget;
    if (witness.cands.empty() ||
        witness.cands.size() > n_rows) {
        out.note = "candidate rows exceed coupled AIR budget";
        return out;
    }
    out.n_rows = n_rows;
    std::vector<std::vector<Fp3>> columns(
        aq::kRcSamplerNumCols,
        std::vector<Fp3>(n_rows, Fp3::Zero()));
    const auto set_bits =
        [&](uint32_t base, uint32_t row,
            uint32_t value, uint32_t bits) {
            for (uint32_t bit = 0; bit < bits; ++bit) {
                columns[base + bit][row] =
                    U((value >> bit) & 1U);
            }
        };
    for (uint32_t row = 0; row < n_rows; ++row) {
        if (row < witness.cands.size()) {
            const auto& cand = witness.cands[row];
            columns[aq::kColAct][row] = Fp3::One();
            columns[aq::kColKappa][row] = U(cand.kappa);
            set_bits(aq::kColKb0, row, cand.kappa, 4);
            columns[aq::kColH][row] = U(cand.h);
            set_bits(aq::kColHb0, row, cand.h, 4);
            columns[aq::kColMixed][row] = U(cand.mixed);
            set_bits(aq::kColMb0, row, cand.mixed, 4);
            columns[aq::kColAcc][row] = U(cand.acc);
            columns[aq::kColMu][row] =
                Fp3::FromFp(gf::FromSigned(cand.mu));
            columns[aq::kColPos][row] = U(cand.pos);
            columns[aq::kColInvLive][row] =
                Fp3::FromFp(cand.inv_live);
            columns[aq::kColUMix][row] = U(cand.u_mix);
            columns[aq::kColGoldQ][row] = U(cand.gold_q);
            columns[aq::kColGoldV][row] = U(cand.gold_v);
            columns[aq::kColVLow28][row] =
                U(cand.gold_v & 0x0fffffffU);
            set_bits(
                aq::kColVb0, row,
                cand.gold_v >> 28, 4);
        } else {
            columns[aq::kColKappa][row] = Fp3::One();
            columns[aq::kColKb0][row] = Fp3::One();
            columns[aq::kColMixed][row] = Fp3::One();
            columns[aq::kColMb0][row] = Fp3::One();
            columns[aq::kColPos][row] = U(kRCMxBlockLen);
        }
        columns[aq::kColE0][row] =
            U(witness.scale_e & 1U);
        columns[aq::kColE1][row] =
            U((witness.scale_e >> 1) & 1U);
        if (row < kRCMxBlockLen) {
            columns[aq::kColMuOut][row] =
                Fp3::FromFp(
                    gf::FromSigned(witness.mantissa[row]));
            columns[aq::kColOut][row] =
                Fp3::FromFp(
                    gf::FromSigned(witness.out[row]));
        }
    }
    const auto dummy =
        aq::BuildRcSamplerConstraintSystem<Fp3>(
            n_rows, Fp3::Zero(), Fp3::Zero(),
            witness.scale_e, tm);
    const uint32_t n_coeffs = FriNextPow2(
        std::max(n_rows, dummy.QuotientLen()));
    std::vector<uint256> base_roots;
    base_roots.reserve(aq::kRcSamplerBaseCols);
    for (uint32_t column = 0;
         column < aq::kRcSamplerBaseCols; ++column) {
        base_roots.push_back(
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], n_coeffs));
    }
    if (!DeriveCoupledSamplerChallenges(
            fs_seed, instance, n_rows, n_coeffs,
            base_roots, out.gamma, out.alpha)) {
        out.note = "Fiat-Shamir challenge derivation failed";
        return out;
    }
    out.cs = aq::BuildRcSamplerConstraintSystem<Fp3>(
        n_rows, out.gamma, out.alpha,
        witness.scale_e, tm);
    const Fp3 gamma2 = gf::Mul(out.gamma, out.gamma);
    // Challenge-INDEPENDENT preprocessed table columns (tbl_a/b/c) + the
    // COMMITTED fingerprint f = kColTfp bound to them by logup.tfp.bind. `table`
    // is the canonical fingerprint f = tbl_a + γ·tbl_b + γ²·tbl_c, computed
    // in-circuit here (no γ baked into any preprocessed column).
    std::vector<Fp3> table(n_rows);
    for (uint32_t row = 0; row < n_rows; ++row) {
        const uint32_t n = (row < 16) ? row : 0;
        columns[aq::kColTblA][row] = U(n);
        columns[aq::kColTblB][row] = U(tm.acc[n]);
        columns[aq::kColTblC][row] =
            Fp3::FromFp(gf::FromSigned(tm.mu[n]));
        table[row] = gf::Add(
            columns[aq::kColTblA][row],
            gf::Add(
                gf::Mul(out.gamma, columns[aq::kColTblB][row]),
                gf::Mul(gamma2, columns[aq::kColTblC][row])));
        columns[aq::kColTfp][row] = table[row];
    }
    std::vector<Fp3> fingerprints(n_rows);
    for (uint32_t row = 0; row < n_rows; ++row) {
        fingerprints[row] = gf::Add(
            columns[aq::kColMixed][row],
            gf::Add(
                gf::Mul(
                    out.gamma, columns[aq::kColAcc][row]),
                gf::Mul(
                    gamma2, columns[aq::kColMu][row])));
        const Fp3 denominator =
            gf::Sub(out.alpha, fingerprints[row]);
        if (gf::IsZero(denominator)) {
            out.note = "alpha collides with witness";
            return out;
        }
        columns[aq::kColPhi][row] = gf::Inv(denominator);
    }
    for (uint32_t j = 0; j < 16 && j < n_rows; ++j) {
        uint64_t multiplicity = 0;
        for (const auto& fingerprint : fingerprints) {
            if (gf::Eq(fingerprint, table[j])) {
                ++multiplicity;
            }
        }
        columns[aq::kColM][j] = U(multiplicity);
        const Fp3 denominator =
            gf::Sub(out.alpha, table[j]);
        if (gf::IsZero(denominator)) {
            out.note = "alpha collides with table";
            return out;
        }
        columns[aq::kColPsi][j] =
            gf::Mul(U(multiplicity), gf::Inv(denominator));
    }
    for (uint32_t row = 1; row < n_rows; ++row) {
        columns[aq::kColS][row] = gf::Add(
            columns[aq::kColS][row - 1],
            gf::Sub(
                columns[aq::kColPhi][row - 1],
                columns[aq::kColPsi][row - 1]));
    }
    const Fp3 total = gf::Add(
        columns[aq::kColS].back(),
        gf::Sub(
            columns[aq::kColPhi].back(),
            columns[aq::kColPsi].back()));
    if (!gf::IsZero(total)) {
        out.note = "LogUp imbalance";
        return out;
    }
    out.columns = std::move(columns);
    out.ok = true;
    return out;
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2 || value > (uint64_t{1} << 31)) return 0;
    uint64_t out = 2;
    while (out < value) out <<= 1;
    return static_cast<uint32_t>(out);
}

void FillBits(
    std::vector<std::vector<Fp3>>& columns,
    uint32_t base, uint32_t row, uint32_t value)
{
    for (uint32_t bit = 0; bit < 32; ++bit) {
        columns[base + bit][row] =
            U((value >> bit) & 1U);
    }
}

bool BuildMix(
    const RCStage3CoupledExtractScheduleEntry& schedule,
    const ga::TileWitness& witness,
    const std::vector<std::vector<Fp3>>& sampler_columns,
    const uint256& statement_commitment,
    RCStage3EpisodeExtractMixPin& pin,
    aq::AirQuotientProof<Fp3>* proof,
    std::string* why)
{
    const uint32_t n_rows = sampler_columns.empty()
        ? 0
        : sampler_columns.front().size();
    if (n_rows < kRCMxBlockLen ||
        sampler_columns.size() != aq::kRcSamplerNumCols ||
        witness.cands.size() > n_rows) {
        return Fail(why, "mix_shape");
    }
    std::vector<std::vector<Fp3>> columns(
        kRCStage3EpisodeExtractMixColumns,
        std::vector<Fp3>(n_rows, Fp3::Zero()));
    for (uint32_t row = 0; row < n_rows; ++row) {
        columns[kRCStage3ExtractMixU][row] =
            sampler_columns[aq::kColUMix][row];
        columns[kRCStage3ExtractMixQ][row] =
            sampler_columns[aq::kColGoldQ][row];
        columns[kRCStage3ExtractMixV][row] =
            sampler_columns[aq::kColGoldV][row];
        columns[kRCStage3ExtractMixH][row] =
            sampler_columns[aq::kColH][row];
        if (row >= witness.cands.size()) {
            // Q is zero on a neutral sampler row, but the Mix AIR still
            // enforces GOLDEN = Q + q_difference on every row.
            FillBits(
                columns, kRCStage3ExtractMixQDifferenceBits,
                row, GOLDEN);
            continue;
        }
        const auto& cand = witness.cands[row];
        columns[kRCStage3ExtractMixBranch][row] =
            U(cand.branch);
        FillBits(
            columns, kRCStage3ExtractMixYLoBits,
            row, cand.y_lo);
        FillBits(
            columns, kRCStage3ExtractMixYHiBits,
            row, cand.y_hi);
        FillBits(
            columns, kRCStage3ExtractMixUBits,
            row, cand.u_mix);
        FillBits(
            columns, kRCStage3ExtractMixQBits,
            row, cand.gold_q);
        FillBits(
            columns, kRCStage3ExtractMixVBits,
            row, cand.gold_v);
        FillBits(
            columns, kRCStage3ExtractMixQDifferenceBits,
            row, GOLDEN - cand.gold_q);
    }
    pin = {};
    pin.statement_commitment = statement_commitment;
    pin.layer_ordinal = schedule.barrier;
    pin.layer_tile_index = schedule.tile;
    pin.logical_rows = witness.cands.size();
    pin.n_rows = n_rows;
    pin.n_coeffs = NextPowerOfTwo(3 * uint64_t{n_rows} - 3);
    pin.column_roots.resize(columns.size());
    for (uint32_t column = 0; column < columns.size(); ++column) {
        pin.column_roots[column] = {
            column,
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], pin.n_coeffs)};
    }
    pin.pin_commitment =
        ComputeRCStage3EpisodeExtractMixPinCommitment(pin);
    if (pin.pin_commitment.IsNull()) {
        return Fail(why, "mix_pin");
    }
    if (proof == nullptr) return true;
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildRCStage3ExtractMixConstraintSystemForRole(
            RCStage3RelationRole::CoupledExtract,
            pin, cs, why)) {
        return false;
    }
    const auto result = aq::AirQuotientProve<Fp3>(
        cs, columns, ComputeRCStage3EpisodeExtractMixSeed(pin));
    if (!result.ok) return Fail(why, "mix_prove:" + result.note);
    *proof = result.proof;
    return true;
}

bool ProveBoundaries(
    const ha::FixedProgram& program,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    hs::FlatBoundaryProofBundle& bundle,
    std::string* why)
{
    bundle.proofs.resize(boundaries.size());
    for (uint32_t i = 0; i < boundaries.size(); ++i) {
        ha::ProgramWitness witness;
        if (!ha::BuildProgramWitness(
                program, boundaries[i].external_values,
                witness, why) ||
            !ha::ProveFixedProgramProvenanceAir(
                program, witness,
                boundaries[i].external_values,
                boundaries[i].final_words,
                hs::ComputeBoundaryProofSeed(
                    bundle.endpoint,
                    bundle.statement_commitment,
                    bundle.manifest_commitment,
                    i, boundaries.size()),
                bundle.proofs[i], why)) {
            return false;
        }
    }
    return true;
}

void StructuralProofRoots(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs,
    aq::AirQuotientProof<Fp3>& proof)
{
    proof = {};
    proof.batch.n_coeffs = n_coeffs;
    proof.batch.columns.resize(columns.size() + 1);
    proof.batch.column_len.assign(
        columns.size() + 1, n_coeffs);
    for (uint32_t i = 0; i < columns.size(); ++i) {
        proof.batch.columns[i].root =
            aq::AirCommittedValuesRoot<Fp3>(
                columns[i], n_coeffs);
    }
    HashWriter quotient;
    quotient << std::string{
        "BTX_RC_STAGE3_COUPLED_EXTRACT_STRUCTURAL_QUOTIENT_V1"};
    for (const auto& column : proof.batch.columns) {
        quotient << column.root;
    }
    proof.batch.columns.back().root = quotient.GetHash();
}

bool BuildSemanticShard(
    RCStage3RelationEndpoint endpoint,
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    uint64_t instance,
    uint64_t total_instances,
    const aq::RcSamplerBuild<Fp3>& sampler,
    uint8_t scale_e,
    bool prove,
    RCStage3CoupledSemanticShard& shard,
    std::string* why)
{
    RCStage3CoupledAirRequest request;
    request.role = RCStage3RelationRole::CoupledExtract;
    request.shape = shape;
    request.gamma = sampler.gamma;
    request.alpha = sampler.alpha;
    request.extract_scale_e = scale_e;
    RCStage3CoupledSemanticEndpointSpec spec;
    RCStage3CoupledAirEntry entry;
    aq::AirConstraintSystem<Fp3> combined;
    RCStage3CoupledSemanticLayout layout;
    if (!ResolveRCStage3CoupledSemanticEndpointSpec(
            endpoint, request, spec, why) ||
        !ResolveRCStage3CoupledAir(request, entry, why) ||
        !entry.constraint_system_available ||
        entry.constraints.n_rows != sampler.n_rows ||
        !BuildRCStage3CoupledSemanticConstraintSystem(
            spec, entry.constraints, combined, &layout, why)) {
        return Fail(why, "semantic_cs");
    }
    std::vector<std::vector<Fp3>> columns;
    if (!BuildRCStage3CoupledSemanticWitness(
            layout, sampler.columns, columns, why)) {
        return false;
    }
    const uint32_t n_coeffs = FriNextPow2(
        std::max(combined.n_rows, combined.QuotientLen()));
    shard = {};
    shard.instance_begin = instance;
    auto& pin = shard.pin;
    pin.endpoint = endpoint;
    pin.request = request;
    pin.statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    pin.shape_commitment = CommitRCStage3CoupledShape(shape);
    pin.instance_begin = instance;
    pin.instance_span = 1;
    pin.instance_count = total_instances;
    pin.schedule_commitment =
        ComputeRCStage3CoupledSemanticShardSchedule(
            spec.schedule_commitment, instance, 1,
            total_instances);
    for (uint32_t column = 0;
         column < entry.constraints.n_columns; ++column) {
        pin.relation_column_roots.push_back(
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], n_coeffs));
    }
    for (uint32_t source : layout.source_columns) {
        pin.value_column_roots.push_back(
            pin.relation_column_roots[source]);
    }
    pin.semantic_memory_root =
        ComputeRCStage3CoupledSemanticMemoryRoot(
            endpoint, request.role, total_instances,
            pin.shape_commitment, pin.schedule_commitment,
            pin.value_column_roots);
    if (pin.semantic_memory_root.IsNull()) {
        return Fail(why, "semantic_pin");
    }
    if (prove) {
        const auto result = aq::AirQuotientProve<Fp3>(
            combined, columns,
            ComputeRCStage3CoupledSemanticProofSeed(pin));
        if (!result.ok) {
            return Fail(why, "semantic_prove:" + result.note);
        }
        shard.proof = result.proof;
    } else {
        StructuralProofRoots(columns, n_coeffs, shard.proof);
    }
    return true;
}

bool BuildHashExecutions(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExtractScheduleEntry& schedule,
    const ga::TileWitness& witness,
    bool prove,
    RCStage3CoupledExtractHashExecution& out,
    std::string* why)
{
    out = {};
    std::array<uint8_t, 32> key{};
    std::copy_n(
        schedule.extract_prf.begin(), key.size(), key.begin());
    if (!ha::BuildChaChaConsumptionManifest(
            key, schedule.tile ^ MX_BLOCK_LANE,
            schedule.tile, 0,
            uint64_t{witness.chacha_blocks} * 64,
            out.chacha_manifest, why) ||
        out.chacha_manifest.output != witness.keystream ||
        !ha::BuildShaManifest(
            ScalePreimage(
                schedule.extract_prf, 0, schedule.tile),
            ha::ShaMode::Single, out.scale_manifest, why) ||
        (out.scale_manifest.digest[0] & 3) != witness.scale_e) {
        return Fail(why, "hash_manifests");
    }
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    out.chacha_proofs.endpoint =
        RCStage3RelationEndpoint::CoupledExtractChaCha;
    out.chacha_proofs.statement_commitment = statement_commitment;
    out.chacha_proofs.manifest_commitment =
        out.chacha_manifest.commitment;
    out.scale_proofs.endpoint =
        RCStage3RelationEndpoint::CoupledExtractScale;
    out.scale_proofs.statement_commitment = statement_commitment;
    out.scale_proofs.manifest_commitment =
        out.scale_manifest.commitment;
    std::vector<ha::FixedProgramBoundaryInstance> chacha_boundaries;
    std::vector<ha::FixedProgramBoundaryInstance> scale_boundaries;
    if (!ha::BuildChaChaManifestBoundaryInstances(
            out.chacha_manifest, chacha_boundaries, why) ||
        !ha::BuildShaManifestBoundaryInstances(
            out.scale_manifest, scale_boundaries, why) ||
        !BuildRCStage3CoupledHashSemanticPin(
            RCStage3RelationEndpoint::CoupledExtractChaCha,
            shape, statement_commitment,
            out.chacha_manifest.commitment, chacha_boundaries,
            hs::BoundaryPort::ExternalThenFinal,
            out.chacha_pin, why)) {
        return false;
    }
    if (!prove) return true;
    return ProveBoundaries(
               ha::BuildCanonicalProgram(
                   ha::ProgramKind::ChaCha20Block),
               chacha_boundaries, out.chacha_proofs, why) &&
           ProveBoundaries(
               ha::BuildCanonicalProgram(
                   ha::ProgramKind::Sha256Compression),
               scale_boundaries, out.scale_proofs, why);
}

bool BuildBarrier(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    uint32_t barrier,
    const std::vector<uint8_t>& state,
    bool prove,
    RCStage3CoupledBarrierEndpointExecution& out,
    std::string* why)
{
    out = {};
    if (!ha::BuildCoupledBarrierManifest(
            shape.transcript_version, shape.barriers,
            barrier, state, out.manifest, why)) {
        return false;
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    if (!ha::BuildDirectSha256dManifestBoundaryInstances(
            out.manifest.direct, boundaries, why) ||
        !BuildRCStage3CoupledBoundaryPortPin(
            RCStage3RelationEndpoint::CoupledBarrierInput,
            hs::BoundaryPort::External, statement, shape,
            out.manifest.direct.commitment, boundaries,
            out.input, why) ||
        !BuildRCStage3CoupledBoundaryPortPin(
            RCStage3RelationEndpoint::CoupledBarrierOutput,
            hs::BoundaryPort::Final, statement, shape,
            out.manifest.direct.commitment, boundaries,
            out.output, why)) {
        return false;
    }
    out.hash_proofs.endpoint =
        RCStage3RelationEndpoint::CoupledBarrierHash;
    out.hash_proofs.statement_commitment = statement_commitment;
    out.hash_proofs.manifest_commitment =
        out.manifest.direct.commitment;
    if (!prove) return true;
    return ProveBoundaries(
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression),
        boundaries, out.hash_proofs, why);
}

uint256 EndpointRoot(
    RCStage3RelationEndpoint endpoint,
    const RCStage3CoupledExtractProduct& product)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_COUPLED_EXTRACT_ENDPOINT_V1"};
    hash << static_cast<uint16_t>(endpoint);
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    for (const auto& tile : product.tiles) {
        switch (endpoint) {
        case RCStage3RelationEndpoint::CoupledExtractInput:
            hash << tile.mix_pin.pin_commitment;
            break;
        case RCStage3RelationEndpoint::CoupledExtractChaCha:
            hash << tile.hashes.chacha_pin.semantic_memory_root;
            break;
        default:
            hash << tile.tile_commitment;
            break;
        }
    }
    if (endpoint == RCStage3RelationEndpoint::CoupledExtractSampler) {
        hash << product.sampler_cells.bundle_commitment;
    } else if (endpoint ==
               RCStage3RelationEndpoint::CoupledExtractInput) {
        hash << product.input_cells.bundle_commitment;
    } else if (endpoint ==
               RCStage3RelationEndpoint::CoupledExtractScale) {
        hash << product.scale_cells.bundle_commitment;
    } else if (endpoint ==
               RCStage3RelationEndpoint::CoupledExtractOutput) {
        hash << product.output_to_barrier.extract_outputs
                    .bundle_commitment;
        hash << product.output_to_barrier.pin.link_commitment;
    }
    return hash.GetHash();
}

bool BuildInternal(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<std::array<int64_t, kRCMxBlockLen>>& inputs,
    bool prove,
    RCStage3CoupledExtractProduct& out,
    std::string* why)
{
    out = {};
    const auto schedule =
        BuildRCStage3CoupledExtractSchedule(statement, shape, why);
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    if (schedule.empty() || schedule.size() != inputs.size() ||
        statement_commitment.IsNull() ||
        shape_commitment.IsNull()) {
        return Fail(why, "build_shape");
    }
    out.statement_commitment = statement_commitment;
    out.shape_commitment = shape_commitment;
    out.expected_tiles = schedule.size();
    for (auto* bundle : {
             &out.input_cells, &out.sampler_cells,
             &out.scale_cells,
             &out.output_to_barrier.extract_outputs}) {
        bundle->statement_commitment = statement_commitment;
        bundle->total_instances = schedule.size();
    }
    out.input_cells.endpoint =
        RCStage3RelationEndpoint::CoupledExtractInput;
    out.sampler_cells.endpoint =
        RCStage3RelationEndpoint::CoupledExtractSampler;
    out.scale_cells.endpoint =
        RCStage3RelationEndpoint::CoupledExtractScale;
    out.output_to_barrier.extract_outputs.endpoint =
        RCStage3RelationEndpoint::CoupledExtractOutput;

    const uint64_t state_cells = StateCells(shape);
    std::vector<std::vector<uint8_t>> barrier_states(
        shape.barriers,
        std::vector<uint8_t>(state_cells));
    for (uint64_t instance = 0;
         instance < schedule.size(); ++instance) {
        const ga::TilePublic pub{
            schedule[instance].extract_prf,
            0, schedule[instance].tile};
        const ga::TileWitness witness =
            ga::TraceTile(pub, inputs[instance]);
        if (!ga::ByteExactVsReference(pub, inputs[instance])) {
            return Fail(why, "byte_exact");
        }
        const ga::TableTM tm;
        const auto sampler = BuildCoupledSampler(
            witness, tm,
            SamplerSeed(
                statement_commitment, shape_commitment,
                instance),
            instance);
        if (!sampler.ok) {
            return Fail(why, "sampler:" + sampler.note);
        }
        RCStage3CoupledExtractTileProduct tile;
        tile.schedule = schedule[instance];
        tile.input = inputs[instance];
        tile.output = witness.out;
        tile.candidate_positions.reserve(witness.cands.size());
        for (const auto& cand : witness.cands) {
            tile.candidate_positions.push_back(cand.pos);
        }
        if (!BuildMix(
                tile.schedule, witness, sampler.columns,
                statement_commitment, tile.mix_pin,
                prove ? &tile.mix_proof : nullptr, why) ||
            !BuildHashExecutions(
                statement, shape, tile.schedule,
                witness, prove, tile.hashes, why)) {
            return false;
        }
        for (auto pair : {
                 std::pair{
                     RCStage3RelationEndpoint::CoupledExtractInput,
                     &out.input_cells},
                 std::pair{
                     RCStage3RelationEndpoint::CoupledExtractSampler,
                     &out.sampler_cells},
                 std::pair{
                     RCStage3RelationEndpoint::CoupledExtractScale,
                     &out.scale_cells},
                 std::pair{
                     RCStage3RelationEndpoint::CoupledExtractOutput,
                     &out.output_to_barrier.extract_outputs}}) {
            RCStage3CoupledSemanticShard shard;
            if (!BuildSemanticShard(
                    pair.first, statement, shape, instance,
                    schedule.size(), sampler, witness.scale_e,
                    prove, shard, why)) {
                return false;
            }
            pair.second->shards.push_back(std::move(shard));
        }
        const uint64_t offset =
            uint64_t{tile.schedule.tile} * kRCMxBlockLen;
        for (uint32_t i = 0; i < kRCMxBlockLen; ++i) {
            barrier_states[tile.schedule.barrier][offset + i] =
                static_cast<uint8_t>(tile.output[i]);
        }
        tile.tile_commitment =
            ComputeRCStage3CoupledExtractTileCommitment(tile);
        if (tile.tile_commitment.IsNull()) {
            return Fail(why, "tile_commitment");
        }
        out.tiles.push_back(std::move(tile));
    }
    for (auto* bundle : {
             &out.input_cells, &out.sampler_cells,
             &out.scale_cells,
             &out.output_to_barrier.extract_outputs}) {
        bundle->bundle_commitment =
            ComputeRCStage3CoupledSemanticFlatBundleCommitment(*bundle);
        if (bundle->bundle_commitment.IsNull()) {
            return Fail(why, "bundle_commitment");
        }
    }
    out.output_to_barrier.barriers.resize(shape.barriers);
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        if (!BuildBarrier(
                statement, shape, barrier,
                barrier_states[barrier], prove,
                out.output_to_barrier.barriers[barrier], why)) {
            return false;
        }
    }
    if (!BuildRCStage3ExtractBarrierLinkPin(
            statement, shape,
            out.output_to_barrier.extract_outputs,
            out.output_to_barrier.barriers,
            out.output_to_barrier.pin, why)) {
        return false;
    }
    out.input_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledExtractInput, out);
    out.sampler_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledExtractSampler, out);
    out.chacha_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledExtractChaCha, out);
    out.scale_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledExtractScale, out);
    out.output_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledExtractOutput, out);
    out.product_commitment =
        ComputeRCStage3CoupledExtractProductCommitment(out);
    return !out.product_commitment.IsNull() ||
           Fail(why, "product_commitment");
}

} // namespace

std::vector<RCStage3CoupledExtractScheduleEntry>
BuildRCStage3CoupledExtractSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    std::string* why)
{
    std::vector<RCStage3CoupledExtractScheduleEntry> out;
    const auto counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledExtract, shape, why);
    const uint64_t state_cells = StateCells(shape);
    if (!IsCoupledStatement(statement) ||
        statement.public_inputs.sigma.IsNull() ||
        statement.public_inputs.transcript_version !=
            shape.transcript_version ||
        !counts.has_value() ||
        state_cells == 0 ||
        state_cells % kRCMxBlockLen != 0 ||
        counts->primary >
            kRCStage3CoupledExtractMaxTiles) {
        return {};
    }
    const uint32_t tiles_per_barrier =
        state_cells / kRCMxBlockLen;
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        const uint256 prf = ExtractPrf(
            statement, shape, barrier);
        if (prf.IsNull()) return {};
        for (uint32_t tile = 0;
             tile < tiles_per_barrier; ++tile) {
            out.push_back({
                out.size(), barrier, tile, prf});
        }
    }
    if (out.size() != counts->primary) {
        Fail(why, "schedule_count");
        return {};
    }
    return out;
}

uint256 ComputeRCStage3CoupledExtractTileCommitment(
    const RCStage3CoupledExtractTileProduct& tile)
{
    if (tile.schedule.extract_prf.IsNull() ||
        tile.mix_pin.pin_commitment.IsNull() ||
        tile.hashes.chacha_manifest.commitment.IsNull() ||
        tile.hashes.chacha_pin.semantic_memory_root.IsNull() ||
        tile.hashes.scale_manifest.commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << TILE_DOMAIN;
    hash << tile.schedule.instance;
    hash << tile.schedule.barrier;
    hash << tile.schedule.tile;
    hash << tile.schedule.extract_prf;
    for (int64_t value : tile.input) hash << value;
    for (int8_t value : tile.output) {
        hash << static_cast<uint8_t>(value);
    }
    hash << tile.candidate_positions;
    hash << tile.mix_pin.pin_commitment;
    hash << tile.hashes.chacha_manifest.commitment;
    hash << tile.hashes.chacha_pin.semantic_memory_root;
    hash << tile.hashes.scale_manifest.commitment;
    return hash.GetHash();
}

uint256 ComputeRCStage3CoupledExtractProductCommitment(
    const RCStage3CoupledExtractProduct& product)
{
    if (product.version !=
            kRCStage3CoupledExtractProductVersion ||
        product.statement_commitment.IsNull() ||
        product.shape_commitment.IsNull() ||
        product.expected_tiles == 0 ||
        product.tiles.size() != product.expected_tiles ||
        product.input_cells.bundle_commitment.IsNull() ||
        product.sampler_cells.bundle_commitment.IsNull() ||
        product.scale_cells.bundle_commitment.IsNull() ||
        product.output_to_barrier.pin.link_commitment.IsNull() ||
        product.input_endpoint_root.IsNull() ||
        product.sampler_endpoint_root.IsNull() ||
        product.chacha_endpoint_root.IsNull() ||
        product.scale_endpoint_root.IsNull() ||
        product.output_endpoint_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCT_DOMAIN;
    hash << product.version;
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    hash << product.expected_tiles;
    for (const auto& tile : product.tiles) {
        if (tile.tile_commitment.IsNull()) return {};
        hash << tile.tile_commitment;
    }
    hash << product.input_cells.bundle_commitment;
    hash << product.sampler_cells.bundle_commitment;
    hash << product.scale_cells.bundle_commitment;
    hash << product.output_to_barrier.pin.link_commitment;
    hash << product.input_endpoint_root;
    hash << product.sampler_endpoint_root;
    hash << product.chacha_endpoint_root;
    hash << product.scale_endpoint_root;
    hash << product.output_endpoint_root;
    return hash.GetHash();
}

bool BuildRCStage3CoupledExtractProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<std::array<int64_t, kRCMxBlockLen>>& inputs,
    RCStage3CoupledExtractProduct& out,
    std::string* why)
{
    return BuildInternal(
        statement, shape, inputs, false, out, why);
}

bool ProveRCStage3CoupledExtractProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<std::array<int64_t, kRCMxBlockLen>>& inputs,
    RCStage3CoupledExtractProduct& out,
    std::string* why)
{
    return BuildInternal(
        statement, shape, inputs, true, out, why);
}

bool ValidateRCStage3CoupledExtractProductSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExtractProduct& product,
    std::string* why)
{
    const auto schedule =
        BuildRCStage3CoupledExtractSchedule(statement, shape, why);
    if (product.version !=
            kRCStage3CoupledExtractProductVersion ||
        product.statement_commitment !=
            CommitRCStage3CoupledStatement(
                statement.public_inputs) ||
        product.shape_commitment !=
            CommitRCStage3CoupledShape(shape) ||
        product.expected_tiles != schedule.size() ||
        product.tiles.size() != schedule.size() ||
        product.input_cells.endpoint !=
            RCStage3RelationEndpoint::CoupledExtractInput ||
        product.sampler_cells.endpoint !=
            RCStage3RelationEndpoint::CoupledExtractSampler ||
        product.scale_cells.endpoint !=
            RCStage3RelationEndpoint::CoupledExtractScale ||
        product.output_to_barrier.extract_outputs.endpoint !=
            RCStage3RelationEndpoint::CoupledExtractOutput ||
        product.input_cells.shards.size() != schedule.size() ||
        product.sampler_cells.shards.size() != schedule.size() ||
        product.scale_cells.shards.size() != schedule.size() ||
        product.output_to_barrier.extract_outputs.shards.size() !=
            schedule.size() ||
        product.input_cells.bundle_commitment !=
            ComputeRCStage3CoupledSemanticFlatBundleCommitment(
                product.input_cells) ||
        product.sampler_cells.bundle_commitment !=
            ComputeRCStage3CoupledSemanticFlatBundleCommitment(
                product.sampler_cells) ||
        product.scale_cells.bundle_commitment !=
            ComputeRCStage3CoupledSemanticFlatBundleCommitment(
                product.scale_cells) ||
        product.output_to_barrier.extract_outputs.bundle_commitment !=
            ComputeRCStage3CoupledSemanticFlatBundleCommitment(
                product.output_to_barrier.extract_outputs)) {
        return Fail(why, "validate_shape");
    }
    for (uint64_t i = 0; i < schedule.size(); ++i) {
        const auto& tile = product.tiles[i];
        const auto& input_pin =
            product.input_cells.shards[i].pin;
        const auto& sampler_pin =
            product.sampler_cells.shards[i].pin;
        const auto& scale_pin =
            product.scale_cells.shards[i].pin;
        const auto& output_pin =
            product.output_to_barrier.extract_outputs.shards[i].pin;
        const ga::TilePublic pub{
            schedule[i].extract_prf, 0, schedule[i].tile};
        const ga::TileWitness witness =
            ga::TraceTile(pub, tile.input);
        std::vector<uint8_t> expected_positions;
        expected_positions.reserve(witness.cands.size());
        for (const auto& cand : witness.cands) {
            expected_positions.push_back(cand.pos);
        }
        const uint32_t n_rows = tile.mix_pin.n_rows;
        const uint32_t n_coeffs =
            product.input_cells.shards[i].proof.batch.n_coeffs;
        if (n_rows != ga::kAirSlotBudget ||
            tile.mix_pin.logical_rows != witness.cands.size() ||
            tile.candidate_positions.size() != witness.cands.size() ||
            tile.mix_pin.n_coeffs != n_coeffs ||
            tile.mix_pin.n_coeffs !=
                NextPowerOfTwo(3 * uint64_t{n_rows} - 3) ||
            tile.mix_pin.column_roots.size() !=
                kRCStage3EpisodeExtractMixColumns ||
            input_pin.relation_column_roots.size() !=
                aq::kRcSamplerNumCols) {
            return Fail(
                why, "validate_mix_shape_" + std::to_string(i));
        }
        const std::vector<uint256> fs_base_roots{
            input_pin.relation_column_roots.begin(),
            input_pin.relation_column_roots.begin() +
                aq::kRcSamplerBaseCols};
        Fp3 expected_gamma;
        Fp3 expected_alpha;
        if (!DeriveCoupledSamplerChallenges(
                SamplerSeed(
                    product.statement_commitment,
                    product.shape_commitment, i),
                i, n_rows, n_coeffs, fs_base_roots,
                expected_gamma, expected_alpha) ||
            !gf::Eq(
                input_pin.request.gamma, expected_gamma) ||
            !gf::Eq(
                input_pin.request.alpha, expected_alpha)) {
            return Fail(
                why, "validate_sampler_fs_" + std::to_string(i));
        }
        std::vector<Fp3> positions(n_rows, U(kRCMxBlockLen));
        std::vector<Fp3> kappas(n_rows, Fp3::One());
        for (uint32_t row = 0;
             row < tile.candidate_positions.size(); ++row) {
            if (tile.candidate_positions[row] >= kRCMxBlockLen ||
                row / 2 >=
                    tile.hashes.chacha_manifest.output.size()) {
                return Fail(why, "validate_stream_shape");
            }
            positions[row] = U(tile.candidate_positions[row]);
            const uint8_t byte =
                tile.hashes.chacha_manifest.output[row / 2];
            kappas[row] =
                U((byte >> (4 * (row & 1U))) & 0x0fU);
        }
        const auto same_relation =
            [&](const RCStage3CoupledSemanticPublicPin& pin) {
                return pin.request.role == input_pin.request.role &&
                       pin.request.shape == input_pin.request.shape &&
                       gf::Eq(
                           pin.request.gamma,
                           input_pin.request.gamma) &&
                       gf::Eq(
                           pin.request.alpha,
                           input_pin.request.alpha) &&
                       pin.request.extract_scale_e ==
                           input_pin.request.extract_scale_e &&
                       pin.relation_column_roots ==
                           input_pin.relation_column_roots;
            };
        if (tile.schedule != schedule[i] ||
            tile.output != witness.out ||
            tile.candidate_positions != expected_positions ||
            tile.mix_pin.statement_commitment !=
                product.statement_commitment ||
            tile.mix_pin.layer_ordinal != schedule[i].barrier ||
            tile.mix_pin.layer_tile_index != schedule[i].tile ||
            tile.mix_pin.pin_commitment !=
                ComputeRCStage3EpisodeExtractMixPinCommitment(
                    tile.mix_pin) ||
            input_pin.instance_begin != i ||
            sampler_pin.instance_begin != i ||
            scale_pin.instance_begin != i ||
            output_pin.instance_begin != i ||
            !same_relation(sampler_pin) ||
            !same_relation(scale_pin) ||
            !same_relation(output_pin) ||
            tile.mix_pin.column_roots[
                kRCStage3ExtractMixU].root !=
                input_pin.relation_column_roots[aq::kColUMix] ||
            tile.mix_pin.column_roots[
                kRCStage3ExtractMixQ].root !=
                input_pin.relation_column_roots[aq::kColGoldQ] ||
            tile.mix_pin.column_roots[
                kRCStage3ExtractMixV].root !=
                input_pin.relation_column_roots[aq::kColGoldV] ||
            tile.mix_pin.column_roots[
                kRCStage3ExtractMixH].root !=
                input_pin.relation_column_roots[aq::kColH] ||
            aq::AirCommittedValuesRoot<Fp3>(
                positions, n_coeffs) !=
                input_pin.relation_column_roots[aq::kColPos] ||
            aq::AirCommittedValuesRoot<Fp3>(
                kappas, n_coeffs) !=
                input_pin.relation_column_roots[aq::kColKappa] ||
            scale_pin.request.extract_scale_e != witness.scale_e ||
            output_pin.request.extract_scale_e != witness.scale_e ||
            !ha::ValidateChaChaConsumptionManifest(
                tile.hashes.chacha_manifest, why) ||
            !ha::ValidateShaManifest(
                tile.hashes.scale_manifest, why) ||
            tile.hashes.chacha_manifest.output !=
                witness.keystream ||
            (tile.hashes.scale_manifest.digest[0] & 3) !=
                witness.scale_e ||
            tile.hashes.chacha_proofs.endpoint !=
                RCStage3RelationEndpoint::CoupledExtractChaCha ||
            tile.hashes.scale_proofs.endpoint !=
                RCStage3RelationEndpoint::CoupledExtractScale ||
            tile.hashes.chacha_proofs.statement_commitment !=
                product.statement_commitment ||
            tile.hashes.scale_proofs.statement_commitment !=
                product.statement_commitment ||
            tile.hashes.chacha_proofs.manifest_commitment !=
                tile.hashes.chacha_manifest.commitment ||
            tile.hashes.scale_proofs.manifest_commitment !=
                tile.hashes.scale_manifest.commitment ||
            tile.tile_commitment !=
                ComputeRCStage3CoupledExtractTileCommitment(tile)) {
            return Fail(why, "validate_tile_" + std::to_string(i));
        }
    }
    if (product.input_endpoint_root != EndpointRoot(
            RCStage3RelationEndpoint::CoupledExtractInput, product) ||
        product.sampler_endpoint_root != EndpointRoot(
            RCStage3RelationEndpoint::CoupledExtractSampler, product) ||
        product.chacha_endpoint_root != EndpointRoot(
            RCStage3RelationEndpoint::CoupledExtractChaCha, product) ||
        product.scale_endpoint_root != EndpointRoot(
            RCStage3RelationEndpoint::CoupledExtractScale, product) ||
        product.output_endpoint_root != EndpointRoot(
            RCStage3RelationEndpoint::CoupledExtractOutput, product) ||
        product.product_commitment !=
            ComputeRCStage3CoupledExtractProductCommitment(product)) {
        return Fail(why, "validate_roots");
    }
    RCStage3ExtractBarrierLinkPin link;
    if (!BuildRCStage3ExtractBarrierLinkPin(
            statement, shape,
            product.output_to_barrier.extract_outputs,
            product.output_to_barrier.barriers,
            link, why) ||
        link != product.output_to_barrier.pin) {
        return Fail(why, "validate_endpoint47");
    }
    return true;
}

bool VerifyRCStage3CoupledExtractProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExtractProduct& product,
    std::string* why)
{
    if (!ValidateRCStage3CoupledExtractProductSchedule(
            statement, shape, product, why) ||
        !VerifyRCStage3CoupledSemanticFlatBundle(
            statement, product.input_cells, why) ||
        !VerifyRCStage3CoupledSemanticFlatBundle(
            statement, product.sampler_cells, why) ||
        !VerifyRCStage3CoupledSemanticFlatBundle(
            statement, product.scale_cells, why)) {
        return false;
    }
    for (const auto& tile : product.tiles) {
        if (!VerifyRCStage3EpisodeExtractMixProof(
                tile.mix_pin, tile.mix_proof, why) ||
            !VerifyRCStage3CoupledChaChaSemantic(
                statement, shape,
                tile.hashes.chacha_manifest,
                tile.hashes.chacha_proofs,
                tile.hashes.chacha_pin, why) ||
            !hs::VerifyShaManifestBundle(
                RCStage3RelationEndpoint::CoupledExtractScale,
                tile.hashes.scale_manifest,
                tile.hashes.scale_proofs, why)) {
            return Fail(why, "tile_proof");
        }
    }
    return VerifyRCStage3ExtractBarrierLinkExecution(
        statement, shape, product.output_to_barrier, why);
}

RCStage3CoupledExtractProductAudit
CurrentRCStage3CoupledExtractProductAudit()
{
    RCStage3CoupledExtractProductAudit out;
    out.exact_all_tile_schedule = true;
    out.int64_mix_binding_executable = true;
    out.sampler_walk_executable = true;
    out.chacha_consumption_executable = true;
    out.scale_sha_executable = true;
    out.output_memory_root_executable = true;
    out.endpoint47_equality_executable = true;
    out.endpoints_42_through_46_bounded_complete =
        kRCStage3CoupledExtractBoundedExecutable;
    out.upstream_producer_provenance_complete = false;
    out.production_streaming_complete =
        kRCStage3CoupledExtractProductionStreaming;
    out.recursively_consumed =
        kRCStage3CoupledExtractRecursivelyConsumed;
    out.transitively_complete = false;
    out.remaining =
        "post-mix producer roots are not equality-linked here; the bounded "
        "flat proof product is not streamed or recursively consumed";
    return out;
}

static_assert(kRCStage3CoupledExtractBoundedExecutable);
static_assert(!kRCStage3CoupledExtractProductionStreaming);
static_assert(!kRCStage3CoupledExtractRecursivelyConsumed);

} // namespace matmul::v4::rc
