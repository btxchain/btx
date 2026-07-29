// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_exchange_permutation_product.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_gkr_wiring.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
using gf::Fp3;
using AirCS = aq::AirConstraintSystem<Fp3>;

constexpr char PIN_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_EXCHANGE_PERMUTATION_PIN_V1";
constexpr char CHALLENGE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_EXCHANGE_PERMUTATION_CHALLENGE_V1";
constexpr char STAGE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_EXCHANGE_PERMUTATION_STAGE_V1";
constexpr char ENDPOINT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_EXCHANGE_PERMUTATION_ENDPOINT_V1";
constexpr char PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_EXCHANGE_PERMUTATION_PRODUCT_V1";

constexpr uint32_t LIMBS = 4;
constexpr uint32_t LIMB_BITS = 16;
constexpr uint32_t LANE_BITS = LIMBS * LIMB_BITS;

enum FixedColumn : uint32_t {
    kFixedInputLimb = 0,
    kFixedOutputLimb = kFixedInputLimb + LIMBS,
    kFixedColumns = kFixedOutputLimb + LIMBS,
};

enum PermutationColumn : uint32_t {
    kPermutationMappedIndex = 0,
    kPermutationDestinationIndex,
    kPermutationInputLimb,
    kPermutationOutputLimb = kPermutationInputLimb + LIMBS,
    kPermutationInverse1 = kPermutationOutputLimb + LIMBS,
    kPermutationProduct1,
    kPermutationInverse2,
    kPermutationProduct2,
    kPermutationColumns,
};

enum MaterialColumn : uint32_t {
    kMaterialMappedIndex = 0,
    kMaterialDestinationIndex,
    kMaterialInputLimb,
    kMaterialKeyLimb = kMaterialInputLimb + LIMBS,
    kMaterialMixedLimb = kMaterialKeyLimb + LIMBS,
    kMaterialOutputLimb = kMaterialMixedLimb + LIMBS,
    kMaterialInputBits = kMaterialOutputLimb + LIMBS,
    kMaterialKeyBits = kMaterialInputBits + LANE_BITS,
    kMaterialMixedBits = kMaterialKeyBits + LANE_BITS,
    kMaterialInverse1 = kMaterialMixedBits + LANE_BITS,
    kMaterialProduct1,
    kMaterialInverse2,
    kMaterialProduct2,
    kMaterialColumns,
};

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:coupled_exchange_permutation_product:" +
            detail;
    }
    return false;
}

bool IsCoupledStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Coupled ||
           statement.statement == RCStage3StatementKind::Composed;
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

uint32_t StateCells(const RCStage3CoupledShape& shape)
{
    const uint64_t count =
        uint64_t{shape.lobes} * shape.rows_per_lobe *
        shape.lobe_width;
    return count <= std::numeric_limits<uint32_t>::max()
        ? static_cast<uint32_t>(count)
        : 0;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    if (value < 2 ||
        value > kRCStage3CoupledExchangePermutationMaxRows) {
        return 0;
    }
    uint32_t out = 2;
    while (out < value) out <<= 1;
    return out;
}

RCCoupParams Params(const RCStage3CoupledShape& shape)
{
    RCCoupParams out;
    out.barriers = shape.barriers;
    out.lobes = shape.lobes;
    out.lobe_width = shape.lobe_width;
    out.bank_pages = shape.bank_pages;
    out.rows_per_lobe = shape.rows_per_lobe;
    out.pages_per_barrier_lobe =
        shape.pages_per_barrier_lobe;
    return out;
}

void AppendLe32(std::vector<uint8_t>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

void AppendLe64(std::vector<uint8_t>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

uint32_t ReadLe32(const uint8_t* bytes)
{
    uint32_t out = 0;
    for (uint32_t i = 0; i < 4; ++i) {
        out |= uint32_t{bytes[i]} << (8 * i);
    }
    return out;
}

uint64_t ReadLe64(const uint8_t* bytes)
{
    uint64_t out = 0;
    for (uint32_t i = 0; i < 8; ++i) {
        out |= uint64_t{bytes[i]} << (8 * i);
    }
    return out;
}

uint16_t Limb(int64_t value, uint32_t limb)
{
    return static_cast<uint16_t>(
        static_cast<uint64_t>(value) >> (16 * limb));
}

uint32_t MaterialBit(
    uint32_t base, uint32_t limb, uint32_t bit)
{
    return base + limb * LIMB_BITS + bit;
}

uint256 DigestUint(const std::array<uint8_t, 32>& digest)
{
    return uint256{Span<const unsigned char>{
        digest.data(), digest.size()}};
}

bool HashPinEqual(
    const RCStage3CoupledHashSemanticPin& a,
    const RCStage3CoupledHashSemanticPin& b)
{
    return a.version == b.version &&
           a.endpoint == b.endpoint &&
           a.port == b.port &&
           a.statement_commitment == b.statement_commitment &&
           a.shape_commitment == b.shape_commitment &&
           a.manifest_commitment == b.manifest_commitment &&
           a.schedule_commitment == b.schedule_commitment &&
           a.instance_count == b.instance_count &&
           a.logical_rows == b.logical_rows &&
           a.n_rows == b.n_rows &&
           a.boundary_value_root == b.boundary_value_root &&
           a.semantic_memory_root == b.semantic_memory_root;
}

bool PinEqual(
    const RCStage3CoupledExchangePermutationAirPin& a,
    const RCStage3CoupledExchangePermutationAirPin& b)
{
    if (a.version != b.version ||
        a.relation_endpoint != b.relation_endpoint ||
        a.statement_commitment != b.statement_commitment ||
        a.shape_commitment != b.shape_commitment ||
        a.schedule_index != b.schedule_index ||
        a.logical_rows != b.logical_rows ||
        a.n_rows != b.n_rows ||
        a.n_coeffs != b.n_coeffs ||
        a.challenge_seed != b.challenge_seed ||
        a.pin_commitment != b.pin_commitment ||
        a.column_roots.size() != b.column_roots.size()) {
        return false;
    }
    for (uint32_t i = 0; i < a.column_roots.size(); ++i) {
        if (a.column_roots[i].column !=
                b.column_roots[i].column ||
            a.column_roots[i].root !=
                b.column_roots[i].root) {
            return false;
        }
    }
    return true;
}

void AddConstraint(
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

AirCS BuildFixedCS(uint32_t n_rows)
{
    AirCS cs;
    cs.n_rows = n_rows;
    cs.n_columns = kFixedColumns;
    for (uint32_t limb = 0; limb < LIMBS; ++limb) {
        AddConstraint(
            cs, "exchange.fixed_limb_equality",
            aq::AirKind::kEverywhere, 1,
            [limb](const auto& row, const auto&) {
                return gf::Sub(
                    row[kFixedInputLimb + limb],
                    row[kFixedOutputLimb + limb]);
            });
    }
    return cs;
}

Fp3 Fingerprint(
    const std::vector<Fp3>& row,
    uint32_t index_column,
    uint32_t limb_base,
    const std::array<Fp3, LIMBS + 1>& beta)
{
    Fp3 out = gf::Mul(beta[0], row[index_column]);
    for (uint32_t limb = 0; limb < LIMBS; ++limb) {
        out = gf::Add(
            out,
            gf::Mul(beta[limb + 1],
                    row[limb_base + limb]));
    }
    return out;
}

void AddPermutationProduct(
    AirCS& cs,
    const RCStage3CoupledExchangePermutationAirPin& pin,
    uint32_t mapped_index,
    uint32_t destination_index,
    uint32_t source_limb,
    uint32_t destination_limb,
    uint32_t inverse1,
    uint32_t product1)
{
    for (uint32_t lane = 0; lane < 2; ++lane) {
        std::array<Fp3, LIMBS + 1> beta;
        for (uint32_t i = 0; i < beta.size(); ++i) {
            beta[i] = WiringChallengeFp3(
                pin.challenge_seed, "stage3_coupled_perm_beta",
                pin.schedule_index, lane * beta.size() + i);
        }
        const Fp3 gamma = WiringChallengeFp3(
            pin.challenge_seed, "stage3_coupled_perm_gamma",
            pin.schedule_index, lane);
        const uint32_t inverse = inverse1 + lane * 2;
        const uint32_t product = product1 + lane * 2;
        AddConstraint(
            cs, "indexed_permutation.denominator_inverse",
            aq::AirKind::kEverywhere, 2,
            [=](const auto& row, const auto&) {
                const Fp3 denominator = gf::Sub(
                    gamma,
                    Fingerprint(
                        row, destination_index,
                        destination_limb, beta));
                return gf::Sub(
                    gf::Mul(row[inverse], denominator),
                    Fp3::One());
            });
        AddConstraint(
            cs, "indexed_permutation.product_first",
            aq::AirKind::kFirstRow, 1,
            [=](const auto& row, const auto&) {
                return gf::Sub(
                    row[product], Fp3::One());
            });
        // The recurrence is cyclic on H. At the last row next[product] is
        // row zero, so terminal equality is enforced without a high-degree
        // last-row selector or a larger commitment domain.
        AddConstraint(
            cs, "indexed_permutation.product_cycle",
            aq::AirKind::kEverywhere, 2,
            [=](const auto& row, const auto& next) {
                const Fp3 numerator = gf::Sub(
                    gamma,
                    Fingerprint(
                        row, mapped_index,
                        source_limb, beta));
                const Fp3 denominator = gf::Sub(
                    gamma,
                    Fingerprint(
                        row, destination_index,
                        destination_limb, beta));
                return gf::Sub(
                    gf::Mul(next[product], denominator),
                    gf::Mul(row[product], numerator));
            });
    }
}

AirCS BuildPermutationCS(
    const RCStage3CoupledExchangePermutationAirPin& pin)
{
    AirCS cs;
    cs.n_rows = pin.n_rows;
    cs.n_columns = kPermutationColumns;
    AddPermutationProduct(
        cs, pin,
        kPermutationMappedIndex,
        kPermutationDestinationIndex,
        kPermutationInputLimb,
        kPermutationOutputLimb,
        kPermutationInverse1,
        kPermutationProduct1);
    return cs;
}

AirCS BuildMaterialCS(
    const RCStage3CoupledExchangePermutationAirPin& pin)
{
    AirCS cs;
    cs.n_rows = pin.n_rows;
    cs.n_columns = kMaterialColumns;
    for (uint32_t limb = 0; limb < LIMBS; ++limb) {
        for (uint32_t bit = 0; bit < LIMB_BITS; ++bit) {
            for (uint32_t base : {
                     kMaterialInputBits,
                     kMaterialKeyBits,
                     kMaterialMixedBits}) {
                const uint32_t column =
                    MaterialBit(base, limb, bit);
                AddConstraint(
                    cs, "exchange.material_boolean",
                    aq::AirKind::kEverywhere, 2,
                    [column](const auto& row, const auto&) {
                        return gf::Mul(
                            row[column],
                            gf::Sub(
                                row[column], Fp3::One()));
                    });
            }
            const uint32_t input =
                MaterialBit(kMaterialInputBits, limb, bit);
            const uint32_t key =
                MaterialBit(kMaterialKeyBits, limb, bit);
            const uint32_t mixed =
                MaterialBit(kMaterialMixedBits, limb, bit);
            AddConstraint(
                cs, "exchange.material_xor",
                aq::AirKind::kEverywhere, 2,
                [=](const auto& row, const auto&) {
                    return gf::Sub(
                        row[mixed],
                        gf::Sub(
                            gf::Add(row[input], row[key]),
                            gf::Mul(
                                U(2),
                                gf::Mul(
                                    row[input], row[key]))));
                });
        }
        const auto recompose =
            [&](uint32_t limb_column, uint32_t bit_base) {
                AddConstraint(
                    cs, "exchange.material_limb_recompose",
                    aq::AirKind::kEverywhere, 1,
                    [=](const auto& row, const auto&) {
                        Fp3 value = Fp3::Zero();
                        for (uint32_t bit = 0;
                             bit < LIMB_BITS; ++bit) {
                            value = gf::Add(
                                value,
                                gf::Mul(
                                    U(uint64_t{1} << bit),
                                    row[MaterialBit(
                                        bit_base, limb, bit)]));
                        }
                        return gf::Sub(
                            row[limb_column + limb], value);
                    });
            };
        recompose(kMaterialInputLimb, kMaterialInputBits);
        recompose(kMaterialKeyLimb, kMaterialKeyBits);
        recompose(kMaterialMixedLimb, kMaterialMixedBits);
    }
    AddPermutationProduct(
        cs, pin,
        kMaterialMappedIndex,
        kMaterialDestinationIndex,
        kMaterialMixedLimb,
        kMaterialOutputLimb,
        kMaterialInverse1,
        kMaterialProduct1);
    return cs;
}

uint256 ChallengeSeed(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& shape_commitment,
    uint32_t schedule_index,
    const std::vector<uint256>& roots)
{
    if (statement_commitment.IsNull() ||
        shape_commitment.IsNull() || roots.empty()) {
        return {};
    }
    HashWriter hash;
    hash << CHALLENGE_DOMAIN;
    hash << kRCStage3CoupledExchangePermutationProductVersion;
    hash << static_cast<uint16_t>(endpoint);
    hash << statement_commitment << shape_commitment;
    hash << schedule_index;
    hash << static_cast<uint32_t>(roots.size());
    for (const auto& root : roots) {
        if (root.IsNull()) return {};
        hash << root;
    }
    return hash.GetHash();
}

void FillRoots(
    RCStage3CoupledExchangePermutationAirPin& pin,
    const std::vector<std::vector<Fp3>>& columns)
{
    pin.column_roots.clear();
    for (uint32_t column = 0;
         column < columns.size(); ++column) {
        pin.column_roots.push_back({
            column,
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], pin.n_coeffs)});
    }
    pin.pin_commitment =
        ComputeRCStage3CoupledExchangePermutationAirPinCommitment(
            pin);
}

void FillLimbs(
    const std::vector<int64_t>& values,
    uint32_t limb_base,
    std::vector<std::vector<Fp3>>& columns)
{
    for (uint32_t row = 0; row < values.size(); ++row) {
        for (uint32_t limb = 0; limb < LIMBS; ++limb) {
            columns[limb_base + limb][row] =
                U(Limb(values[row], limb));
        }
    }
}

bool FillRunningProducts(
    const RCStage3CoupledExchangePermutationAirPin& pin,
    uint32_t mapped_index,
    uint32_t destination_index,
    uint32_t source_limb,
    uint32_t destination_limb,
    uint32_t inverse1,
    uint32_t product1,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    for (uint32_t lane = 0; lane < 2; ++lane) {
        std::array<Fp3, LIMBS + 1> beta;
        for (uint32_t i = 0; i < beta.size(); ++i) {
            beta[i] = WiringChallengeFp3(
                pin.challenge_seed, "stage3_coupled_perm_beta",
                pin.schedule_index, lane * beta.size() + i);
        }
        const Fp3 gamma = WiringChallengeFp3(
            pin.challenge_seed, "stage3_coupled_perm_gamma",
            pin.schedule_index, lane);
        const uint32_t inverse = inverse1 + lane * 2;
        const uint32_t product = product1 + lane * 2;
        Fp3 running = Fp3::One();
        for (uint32_t row = 0; row < pin.n_rows; ++row) {
            columns[product][row] = running;
            const std::vector<Fp3> current = [&] {
                std::vector<Fp3> out(columns.size());
                for (uint32_t column = 0;
                     column < columns.size(); ++column) {
                    out[column] = columns[column][row];
                }
                return out;
            }();
            const Fp3 source = gf::Sub(
                gamma,
                Fingerprint(
                    current, mapped_index,
                    source_limb, beta));
            const Fp3 destination = gf::Sub(
                gamma,
                Fingerprint(
                    current, destination_index,
                    destination_limb, beta));
            if (gf::Eq(destination, Fp3::Zero())) {
                return Fail(why, "permutation_challenge_pole");
            }
            columns[inverse][row] = gf::Inv(destination);
            running = gf::Mul(
                running,
                gf::Mul(source, gf::Inv(destination)));
        }
        if (!gf::Eq(running, Fp3::One())) {
            return Fail(why, "permutation_terminal");
        }
    }
    return true;
}

bool BuildFixedColumns(
    const RCStage3CoupledExchangeStageProduct& stage,
    RCStage3CoupledExchangePermutationAirPin& pin,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    if (stage.input.size() != stage.schedule.value_count ||
        stage.output != stage.input ||
        stage.schedule.value_count < 2) {
        return Fail(why, "fixed_values");
    }
    pin.logical_rows = stage.schedule.value_count;
    pin.n_rows = NextPowerOfTwo(stage.schedule.value_count);
    if (pin.n_rows == 0) {
        return Fail(why, "fixed_row_bound");
    }
    pin.n_coeffs = pin.n_rows;
    columns.assign(
        kFixedColumns,
        std::vector<Fp3>(pin.n_rows, Fp3::Zero()));
    FillLimbs(stage.input, kFixedInputLimb, columns);
    FillLimbs(stage.output, kFixedOutputLimb, columns);
    std::vector<uint256> roots;
    for (uint32_t column = 0; column < columns.size(); ++column) {
        roots.push_back(aq::AirCommittedValuesRoot<Fp3>(
            columns[column], pin.n_coeffs));
    }
    pin.challenge_seed = ChallengeSeed(
        pin.relation_endpoint, pin.statement_commitment,
        pin.shape_commitment, pin.schedule_index, roots);
    FillRoots(pin, columns);
    return !pin.pin_commitment.IsNull() ||
           Fail(why, "fixed_pin");
}

bool BuildPermutationColumns(
    const std::vector<int64_t>& input,
    const std::vector<int64_t>& output,
    const std::vector<uint32_t>& mapping,
    RCStage3CoupledExchangePermutationAirPin& pin,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    if (input.size() < 2 || input.size() != output.size() ||
        input.size() != mapping.size() ||
        input.size() > kRCStage3CoupledExchangePermutationMaxRows) {
        return Fail(why, "permutation_values");
    }
    pin.logical_rows = input.size();
    pin.n_rows = input.size();
    pin.n_coeffs = pin.n_rows;
    columns.assign(
        kPermutationColumns,
        std::vector<Fp3>(pin.n_rows, Fp3::Zero()));
    FillLimbs(input, kPermutationInputLimb, columns);
    FillLimbs(output, kPermutationOutputLimb, columns);
    for (uint32_t row = 0; row < pin.n_rows; ++row) {
        if (mapping[row] >= pin.n_rows) {
            return Fail(why, "permutation_mapping");
        }
        columns[kPermutationMappedIndex][row] = U(mapping[row]);
        columns[kPermutationDestinationIndex][row] = U(row);
    }
    std::vector<uint256> roots;
    for (uint32_t column = 0;
         column < kPermutationInverse1; ++column) {
        roots.push_back(aq::AirCommittedValuesRoot<Fp3>(
            columns[column], pin.n_coeffs));
    }
    pin.challenge_seed = ChallengeSeed(
        pin.relation_endpoint, pin.statement_commitment,
        pin.shape_commitment, pin.schedule_index, roots);
    if (pin.challenge_seed.IsNull() ||
        !FillRunningProducts(
            pin,
            kPermutationMappedIndex,
            kPermutationDestinationIndex,
            kPermutationInputLimb,
            kPermutationOutputLimb,
            kPermutationInverse1,
            kPermutationProduct1,
            columns, why)) {
        return false;
    }
    FillRoots(pin, columns);
    return !pin.pin_commitment.IsNull() ||
           Fail(why, "permutation_pin");
}

std::vector<uint8_t> ExchangeSeedPreimage(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    uint32_t barrier,
    uint32_t round,
    uint64_t fold)
{
    const auto& tags =
        RCCoupDomainTagsForVersion(shape.transcript_version);
    std::vector<uint8_t> out(
        reinterpret_cast<const uint8_t*>(tags.exchange_rounds),
        reinterpret_cast<const uint8_t*>(tags.exchange_rounds) +
            std::strlen(tags.exchange_rounds));
    out.insert(
        out.end(), statement.public_inputs.sigma.begin(),
        statement.public_inputs.sigma.end());
    AppendLe32(out, barrier);
    AppendLe32(out, round);
    AppendLe64(out, fold);
    return out;
}

uint64_t XorFold(const std::vector<int64_t>& values)
{
    uint64_t out = 0;
    for (int64_t value : values) {
        out ^= static_cast<uint64_t>(value);
    }
    return out;
}

bool BuildHashExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<uint8_t>& preimage,
    ha::ShaMode mode,
    RCStage3CoupledExchangeHashExecution& out,
    std::string* why)
{
    out = {};
    if (!ha::BuildShaManifest(
            preimage, mode, out.manifest, why)) {
        return false;
    }
    out.proof.endpoint =
        RCStage3RelationEndpoint::CoupledExchangeHashXof;
    out.proof.statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    out.proof.manifest_commitment = out.manifest.commitment;
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    return ha::BuildShaManifestBoundaryInstances(
               out.manifest, boundaries, why) &&
           BuildRCStage3CoupledHashSemanticPin(
               RCStage3RelationEndpoint::CoupledExchangeHashXof,
               shape, out.proof.statement_commitment,
               out.manifest.commitment, boundaries,
               hs::BoundaryPort::ExternalThenFinal,
               out.semantic_pin, why);
}

bool ProveHashExecution(
    const RCStage3CoupledExchangeHashExecution& expected,
    RCStage3CoupledExchangeHashExecution& out,
    std::string* why)
{
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildShaManifestBoundaryInstances(
            expected.manifest, boundaries, why)) {
        return false;
    }
    out = expected;
    out.proof.proofs.resize(boundaries.size());
    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::Sha256Compression);
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
                    out.proof.endpoint,
                    out.proof.statement_commitment,
                    out.proof.manifest_commitment,
                    i, boundaries.size()),
                out.proof.proofs[i], why)) {
            return false;
        }
    }
    return true;
}

bool VerifyHashExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangeHashExecution& execution,
    std::string* why)
{
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    RCStage3CoupledHashSemanticPin expected_pin;
    if (!ha::BuildShaManifestBoundaryInstances(
            execution.manifest, boundaries, why) ||
        !BuildRCStage3CoupledHashSemanticPin(
            RCStage3RelationEndpoint::CoupledExchangeHashXof,
            shape,
            CommitRCStage3CoupledStatement(statement.public_inputs),
            execution.manifest.commitment, boundaries,
            hs::BoundaryPort::ExternalThenFinal,
            expected_pin, why) ||
        !HashPinEqual(execution.semantic_pin, expected_pin) ||
        !hs::VerifyShaManifestBundle(
            RCStage3RelationEndpoint::CoupledExchangeHashXof,
            execution.manifest, execution.proof, why)) {
        return Fail(why, "hash_execution");
    }
    return true;
}

bool BuildMaterial(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangeScheduleEntry& schedule,
    const std::vector<int64_t>& input,
    RCStage3CoupledExchangeStageProduct& out,
    std::vector<uint64_t>& keys,
    std::vector<uint32_t>& mapping,
    std::string* why)
{
    out = {};
    out.schedule = schedule;
    out.input = input;
    if (input.size() != schedule.value_count) {
        return Fail(why, "material_input_count");
    }
    RCStage3CoupledExchangeHashExecution seed_hash;
    if (!BuildHashExecution(
            statement, shape,
            ExchangeSeedPreimage(
                statement, shape, schedule.barrier,
                schedule.lobe_or_round, XorFold(input)),
            ha::ShaMode::Double, seed_hash, why)) {
        return Fail(why, "material_seed");
    }
    out.hash_executions.push_back(std::move(seed_hash));
    const uint256 seed =
        DigestUint(out.hash_executions[0].manifest.digest);
    const uint64_t byte_count = uint64_t{input.size()} * 8;
    const uint32_t block_count = static_cast<uint32_t>(
        (byte_count + 31) / 32);
    std::vector<uint8_t> xof_bytes;
    xof_bytes.reserve(uint64_t{block_count} * 32);
    for (uint32_t counter = 0;
         counter < block_count; ++counter) {
        std::vector<uint8_t> preimage(
            seed.begin(), seed.end());
        AppendLe32(preimage, counter);
        RCStage3CoupledExchangeHashExecution block;
        if (!BuildHashExecution(
                statement, shape, preimage,
                ha::ShaMode::Single, block, why)) {
            return Fail(why, "material_xof_block");
        }
        xof_bytes.insert(
            xof_bytes.end(), block.manifest.digest.begin(),
            block.manifest.digest.end());
        out.hash_executions.push_back(std::move(block));
    }
    if (xof_bytes.size() < byte_count ||
        xof_bytes.size() < uint64_t{input.size() - 1} * 4) {
        return Fail(why, "material_xof_bytes");
    }
    keys.resize(input.size());
    std::vector<int64_t> mixed(input.size());
    for (uint32_t i = 0; i < input.size(); ++i) {
        keys[i] = ReadLe64(xof_bytes.data() + 8 * i);
        mixed[i] = static_cast<int64_t>(
            static_cast<uint64_t>(input[i]) ^ keys[i]);
    }
    mapping.resize(input.size());
    for (uint32_t i = 0; i < mapping.size(); ++i) mapping[i] = i;
    uint32_t word = 0;
    for (uint32_t i = mapping.size() - 1; i > 0; --i) {
        const uint32_t j =
            ReadLe32(xof_bytes.data() + 4 * word++) % (i + 1);
        std::swap(mapping[i], mapping[j]);
    }
    out.output.assign(input.size(), 0);
    for (uint32_t i = 0; i < input.size(); ++i) {
        out.output[mapping[i]] = mixed[i];
    }
    return true;
}

bool BuildMaterialColumns(
    const RCStage3CoupledExchangeStageProduct& stage,
    const std::vector<uint64_t>& keys,
    const std::vector<uint32_t>& mapping,
    RCStage3CoupledExchangePermutationAirPin& pin,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    if (stage.input.size() != keys.size() ||
        stage.input.size() != mapping.size() ||
        stage.input.size() != stage.output.size() ||
        stage.input.size() < 2) {
        return Fail(why, "material_column_shape");
    }
    pin.logical_rows = stage.input.size();
    pin.n_rows = stage.input.size();
    pin.n_coeffs = pin.n_rows;
    columns.assign(
        kMaterialColumns,
        std::vector<Fp3>(pin.n_rows, Fp3::Zero()));
    FillLimbs(stage.input, kMaterialInputLimb, columns);
    FillLimbs(stage.output, kMaterialOutputLimb, columns);
    for (uint32_t row = 0; row < pin.n_rows; ++row) {
        const uint64_t input =
            static_cast<uint64_t>(stage.input[row]);
        const uint64_t mixed = input ^ keys[row];
        columns[kMaterialMappedIndex][row] = U(mapping[row]);
        columns[kMaterialDestinationIndex][row] = U(row);
        for (uint32_t limb = 0; limb < LIMBS; ++limb) {
            columns[kMaterialKeyLimb + limb][row] =
                U((keys[row] >> (16 * limb)) & 0xffffU);
            columns[kMaterialMixedLimb + limb][row] =
                U((mixed >> (16 * limb)) & 0xffffU);
            for (uint32_t bit = 0; bit < LIMB_BITS; ++bit) {
                columns[MaterialBit(
                    kMaterialInputBits, limb, bit)][row] =
                    U((input >> (16 * limb + bit)) & 1U);
                columns[MaterialBit(
                    kMaterialKeyBits, limb, bit)][row] =
                    U((keys[row] >> (16 * limb + bit)) & 1U);
                columns[MaterialBit(
                    kMaterialMixedBits, limb, bit)][row] =
                    U((mixed >> (16 * limb + bit)) & 1U);
            }
        }
    }
    std::vector<uint256> roots;
    for (uint32_t column = 0;
         column < kMaterialInverse1; ++column) {
        roots.push_back(aq::AirCommittedValuesRoot<Fp3>(
            columns[column], pin.n_coeffs));
    }
    pin.challenge_seed = ChallengeSeed(
        pin.relation_endpoint, pin.statement_commitment,
        pin.shape_commitment, pin.schedule_index, roots);
    if (pin.challenge_seed.IsNull() ||
        !FillRunningProducts(
            pin,
            kMaterialMappedIndex,
            kMaterialDestinationIndex,
            kMaterialMixedLimb,
            kMaterialOutputLimb,
            kMaterialInverse1,
            kMaterialProduct1,
            columns, why)) {
        return false;
    }
    FillRoots(pin, columns);
    return !pin.pin_commitment.IsNull() ||
           Fail(why, "material_pin");
}

std::vector<uint32_t> ScheduleMapping(
    const RCStage3CoupledPermutationScheduleEntry& schedule)
{
    RCCoupProofFriendlyPermutationSpec spec;
    spec.n = schedule.value_count;
    spec.bits = schedule.index_bits;
    spec.out_to_in_bit = schedule.out_to_in_bit;
    spec.xor_mask_bit = schedule.xor_mask_bit;
    std::vector<uint32_t> out(schedule.value_count);
    for (uint32_t i = 0; i < out.size(); ++i) {
        out[i] =
            ApplyCoupledProofFriendlyPermutationIndex(i, spec);
    }
    return out;
}

uint256 StageCommitment(
    const RCStage3CoupledExchangeStageProduct& stage)
{
    if (stage.pin.pin_commitment.IsNull()) return {};
    HashWriter hash;
    hash << STAGE_DOMAIN;
    hash << static_cast<uint8_t>(stage.schedule.kind);
    hash << stage.schedule.schedule_index;
    hash << stage.schedule.barrier;
    hash << stage.schedule.lobe_or_round;
    hash << stage.schedule.value_count;
    hash << stage.pin.pin_commitment;
    hash << static_cast<uint32_t>(stage.hash_executions.size());
    for (const auto& execution : stage.hash_executions) {
        if (execution.manifest.commitment.IsNull() ||
            execution.semantic_pin.semantic_memory_root.IsNull()) {
            return {};
        }
        hash << execution.manifest.commitment;
        hash << execution.semantic_pin.semantic_memory_root;
    }
    return hash.GetHash();
}

uint256 StageCommitment(
    const RCStage3CoupledPermutationStageProduct& stage)
{
    if (stage.pin.pin_commitment.IsNull()) return {};
    HashWriter hash;
    hash << STAGE_DOMAIN;
    hash << static_cast<uint8_t>(3);
    hash << stage.schedule.schedule_index;
    hash << stage.schedule.barrier;
    hash << stage.schedule.value_count;
    hash << stage.schedule.index_bits;
    hash << stage.pin.pin_commitment;
    return hash.GetHash();
}

std::vector<uint256> LimbRoots(
    const RCStage3CoupledExchangeStageProduct& stage,
    bool output)
{
    uint32_t base = 0;
    if (stage.schedule.kind ==
        RCStage3CoupledExchangeStageKind::FixedSegment) {
        base = output ? kFixedOutputLimb : kFixedInputLimb;
    } else {
        base = output ? kMaterialOutputLimb : kMaterialInputLimb;
    }
    std::vector<uint256> out;
    for (uint32_t limb = 0; limb < LIMBS; ++limb) {
        out.push_back(stage.pin.column_roots[base + limb].root);
    }
    return out;
}

std::vector<uint256> LimbRoots(
    const RCStage3CoupledPermutationStageProduct& stage,
    bool output)
{
    const uint32_t base =
        output ? kPermutationOutputLimb : kPermutationInputLimb;
    std::vector<uint256> out;
    for (uint32_t limb = 0; limb < LIMBS; ++limb) {
        out.push_back(stage.pin.column_roots[base + limb].root);
    }
    return out;
}

uint256 EndpointRoot(
    RCStage3RelationEndpoint endpoint,
    const RCStage3CoupledExchangePermutationProduct& product)
{
    HashWriter hash;
    hash << ENDPOINT_DOMAIN;
    hash << kRCStage3CoupledExchangePermutationProductVersion;
    hash << static_cast<uint16_t>(endpoint);
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    if (endpoint == RCStage3RelationEndpoint::CoupledExchangeInput ||
        endpoint == RCStage3RelationEndpoint::CoupledExchangeOutput) {
        hash << static_cast<uint32_t>(product.exchange_stages.size());
        for (const auto& stage : product.exchange_stages) {
            hash << stage.schedule.schedule_index;
            const auto roots = LimbRoots(
                stage,
                endpoint ==
                    RCStage3RelationEndpoint::CoupledExchangeOutput);
            for (const auto& root : roots) hash << root;
        }
    } else if (
        endpoint ==
        RCStage3RelationEndpoint::CoupledExchangeHashXof) {
        uint32_t count = 0;
        for (const auto& stage : product.exchange_stages) {
            count += stage.hash_executions.size();
        }
        hash << count;
        for (const auto& stage : product.exchange_stages) {
            for (const auto& execution : stage.hash_executions) {
                hash << execution.manifest.commitment;
                hash << execution.semantic_pin.semantic_memory_root;
            }
        }
    } else if (
        endpoint ==
            RCStage3RelationEndpoint::CoupledPermutationInput ||
        endpoint ==
            RCStage3RelationEndpoint::CoupledPermutationOutput) {
        hash << static_cast<uint32_t>(
            product.permutation_stages.size());
        for (const auto& stage : product.permutation_stages) {
            hash << stage.schedule.schedule_index;
            const auto roots = LimbRoots(
                stage,
                endpoint ==
                    RCStage3RelationEndpoint::CoupledPermutationOutput);
            for (const auto& root : roots) hash << root;
        }
    } else {
        return {};
    }
    return hash.GetHash();
}

bool ProofShape(
    const RCStage3CoupledExchangePermutationAirPin& pin,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    if (proof.batch.columns.size() !=
            pin.column_roots.size() + 1 ||
        proof.batch.column_len.size() !=
            pin.column_roots.size() + 1 ||
        proof.batch.n_coeffs != pin.n_coeffs) {
        return Fail(why, "air_proof_shape");
    }
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (proof.batch.column_len[i] != pin.n_rows ||
            proof.batch.columns[i].root !=
                pin.column_roots[i].root) {
            return Fail(why, "air_proof_root");
        }
    }
    return true;
}

bool VerifyAir(
    const RCStage3CoupledExchangePermutationAirPin& pin,
    AirCS cs,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    for (const auto& root : pin.column_roots) {
        // Exact root equality is the endpoint-memory alias.
        cs.preprocessed_roots.emplace_back(
            root.column, root.root);
    }
    std::string air_why;
    return ProofShape(pin, proof, why) &&
           (aq::AirQuotientVerify<Fp3>(
                cs, proof, pin.pin_commitment, &air_why) ||
            Fail(why, "air:" + air_why));
}

} // namespace

aq::AirConstraintSystem<Fp3>
BuildRCStage3CoupledPermutationTransportConstraintSystem(
    const RCStage3CoupledExchangePermutationAirPin& pin)
{
    return BuildPermutationCS(pin);
}

aq::AirConstraintSystem<Fp3>
BuildRCStage3CoupledExchangeTransportConstraintSystem(
    const RCStage3CoupledExchangePermutationAirPin& pin)
{
    return BuildMaterialCS(pin);
}

std::array<Fp3, 12>
RCStage3CoupledExchangePermutationTransportChallengeVector(
    const uint256& challenge_seed, uint32_t schedule_index)
{
    // Packing: per lane L, beta[0..4] at L*6+0..4, gamma at L*6+5. Matches the
    // native AddPermutationProduct derivation (beta.size() == LIMBS+1 == 5).
    std::array<Fp3, 12> out{};
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t i = 0; i < LIMBS + 1; ++i) {
            out[lane * 6 + i] = WiringChallengeFp3(
                challenge_seed, "stage3_coupled_perm_beta",
                schedule_index, lane * (LIMBS + 1) + i);
        }
        out[lane * 6 + 5] = WiringChallengeFp3(
            challenge_seed, "stage3_coupled_perm_gamma",
            schedule_index, lane);
    }
    return out;
}

std::vector<RCStage3CoupledExchangeScheduleEntry>
BuildRCStage3CoupledExchangeSchedule(
    const RCStage3CoupledShape& shape,
    std::string* why)
{
    std::vector<RCStage3CoupledExchangeScheduleEntry> out;
    const auto counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledExchange, shape, why);
    const uint32_t state_cells = StateCells(shape);
    const uint64_t lobe_cells =
        uint64_t{shape.rows_per_lobe} * shape.lobe_width;
    if (!counts.has_value() || state_cells < 2 ||
        lobe_cells < 2 ||
        lobe_cells > kRCStage3CoupledExchangePermutationMaxRows ||
        counts->primary >
            kRCStage3CoupledExchangePermutationMaxStages) {
        return {};
    }
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        for (uint32_t lobe = 0;
             lobe < shape.lobes; ++lobe) {
            out.push_back({
                static_cast<uint32_t>(out.size()),
                RCStage3CoupledExchangeStageKind::FixedSegment,
                barrier, lobe,
                static_cast<uint32_t>(lobe_cells)});
        }
        for (uint32_t round = 0;
             round < shape.exchange_rounds; ++round) {
            out.push_back({
                static_cast<uint32_t>(out.size()),
                RCStage3CoupledExchangeStageKind::MaterialRound,
                barrier, round, state_cells});
        }
    }
    if (out.size() != counts->primary) {
        Fail(why, "exchange_schedule_count");
        return {};
    }
    return out;
}

std::vector<RCStage3CoupledPermutationScheduleEntry>
BuildRCStage3CoupledPermutationSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    std::string* why)
{
    std::vector<RCStage3CoupledPermutationScheduleEntry> out;
    const auto counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledPermutation, shape, why);
    const uint32_t state_cells = StateCells(shape);
    if (!IsCoupledStatement(statement) ||
        statement.public_inputs.transcript_version !=
            shape.transcript_version ||
        statement.public_inputs.sigma.IsNull() ||
        !counts.has_value() ||
        counts->primary != shape.barriers ||
        state_cells < 2 ||
        state_cells >
            kRCStage3CoupledExchangePermutationMaxRows) {
        return {};
    }
    const auto params = Params(shape);
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        const auto spec =
            DeriveCoupledProofFriendlyPermutationSpec(
                statement.public_inputs.sigma, barrier,
                params, shape.transcript_version);
        if (spec.n != state_cells || spec.bits == 0 ||
            spec.out_to_in_bit.size() != spec.bits ||
            spec.xor_mask_bit.size() != spec.bits) {
            Fail(why, "permutation_spec");
            return {};
        }
        out.push_back({
            barrier, barrier, state_cells, spec.bits,
            spec.out_to_in_bit, spec.xor_mask_bit});
    }
    return out;
}

uint256
ComputeRCStage3CoupledExchangePermutationAirPinCommitment(
    const RCStage3CoupledExchangePermutationAirPin& pin)
{
    const uint16_t endpoint =
        static_cast<uint16_t>(pin.relation_endpoint);
    if (pin.version !=
            kRCStage3CoupledExchangePermutationProductVersion ||
        (endpoint != static_cast<uint16_t>(
                         RCStage3RelationEndpoint::
                             CoupledExchangeOutput) &&
         endpoint != static_cast<uint16_t>(
                         RCStage3RelationEndpoint::
                             CoupledPermutationOutput)) ||
        pin.statement_commitment.IsNull() ||
        pin.shape_commitment.IsNull() ||
        pin.logical_rows < 2 ||
        pin.logical_rows > pin.n_rows ||
        pin.n_rows != pin.n_coeffs ||
        (pin.n_rows & (pin.n_rows - 1)) != 0 ||
        pin.challenge_seed.IsNull() ||
        pin.column_roots.empty()) {
        return {};
    }
    HashWriter hash;
    hash << PIN_DOMAIN << pin.version;
    hash << endpoint;
    hash << pin.statement_commitment;
    hash << pin.shape_commitment;
    hash << pin.schedule_index;
    hash << pin.logical_rows << pin.n_rows << pin.n_coeffs;
    hash << pin.challenge_seed;
    hash << static_cast<uint32_t>(pin.column_roots.size());
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (pin.column_roots[i].column != i ||
            pin.column_roots[i].root.IsNull()) {
            return {};
        }
        hash << i << pin.column_roots[i].root;
    }
    return hash.GetHash();
}

uint256
ComputeRCStage3CoupledExchangePermutationProductCommitment(
    const RCStage3CoupledExchangePermutationProduct& product)
{
    if (product.version !=
            kRCStage3CoupledExchangePermutationProductVersion ||
        product.statement_commitment.IsNull() ||
        product.shape_commitment.IsNull() ||
        product.sigma.IsNull() ||
        product.exchange_stages.empty() ||
        product.permutation_stages.empty() ||
        product.exchange_input_endpoint_root.IsNull() ||
        product.exchange_hash_xof_endpoint_root.IsNull() ||
        product.exchange_output_endpoint_root.IsNull() ||
        product.permutation_input_endpoint_root.IsNull() ||
        product.permutation_output_endpoint_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCT_DOMAIN << product.version;
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    hash << product.sigma;
    hash << static_cast<uint32_t>(product.exchange_stages.size());
    for (const auto& stage : product.exchange_stages) {
        if (stage.stage_commitment.IsNull()) return {};
        hash << stage.stage_commitment;
    }
    hash << static_cast<uint32_t>(
        product.permutation_stages.size());
    for (const auto& stage : product.permutation_stages) {
        if (stage.stage_commitment.IsNull()) return {};
        hash << stage.stage_commitment;
    }
    hash << product.exchange_input_endpoint_root;
    hash << product.exchange_hash_xof_endpoint_root;
    hash << product.exchange_output_endpoint_root;
    hash << product.permutation_input_endpoint_root;
    hash << product.permutation_output_endpoint_root;
    return hash.GetHash();
}

bool BuildRCStage3CoupledExchangePermutationProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangePermutationWitness& witness,
    RCStage3CoupledExchangePermutationProduct& out,
    std::string* why)
{
    out = {};
    const auto exchange_schedule =
        BuildRCStage3CoupledExchangeSchedule(shape, why);
    const auto permutation_schedule =
        BuildRCStage3CoupledPermutationSchedule(
            statement, shape, why);
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    const uint64_t fixed_count =
        uint64_t{shape.barriers} * shape.lobes;
    const uint64_t material_count =
        uint64_t{shape.barriers} * shape.exchange_rounds;
    const uint64_t material_cells =
        material_count * StateCells(shape);
    const uint64_t fixed_cells =
        fixed_count * uint64_t{shape.rows_per_lobe} *
        shape.lobe_width;
    const uint64_t permutation_cells =
        uint64_t{shape.barriers} * StateCells(shape);
    if (!IsCoupledStatement(statement) ||
        statement.public_inputs.transcript_version !=
            shape.transcript_version ||
        statement.public_inputs.sigma.IsNull() ||
        statement_commitment.IsNull() ||
        shape_commitment.IsNull() ||
        exchange_schedule.empty() ||
        permutation_schedule.empty() ||
        witness.fixed_exchange_inputs.size() != fixed_count ||
        witness.material_exchange_inputs.size() != material_count ||
        witness.permutation_inputs.size() != shape.barriers ||
        fixed_cells >
            kRCStage3CoupledExchangePermutationMaxRows ||
        material_cells >
            kRCStage3CoupledExchangePermutationMaxRows ||
        permutation_cells >
            kRCStage3CoupledExchangePermutationMaxRows) {
        return Fail(why, "build_public_shape");
    }
    out.statement_commitment = statement_commitment;
    out.shape_commitment = shape_commitment;
    out.sigma = statement.public_inputs.sigma;

    uint32_t fixed_index = 0;
    uint32_t material_index = 0;
    for (const auto& schedule : exchange_schedule) {
        RCStage3CoupledExchangeStageProduct stage;
        stage.schedule = schedule;
        stage.pin.relation_endpoint =
            RCStage3RelationEndpoint::CoupledExchangeOutput;
        stage.pin.statement_commitment = statement_commitment;
        stage.pin.shape_commitment = shape_commitment;
        stage.pin.schedule_index = schedule.schedule_index;
        std::vector<std::vector<Fp3>> columns;
        if (schedule.kind ==
            RCStage3CoupledExchangeStageKind::FixedSegment) {
            stage.input =
                witness.fixed_exchange_inputs[fixed_index++];
            stage.output = stage.input;
            if (!BuildFixedColumns(
                    stage, stage.pin, columns, why)) {
                return false;
            }
        } else {
            std::vector<uint64_t> keys;
            std::vector<uint32_t> mapping;
            if (!BuildMaterial(
                    statement, shape, schedule,
                    witness.material_exchange_inputs[
                        material_index++],
                    stage, keys, mapping, why)) {
                return false;
            }
            stage.pin.relation_endpoint =
                RCStage3RelationEndpoint::CoupledExchangeOutput;
            stage.pin.statement_commitment = statement_commitment;
            stage.pin.shape_commitment = shape_commitment;
            stage.pin.schedule_index = schedule.schedule_index;
            if (!BuildMaterialColumns(
                    stage, keys, mapping,
                    stage.pin, columns, why)) {
                return false;
            }
        }
        stage.stage_commitment = StageCommitment(stage);
        if (stage.stage_commitment.IsNull()) {
            return Fail(why, "build_exchange_stage");
        }
        out.exchange_stages.push_back(std::move(stage));
    }

    for (const auto& schedule : permutation_schedule) {
        RCStage3CoupledPermutationStageProduct stage;
        stage.schedule = schedule;
        stage.input =
            witness.permutation_inputs[schedule.schedule_index];
        const auto mapping = ScheduleMapping(schedule);
        if (stage.input.size() != mapping.size()) {
            return Fail(why, "build_permutation_input");
        }
        stage.output.assign(stage.input.size(), 0);
        for (uint32_t i = 0; i < stage.input.size(); ++i) {
            if (mapping[i] >= stage.output.size()) {
                return Fail(why, "build_permutation_mapping");
            }
            stage.output[mapping[i]] = stage.input[i];
        }
        stage.pin.relation_endpoint =
            RCStage3RelationEndpoint::CoupledPermutationOutput;
        stage.pin.statement_commitment = statement_commitment;
        stage.pin.shape_commitment = shape_commitment;
        stage.pin.schedule_index = schedule.schedule_index;
        std::vector<std::vector<Fp3>> columns;
        if (!BuildPermutationColumns(
                stage.input, stage.output, mapping,
                stage.pin, columns, why)) {
            return false;
        }
        stage.stage_commitment = StageCommitment(stage);
        if (stage.stage_commitment.IsNull()) {
            return Fail(why, "build_permutation_stage");
        }
        out.permutation_stages.push_back(std::move(stage));
    }

    out.exchange_input_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledExchangeInput, out);
    out.exchange_hash_xof_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledExchangeHashXof, out);
    out.exchange_output_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledExchangeOutput, out);
    out.permutation_input_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledPermutationInput, out);
    out.permutation_output_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledPermutationOutput, out);
    out.product_commitment =
        ComputeRCStage3CoupledExchangePermutationProductCommitment(
            out);
    return !out.product_commitment.IsNull() ||
           Fail(why, "build_product");
}

bool ProveRCStage3CoupledExchangePermutationProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangePermutationWitness& witness,
    RCStage3CoupledExchangePermutationProduct& out,
    std::string* why)
{
    if (!BuildRCStage3CoupledExchangePermutationProduct(
            statement, shape, witness, out, why)) {
        return false;
    }
    for (auto& stage : out.exchange_stages) {
        std::vector<std::vector<Fp3>> columns;
        AirCS cs;
        if (stage.schedule.kind ==
            RCStage3CoupledExchangeStageKind::FixedSegment) {
            auto pin = stage.pin;
            if (!BuildFixedColumns(
                    stage, pin, columns, why)) {
                return false;
            }
            cs = BuildFixedCS(pin.n_rows);
        } else {
            RCStage3CoupledExchangeStageProduct expected;
            std::vector<uint64_t> keys;
            std::vector<uint32_t> mapping;
            if (!BuildMaterial(
                    statement, shape, stage.schedule,
                    stage.input, expected,
                    keys, mapping, why)) {
                return false;
            }
            auto pin = stage.pin;
            if (!BuildMaterialColumns(
                    stage, keys, mapping, pin,
                    columns, why)) {
                return false;
            }
            cs = BuildMaterialCS(pin);
            for (uint32_t i = 0;
                 i < stage.hash_executions.size(); ++i) {
                RCStage3CoupledExchangeHashExecution proved;
                if (!ProveHashExecution(
                        stage.hash_executions[i],
                        proved, why)) {
                    return Fail(why, "prove_hash");
                }
                stage.hash_executions[i] = std::move(proved);
            }
        }
        const auto proved = aq::AirQuotientProve<Fp3>(
            cs, columns, stage.pin.pin_commitment);
        if (!proved.ok || !proved.division_exact) {
            return Fail(why, "prove_exchange_air:" + proved.note);
        }
        stage.proof = proved.proof;
    }
    for (auto& stage : out.permutation_stages) {
        std::vector<std::vector<Fp3>> columns;
        auto pin = stage.pin;
        if (!BuildPermutationColumns(
                stage.input, stage.output,
                ScheduleMapping(stage.schedule),
                pin, columns, why)) {
            return false;
        }
        const auto proved = aq::AirQuotientProve<Fp3>(
            BuildPermutationCS(pin), columns,
            stage.pin.pin_commitment);
        if (!proved.ok || !proved.division_exact) {
            return Fail(
                why, "prove_permutation_air:" + proved.note);
        }
        stage.proof = proved.proof;
    }
    return true;
}

bool
ValidateRCStage3CoupledExchangePermutationProductSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangePermutationProduct& product,
    std::string* why)
{
    RCStage3CoupledExchangePermutationWitness witness;
    const auto exchange_schedule =
        BuildRCStage3CoupledExchangeSchedule(shape, why);
    const auto permutation_schedule =
        BuildRCStage3CoupledPermutationSchedule(
            statement, shape, why);
    if (product.exchange_stages.size() !=
            exchange_schedule.size() ||
        product.permutation_stages.size() !=
            permutation_schedule.size()) {
        return Fail(why, "validate_stage_count");
    }
    for (uint32_t i = 0; i < product.exchange_stages.size(); ++i) {
        const auto& stage = product.exchange_stages[i];
        if (stage.schedule != exchange_schedule[i]) {
            return Fail(why, "validate_exchange_order");
        }
        if (stage.schedule.kind ==
            RCStage3CoupledExchangeStageKind::FixedSegment) {
            witness.fixed_exchange_inputs.push_back(stage.input);
        } else {
            witness.material_exchange_inputs.push_back(stage.input);
        }
    }
    for (uint32_t i = 0; i < product.permutation_stages.size(); ++i) {
        if (product.permutation_stages[i].schedule !=
            permutation_schedule[i]) {
            return Fail(why, "validate_permutation_order");
        }
        witness.permutation_inputs.push_back(
            product.permutation_stages[i].input);
    }
    RCStage3CoupledExchangePermutationProduct expected;
    if (!BuildRCStage3CoupledExchangePermutationProduct(
            statement, shape, witness, expected, why)) {
        return false;
    }
    if (product.version != expected.version ||
        product.statement_commitment !=
            expected.statement_commitment ||
        product.shape_commitment != expected.shape_commitment ||
        product.sigma != expected.sigma ||
        product.exchange_input_endpoint_root !=
            expected.exchange_input_endpoint_root ||
        product.exchange_hash_xof_endpoint_root !=
            expected.exchange_hash_xof_endpoint_root ||
        product.exchange_output_endpoint_root !=
            expected.exchange_output_endpoint_root ||
        product.permutation_input_endpoint_root !=
            expected.permutation_input_endpoint_root ||
        product.permutation_output_endpoint_root !=
            expected.permutation_output_endpoint_root ||
        product.product_commitment !=
            expected.product_commitment) {
        return Fail(why, "validate_public_roots");
    }
    for (uint32_t i = 0; i < product.exchange_stages.size(); ++i) {
        const auto& actual = product.exchange_stages[i];
        const auto& canonical = expected.exchange_stages[i];
        if (actual.input != canonical.input ||
            actual.output != canonical.output ||
            !PinEqual(actual.pin, canonical.pin) ||
            actual.stage_commitment !=
                canonical.stage_commitment ||
            actual.hash_executions.size() !=
                canonical.hash_executions.size()) {
            return Fail(why, "validate_exchange_stage");
        }
        for (uint32_t j = 0;
             j < actual.hash_executions.size(); ++j) {
            const auto& hash = actual.hash_executions[j];
            const auto& expected_hash =
                canonical.hash_executions[j];
            if (!(hash.manifest == expected_hash.manifest) ||
                !HashPinEqual(
                    hash.semantic_pin,
                    expected_hash.semantic_pin) ||
                hash.proof.endpoint !=
                    RCStage3RelationEndpoint::
                        CoupledExchangeHashXof ||
                hash.proof.statement_commitment !=
                    product.statement_commitment ||
                hash.proof.manifest_commitment !=
                    hash.manifest.commitment) {
                return Fail(why, "validate_hash_stage");
            }
        }
    }
    for (uint32_t i = 0;
         i < product.permutation_stages.size(); ++i) {
        const auto& actual = product.permutation_stages[i];
        const auto& canonical = expected.permutation_stages[i];
        if (actual.input != canonical.input ||
            actual.output != canonical.output ||
            !PinEqual(actual.pin, canonical.pin) ||
            actual.stage_commitment !=
                canonical.stage_commitment) {
            return Fail(why, "validate_permutation_stage");
        }
    }
    return true;
}

bool VerifyRCStage3CoupledExchangeStages(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangePermutationProduct& product,
    std::string* why)
{
    if (!ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, product, why)) {
        return false;
    }
    for (const auto& stage : product.exchange_stages) {
        if (stage.schedule.kind ==
            RCStage3CoupledExchangeStageKind::FixedSegment) {
            if (!VerifyAir(
                    stage.pin,
                    BuildFixedCS(stage.pin.n_rows),
                    stage.proof, why)) {
                return false;
            }
        } else {
            for (const auto& hash : stage.hash_executions) {
                if (!VerifyHashExecution(
                        statement, shape, hash, why)) {
                    return false;
                }
            }
            if (!VerifyAir(
                    stage.pin,
                    BuildMaterialCS(stage.pin),
                    stage.proof, why)) {
                return false;
            }
        }
    }
    return true;
}

bool VerifyRCStage3CoupledPermutationStages(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangePermutationProduct& product,
    std::string* why)
{
    if (!ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, product, why)) {
        return false;
    }
    for (const auto& stage : product.permutation_stages) {
        if (!VerifyAir(
                stage.pin,
                BuildPermutationCS(stage.pin),
                stage.proof, why)) {
            return false;
        }
    }
    return true;
}

bool VerifyRCStage3CoupledExchangePermutationProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangePermutationProduct& product,
    std::string* why)
{
    return VerifyRCStage3CoupledExchangeStages(
               statement, shape, product, why) &&
           VerifyRCStage3CoupledPermutationStages(
               statement, shape, product, why);
}

RCStage3CoupledExchangePermutationProductAudit
CurrentRCStage3CoupledExchangePermutationProductAudit()
{
    RCStage3CoupledExchangePermutationProductAudit out;
    out.exact_exchange_schedule = true;
    out.fixed_segment_equality_executable = true;
    out.material_seed_sha256d_executable = true;
    out.material_sha_xof_executable = true;
    out.xor_and_indexed_permutation_executable = true;
    out.exact_public_permutation_schedule = true;
    out.permutation_indexed_product_executable = true;
    out.proof_owned_endpoint_roots = true;
    out.endpoints_34_through_38_bounded_local_complete =
        kRCStage3CoupledExchangePermutationBoundedLocalExecutable;
    out.external_producer_provenance_complete = false;
    out.production_streaming_complete =
        kRCStage3CoupledExchangePermutationProductionStreamingComplete;
    out.recursively_consumed =
        kRCStage3CoupledExchangePermutationRecursivelyConsumed;
    out.transitively_complete = false;
    out.remaining =
        "GEMM/mix producer roots and downstream consumer roots are not "
        "executed here; production material-exchange vectors require "
        "streamed shards and normalized recursive consumption";
    return out;
}

static_assert(
    kRCStage3CoupledExchangePermutationBoundedLocalExecutable);
static_assert(
    !kRCStage3CoupledExchangePermutationProductionStreamingComplete);
static_assert(
    !kRCStage3CoupledExchangePermutationRecursivelyConsumed);

} // namespace matmul::v4::rc
