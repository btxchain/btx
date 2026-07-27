// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_mix_product.h>

#include <hash.h>

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
namespace col = coupled_air_col;
using gf::Fp3;

constexpr char PIN_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_MIX_PIN_V1";
constexpr char AIR_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_MIX_AIR_V1";
constexpr char SEED_RECEIPT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_MIX_SEED_RECEIPT_V1";
constexpr char SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_MIX_SCHEDULE_V1";
constexpr char INPUT_ENDPOINT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_MIX_INPUT_ENDPOINT_V1";
constexpr char ARITHMETIC_ENDPOINT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_MIX_ARITHMETIC_ENDPOINT_V1";
constexpr char OUTPUT_ENDPOINT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_MIX_OUTPUT_ENDPOINT_V1";
constexpr char PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_MIX_PRODUCT_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:coupled_mix_product:" + detail;
    }
    return false;
}

bool IsCoupledStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Coupled ||
           statement.statement == RCStage3StatementKind::Composed;
}

bool IsPowerOfTwo(uint64_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2) return 2;
    if (value > (uint64_t{1} << 31)) return 0;
    uint64_t out{1};
    while (out < value) out <<= 1;
    return static_cast<uint32_t>(out);
}

uint32_t ExpectedMixNCoeffs(
    uint32_t n_rows, bool u64_wrap)
{
    if (!IsPowerOfTwo(n_rows)) return 0;
    if (u64_wrap) return n_rows;
    // The signed no-overflow identities have algebraic degree four:
    // deg(C) <= 4(N-1), hence quotient length <= 3N-3.
    return NextPowerOfTwo(
        uint64_t{3} * n_rows - 3);
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

Fp3 S(int64_t value)
{
    return Fp3::FromFp(gf::FromSigned(value));
}

void AppendLe32(std::vector<uint8_t>& out, uint32_t value)
{
    for (uint32_t shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

uint32_t ReadLe32(const std::array<uint8_t, 32>& bytes)
{
    return uint32_t{bytes[0]} |
           (uint32_t{bytes[1]} << 8) |
           (uint32_t{bytes[2]} << 16) |
           (uint32_t{bytes[3]} << 24);
}

uint256 DigestUint(const std::array<uint8_t, 32>& digest)
{
    return uint256{Span<const unsigned char>{
        digest.data(), digest.size()}};
}

RCCoupParams ParamsFromShape(const RCStage3CoupledShape& shape)
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

uint32_t StateCells(const RCStage3CoupledShape& shape)
{
    const uint64_t value =
        uint64_t{shape.lobes} * shape.rows_per_lobe *
        shape.lobe_width;
    return value <= std::numeric_limits<uint32_t>::max()
        ? static_cast<uint32_t>(value)
        : 0;
}

uint32_t Log2Exact(uint32_t value)
{
    if (!IsPowerOfTwo(value)) return 0;
    uint32_t bits{0};
    while (value > 1) {
        value >>= 1;
        ++bits;
    }
    return bits;
}

uint32_t RotlIndex(
    uint32_t value, uint32_t amount,
    uint32_t bits, uint32_t n)
{
    amount %= bits;
    return ((value << amount) |
            (value >> (bits - amount))) &
           (n - 1);
}

std::vector<uint8_t> MixSeedPreimage(
    const RCStage3CoupledShape& shape,
    const uint256& sigma, uint32_t barrier)
{
    const auto& tags =
        RCCoupDomainTagsForVersion(shape.transcript_version);
    const char* tag =
        shape.material_exchange ? tags.exchange : tags.mix;
    std::vector<uint8_t> out(
        reinterpret_cast<const uint8_t*>(tag),
        reinterpret_cast<const uint8_t*>(tag) +
            std::strlen(tag));
    out.insert(out.end(), sigma.begin(), sigma.end());
    AppendLe32(out, barrier);
    if (shape.material_exchange) {
        AppendLe32(out, shape.exchange_rows);
    }
    return out;
}

std::vector<uint8_t> MaskBlockPreimage(const uint256& mix_seed)
{
    std::vector<uint8_t> out(
        mix_seed.begin(), mix_seed.end());
    AppendLe32(out, 0);
    return out;
}

bool ShaShape(
    const RCStage3CoupledMixHashExecution& execution,
    const std::vector<uint8_t>& preimage,
    const uint256& statement_commitment,
    std::string* why)
{
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (execution.manifest.mode != ha::ShaMode::Single ||
        execution.manifest.preimage != preimage ||
        execution.manifest.commitment !=
            ha::CommitShaManifest(execution.manifest) ||
        !ha::BuildShaManifestBoundaryInstances(
            execution.manifest, boundaries, why) ||
        boundaries.empty() ||
        execution.proof.endpoint !=
            RCStage3RelationEndpoint::CoupledMixArithmetic ||
        execution.proof.statement_commitment !=
            statement_commitment ||
        execution.proof.manifest_commitment !=
            execution.manifest.commitment) {
        return Fail(why, "sha_shape");
    }
    return true;
}

bool ProveBundle(
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    hs::FlatBoundaryProofBundle& out,
    std::string* why)
{
    out = {};
    out.endpoint =
        RCStage3RelationEndpoint::CoupledMixArithmetic;
    out.statement_commitment = statement_commitment;
    out.manifest_commitment = manifest_commitment;
    out.proofs.resize(boundaries.size());
    const auto program =
        ha::BuildCanonicalProgram(
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
                    RCStage3RelationEndpoint::
                        CoupledMixArithmetic,
                    statement_commitment,
                    manifest_commitment,
                    i, boundaries.size()),
                out.proofs[i], why)) {
            return false;
        }
    }
    return true;
}

uint256 SeedReceipt(
    const RCStage3CoupledMixBarrierSeed& seed)
{
    if (seed.pattern >= kRCCoupMixPatterns ||
        seed.mix_seed.manifest.commitment.IsNull() ||
        seed.mask_block.manifest.commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << SEED_RECEIPT_DOMAIN;
    hash << kRCStage3CoupledMixProductVersion;
    hash << seed.barrier << seed.pattern << seed.mask;
    hash << seed.mix_seed.manifest.commitment;
    hash << seed.mask_block.manifest.commitment;
    return hash.GetHash();
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = aq::AirKind::kEverywhere;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

uint32_t MixBitColumn(uint32_t limb, uint32_t bit)
{
    return col::MIX_BITS + limb * 16U + bit;
}

Fp3 XorBit(const Fp3& a, const Fp3& b)
{
    return gf::Sub(
        gf::Add(a, b),
        gf::Mul(U(2), gf::Mul(a, b)));
}

void SetMixRow(
    std::vector<std::vector<Fp3>>& columns,
    uint32_t row, uint64_t a, uint64_t b)
{
    const std::array<uint64_t, 4> words{
        a, b, a + b, b - a};
    for (uint32_t family = 0; family < words.size();
         ++family) {
        for (uint32_t limb = 0; limb < 4; ++limb) {
            const uint32_t value = static_cast<uint32_t>(
                (words[family] >> (16U * limb)) &
                0xffffU);
            const uint32_t limb_index =
                family * 4 + limb;
            columns[limb_index][row] = U(value);
            for (uint32_t bit = 0; bit < 16; ++bit) {
                columns[MixBitColumn(
                    limb_index, bit)][row] =
                    U((value >> bit) & 1U);
            }
        }
    }
    uint32_t carry{0};
    uint32_t borrow{0};
    for (uint32_t limb = 0; limb < 4; ++limb) {
        const uint32_t av = static_cast<uint16_t>(
            a >> (16U * limb));
        const uint32_t bv = static_cast<uint16_t>(
            b >> (16U * limb));
        const uint32_t total = av + bv + carry;
        carry = total >> 16;
        columns[col::MIX_CARRY + limb][row] =
            U(carry);
        const uint32_t subtrahend = av + borrow;
        borrow = bv < subtrahend ? 1U : 0U;
        columns[col::MIX_BORROW + limb][row] =
            U(borrow);
    }
}

bool BuildColumnsAndOutputs(
    const RCStage3CoupledShape& shape,
    const std::vector<RCStage3CoupledMixOperation>& schedule,
    const std::vector<std::vector<int64_t>>& inputs,
    uint32_t n_rows,
    std::vector<std::vector<Fp3>>& columns,
    std::vector<std::vector<int64_t>>& outputs,
    std::string* why)
{
    const uint32_t n = StateCells(shape);
    if (n == 0 || schedule.empty() ||
        schedule.size() > n_rows ||
        inputs.size() != shape.barriers) {
        return Fail(why, "columns_public_shape");
    }
    columns.assign(
        kRCStage3CoupledMixColumns,
        std::vector<Fp3>(n_rows, Fp3::Zero()));
    outputs = inputs;
    uint64_t cursor{0};
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        if (outputs[barrier].size() != n) {
            return Fail(why, "columns_input_shape");
        }
        while (cursor < schedule.size() &&
               schedule[cursor].barrier == barrier) {
            const auto& op = schedule[cursor];
            if (op.operation_index != cursor ||
                op.pi >= n || op.pj >= n ||
                op.pi == op.pj) {
                return Fail(why, "columns_operation");
            }
            const uint64_t left = static_cast<uint64_t>(
                outputs[barrier][op.pi]);
            const uint64_t right = static_cast<uint64_t>(
                outputs[barrier][op.pj]);
            // The immutable arithmetic kernel exposes (A+B, B-A). Pattern
            // zero swaps its input ports so DIFF is left-right; pattern one
            // keeps them so DIFF is right-left.
            const uint64_t a =
                op.pattern == 0 ? right : left;
            const uint64_t b =
                op.pattern == 0 ? left : right;
            SetMixRow(columns, cursor, a, b);
            const uint64_t sum = a + b;
            const uint64_t diff = b - a;
            outputs[barrier][op.pi] =
                std::bit_cast<int64_t>(sum);
            outputs[barrier][op.pj] =
                std::bit_cast<int64_t>(diff);

            columns[kRCStage3CoupledMixActive][cursor] =
                Fp3::One();
            columns[kRCStage3CoupledMixBarrier][cursor] =
                U(op.barrier);
            columns[kRCStage3CoupledMixStageOrdinal][cursor] =
                U(op.stage_ordinal);
            columns[kRCStage3CoupledMixLogicalStage][cursor] =
                U(op.logical_stage);
            columns[kRCStage3CoupledMixPairOrdinal][cursor] =
                U(op.pair_ordinal);
            columns[kRCStage3CoupledMixI][cursor] =
                U(op.i);
            columns[kRCStage3CoupledMixJ][cursor] =
                U(op.j);
            columns[kRCStage3CoupledMixPi][cursor] =
                U(op.pi);
            columns[kRCStage3CoupledMixPj][cursor] =
                U(op.pj);
            columns[kRCStage3CoupledMixStride][cursor] =
                U(op.stride);
            columns[kRCStage3CoupledMixPattern][cursor] =
                U(op.pattern);
            columns[kRCStage3CoupledMixMask][cursor] =
                U(op.mask);
            columns[kRCStage3CoupledMixWrap][cursor] =
                U(RCCoupUseMixU64Wrap(
                    ParamsFromShape(shape),
                    shape.force_signed_mix));
            ++cursor;
        }
    }
    return cursor == schedule.size() ||
           Fail(why, "columns_schedule_coverage");
}

uint256 StateEndpointRoot(
    const char* domain,
    RCStage3RelationEndpoint endpoint,
    const RCStage3CoupledMixProduct& product,
    const std::vector<std::vector<int64_t>>& states)
{
    if (product.statement_commitment.IsNull() ||
        product.shape_commitment.IsNull() ||
        product.schedule_commitment.IsNull() ||
        states.empty()) {
        return {};
    }
    HashWriter hash;
    hash << domain << kRCStage3CoupledMixProductVersion;
    hash << static_cast<uint16_t>(endpoint);
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    hash << product.sigma;
    hash << product.schedule_commitment;
    hash << static_cast<uint64_t>(states.size());
    for (uint32_t barrier = 0;
         barrier < states.size(); ++barrier) {
        if (states[barrier].size() !=
            product.state_cells) {
            return {};
        }
        std::vector<Fp3> values;
        values.reserve(states[barrier].size());
        for (int64_t value : states[barrier]) {
            values.push_back(S(value));
        }
        const uint32_t n_coeffs =
            NextPowerOfTwo(values.size());
        if (n_coeffs == 0) return {};
        const uint256 root =
            aq::AirCommittedValuesRoot<Fp3>(
                values, n_coeffs);
        if (root.IsNull()) return {};
        hash << barrier << root;
    }
    return hash.GetHash();
}

uint256 ArithmeticEndpointRoot(
    const RCStage3CoupledMixProduct& product)
{
    const uint256 pin =
        ComputeRCStage3CoupledMixPinCommitment(
            product.arithmetic_pin);
    if (pin.IsNull() ||
        product.barrier_seeds.empty()) {
        return {};
    }
    HashWriter hash;
    hash << ARITHMETIC_ENDPOINT_DOMAIN;
    hash << kRCStage3CoupledMixProductVersion;
    hash << static_cast<uint16_t>(
        RCStage3RelationEndpoint::
            CoupledMixArithmetic);
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    hash << product.sigma;
    hash << product.schedule_commitment;
    hash << pin;
    hash << static_cast<uint64_t>(
        product.barrier_seeds.size());
    for (const auto& seed : product.barrier_seeds) {
        if (seed.receipt_commitment.IsNull()) return {};
        hash << seed.receipt_commitment;
    }
    return hash.GetHash();
}

uint256 ProductCommitment(
    const RCStage3CoupledMixProduct& product)
{
    if (product.version !=
            kRCStage3CoupledMixProductVersion ||
        product.statement_commitment.IsNull() ||
        product.shape_commitment.IsNull() ||
        product.sigma.IsNull() ||
        product.state_cells == 0 ||
        product.barrier_seeds.empty() ||
        product.schedule.empty() ||
        product.schedule_commitment.IsNull() ||
        product.input_endpoint_root.IsNull() ||
        product.arithmetic_endpoint_root.IsNull() ||
        product.output_endpoint_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCT_DOMAIN << product.version;
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    hash << product.sigma;
    hash << product.u64_wrap << product.state_cells;
    hash << product.schedule_commitment;
    hash << static_cast<uint64_t>(
        product.barrier_seeds.size());
    for (const auto& seed : product.barrier_seeds) {
        hash << seed.receipt_commitment;
    }
    hash << product.arithmetic_pin.pin_commitment;
    hash << product.input_endpoint_root;
    hash << product.arithmetic_endpoint_root;
    hash << product.output_endpoint_root;
    return hash.GetHash();
}

} // namespace

bool BuildRCStage3CoupledMixSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<RCStage3CoupledMixBarrierSeed>& barrier_seeds,
    std::vector<RCStage3CoupledMixOperation>& out,
    uint256& schedule_commitment,
    std::string* why)
{
    out.clear();
    schedule_commitment.SetNull();
    const auto counts =
        ExpectedRCStage3CoupledRelationCounts(
            RCStage3RelationRole::CoupledMix,
            shape, why);
    const uint32_t n = StateCells(shape);
    const uint32_t bits = Log2Exact(n);
    if (!IsCoupledStatement(statement) ||
        statement.public_inputs.sigma.IsNull() ||
        !counts.has_value() ||
        barrier_seeds.size() != shape.barriers ||
        n == 0 || bits == 0 ||
        counts->primary !=
            uint64_t{shape.barriers} * bits ||
        counts->secondary !=
            uint64_t{shape.barriers} * n) {
        return Fail(why, "schedule_public_shape");
    }
    const uint64_t operations =
        uint64_t{shape.barriers} * bits *
        (n / 2);
    if (operations == 0 ||
        operations >
            kRCStage3CoupledMixMaxOperations) {
        return Fail(why, "schedule_bounded_size");
    }
    out.reserve(operations);
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        const auto& seed = barrier_seeds[barrier];
        const uint32_t pattern =
            barrier % kRCCoupMixPatterns;
        if (seed.barrier != barrier ||
            seed.pattern != pattern ||
            seed.mask >= n ||
            seed.receipt_commitment != SeedReceipt(seed)) {
            return Fail(why, "schedule_seed");
        }
        for (uint32_t ordinal = 0;
             ordinal < bits; ++ordinal) {
            const uint32_t logical_stage =
                pattern == 0 ? ordinal
                             : bits - 1 - ordinal;
            const uint32_t stride =
                uint32_t{1} << logical_stage;
            uint32_t pair_ordinal{0};
            for (uint32_t i = 0; i < n; ++i) {
                const uint32_t j = i ^ stride;
                if (i >= j) continue;
                uint32_t pi;
                uint32_t pj;
                if (pattern == 0) {
                    pi = i ^ seed.mask;
                    pj = j ^ seed.mask;
                } else {
                    pi = RotlIndex(
                        i ^ seed.mask, 3, bits, n);
                    pj = RotlIndex(
                        j ^ seed.mask, 3, bits, n);
                }
                out.push_back({
                    out.size(), barrier, ordinal,
                    logical_stage, pair_ordinal,
                    i, j, pi, pj, stride,
                    pattern, seed.mask});
                ++pair_ordinal;
            }
            if (pair_ordinal != n / 2) {
                return Fail(why, "schedule_pairs");
            }
        }
    }
    if (out.size() != operations) {
        return Fail(why, "schedule_count");
    }
    HashWriter hash;
    hash << SCHEDULE_DOMAIN;
    hash << kRCStage3CoupledMixProductVersion;
    hash << CommitRCStage3CoupledStatement(
        statement.public_inputs);
    hash << CommitRCStage3CoupledShape(shape);
    hash << statement.public_inputs.sigma;
    hash << static_cast<uint64_t>(
        barrier_seeds.size());
    for (const auto& seed : barrier_seeds) {
        hash << seed.receipt_commitment;
    }
    hash << static_cast<uint64_t>(out.size());
    for (const auto& op : out) {
        hash << op.operation_index;
        hash << op.barrier << op.stage_ordinal;
        hash << op.logical_stage << op.pair_ordinal;
        hash << op.i << op.j << op.pi << op.pj;
        hash << op.stride << op.pattern << op.mask;
    }
    schedule_commitment = hash.GetHash();
    return !schedule_commitment.IsNull() ||
           Fail(why, "schedule_commitment");
}

uint256 ComputeRCStage3CoupledMixPinCommitment(
    const RCStage3CoupledMixPin& pin)
{
    if (pin.version !=
            kRCStage3CoupledMixProductVersion ||
        pin.statement_commitment.IsNull() ||
        pin.shape_commitment.IsNull() ||
        pin.sigma.IsNull() ||
        pin.schedule_commitment.IsNull() ||
        pin.logical_rows == 0 ||
        pin.logical_rows >
            kRCStage3CoupledMixMaxOperations ||
        !IsPowerOfTwo(pin.n_rows) ||
        pin.n_rows < pin.logical_rows ||
        pin.n_coeffs != ExpectedMixNCoeffs(
            pin.n_rows, pin.u64_wrap) ||
        pin.column_roots.size() !=
            kRCStage3CoupledMixColumns) {
        return {};
    }
    HashWriter hash;
    hash << PIN_DOMAIN << pin.version;
    hash << pin.statement_commitment;
    hash << pin.shape_commitment;
    hash << pin.sigma << pin.schedule_commitment;
    hash << pin.u64_wrap;
    hash << pin.logical_rows;
    hash << pin.n_rows << pin.n_coeffs;
    for (uint32_t i = 0;
         i < pin.column_roots.size(); ++i) {
        if (pin.column_roots[i].column != i ||
            pin.column_roots[i].root.IsNull()) {
            return {};
        }
        hash << i << pin.column_roots[i].root;
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3CoupledMixSeed(
    const RCStage3CoupledMixPin& pin)
{
    const uint256 commitment =
        ComputeRCStage3CoupledMixPinCommitment(pin);
    if (commitment.IsNull()) return {};
    HashWriter hash;
    hash << AIR_SEED_DOMAIN << commitment;
    return hash.GetHash();
}

bool BuildRCStage3CoupledMixConstraintSystem(
    const RCStage3CoupledMixPin& pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (pin.pin_commitment !=
            ComputeRCStage3CoupledMixPinCommitment(pin) ||
        pin.pin_commitment.IsNull()) {
        return Fail(why, "arithmetic_pin");
    }
    out.n_rows = pin.n_rows;
    out.n_columns = kRCStage3CoupledMixColumns;
    for (uint32_t limb = 0; limb < 16; ++limb) {
        for (uint32_t bit = 0; bit < 16; ++bit) {
            const uint32_t column =
                MixBitColumn(limb, bit);
            AddConstraint(
                out, "coupled.mix.limb_bit", 2,
                [column](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[column],
                        gf::Sub(
                            row[column], Fp3::One()));
                });
        }
        AddConstraint(
            out, "coupled.mix.limb_recompose", 1,
            [limb](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 value = Fp3::Zero();
                for (uint32_t bit = 0;
                     bit < 16; ++bit) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            U(1U << bit),
                            row[MixBitColumn(
                                limb, bit)]));
                }
                return gf::Sub(row[limb], value);
            });
    }
    for (uint32_t limb = 0; limb < 4; ++limb) {
        for (uint32_t column : {
                 col::MIX_CARRY + limb,
                 col::MIX_BORROW + limb}) {
            AddConstraint(
                out, "coupled.mix.carry_borrow_bit", 2,
                [column](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[column],
                        gf::Sub(
                            row[column], Fp3::One()));
                });
        }
        AddConstraint(
            out, "coupled.mix.add_u64", 1,
            [limb](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 carry_in =
                    limb == 0 ? Fp3::Zero()
                              : row[
                                    col::MIX_CARRY +
                                    limb - 1U];
                const Fp3 lhs = gf::Add(
                    gf::Add(
                        row[col::MIX_A_LIMB + limb],
                        row[col::MIX_B_LIMB + limb]),
                    carry_in);
                const Fp3 rhs = gf::Add(
                    row[col::MIX_SUM_LIMB + limb],
                    gf::Mul(
                        U(1U << 16),
                        row[
                            col::MIX_CARRY + limb]));
                return gf::Sub(lhs, rhs);
            });
        AddConstraint(
            out, "coupled.mix.sub_u64", 1,
            [limb](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 borrow_in =
                    limb == 0 ? Fp3::Zero()
                              : row[
                                    col::MIX_BORROW +
                                    limb - 1U];
                Fp3 relation = gf::Sub(
                    row[col::MIX_B_LIMB + limb],
                    row[col::MIX_A_LIMB + limb]);
                relation = gf::Sub(
                    relation, borrow_in);
                relation = gf::Add(
                    relation,
                    gf::Mul(
                        U(1U << 16),
                        row[
                            col::MIX_BORROW + limb]));
                return gf::Sub(
                    relation,
                    row[
                        col::MIX_DIFF_LIMB + limb]);
            });
    }
    for (uint32_t column : {
             kRCStage3CoupledMixActive,
             kRCStage3CoupledMixPattern,
             kRCStage3CoupledMixWrap}) {
        AddConstraint(
            out, "coupled.mix.control_bit", 2,
            [column](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[column],
                    gf::Sub(
                        row[column], Fp3::One()));
            });
    }
    if (!pin.u64_wrap) {
        const uint32_t sign_a =
            MixBitColumn(
                col::MIX_A_LIMB + 3, 15);
        const uint32_t sign_b =
            MixBitColumn(
                col::MIX_B_LIMB + 3, 15);
        const uint32_t sign_sum =
            MixBitColumn(
                col::MIX_SUM_LIMB + 3, 15);
        const uint32_t sign_diff =
            MixBitColumn(
                col::MIX_DIFF_LIMB + 3, 15);
        AddConstraint(
            out, "coupled.mix.signed_add_no_overflow", 4,
            [sign_a, sign_b, sign_sum](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 same = gf::Sub(
                    Fp3::One(),
                    XorBit(
                        row[sign_a], row[sign_b]));
                return gf::Mul(
                    same,
                    XorBit(
                        row[sign_sum], row[sign_a]));
            });
        AddConstraint(
            out, "coupled.mix.signed_sub_no_overflow", 4,
            [sign_a, sign_b, sign_diff](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    XorBit(
                        row[sign_b], row[sign_a]),
                    XorBit(
                        row[sign_diff], row[sign_b]));
            });
    }
    for (const auto& root : pin.column_roots) {
        out.preprocessed_roots.emplace_back(
            root.column, root.root);
    }
    return true;
}

bool VerifyRCStage3CoupledMixArithmeticProof(
    const RCStage3CoupledMixPin& pin,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildRCStage3CoupledMixConstraintSystem(
            pin, cs, why) ||
        proof.batch.columns.size() !=
            kRCStage3CoupledMixColumns + 1 ||
        proof.batch.column_len.size() !=
            kRCStage3CoupledMixColumns + 1 ||
        proof.batch.n_coeffs != pin.n_coeffs) {
        return Fail(why, "arithmetic_proof_shape");
    }
    for (uint32_t i = 0;
         i < pin.column_roots.size(); ++i) {
        if (proof.batch.columns[i].root !=
            pin.column_roots[i].root) {
            return Fail(why, "arithmetic_proof_root");
        }
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof,
            ComputeRCStage3CoupledMixSeed(pin),
            &air_why)) {
        return Fail(
            why, "arithmetic_air:" + air_why);
    }
    return true;
}

bool BuildRCStage3CoupledMixProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<std::vector<int64_t>>& input_states,
    RCStage3CoupledMixProduct& out,
    std::string* why)
{
    out = {};
    const auto counts =
        ExpectedRCStage3CoupledRelationCounts(
            RCStage3RelationRole::CoupledMix,
            shape, why);
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(
            statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    const uint32_t n = StateCells(shape);
    const RCCoupParams params = ParamsFromShape(shape);
    const bool u64_wrap = RCCoupUseMixU64Wrap(
        params, shape.force_signed_mix);
    if (!IsCoupledStatement(statement) ||
        statement_commitment.IsNull() ||
        shape_commitment.IsNull() ||
        statement.public_inputs.sigma.IsNull() ||
        statement.public_inputs.transcript_version !=
            shape.transcript_version ||
        !counts.has_value() || n == 0 ||
        input_states.size() != shape.barriers ||
        uint64_t{shape.barriers} * n >
            kRCStage3CoupledMixMaxInputCells ||
        (!u64_wrap &&
         !RCCoupPostMixFitsInt64(params))) {
        return Fail(why, "build_public_shape");
    }
    for (const auto& state : input_states) {
        if (state.size() != n) {
            return Fail(why, "build_input_shape");
        }
    }
    out.statement_commitment = statement_commitment;
    out.shape_commitment = shape_commitment;
    out.sigma = statement.public_inputs.sigma;
    out.u64_wrap = u64_wrap;
    out.state_cells = n;
    out.input_states = input_states;
    out.barrier_seeds.reserve(shape.barriers);
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        RCStage3CoupledMixBarrierSeed seed;
        seed.barrier = barrier;
        seed.pattern =
            barrier % kRCCoupMixPatterns;
        if (!ha::BuildShaManifest(
                MixSeedPreimage(
                    shape, out.sigma, barrier),
                ha::ShaMode::Single,
                seed.mix_seed.manifest, why)) {
            return Fail(why, "build_mix_seed");
        }
        seed.mix_seed.proof.endpoint =
            RCStage3RelationEndpoint::
                CoupledMixArithmetic;
        seed.mix_seed.proof.statement_commitment =
            statement_commitment;
        seed.mix_seed.proof.manifest_commitment =
            seed.mix_seed.manifest.commitment;
        const uint256 mix_seed =
            DigestUint(seed.mix_seed.manifest.digest);
        if (!ha::BuildShaManifest(
                MaskBlockPreimage(mix_seed),
                ha::ShaMode::Single,
                seed.mask_block.manifest, why)) {
            return Fail(why, "build_mask_block");
        }
        seed.mask_block.proof.endpoint =
            RCStage3RelationEndpoint::
                CoupledMixArithmetic;
        seed.mask_block.proof.statement_commitment =
            statement_commitment;
        seed.mask_block.proof.manifest_commitment =
            seed.mask_block.manifest.commitment;
        seed.mask =
            ReadLe32(seed.mask_block.manifest.digest) &
            (n - 1);
        seed.receipt_commitment = SeedReceipt(seed);
        if (seed.receipt_commitment.IsNull()) {
            return Fail(why, "build_seed_receipt");
        }
        out.barrier_seeds.push_back(std::move(seed));
    }
    if (!BuildRCStage3CoupledMixSchedule(
            statement, shape, out.barrier_seeds,
            out.schedule, out.schedule_commitment,
            why)) {
        return false;
    }
    auto& pin = out.arithmetic_pin;
    pin.statement_commitment = statement_commitment;
    pin.shape_commitment = shape_commitment;
    pin.sigma = out.sigma;
    pin.schedule_commitment = out.schedule_commitment;
    pin.u64_wrap = u64_wrap;
    pin.logical_rows = out.schedule.size();
    pin.n_rows = NextPowerOfTwo(pin.logical_rows);
    pin.n_coeffs = ExpectedMixNCoeffs(
        pin.n_rows, pin.u64_wrap);
    std::vector<std::vector<Fp3>> columns;
    if (pin.n_rows == 0 ||
        !BuildColumnsAndOutputs(
            shape, out.schedule, input_states,
            pin.n_rows, columns,
            out.output_states, why)) {
        return false;
    }
    for (uint32_t column = 0;
         column < columns.size(); ++column) {
        pin.column_roots.push_back({
            column,
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], pin.n_coeffs)});
    }
    pin.pin_commitment =
        ComputeRCStage3CoupledMixPinCommitment(pin);
    out.input_endpoint_root = StateEndpointRoot(
        INPUT_ENDPOINT_DOMAIN,
        RCStage3RelationEndpoint::CoupledMixInput,
        out, out.input_states);
    out.arithmetic_endpoint_root =
        ArithmeticEndpointRoot(out);
    out.output_endpoint_root = StateEndpointRoot(
        OUTPUT_ENDPOINT_DOMAIN,
        RCStage3RelationEndpoint::CoupledMixOutput,
        out, out.output_states);
    out.product_commitment = ProductCommitment(out);
    return !out.product_commitment.IsNull() ||
           Fail(why, "build_product_commitment");
}

bool ProveRCStage3CoupledMixProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<std::vector<int64_t>>& input_states,
    RCStage3CoupledMixProduct& out,
    std::string* why)
{
    if (!BuildRCStage3CoupledMixProduct(
            statement, shape, input_states, out, why)) {
        return false;
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    for (auto& seed : out.barrier_seeds) {
        for (auto* execution : {
                 &seed.mix_seed, &seed.mask_block}) {
            if (!ha::BuildShaManifestBoundaryInstances(
                    execution->manifest,
                    boundaries, why) ||
                !ProveBundle(
                    out.statement_commitment,
                    execution->manifest.commitment,
                    boundaries, execution->proof, why)) {
                return Fail(why, "prove_seed_sha");
            }
        }
    }
    std::vector<std::vector<Fp3>> columns;
    std::vector<std::vector<int64_t>> outputs;
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildColumnsAndOutputs(
            shape, out.schedule, out.input_states,
            out.arithmetic_pin.n_rows,
            columns, outputs, why) ||
        outputs != out.output_states ||
        !BuildRCStage3CoupledMixConstraintSystem(
            out.arithmetic_pin, cs, why)) {
        return Fail(why, "prove_columns");
    }
    auto proved = aq::AirQuotientProve<Fp3>(
        cs, columns,
        ComputeRCStage3CoupledMixSeed(
            out.arithmetic_pin));
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, "prove_arithmetic:" + proved.note);
    }
    out.arithmetic_proof = std::move(proved.proof);
    return true;
}

bool ValidateRCStage3CoupledMixProductSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledMixProduct& product,
    std::string* why)
{
    const auto counts =
        ExpectedRCStage3CoupledRelationCounts(
            RCStage3RelationRole::CoupledMix,
            shape, why);
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(
            statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    const uint32_t n = StateCells(shape);
    const RCCoupParams params = ParamsFromShape(shape);
    const bool u64_wrap = RCCoupUseMixU64Wrap(
        params, shape.force_signed_mix);
    if (!IsCoupledStatement(statement) ||
        product.version !=
            kRCStage3CoupledMixProductVersion ||
        product.statement_commitment !=
            statement_commitment ||
        product.shape_commitment != shape_commitment ||
        product.sigma !=
            statement.public_inputs.sigma ||
        product.sigma.IsNull() ||
        statement.public_inputs.transcript_version !=
            shape.transcript_version ||
        !counts.has_value() || n == 0 ||
        product.u64_wrap != u64_wrap ||
        product.state_cells != n ||
        product.barrier_seeds.size() !=
            shape.barriers ||
        product.input_states.size() !=
            shape.barriers ||
        product.output_states.size() !=
            shape.barriers ||
        uint64_t{shape.barriers} * n >
            kRCStage3CoupledMixMaxInputCells ||
        (!u64_wrap &&
         !RCCoupPostMixFitsInt64(params))) {
        return Fail(why, "schedule_public_shape");
    }
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        const auto& seed =
            product.barrier_seeds[barrier];
        if (seed.barrier != barrier ||
            seed.pattern !=
                barrier % kRCCoupMixPatterns ||
            !ShaShape(
                seed.mix_seed,
                MixSeedPreimage(
                    shape, product.sigma, barrier),
                statement_commitment, why)) {
            return Fail(why, "schedule_mix_seed");
        }
        const uint256 mix_seed =
            DigestUint(
                seed.mix_seed.manifest.digest);
        if (!ShaShape(
                seed.mask_block,
                MaskBlockPreimage(mix_seed),
                statement_commitment, why) ||
            seed.mask !=
                (ReadLe32(
                     seed.mask_block.manifest.digest) &
                 (n - 1)) ||
            seed.receipt_commitment !=
                SeedReceipt(seed)) {
            return Fail(why, "schedule_mask_seed");
        }
    }
    std::vector<RCStage3CoupledMixOperation>
        expected_schedule;
    uint256 expected_schedule_commitment;
    if (!BuildRCStage3CoupledMixSchedule(
            statement, shape, product.barrier_seeds,
            expected_schedule,
            expected_schedule_commitment, why) ||
        product.schedule != expected_schedule ||
        product.schedule_commitment !=
            expected_schedule_commitment) {
        return Fail(why, "schedule_operations");
    }
    const auto& pin = product.arithmetic_pin;
    if (pin.statement_commitment !=
            statement_commitment ||
        pin.shape_commitment != shape_commitment ||
        pin.sigma != product.sigma ||
        pin.schedule_commitment !=
            product.schedule_commitment ||
        pin.u64_wrap != u64_wrap ||
        pin.logical_rows != product.schedule.size() ||
        pin.n_rows !=
            NextPowerOfTwo(product.schedule.size()) ||
        pin.n_coeffs != ExpectedMixNCoeffs(
            pin.n_rows, pin.u64_wrap) ||
        pin.pin_commitment !=
            ComputeRCStage3CoupledMixPinCommitment(
                pin)) {
        return Fail(why, "schedule_pin");
    }
    std::vector<std::vector<Fp3>> columns;
    std::vector<std::vector<int64_t>> outputs;
    if (!BuildColumnsAndOutputs(
            shape, product.schedule,
            product.input_states, pin.n_rows,
            columns, outputs, why) ||
        outputs != product.output_states ||
        pin.column_roots.size() != columns.size()) {
        return Fail(why, "schedule_state_link");
    }
    for (uint32_t column = 0;
         column < columns.size(); ++column) {
        const uint256 expected =
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], pin.n_coeffs);
        if (pin.column_roots[column].column != column ||
            pin.column_roots[column].root != expected) {
            return Fail(why, "schedule_column_root");
        }
    }
    if (product.input_endpoint_root !=
            StateEndpointRoot(
                INPUT_ENDPOINT_DOMAIN,
                RCStage3RelationEndpoint::
                    CoupledMixInput,
                product, product.input_states) ||
        product.arithmetic_endpoint_root !=
            ArithmeticEndpointRoot(product) ||
        product.output_endpoint_root !=
            StateEndpointRoot(
                OUTPUT_ENDPOINT_DOMAIN,
                RCStage3RelationEndpoint::
                    CoupledMixOutput,
                product, product.output_states) ||
        product.product_commitment !=
            ProductCommitment(product)) {
        return Fail(why, "schedule_endpoint_roots");
    }
    return true;
}

bool VerifyRCStage3CoupledMixProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledMixProduct& product,
    std::string* why)
{
    if (!ValidateRCStage3CoupledMixProductSchedule(
            statement, shape, product, why)) {
        return Fail(why, "schedule");
    }
    for (const auto& seed : product.barrier_seeds) {
        if (!hs::VerifyShaManifestBundle(
                RCStage3RelationEndpoint::
                    CoupledMixArithmetic,
                seed.mix_seed.manifest,
                seed.mix_seed.proof, why) ||
            !hs::VerifyShaManifestBundle(
                RCStage3RelationEndpoint::
                    CoupledMixArithmetic,
                seed.mask_block.manifest,
                seed.mask_block.proof, why)) {
            return Fail(why, "seed_sha_proof");
        }
    }
    return VerifyRCStage3CoupledMixArithmeticProof(
        product.arithmetic_pin,
        product.arithmetic_proof, why);
}

RCStage3CoupledMixProductAudit
CurrentRCStage3CoupledMixProductAudit()
{
    RCStage3CoupledMixProductAudit out;
    out.immutable_full_butterfly_schedule = true;
    out.mix_seed_and_mask_sha_executed = true;
    out.index_relabelling_bound = true;
    out.complete_u64_limb_range_executed = true;
    out.signed_overflow_excluded = true;
    out.all_sum_difference_arithmetic_executed = true;
    out.stage_state_equality_executed = true;
    out.endpoints_39_40_41_bounded_local_complete =
        kRCStage3CoupledMixBoundedLocalProductExecutable;
    out.producer_provenance_complete = false;
    out.production_streaming_complete =
        kRCStage3CoupledMixProductionStreamingComplete;
    out.recursively_consumed = false;
    out.transitively_complete = false;
    out.remaining =
        "Pre-mix state roots are not yet equality-linked to the permutation/"
        "exchange producer; the bounded flat seed-SHA children and wide limb "
        "quotient are not yet streamed or consumed by the normalized "
        "recursive verifier.";
    return out;
}

} // namespace matmul::v4::rc
