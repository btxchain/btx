// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_extract_stream_ctl.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_tile_tree_hash_ctl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <utility>
#include <vector>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;
using gf::Fp3;

constexpr uint32_t BUILDER_MANTISSA = 0;
constexpr uint32_t BUILDER_REPEATED_SCALE = 1;
constexpr uint32_t BUILDER_SCALE_BIT0 = 2;
constexpr uint32_t BUILDER_SCALE_BIT1 = 3;
constexpr uint32_t BUILDER_SCALE_FACTOR = 4;
constexpr uint32_t BUILDER_OUTPUT = 5;
constexpr uint32_t BUILDER_COLUMNS = 6;

constexpr uint32_t MEMORY_ACTIVE = 0;
constexpr uint32_t MEMORY_VALUE = 5;
constexpr uint32_t MEMORY_EXPORT = 6;
constexpr uint32_t MEMORY_COLUMNS = 7;

constexpr uint32_t ROOT_ACTIVE = 0;
constexpr uint32_t ROOT_EXPECTED = 2;
constexpr uint32_t ROOT_VALUE = 3;
constexpr uint32_t ROOT_EXPORT = 4;
constexpr uint32_t ROOT_COLUMNS = 5;

constexpr uint32_t DIGEST_BRIDGE_ACTIVE = 0;
constexpr uint32_t DIGEST_BRIDGE_EXPECTED = 2;
constexpr uint32_t DIGEST_BRIDGE_VALUE = 3;
constexpr uint32_t DIGEST_BRIDGE_EXPORT = 4;
constexpr uint32_t DIGEST_BRIDGE_BIT_BASE = 5;
constexpr uint32_t DIGEST_BRIDGE_COLUMNS = 13;

constexpr uint32_t TILE_BRIDGE_ACTIVE = 0;
constexpr uint32_t TILE_BRIDGE_EXPECTED = 2;
constexpr uint32_t TILE_BRIDGE_VALUE = 3;
constexpr uint32_t TILE_BRIDGE_EXPORT = 4;
constexpr uint32_t TILE_BRIDGE_BYTE = 5;
constexpr uint32_t TILE_BRIDGE_SIGN = 6;
constexpr uint32_t TILE_BRIDGE_BIT_BASE = 7;
constexpr uint32_t TILE_BRIDGE_COLUMNS = 15;

constexpr uint32_t BANK_BRIDGE_OUTPUT = 5;
constexpr uint32_t BANK_BRIDGE_BYTE = 6;
constexpr uint32_t BANK_BRIDGE_BIT_BASE = 7;
constexpr uint32_t BANK_BRIDGE_ADDRESS = 15;
constexpr uint32_t BANK_BRIDGE_COLUMNS = 16;

constexpr uint32_t GOLDEN = 0x9E3779B9U;

// EpisodeWiring transpose dual-LogUp transport lane. Trace column layout
// mirrors matmul_v4_rc_stage3_episode_wiring_product.cpp's TransposeColumn.
constexpr uint32_t TRANSPOSE_MAPPED_INDEX = 0;
constexpr uint32_t TRANSPOSE_SOURCE_VALUE = 1;
constexpr uint32_t TRANSPOSE_DESTINATION_INDEX = 2;
constexpr uint32_t TRANSPOSE_DESTINATION_VALUE = 3;
constexpr uint32_t TRANSPOSE_DENOM_INVERSE_1 = 4;
constexpr uint32_t TRANSPOSE_RUNNING_PRODUCT_1 = 5;
constexpr uint32_t TRANSPOSE_DENOM_INVERSE_2 = 6;
constexpr uint32_t TRANSPOSE_RUNNING_PRODUCT_2 = 7;
constexpr uint32_t TRANSPOSE_COLUMNS = 8;
// Verifier-owned post-challenge columns: [beta0, gamma0, beta1, gamma1].
constexpr uint32_t TRANSPOSE_CHALLENGE_WIDTH = 4;

// Coupled indexed-permutation grand-product transport (Exchange/Permutation).
// Fingerprint uses a beta vector of LIMBS+1 components plus gamma, per lane.
constexpr uint32_t PERM_LIMBS = 4;
// Per lane L: beta[0..LIMBS] at L*6+0..4, gamma at L*6+5. Two lanes -> width 12.
constexpr uint32_t PERM_CHALLENGE_WIDTH = 12;
// Pure-permutation column layout (kPermutation* in the native product).
constexpr uint32_t PERM_MAPPED_INDEX = 0;
constexpr uint32_t PERM_DESTINATION_INDEX = 1;
constexpr uint32_t PERM_INPUT_LIMB = 2;
constexpr uint32_t PERM_OUTPUT_LIMB = PERM_INPUT_LIMB + PERM_LIMBS;
constexpr uint32_t PERM_INVERSE_1 = PERM_OUTPUT_LIMB + PERM_LIMBS;
constexpr uint32_t PERM_PRODUCT_1 = PERM_INVERSE_1 + 1;
constexpr uint32_t PERM_COLUMNS = PERM_INVERSE_1 + 4;
// Exchange (material) column layout (kMaterial* in the native product).
constexpr uint32_t EXCH_MAPPED_INDEX = 0;
constexpr uint32_t EXCH_DESTINATION_INDEX = 1;
constexpr uint32_t EXCH_MIXED_LIMB = 10;   // kMaterialMixedLimb
constexpr uint32_t EXCH_OUTPUT_LIMB = 14;  // kMaterialOutputLimb
constexpr uint32_t EXCH_INVERSE_1 = 210;   // kMaterialInverse1
constexpr uint32_t EXCH_PRODUCT_1 = 211;   // kMaterialProduct1
constexpr uint32_t EXCH_COLUMNS = 214;     // kMaterialColumns

// Additive gamma-power LogUp lanes (EpisodeExtract stream, EpisodeTileTree
// producer). Tuple = NS + gamma*stage + gamma^2*addr + gamma^3*value; with
// gamma a verifier-owned column the inverse constraint is raw degree 5. Shared
// challenge packing [gamma1, alpha1, gamma2, alpha2, sum1, sum2] (width 6),
// lane L: gamma=2L, alpha=2L+1, terminal-sum=4+L.
constexpr uint32_t GAMMA_POWER_CHALLENGE_WIDTH = 6;
// extract_stream: source at 0, then mask, address, inverse1/2, running1/2.
constexpr uint32_t XSTREAM_SOURCE = 0;
constexpr uint32_t XSTREAM_MASK = 1;
constexpr uint32_t XSTREAM_ADDRESS = 2;
constexpr uint32_t XSTREAM_INVERSE_1 = 3;
constexpr uint32_t XSTREAM_INVERSE_2 = 4;
constexpr uint32_t XSTREAM_RUNNING_1 = 5;
constexpr uint32_t XSTREAM_RUNNING_2 = 6;
constexpr uint32_t XSTREAM_COLUMNS = 7;
// tile_tree producer: 32 output bytes, then two 32-wide inverse banks and two
// running columns (ProducerColumns(32)).
constexpr uint32_t TILETREE_INVERSE_1_BASE = 32;
constexpr uint32_t TILETREE_INVERSE_2_BASE = 64;
constexpr uint32_t TILETREE_RUNNING_1 = 96;
constexpr uint32_t TILETREE_RUNNING_2 = 97;
constexpr uint32_t TILETREE_COLUMNS = 98;

bool Fail(std::string* why, const char* detail)
{
    if (why != nullptr) {
        *why = std::string{"stage3:role_bytecode:"} + detail;
    }
    return false;
}

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

class ProgramBuilder {
public:
    ProgramBuilder(
        RCStage3RelationRole role,
        uint32_t ordinal,
        aq::AirKind kind,
        uint32_t degree,
        uint32_t width,
        uint32_t challenge_width = 0)
    {
        m_program.role = role;
        m_program.constraint_ordinal = ordinal;
        m_program.kind = kind;
        m_program.declared_degree = degree;
        m_program.current_width = width;
        m_program.next_width = width;
        m_program.challenge_width = challenge_width;
    }

    uint32_t Current(uint32_t column)
    {
        return Push(
            {cb::Opcode::Current, column, 0, Fp3::Zero()});
    }
    uint32_t Next(uint32_t column)
    {
        return Push(
            {cb::Opcode::Next, column, 0, Fp3::Zero()});
    }
    /** Load a verifier-owned post-challenge column (beta/gamma). */
    uint32_t Challenge(uint32_t column)
    {
        return Push(
            {cb::Opcode::Challenge, column, 0, Fp3::Zero()});
    }
    uint32_t Constant(const Fp3& value)
    {
        return Push(
            {cb::Opcode::Constant, 0, 0, value});
    }
    uint32_t Add(uint32_t lhs, uint32_t rhs)
    {
        return Push(
            {cb::Opcode::Add, lhs, rhs, Fp3::Zero()});
    }
    uint32_t Sub(uint32_t lhs, uint32_t rhs)
    {
        return Push(
            {cb::Opcode::Sub, lhs, rhs, Fp3::Zero()});
    }
    uint32_t Mul(uint32_t lhs, uint32_t rhs)
    {
        return Push(
            {cb::Opcode::Mul, lhs, rhs, Fp3::Zero()});
    }
    cb::Program Take() { return std::move(m_program); }

private:
    uint32_t Push(cb::Instruction instruction)
    {
        const uint32_t result =
            static_cast<uint32_t>(
                m_program.instructions.size());
        m_program.instructions.push_back(
            std::move(instruction));
        return result;
    }

    cb::Program m_program;
};

template <typename Fn>
void Append(
    cb::ProgramTable& table,
    aq::AirKind kind,
    uint32_t degree,
    Fn&& build)
{
    ProgramBuilder builder{
        table.role,
        static_cast<uint32_t>(table.programs.size()),
        kind,
        degree,
        table.current_width,
        table.challenge_width};
    build(builder);
    table.programs.push_back(builder.Take());
}

template <typename Fn>
void Append(
    cb::ProgramTable& table,
    uint32_t degree,
    Fn&& build)
{
    Append(
        table, aq::AirKind::kEverywhere,
        degree, std::forward<Fn>(build));
}

void AppendBoolean(
    cb::ProgramTable& table,
    uint32_t column)
{
    Append(table, 2, [column](ProgramBuilder& b) {
        const uint32_t value = b.Current(column);
        const uint32_t one = b.Constant(Fp3::One());
        b.Mul(value, b.Sub(value, one));
    });
}

uint32_t BitSum(
    ProgramBuilder& b,
    uint32_t first,
    uint32_t count)
{
    uint32_t sum = b.Constant(Fp3::Zero());
    uint64_t weight = 1;
    for (uint32_t bit = 0; bit < count; ++bit) {
        const uint32_t value = b.Current(first + bit);
        const uint32_t coefficient =
            b.Constant(U(weight));
        sum = b.Add(
            sum, b.Mul(value, coefficient));
        weight <<= 1;
    }
    return sum;
}

// Raw SSA degree of the final register, using the exact rule the bytecode
// validator enforces (Current/Next/Challenge = 1, Constant = 0, Mul adds
// operand degrees, Add/Sub take the max). Setting declared_degree from this
// keeps the ValidateProgram degree check exact for programs whose algebraic
// degree is inconvenient to track by hand (the SHA/RcSampler kernels below).
uint32_t RawDegree(const std::vector<cb::Instruction>& ins)
{
    std::vector<uint32_t> degree(ins.size(), 0);
    for (uint32_t i = 0; i < ins.size(); ++i) {
        const cb::Instruction& in = ins[i];
        switch (in.opcode) {
        case cb::Opcode::Current:
        case cb::Opcode::Next:
        case cb::Opcode::Challenge:
            degree[i] = 1;
            break;
        case cb::Opcode::Constant:
            degree[i] = 0;
            break;
        case cb::Opcode::Mul:
            degree[i] = degree[in.lhs] + degree[in.rhs];
            break;
        default: // Add / Sub
            degree[i] = std::max(degree[in.lhs], degree[in.rhs]);
            break;
        }
    }
    return ins.empty() ? 0 : degree.back();
}

// Append a program whose declared_degree is recomputed from its instructions.
template <typename Fn>
void AppendAuto(
    cb::ProgramTable& table,
    aq::AirKind kind,
    Fn&& build)
{
    ProgramBuilder builder{
        table.role,
        static_cast<uint32_t>(table.programs.size()),
        kind,
        1,
        table.current_width,
        table.challenge_width};
    build(builder);
    cb::Program program = builder.Take();
    program.declared_degree = RawDegree(program.instructions);
    table.programs.push_back(std::move(program));
}

bool Finalize(
    cb::ProgramTable& table,
    std::string* why)
{
    table.next_width = table.current_width;
    return cb::ValidateProgramTable(table, why);
}

namespace ha = stage3_hash_air;

// ---- Shared emit primitives for the RcSampler and SHA-256 hash kernels. ----
// Each reproduces the exact FIELD VALUE of its native counterpart; the SSA tree
// shape is irrelevant because Fp3 values are canonical, so evaluation stays
// bit-identical to the native constraint closure.

// nibble(base) = sum_{i<4} 2^i * CURRENT[base+i].
uint32_t Nibble(ProgramBuilder& b, uint32_t base)
{
    uint32_t acc = b.Constant(Fp3::Zero());
    for (uint32_t i = 0; i < 4; ++i) {
        const uint32_t coeff = b.Constant(U(uint64_t{1} << i));
        acc = b.Add(acc, b.Mul(coeff, b.Current(base + i)));
    }
    return acc;
}

// Bool(v) = v*(v-1).
uint32_t EmitBool(ProgramBuilder& b, uint32_t v)
{
    return b.Mul(v, b.Sub(v, b.Constant(Fp3::One())));
}

// Xor2(a,c) = a + c - 2*a*c.
uint32_t EmitXor2(ProgramBuilder& b, uint32_t a, uint32_t c)
{
    const uint32_t two = b.Constant(U(2));
    return b.Sub(b.Add(a, c), b.Mul(two, b.Mul(a, c)));
}

uint32_t EmitXor3(ProgramBuilder& b, uint32_t a, uint32_t c, uint32_t d)
{
    return EmitXor2(b, EmitXor2(b, a, c), d);
}

// Choice(a,c,d) = d + a*(c-d).
uint32_t EmitChoice(ProgramBuilder& b, uint32_t a, uint32_t c, uint32_t d)
{
    return b.Add(d, b.Mul(a, b.Sub(c, d)));
}

// Majority(a,c,d) = a*c + a*d + c*d - 2*a*c*d.
uint32_t EmitMajority(ProgramBuilder& b, uint32_t a, uint32_t c, uint32_t d)
{
    const uint32_t ac = b.Mul(a, c);
    const uint32_t two = b.Constant(U(2));
    const uint32_t sum =
        b.Add(b.Add(ac, b.Mul(a, d)), b.Mul(c, d));
    return b.Sub(sum, b.Mul(two, b.Mul(ac, d)));
}

// Native stage3_hash_air::TransformBit over word-0 bits: rotate-right reads
// bit (out+amount)&31; shift-right reads (out+amount) or a zero constant when
// the source falls off the high end.
//
// The off-the-high-end case is padded as Constant(0)*Current(col) rather than
// a bare Constant(0): both evaluate to the identical field value (zero), but
// the padded form keeps this operand's RAW SSA degree at 1, matching the
// degree of the ordinary in-range read. Native declares every sigma S-box
// constraint's alg_degree as a uniform 4 regardless of which bit is being
// produced (see stage3_hash_air::BuildFixedProgramConstraintSystem), so the
// bytecode's auto-derived declared_degree (RawDegree of the actual
// instruction DAG) must also come out to a uniform 4 for every bit, not drop
// to 3 whenever this fallback fires -- otherwise AttachConstraintBytecodeInterpreter's
// per-ordinal (kind, alg_degree) cross-check against the child's native
// constraint list fails closed for those specific bit ordinals.
uint32_t EmitTransformBit(
    ProgramBuilder& b, uint32_t out,
    ha::BitTransformKind kind, uint8_t amount)
{
    if (kind == ha::BitTransformKind::RotateRight) {
        return b.Current(ha::BitColumn(0, (out + amount) & 31U));
    }
    const uint32_t source = out + amount;
    if (source < 32U) return b.Current(ha::BitColumn(0, source));
    return b.Mul(b.Constant(Fp3::Zero()), b.Current(ha::BitColumn(0, 0)));
}

// XorRot rotate amounts for fixed-program selectors 1..4 (native ROTS).
constexpr std::array<uint8_t, 4> SHA_FIXED_ROTS{16, 12, 8, 7};

// Native stage3_hash_air::SelectorTransforms(7+which): the three fixed
// right-transforms of the small/big sigma S-boxes.
std::array<ha::BitTransform, 3> SigmaTransforms(uint32_t which)
{
    using K = ha::BitTransformKind;
    switch (which) {
    case 0: // selector 7: small sigma0
        return {{{K::RotateRight, 7}, {K::RotateRight, 18}, {K::ShiftRight, 3}}};
    case 1: // selector 8: small sigma1
        return {{{K::RotateRight, 17}, {K::RotateRight, 19}, {K::ShiftRight, 10}}};
    case 2: // selector 9: big sigma0
        return {{{K::RotateRight, 2}, {K::RotateRight, 13}, {K::RotateRight, 22}}};
    default: // selector 10: big sigma1
        return {{{K::RotateRight, 6}, {K::RotateRight, 11}, {K::RotateRight, 25}}};
    }
}

bool BuildDequantProgramTable(
    RCStage3RelationRole role,
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.role = role;
    out.current_width = BUILDER_COLUMNS;

    AppendBoolean(out, BUILDER_SCALE_BIT0);
    AppendBoolean(out, BUILDER_SCALE_BIT1);
    Append(out, 1, [](ProgramBuilder& b) {
        const uint32_t scale =
            b.Current(BUILDER_REPEATED_SCALE);
        const uint32_t bit0 =
            b.Current(BUILDER_SCALE_BIT0);
        const uint32_t two = b.Constant(U(2));
        const uint32_t bit1 =
            b.Current(BUILDER_SCALE_BIT1);
        b.Sub(scale, b.Add(bit0, b.Mul(two, bit1)));
    });
    Append(out, 2, [](ProgramBuilder& b) {
        const uint32_t factor =
            b.Current(BUILDER_SCALE_FACTOR);
        const uint32_t one0 =
            b.Constant(Fp3::One());
        const uint32_t bit0 =
            b.Current(BUILDER_SCALE_BIT0);
        const uint32_t one1 =
            b.Constant(Fp3::One());
        const uint32_t three = b.Constant(U(3));
        const uint32_t bit1 =
            b.Current(BUILDER_SCALE_BIT1);
        const uint32_t lhs = b.Add(one0, bit0);
        const uint32_t rhs =
            b.Add(one1, b.Mul(three, bit1));
        b.Sub(factor, b.Mul(lhs, rhs));
    });
    Append(out, 2, [](ProgramBuilder& b) {
        const uint32_t output =
            b.Current(BUILDER_OUTPUT);
        const uint32_t mantissa =
            b.Current(BUILDER_MANTISSA);
        const uint32_t factor =
            b.Current(BUILDER_SCALE_FACTOR);
        b.Sub(output, b.Mul(mantissa, factor));
    });
    return Finalize(out, why);
}

} // namespace

bool BuildRCStage3EpisodeBuilderTraceProgramTable(
    cb::ProgramTable& out,
    std::string* why)
{
    return BuildDequantProgramTable(
        RCStage3RelationRole::EpisodeDeterministicBuilder,
        out, why);
}

bool BuildRCStage3EpisodeHeaderTargetEqualityProgramTable(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.role = RCStage3RelationRole::EpisodeDigest;
    out.current_width = 2;
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(b.Current(0), b.Current(1));
    });
    return Finalize(out, why);
}

bool BuildRCStage3EpisodePowProgramTable(
    cb::ProgramTable& out,
    std::string* why)
{
    constexpr uint32_t digest = 0;
    constexpr uint32_t target = 1;
    constexpr uint32_t borrow = 2;
    constexpr uint32_t borrow_out = 3;
    constexpr uint32_t diff_bit_base = 4;
    constexpr uint32_t columns = 12;
    out = {};
    out.role = RCStage3RelationRole::EpisodeDigest;
    out.current_width = columns;
    AppendBoolean(out, borrow);
    AppendBoolean(out, borrow_out);
    for (uint32_t bit = 0; bit < 8; ++bit) {
        AppendBoolean(out, diff_bit_base + bit);
    }
    Append(out, 1, [](ProgramBuilder& b) {
        uint32_t difference =
            b.Constant(Fp3::Zero());
        for (uint32_t bit = 0; bit < 8; ++bit) {
            difference = b.Add(
                difference,
                b.Mul(
                    b.Constant(U(uint64_t{1} << bit)),
                    b.Current(diff_bit_base + bit)));
        }
        b.Sub(
            b.Add(
                b.Sub(
                    b.Sub(
                        b.Current(target),
                        b.Current(digest)),
                    b.Current(borrow)),
                b.Mul(
                    b.Constant(U(256)),
                    b.Current(borrow_out))),
            difference);
    });
    Append(
        out, aq::AirKind::kTransition, 1,
        [](ProgramBuilder& b) {
            b.Sub(
                b.Next(borrow),
                b.Current(borrow_out));
        });
    Append(
        out, aq::AirKind::kFirstRow, 1,
        [](ProgramBuilder& b) {
            b.Current(borrow);
        });
    Append(
        out, aq::AirKind::kLastRow, 1,
        [](ProgramBuilder& b) {
            b.Current(borrow_out);
        });
    return Finalize(out, why);
}

bool BuildRCStage3CoupledBankDequantProgramTableCanonical(
    cb::ProgramTable& out,
    std::string* why)
{
    return BuildDequantProgramTable(
        RCStage3RelationRole::CoupledBank,
        out, why);
}

bool BuildRCStage3CoupledBankByteBridgeProgramTable(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.role = RCStage3RelationRole::CoupledBank;
    out.current_width = BANK_BRIDGE_COLUMNS;
    for (uint32_t bit = 0; bit < 8; ++bit) {
        AppendBoolean(
            out, BANK_BRIDGE_BIT_BASE + bit);
    }
    Append(out, 1, [](ProgramBuilder& b) {
        uint32_t reconstructed =
            b.Constant(Fp3::Zero());
        for (uint32_t bit = 0; bit < 8; ++bit) {
            reconstructed = b.Add(
                reconstructed,
                b.Mul(
                    b.Constant(U(uint64_t{1} << bit)),
                    b.Current(
                        BANK_BRIDGE_BIT_BASE + bit)));
        }
        b.Sub(
            b.Current(BANK_BRIDGE_BYTE),
            reconstructed);
    });
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(
            b.Current(BANK_BRIDGE_OUTPUT),
            b.Sub(
                b.Current(BANK_BRIDGE_BYTE),
                b.Mul(
                    b.Constant(U(256)),
                    b.Current(
                        BANK_BRIDGE_BIT_BASE + 7))));
    });
    // ADDRESS is verifier-owned preprocessing used by the two CTL lanes. It
    // is part of the immutable table width even though the pre-challenge
    // byte relation does not load it.
    static_assert(BANK_BRIDGE_ADDRESS + 1 == BANK_BRIDGE_COLUMNS);
    return Finalize(out, why);
}

bool BuildRCStage3EpisodeSemanticMemoryProgramTable(
    RCStage3RelationRole role,
    cb::ProgramTable& out,
    std::string* why)
{
    if (!IsRCStage3EpisodeRole(role)) {
        out = {};
        return Fail(why, "episode_memory_role");
    }
    out = {};
    out.role = role;
    out.current_width = MEMORY_COLUMNS;
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(
            b.Current(MEMORY_EXPORT),
            b.Current(MEMORY_VALUE));
    });
    for (const uint32_t column : {
             MEMORY_VALUE, MEMORY_EXPORT}) {
        Append(out, 2, [column](ProgramBuilder& b) {
            const uint32_t one =
                b.Constant(Fp3::One());
            const uint32_t active =
                b.Current(MEMORY_ACTIVE);
            const uint32_t value =
                b.Current(column);
            b.Mul(b.Sub(one, active), value);
        });
    }
    return Finalize(out, why);
}

bool BuildRCStage3ExtractMixProgramTable(
    RCStage3RelationRole role,
    cb::ProgramTable& out,
    std::string* why)
{
    if (role != RCStage3RelationRole::EpisodeExtract &&
        role != RCStage3RelationRole::CoupledExtract) {
        out = {};
        return Fail(why, "extract_role");
    }
    out = {};
    out.role = role;
    out.current_width =
        kRCStage3EpisodeExtractMixColumns;

    for (uint32_t column = kRCStage3ExtractMixBranch;
         column < kRCStage3EpisodeExtractMixColumns;
         ++column) {
        AppendBoolean(out, column);
    }
    Append(out, 4, [](ProgramBuilder& b) {
        const uint32_t branch =
            b.Current(kRCStage3ExtractMixBranch);
        const uint32_t one = b.Constant(Fp3::One());
        const uint32_t boolean =
            b.Mul(branch, b.Sub(branch, one));
        b.Mul(boolean, boolean);
    });
    for (const auto [target, first] : {
             std::pair{
                 kRCStage3ExtractMixU,
                 kRCStage3ExtractMixUBits},
             std::pair{
                 kRCStage3ExtractMixQ,
                 kRCStage3ExtractMixQBits},
             std::pair{
                 kRCStage3ExtractMixV,
                 kRCStage3ExtractMixVBits}}) {
        Append(out, 1, [target, first](ProgramBuilder& b) {
            const uint32_t value = b.Current(target);
            b.Sub(
                value,
                BitSum(
                    b, first,
                    kRCStage3EpisodeExtractMixBits));
        });
    }
    Append(out, 1, [](ProgramBuilder& b) {
        const uint32_t golden = b.Constant(U(GOLDEN));
        const uint32_t q =
            b.Current(kRCStage3ExtractMixQ);
        const uint32_t difference = BitSum(
            b, kRCStage3ExtractMixQDifferenceBits,
            kRCStage3EpisodeExtractMixBits);
        b.Sub(golden, b.Add(q, difference));
    });
    Append(out, 1, [](ProgramBuilder& b) {
        const uint32_t u =
            b.Current(kRCStage3ExtractMixU);
        const uint32_t golden = b.Constant(U(GOLDEN));
        const uint32_t q =
            b.Current(kRCStage3ExtractMixQ);
        const uint32_t two32 =
            b.Constant(U(UINT64_C(1) << 32));
        const uint32_t v =
            b.Current(kRCStage3ExtractMixV);
        b.Sub(
            b.Mul(u, golden),
            b.Add(b.Mul(q, two32), v));
    });
    Append(out, 1, [](ProgramBuilder& b) {
        const uint32_t h =
            b.Current(kRCStage3ExtractMixH);
        b.Sub(
            h,
            BitSum(
                b, kRCStage3ExtractMixVBits + 28, 4));
    });
    // This expression is algebraic degree three: branch times the quadratic
    // XOR expansion.  The old callback metadata said degree two, relying on
    // separate Boolean reductions.  The canonical bytecode records the raw
    // polynomial degree so quotient sizing cannot silently understate it.
    Append(out, 3, [](ProgramBuilder& b) {
        const uint32_t lo = BitSum(
            b, kRCStage3ExtractMixYLoBits,
            kRCStage3EpisodeExtractMixBits);
        uint32_t xored =
            b.Constant(Fp3::Zero());
        uint64_t weight = 1;
        for (uint32_t bit = 0;
             bit < kRCStage3EpisodeExtractMixBits;
             ++bit) {
            const uint32_t a = b.Current(
                kRCStage3ExtractMixYLoBits + bit);
            const uint32_t other = b.Current(
                kRCStage3ExtractMixYHiBits + bit);
            const uint32_t two = b.Constant(U(2));
            const uint32_t x = b.Sub(
                b.Add(a, other),
                b.Mul(two, b.Mul(a, other)));
            const uint32_t coefficient =
                b.Constant(U(weight));
            xored = b.Add(
                xored, b.Mul(x, coefficient));
            weight <<= 1;
        }
        const uint32_t branch =
            b.Current(kRCStage3ExtractMixBranch);
        const uint32_t one = b.Constant(Fp3::One());
        const uint32_t selected = b.Add(
            b.Mul(branch, lo),
            b.Mul(b.Sub(one, branch), xored));
        const uint32_t u =
            b.Current(kRCStage3ExtractMixU);
        b.Sub(u, selected);
    });
    return Finalize(out, why);
}

bool BuildRCStage3RootChainVectorProgramTable(
    RCStage3RelationRole role,
    cb::ProgramTable& out,
    std::string* why)
{
    if (role != RCStage3RelationRole::EpisodeDigest &&
        role != RCStage3RelationRole::CoupledBarrier &&
        role != RCStage3RelationRole::CoupledDigest) {
        out = {};
        return Fail(why, "root_chain_role");
    }
    out = {};
    out.role = role;
    out.current_width = ROOT_COLUMNS;
    AppendBoolean(out, ROOT_ACTIVE);
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(
            b.Current(ROOT_VALUE),
            b.Current(ROOT_EXPECTED));
    });
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(
            b.Current(ROOT_EXPORT),
            b.Current(ROOT_VALUE));
    });
    Append(out, 2, [](ProgramBuilder& b) {
        const uint32_t one = b.Constant(Fp3::One());
        const uint32_t active =
            b.Current(ROOT_ACTIVE);
        const uint32_t value =
            b.Current(ROOT_VALUE);
        b.Mul(b.Sub(one, active), value);
    });
    return Finalize(out, why);
}

bool BuildRCStage3EpisodeDigestPreimageByteBridgeProgramTable(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.role = RCStage3RelationRole::EpisodeDigest;
    out.current_width = DIGEST_BRIDGE_COLUMNS;
    AppendBoolean(out, DIGEST_BRIDGE_ACTIVE);
    for (uint32_t bit = 0; bit < 8; ++bit) {
        AppendBoolean(out, DIGEST_BRIDGE_BIT_BASE + bit);
    }
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(
            b.Current(DIGEST_BRIDGE_VALUE),
            BitSum(b, DIGEST_BRIDGE_BIT_BASE, 8));
    });
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(
            b.Current(DIGEST_BRIDGE_VALUE),
            b.Current(DIGEST_BRIDGE_EXPECTED));
    });
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(
            b.Current(DIGEST_BRIDGE_EXPORT),
            b.Current(DIGEST_BRIDGE_VALUE));
    });
    Append(out, 2, [](ProgramBuilder& b) {
        const uint32_t one = b.Constant(Fp3::One());
        b.Mul(
            b.Sub(
                one,
                b.Current(DIGEST_BRIDGE_ACTIVE)),
            b.Current(DIGEST_BRIDGE_VALUE));
    });
    return Finalize(out, why);
}

// Emit the two indexed-permutation grand-product lanes for a coupled role.
// fingerprint = beta[0]*row[index] + sum_l beta[l+1]*row[limb_base+l], with
// beta/gamma verifier-owned columns. Per lane: denominator-inverse (deg 3),
// product-first (deg 1), product-cycle (deg 3). Column and challenge layout
// mirror AddPermutationProduct in the native product.
void AppendPermutationGrandProduct(
    cb::ProgramTable& out,
    uint32_t mapped_index,
    uint32_t destination_index,
    uint32_t source_limb,
    uint32_t destination_limb,
    uint32_t inverse1,
    uint32_t product1)
{
    const auto fingerprint =
        [](ProgramBuilder& b, uint32_t lane, uint32_t index_column,
           uint32_t limb_base) {
            // beta[i] challenge index = lane*6 + i.
            uint32_t fp = b.Mul(
                b.Challenge(lane * 6 + 0),
                b.Current(index_column));
            for (uint32_t limb = 0; limb < PERM_LIMBS; ++limb) {
                fp = b.Add(
                    fp,
                    b.Mul(
                        b.Challenge(lane * 6 + 1 + limb),
                        b.Current(limb_base + limb)));
            }
            return fp;
        };
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t inverse = inverse1 + lane * 2;
        const uint32_t product = product1 + lane * 2;
        const uint32_t gamma_idx = lane * 6 + 5;
        Append(out, 3, [&, inverse, gamma_idx, lane](ProgramBuilder& b) {
            const uint32_t den = b.Sub(
                b.Challenge(gamma_idx),
                fingerprint(
                    b, lane, destination_index,
                    destination_limb));
            b.Sub(
                b.Mul(b.Current(inverse), den),
                b.Constant(Fp3::One()));
        });
        Append(
            out, aq::AirKind::kFirstRow, 1,
            [product](ProgramBuilder& b) {
                b.Sub(
                    b.Current(product),
                    b.Constant(Fp3::One()));
            });
        Append(out, 3, [&, product, gamma_idx, lane](ProgramBuilder& b) {
            const uint32_t numerator = b.Sub(
                b.Challenge(gamma_idx),
                fingerprint(
                    b, lane, mapped_index, source_limb));
            const uint32_t den = b.Sub(
                b.Challenge(gamma_idx),
                fingerprint(
                    b, lane, destination_index,
                    destination_limb));
            b.Sub(
                b.Mul(b.Next(product), den),
                b.Mul(b.Current(product), numerator));
        });
    }
}

bool BuildRCStage3EpisodeWiringTransposeProgramTable(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.role = RCStage3RelationRole::EpisodeWiring;
    out.current_width = TRANSPOSE_COLUMNS;
    out.next_width = TRANSPOSE_COLUMNS;
    out.challenge_width = TRANSPOSE_CHALLENGE_WIDTH;

    struct Lane {
        uint32_t inv_col;
        uint32_t z_col;
        uint32_t beta;   // challenge index
        uint32_t gamma;  // challenge index
    };
    const std::array<Lane, 2> lanes{{
        {TRANSPOSE_DENOM_INVERSE_1, TRANSPOSE_RUNNING_PRODUCT_1, 0, 1},
        {TRANSPOSE_DENOM_INVERSE_2, TRANSPOSE_RUNNING_PRODUCT_2, 2, 3},
    }};

    // denominator = gamma - (dest_value + beta*dest_index).
    const auto denominator =
        [](ProgramBuilder& b, const Lane& lane) {
            const uint32_t beta = b.Challenge(lane.beta);
            const uint32_t gamma = b.Challenge(lane.gamma);
            const uint32_t dest_index =
                b.Current(TRANSPOSE_DESTINATION_INDEX);
            const uint32_t dest_value =
                b.Current(TRANSPOSE_DESTINATION_VALUE);
            const uint32_t fp = b.Add(
                dest_value, b.Mul(beta, dest_index));
            return b.Sub(gamma, fp);
        };

    for (const Lane& lane : lanes) {
        // inv * (gamma - (dest_value + beta*dest_index)) - 1 == 0.
        // beta/gamma are verifier-owned columns (degree 1), so the raw degree
        // is 1*(1 + 1*1) = 3 -- the honest post-challenge-column degree.
        Append(out, 3, [&](ProgramBuilder& b) {
            const uint32_t inv = b.Current(lane.inv_col);
            const uint32_t den = denominator(b, lane);
            const uint32_t one = b.Constant(Fp3::One());
            b.Sub(b.Mul(inv, den), one);
        });
        // First row: running product starts at one.
        Append(
            out, aq::AirKind::kFirstRow, 1,
            [&](ProgramBuilder& b) {
                b.Sub(
                    b.Current(lane.z_col),
                    b.Constant(Fp3::One()));
            });
        // Cycle: next_z * denominator - z * numerator == 0, with
        // numerator = gamma - (source_value + beta*mapped_index).
        Append(out, 3, [&](ProgramBuilder& b) {
            const uint32_t beta = b.Challenge(lane.beta);
            const uint32_t gamma = b.Challenge(lane.gamma);
            const uint32_t source_value =
                b.Current(TRANSPOSE_SOURCE_VALUE);
            const uint32_t mapped_index =
                b.Current(TRANSPOSE_MAPPED_INDEX);
            const uint32_t dest_value =
                b.Current(TRANSPOSE_DESTINATION_VALUE);
            const uint32_t dest_index =
                b.Current(TRANSPOSE_DESTINATION_INDEX);
            const uint32_t z = b.Current(lane.z_col);
            const uint32_t next_z = b.Next(lane.z_col);
            const uint32_t numerator = b.Sub(
                gamma,
                b.Add(
                    source_value,
                    b.Mul(beta, mapped_index)));
            const uint32_t den = b.Sub(
                gamma,
                b.Add(
                    dest_value,
                    b.Mul(beta, dest_index)));
            b.Sub(
                b.Mul(next_z, den),
                b.Mul(z, numerator));
        });
    }
    return Finalize(out, why);
}

bool BuildRCStage3CoupledPermutationTransportProgramTable(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.role = RCStage3RelationRole::CoupledPermutation;
    out.current_width = PERM_COLUMNS;
    out.next_width = PERM_COLUMNS;
    out.challenge_width = PERM_CHALLENGE_WIDTH;
    AppendPermutationGrandProduct(
        out, PERM_MAPPED_INDEX, PERM_DESTINATION_INDEX,
        PERM_INPUT_LIMB, PERM_OUTPUT_LIMB,
        PERM_INVERSE_1, PERM_PRODUCT_1);
    return Finalize(out, why);
}

bool BuildRCStage3CoupledExchangeTransportProgramTable(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.role = RCStage3RelationRole::CoupledExchange;
    out.current_width = EXCH_COLUMNS;
    out.next_width = EXCH_COLUMNS;
    out.challenge_width = PERM_CHALLENGE_WIDTH;
    AppendPermutationGrandProduct(
        out, EXCH_MAPPED_INDEX, EXCH_DESTINATION_INDEX,
        EXCH_MIXED_LIMB, EXCH_OUTPUT_LIMB,
        EXCH_INVERSE_1, EXCH_PRODUCT_1);
    return Finalize(out, why);
}

bool BuildRCStage3EpisodeExtractStreamTransportProgramTable(
    uint32_t tile,
    int8_t multiplicity,
    cb::ProgramTable& out,
    std::string* why)
{
    if (multiplicity != 1 && multiplicity != -1) {
        out = {};
        return Fail(why, "extract_stream_multiplicity");
    }
    out = {};
    out.role = RCStage3RelationRole::EpisodeExtract;
    out.current_width = XSTREAM_COLUMNS;
    out.next_width = XSTREAM_COLUMNS;
    out.challenge_width = GAMMA_POWER_CHALLENGE_WIDTH;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t inverse =
            lane == 0 ? XSTREAM_INVERSE_1 : XSTREAM_INVERSE_2;
        const uint32_t running =
            lane == 0 ? XSTREAM_RUNNING_1 : XSTREAM_RUNNING_2;
        const uint32_t gamma_idx = 2 * lane;
        const uint32_t alpha_idx = 2 * lane + 1;
        const uint32_t sum_idx = 4 + lane;
        // mask boolean (deg 2).
        Append(out, 2, [](ProgramBuilder& b) {
            const uint32_t m = b.Current(XSTREAM_MASK);
            b.Mul(m, b.Sub(m, b.Constant(Fp3::One())));
        });
        // inverse (raw deg 5): inv*(alpha - Tuple) - mask, with
        // Tuple = NS + gamma*tile + gamma^2*address + gamma^3*value.
        Append(out, 5, [=](ProgramBuilder& b) {
            const uint32_t g = b.Challenge(gamma_idx);
            const uint32_t g2 = b.Mul(g, g);
            const uint32_t g3 = b.Mul(g2, g);
            const uint32_t tuple = b.Add(
                b.Constant(U(kRCStage3ExtractStreamCtlBusId)),
                b.Add(
                    b.Mul(g, b.Constant(U(tile))),
                    b.Add(
                        b.Mul(g2, b.Current(XSTREAM_ADDRESS)),
                        b.Mul(g3, b.Current(XSTREAM_SOURCE)))));
            const uint32_t diff =
                b.Sub(b.Challenge(alpha_idx), tuple);
            b.Sub(
                b.Mul(b.Current(inverse), diff),
                b.Current(XSTREAM_MASK));
        });
        // inverse inactive (deg 2): (1 - mask) * inverse.
        Append(out, 2, [inverse](ProgramBuilder& b) {
            b.Mul(
                b.Sub(b.Constant(Fp3::One()), b.Current(XSTREAM_MASK)),
                b.Current(inverse));
        });
        // running first (deg 1).
        Append(
            out, aq::AirKind::kFirstRow, 1,
            [running](ProgramBuilder& b) { b.Current(running); });
        // running transition (deg 2): next - (cur + contribution).
        Append(
            out, aq::AirKind::kTransition, 2,
            [=](ProgramBuilder& b) {
                const uint32_t selected = b.Mul(
                    b.Current(XSTREAM_MASK), b.Current(inverse));
                const uint32_t contribution =
                    multiplicity == 1
                    ? selected
                    : b.Sub(b.Constant(Fp3::Zero()), selected);
                b.Sub(
                    b.Next(running),
                    b.Add(b.Current(running), contribution));
            });
        // running last (deg 2): (cur + contribution) - expected(sum).
        Append(
            out, aq::AirKind::kLastRow, 2,
            [=](ProgramBuilder& b) {
                const uint32_t selected = b.Mul(
                    b.Current(XSTREAM_MASK), b.Current(inverse));
                const uint32_t contribution =
                    multiplicity == 1
                    ? selected
                    : b.Sub(b.Constant(Fp3::Zero()), selected);
                b.Sub(
                    b.Add(b.Current(running), contribution),
                    b.Challenge(sum_idx));
            });
    }
    return Finalize(out, why);
}

// ---------------------------------------------------------------------------
// CoupledExtract sampler transport: the T_M LogUp lane of the RcSampler.
//
// Post-challenge column class (width 11): mixed, acc, mu, phi, f, m, psi, S,
// tbl_a, tbl_b, tbl_c. Verifier-owned challenge columns: gamma (0), alpha (1).
//
// The fingerprint is NO LONGER a gamma-baked PREPROCESSED column. The committed
// f is bound to the CHALLENGE-INDEPENDENT table columns (tbl_a=n, tbl_b=acc[n],
// tbl_c=mu[n]) by the in-circuit identity f = tbl_a + gamma*tbl_b +
// gamma^2*tbl_c (logup.tfp.bind). Restoring the RAP two-phase order this way is
// exactly what lets the whole lane be expressed as challenge-independent
// bytecode. Constraint order MUST match the two builders below and the RcSampler
// LogUp lane in aq::BuildRcSamplerConstraintSystem (logup.phi / logup.tfp.bind /
// logup.psi / logup.S.first / logup.S.trans / logup.S.last).
constexpr uint32_t CXTFP_MIXED = 0;
constexpr uint32_t CXTFP_ACC = 1;
constexpr uint32_t CXTFP_MU = 2;
constexpr uint32_t CXTFP_PHI = 3;
constexpr uint32_t CXTFP_F = 4;
constexpr uint32_t CXTFP_M = 5;
constexpr uint32_t CXTFP_PSI = 6;
constexpr uint32_t CXTFP_S = 7;
constexpr uint32_t CXTFP_TBLA = 8;
constexpr uint32_t CXTFP_TBLB = 9;
constexpr uint32_t CXTFP_TBLC = 10;
constexpr uint32_t CXTFP_COLUMNS = 11;
constexpr uint32_t CXTFP_CHALLENGE_WIDTH = 2;  // [gamma, alpha]
constexpr uint32_t CXTFP_GAMMA = 0;
constexpr uint32_t CXTFP_ALPHA = 1;

bool BuildRCStage3CoupledExtractSamplerTransportProgramTable(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.role = RCStage3RelationRole::CoupledExtract;
    out.current_width = CXTFP_COLUMNS;
    out.next_width = CXTFP_COLUMNS;
    out.challenge_width = CXTFP_CHALLENGE_WIDTH;

    // 0: logup.phi (raw deg 4): phi*(alpha - (mixed + gamma*acc + gamma^2*mu)) - 1.
    Append(out, 4, [](ProgramBuilder& b) {
        const uint32_t g = b.Challenge(CXTFP_GAMMA);
        const uint32_t g2 = b.Mul(g, g);
        const uint32_t w = b.Add(
            b.Current(CXTFP_MIXED),
            b.Add(b.Mul(g, b.Current(CXTFP_ACC)),
                  b.Mul(g2, b.Current(CXTFP_MU))));
        const uint32_t diff = b.Sub(b.Challenge(CXTFP_ALPHA), w);
        b.Sub(b.Mul(b.Current(CXTFP_PHI), diff), b.Constant(Fp3::One()));
    });
    // 1: logup.tfp.bind (raw deg 3): f - (tbl_a + gamma*tbl_b + gamma^2*tbl_c).
    Append(out, 3, [](ProgramBuilder& b) {
        const uint32_t g = b.Challenge(CXTFP_GAMMA);
        const uint32_t g2 = b.Mul(g, g);
        const uint32_t rhs = b.Add(
            b.Current(CXTFP_TBLA),
            b.Add(b.Mul(g, b.Current(CXTFP_TBLB)),
                  b.Mul(g2, b.Current(CXTFP_TBLC))));
        b.Sub(b.Current(CXTFP_F), rhs);
    });
    // 2: logup.psi (raw deg 2): psi*(alpha - f) - m.
    Append(out, 2, [](ProgramBuilder& b) {
        const uint32_t diff =
            b.Sub(b.Challenge(CXTFP_ALPHA), b.Current(CXTFP_F));
        b.Sub(b.Mul(b.Current(CXTFP_PSI), diff), b.Current(CXTFP_M));
    });
    // 3: logup.S.first (deg 1): S = 0 at row 0.
    Append(out, aq::AirKind::kFirstRow, 1,
           [](ProgramBuilder& b) { b.Current(CXTFP_S); });
    // 4: logup.S.trans (deg 1): S_next - (S + phi - psi).
    Append(out, aq::AirKind::kTransition, 1, [](ProgramBuilder& b) {
        b.Sub(b.Next(CXTFP_S),
              b.Add(b.Current(CXTFP_S),
                    b.Sub(b.Current(CXTFP_PHI), b.Current(CXTFP_PSI))));
    });
    // 5: logup.S.last (deg 1): S + phi - psi = 0 at the last row.
    Append(out, aq::AirKind::kLastRow, 1, [](ProgramBuilder& b) {
        b.Add(b.Current(CXTFP_S),
              b.Sub(b.Current(CXTFP_PHI), b.Current(CXTFP_PSI)));
    });
    return Finalize(out, why);
}

aq::AirConstraintSystem<Fp3>
BuildRCStage3CoupledExtractSamplerTransportConstraintSystem(
    const Fp3& gamma, const Fp3& alpha, uint32_t n_rows)
{
    using T = aq::AirField<Fp3>;
    aq::AirConstraintSystem<Fp3> cs;
    cs.n_rows = n_rows;
    cs.n_columns = CXTFP_COLUMNS;
    const Fp3 g2 = T::Mul(gamma, gamma);
    auto add = [&](aq::AirKind kind, uint32_t deg,
                   std::function<Fp3(const std::vector<Fp3>&,
                                     const std::vector<Fp3>&)> ev) {
        aq::AirConstraint<Fp3> c;
        c.kind = kind;
        c.alg_degree = deg;
        c.eval = std::move(ev);
        cs.constraints.push_back(std::move(c));
    };
    add(aq::AirKind::kEverywhere, 4,
        [gamma, g2, alpha](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            const Fp3 w = T::Add(
                r[CXTFP_MIXED],
                T::Add(T::Mul(gamma, r[CXTFP_ACC]), T::Mul(g2, r[CXTFP_MU])));
            return T::Sub(T::Mul(r[CXTFP_PHI], T::Sub(alpha, w)), T::One());
        });
    add(aq::AirKind::kEverywhere, 3,
        [gamma, g2](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return T::Sub(r[CXTFP_F],
                          T::Add(r[CXTFP_TBLA],
                                 T::Add(T::Mul(gamma, r[CXTFP_TBLB]),
                                        T::Mul(g2, r[CXTFP_TBLC]))));
        });
    add(aq::AirKind::kEverywhere, 2,
        [alpha](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return T::Sub(T::Mul(r[CXTFP_PSI], T::Sub(alpha, r[CXTFP_F])),
                          r[CXTFP_M]);
        });
    add(aq::AirKind::kFirstRow, 1,
        [](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return r[CXTFP_S];
        });
    add(aq::AirKind::kTransition, 1,
        [](const std::vector<Fp3>& r, const std::vector<Fp3>& n) {
            return T::Sub(n[CXTFP_S],
                          T::Add(r[CXTFP_S],
                                 T::Sub(r[CXTFP_PHI], r[CXTFP_PSI])));
        });
    add(aq::AirKind::kLastRow, 1,
        [](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return T::Add(r[CXTFP_S], T::Sub(r[CXTFP_PHI], r[CXTFP_PSI]));
        });
    return cs;
}

bool BuildRCStage3EpisodeTileTreeProducerTransportProgramTable(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.role = RCStage3RelationRole::EpisodeTileTree;
    out.current_width = TILETREE_COLUMNS;
    out.next_width = TILETREE_COLUMNS;
    out.challenge_width = GAMMA_POWER_CHALLENGE_WIDTH;
    for (uint32_t byte = 0; byte < 32; ++byte) {
        for (uint32_t lane = 0; lane < 2; ++lane) {
            const uint32_t inverse =
                (lane == 0 ? TILETREE_INVERSE_1_BASE
                           : TILETREE_INVERSE_2_BASE) + byte;
            const uint32_t gamma_idx = 2 * lane;
            const uint32_t alpha_idx = 2 * lane + 1;
            const uint32_t value_col = byte;  // output_byte_base == 0
            // output byte inverse (first row, raw deg 5):
            // inv*(alpha - (NS + gamma*stage + gamma^2*byte + gamma^3*value)) - 1.
            Append(
                out, aq::AirKind::kFirstRow, 5,
                [=](ProgramBuilder& b) {
                    const uint32_t g = b.Challenge(gamma_idx);
                    const uint32_t g2 = b.Mul(g, g);
                    const uint32_t g3 = b.Mul(g2, g);
                    const uint32_t tuple = b.Add(
                        b.Constant(U(kRCStage3TileTreeCtlEdgeNamespace)),
                        b.Add(
                            b.Mul(
                                g,
                                b.Constant(
                                    U(kRCStage3TileTreeCtlEdgeStage))),
                            b.Add(
                                b.Mul(g2, b.Constant(U(byte))),
                                b.Mul(g3, b.Current(value_col)))));
                    const uint32_t diff =
                        b.Sub(b.Challenge(alpha_idx), tuple);
                    b.Sub(
                        b.Mul(b.Current(inverse), diff),
                        b.Constant(Fp3::One()));
                });
            // padding (transition, deg 1): next[inverse] == 0.
            Append(
                out, aq::AirKind::kTransition, 1,
                [inverse](ProgramBuilder& b) { b.Next(inverse); });
        }
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t inverse_base =
            lane == 0 ? TILETREE_INVERSE_1_BASE
                      : TILETREE_INVERSE_2_BASE;
        const uint32_t running =
            lane == 0 ? TILETREE_RUNNING_1 : TILETREE_RUNNING_2;
        const uint32_t sum_idx = 4 + lane;
        Append(
            out, aq::AirKind::kFirstRow, 1,
            [running](ProgramBuilder& b) { b.Current(running); });
        Append(
            out, aq::AirKind::kTransition, 1,
            [=](ProgramBuilder& b) {
                uint32_t contribution = b.Constant(Fp3::Zero());
                for (uint32_t byte = 0; byte < 32; ++byte) {
                    contribution = b.Add(
                        contribution,
                        b.Current(inverse_base + byte));
                }
                b.Sub(
                    b.Next(running),
                    b.Add(b.Current(running), contribution));
            });
        Append(
            out, aq::AirKind::kLastRow, 1,
            [=](ProgramBuilder& b) {
                uint32_t contribution = b.Constant(Fp3::Zero());
                for (uint32_t byte = 0; byte < 32; ++byte) {
                    contribution = b.Add(
                        contribution,
                        b.Current(inverse_base + byte));
                }
                b.Sub(
                    b.Add(b.Current(running), contribution),
                    b.Challenge(sum_idx));
            });
    }
    return Finalize(out, why);
}

bool BuildRCStage3EpisodeTileTreeByteBridgeProgramTable(
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    out.role = RCStage3RelationRole::EpisodeTileTree;
    out.current_width = TILE_BRIDGE_COLUMNS;
    AppendBoolean(out, TILE_BRIDGE_ACTIVE);
    AppendBoolean(out, TILE_BRIDGE_SIGN);
    for (uint32_t bit = 0; bit < 8; ++bit) {
        AppendBoolean(out, TILE_BRIDGE_BIT_BASE + bit);
    }
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(
            b.Current(TILE_BRIDGE_BYTE),
            BitSum(b, TILE_BRIDGE_BIT_BASE, 8));
    });
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(
            b.Current(TILE_BRIDGE_SIGN),
            b.Current(TILE_BRIDGE_BIT_BASE + 7));
    });
    Append(out, 1, [](ProgramBuilder& b) {
        const uint32_t signed_value = b.Sub(
            b.Current(TILE_BRIDGE_BYTE),
            b.Mul(
                b.Constant(U(256)),
                b.Current(TILE_BRIDGE_SIGN)));
        b.Sub(
            b.Current(TILE_BRIDGE_VALUE),
            signed_value);
    });
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(
            b.Current(TILE_BRIDGE_VALUE),
            b.Current(TILE_BRIDGE_EXPECTED));
    });
    Append(out, 1, [](ProgramBuilder& b) {
        b.Sub(
            b.Current(TILE_BRIDGE_EXPORT),
            b.Current(TILE_BRIDGE_VALUE));
    });
    Append(out, 2, [](ProgramBuilder& b) {
        const uint32_t one = b.Constant(Fp3::One());
        b.Mul(
            b.Sub(
                one,
                b.Current(TILE_BRIDGE_ACTIVE)),
            b.Current(TILE_BRIDGE_VALUE));
    });
    return Finalize(out, why);
}

// ---------------------------------------------------------------------------
// RcSampler local kernel: the complete RcSampler relation as bytecode.
//
// This is the bytecode form of air_quotient::BuildRcSamplerConstraintSystem in
// its exact 47-constraint order over the 40-column kRcSampler* layout. gamma
// (challenge 0) and alpha (challenge 1) enter only through the verifier-owned
// post-challenge column class, so the committed table stays challenge-
// independent; gamma^2 is formed in-circuit. The public scale exponent baked as
// the e0/e1 first-row boundaries is `scale_e`.
//
// The CoupledExtract and EpisodeExtract kernels are the identical RcSampler
// relation; the only role-dependent field is the committed table role (anti
// cross-role replay). Both public entry points delegate to this shared emit so
// they stay bit-identical to the native constraint system for every exponent.
// ---------------------------------------------------------------------------
static bool EmitRcSamplerLocalKernel(
    RCStage3RelationRole role,
    uint8_t scale_e,
    cb::ProgramTable& out,
    std::string* why)
{
    if (scale_e > 3) return Fail(why, "extract_scale_e");
    out = {};
    out.role = role;
    out.current_width = aq::kRcSamplerNumCols;
    out.challenge_width = 2; // [gamma, alpha]

    constexpr auto E = aq::AirKind::kEverywhere;
    constexpr auto T = aq::AirKind::kTransition;
    constexpr auto FR = aq::AirKind::kFirstRow;
    constexpr auto LR = aq::AirKind::kLastRow;
    constexpr uint64_t kBlockLen = 32; // kRCMxBlockLen

    // -- 20 boolean columns (native order). --
    for (uint32_t col :
         {aq::kColAct,
          aq::kColKb0, aq::kColKb1, aq::kColKb2, aq::kColKb3,
          aq::kColHb0, aq::kColHb1, aq::kColHb2, aq::kColHb3,
          aq::kColMb0, aq::kColMb1, aq::kColMb2, aq::kColMb3,
          aq::kColAcc,
          aq::kColVb0, aq::kColVb1, aq::kColVb2, aq::kColVb3,
          aq::kColE0, aq::kColE1}) {
        AppendAuto(out, E, [col](ProgramBuilder& b) {
            EmitBool(b, b.Current(col));
        });
    }
    // -- nibble recompositions. --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        b.Sub(b.Current(aq::kColKappa), Nibble(b, aq::kColKb0));
    });
    AppendAuto(out, E, [](ProgramBuilder& b) {
        b.Sub(b.Current(aq::kColH), Nibble(b, aq::kColHb0));
    });
    AppendAuto(out, E, [](ProgramBuilder& b) {
        b.Sub(b.Current(aq::kColMixed), Nibble(b, aq::kColMb0));
    });
    // -- mixed.xor: mixed = kappa XOR h, per bit. --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        uint32_t acc = b.Constant(Fp3::Zero());
        uint64_t weight = 1;
        for (uint32_t i = 0; i < 4; ++i) {
            const uint32_t x = EmitXor2(
                b, b.Current(aq::kColKb0 + i), b.Current(aq::kColHb0 + i));
            acc = b.Add(acc, b.Mul(b.Constant(U(weight)), x));
            weight <<= 1;
        }
        b.Sub(b.Current(aq::kColMixed), acc);
    });
    // -- accept.poly (degree-4 acceptance selector). --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        const uint32_t one = b.Constant(Fp3::One());
        const uint32_t b0 = b.Current(aq::kColMb0);
        const uint32_t b1 = b.Current(aq::kColMb1);
        const uint32_t b2 = b.Current(aq::kColMb2);
        const uint32_t b3 = b.Current(aq::kColMb3);
        const uint32_t inner = b.Add(
            b.Mul(b.Sub(one, b3), b0),
            b.Mul(b3, b.Add(b.Sub(one, b1), b.Mul(b1, b0))));
        const uint32_t rejected = b.Mul(b.Sub(one, b2), inner);
        const uint32_t accept = b.Sub(one, rejected);
        b.Sub(b.Current(aq::kColAcc), accept);
    });
    // -- liveness: act*((32 - pos)*inv_live - 1). --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        const uint32_t lv = b.Sub(
            b.Mul(b.Sub(b.Constant(U(kBlockLen)), b.Current(aq::kColPos)),
                  b.Current(aq::kColInvLive)),
            b.Constant(Fp3::One()));
        b.Mul(b.Current(aq::kColAct), lv);
    });
    // -- inactive.pos: (1 - act)*(pos - 32). --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        b.Mul(b.Sub(b.Constant(Fp3::One()), b.Current(aq::kColAct)),
              b.Sub(b.Current(aq::kColPos), b.Constant(U(kBlockLen))));
    });
    // -- golden.mix: u*G = q*2^32 + v. --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        const uint32_t lhs =
            b.Mul(b.Current(aq::kColUMix), b.Constant(U(GOLDEN)));
        const uint32_t rhs = b.Add(
            b.Mul(b.Constant(U(uint64_t{1} << 32)), b.Current(aq::kColGoldQ)),
            b.Current(aq::kColGoldV));
        b.Sub(lhs, rhs);
    });
    // -- goldv.decomp: gold_v = v_low28 + 2^28*top_nibble(vb). --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        b.Sub(b.Current(aq::kColGoldV),
              b.Add(b.Current(aq::kColVLow28),
                    b.Mul(b.Constant(U(uint64_t{1} << 28)),
                          Nibble(b, aq::kColVb0))));
    });
    // -- h.top_nibble: h = nibble(vb). --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        b.Sub(b.Current(aq::kColH), Nibble(b, aq::kColVb0));
    });
    // -- pad.zero: reserved column stays zero. --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        b.Current(aq::kColPad0);
    });
    // -- out.dequant: out = mu_out*(1+e0)(1+3*e1). --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        const uint32_t one = b.Constant(Fp3::One());
        const uint32_t scale = b.Mul(
            b.Add(one, b.Current(aq::kColE0)),
            b.Add(one, b.Mul(b.Constant(U(3)), b.Current(aq::kColE1))));
        b.Sub(b.Current(aq::kColOut), b.Mul(b.Current(aq::kColMuOut), scale));
    });
    // -- logup.phi: phi*(alpha - w) - 1, w = mixed + g*acc + g^2*mu. --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        const uint32_t gamma = b.Challenge(0);
        const uint32_t alpha = b.Challenge(1);
        const uint32_t g2 = b.Mul(gamma, gamma);
        const uint32_t w = b.Add(
            b.Current(aq::kColMixed),
            b.Add(b.Mul(gamma, b.Current(aq::kColAcc)),
                  b.Mul(g2, b.Current(aq::kColMu))));
        b.Sub(b.Mul(b.Current(aq::kColPhi), b.Sub(alpha, w)),
              b.Constant(Fp3::One()));
    });
    // -- logup.psi: psi*(alpha - t_fp) - m. --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        const uint32_t alpha = b.Challenge(1);
        b.Sub(b.Mul(b.Current(aq::kColPsi),
                    b.Sub(alpha, b.Current(aq::kColTfp))),
              b.Current(aq::kColM));
    });
    // -- logup.tfp.bind: t_fp = tbl_a + g*tbl_b + g^2*tbl_c. --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        const uint32_t gamma = b.Challenge(0);
        const uint32_t g2 = b.Mul(gamma, gamma);
        b.Sub(b.Current(aq::kColTfp),
              b.Add(b.Current(aq::kColTblA),
                    b.Add(b.Mul(gamma, b.Current(aq::kColTblB)),
                          b.Mul(g2, b.Current(aq::kColTblC)))));
    });
    // -- transitions. --
    AppendAuto(out, T, [](ProgramBuilder& b) {
        b.Sub(b.Next(aq::kColPos),
              b.Add(b.Current(aq::kColPos), b.Current(aq::kColAcc)));
    });
    AppendAuto(out, T, [](ProgramBuilder& b) {
        b.Mul(b.Next(aq::kColAct),
              b.Sub(b.Constant(Fp3::One()), b.Current(aq::kColAct)));
    });
    AppendAuto(out, T, [](ProgramBuilder& b) {
        b.Sub(b.Next(aq::kColE0), b.Current(aq::kColE0));
    });
    AppendAuto(out, T, [](ProgramBuilder& b) {
        b.Sub(b.Next(aq::kColE1), b.Current(aq::kColE1));
    });
    AppendAuto(out, T, [](ProgramBuilder& b) {
        b.Sub(b.Next(aq::kColS),
              b.Add(b.Current(aq::kColS),
                    b.Sub(b.Current(aq::kColPhi), b.Current(aq::kColPsi))));
    });
    // -- boundaries. --
    AppendAuto(out, FR, [](ProgramBuilder& b) { b.Current(aq::kColPos); });
    AppendAuto(out, FR, [](ProgramBuilder& b) {
        b.Sub(b.Current(aq::kColAct), b.Constant(Fp3::One()));
    });
    AppendAuto(out, FR, [](ProgramBuilder& b) { b.Current(aq::kColS); });
    const uint64_t pub_e0 = scale_e & 1u;
    const uint64_t pub_e1 = (scale_e >> 1) & 1u;
    AppendAuto(out, FR, [pub_e0](ProgramBuilder& b) {
        b.Sub(b.Current(aq::kColE0), b.Constant(U(pub_e0)));
    });
    AppendAuto(out, FR, [pub_e1](ProgramBuilder& b) {
        b.Sub(b.Current(aq::kColE1), b.Constant(U(pub_e1)));
    });
    AppendAuto(out, LR, [](ProgramBuilder& b) {
        b.Sub(b.Add(b.Current(aq::kColPos), b.Current(aq::kColAcc)),
              b.Constant(U(kBlockLen)));
    });
    AppendAuto(out, LR, [](ProgramBuilder& b) {
        b.Add(b.Current(aq::kColS),
              b.Sub(b.Current(aq::kColPhi), b.Current(aq::kColPsi)));
    });
    return Finalize(out, why);
}

bool BuildRCStage3CoupledExtractLocalKernelProgramTable(
    uint8_t scale_e,
    cb::ProgramTable& out,
    std::string* why)
{
    return EmitRcSamplerLocalKernel(
        RCStage3RelationRole::CoupledExtract, scale_e, out, why);
}

// EpisodeExtract local kernel: the same RcSampler relation as bytecode, committed
// under the EpisodeExtract role. This is the episode analogue of the coupled
// sampler and is the migrated source for the EpisodeExtract C_rho.
bool BuildRCStage3EpisodeExtractLocalKernelProgramTable(
    uint8_t scale_e,
    cb::ProgramTable& out,
    std::string* why)
{
    return EmitRcSamplerLocalKernel(
        RCStage3RelationRole::EpisodeExtract, scale_e, out, why);
}

// ---------------------------------------------------------------------------
// CoupledBarrier / CoupledDigest / EpisodeTileTree / EpisodeDigest hash
// kernel: the selector-pinned SHA-256 compression AIR as bytecode. This is
// the bytecode form of stage3_hash_air::BuildFixedProgramConstraintSystem
// over the canonical Sha256Compression program, in the identical
// 462-constraint order over the 144-column fixed-program layout. All four
// roles are executed by the same compression program (EpisodeDigest via
// DirectHashRelation::EpisodeDigest, EpisodeTileTree via
// BuildTileTreeManifestBoundaryInstances -> BuildShaManifestBoundaryInstances,
// both bit-identical callers of the same fixed-program AIR already used by
// CoupledBarrier/CoupledDigest), so they share this kernel; only the
// committed table role differs (anti cross-role replay).
// ---------------------------------------------------------------------------
bool BuildRCStage3CoupledHashKernelProgramTable(
    RCStage3RelationRole role,
    cb::ProgramTable& out,
    std::string* why)
{
    if (role != RCStage3RelationRole::CoupledBarrier &&
        role != RCStage3RelationRole::CoupledDigest &&
        role != RCStage3RelationRole::EpisodeTileTree &&
        role != RCStage3RelationRole::EpisodeDigest) {
        return Fail(why, "hash_kernel_role");
    }
    out = {};
    out.role = role;
    out.current_width = ha::kFixedProgramColumns; // 144
    out.challenge_width = 0;

    constexpr auto E = aq::AirKind::kEverywhere;
    const uint32_t sel = ha::kFixedProgramSelectorBase;
    const uint32_t carry = ha::kFixedProgramCarryColumn;

    // -- word range-decomposition (words 0..3): 32 bit-booleans + recompose. --
    for (uint32_t word = 0; word < 4; ++word) {
        for (uint32_t bit = 0; bit < 32; ++bit) {
            AppendAuto(out, E, [word, bit](ProgramBuilder& b) {
                EmitBool(b, b.Current(ha::BitColumn(word, bit)));
            });
        }
        AppendAuto(out, E, [word](ProgramBuilder& b) {
            uint32_t sum = b.Constant(Fp3::Zero());
            for (uint32_t bit = 0; bit < 32; ++bit) {
                sum = b.Add(
                    sum,
                    b.Mul(b.Constant(U(uint64_t{1} << bit)),
                          b.Current(ha::BitColumn(word, bit))));
            }
            b.Sub(sum, b.Current(ha::ValueColumn(word)));
        });
    }
    // -- carry boolean. --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        EmitBool(b, b.Current(carry));
    });
    // -- selector sum is boolean (at most one active). --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        uint32_t sum = b.Current(sel);
        for (uint32_t i = 1; i < ha::kFixedProgramOpcodeCount; ++i) {
            sum = b.Add(sum, b.Current(sel + i));
        }
        EmitBool(b, sum);
    });
    // -- padding rows (no selector active) force each word slot to zero. --
    for (uint32_t word = 0; word < 4; ++word) {
        AppendAuto(out, E, [word](ProgramBuilder& b) {
            uint32_t active = b.Current(sel);
            for (uint32_t i = 1; i < ha::kFixedProgramOpcodeCount; ++i) {
                active = b.Add(active, b.Current(sel + i));
            }
            b.Mul(b.Sub(b.Constant(Fp3::One()), active),
                  b.Current(ha::ValueColumn(word)));
        });
    }
    // -- add carry is zero off the add selector. --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        b.Mul(b.Sub(b.Constant(Fp3::One()), b.Current(sel)),
              b.Current(carry));
    });
    // -- add32: sel0 * (v0 + v1 - v2 - 2^32*carry). --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        const uint32_t residual = b.Sub(
            b.Sub(b.Add(b.Current(ha::ValueColumn(0)),
                        b.Current(ha::ValueColumn(1))),
                  b.Current(ha::ValueColumn(2))),
            b.Mul(b.Constant(U(uint64_t{1} << 32)), b.Current(carry)));
        b.Mul(b.Current(sel), residual);
    });
    // -- xor_rot (selectors 1..4), which outer, bit inner. --
    for (uint32_t which = 0; which < 4; ++which) {
        for (uint32_t bit = 0; bit < 32; ++bit) {
            const uint32_t source =
                (bit + 32U - SHA_FIXED_ROTS[which]) & 31U;
            AppendAuto(out, E, [which, bit, source](ProgramBuilder& b) {
                const uint32_t residual = b.Sub(
                    b.Current(ha::BitColumn(2, bit)),
                    EmitXor2(b, b.Current(ha::BitColumn(0, source)),
                             b.Current(ha::BitColumn(1, source))));
                b.Mul(b.Current(sel + 1 + which), residual);
            });
        }
    }
    // -- choice (selector 5) and majority (selector 6), interleaved per bit. --
    for (uint32_t bit = 0; bit < 32; ++bit) {
        AppendAuto(out, E, [bit](ProgramBuilder& b) {
            const uint32_t residual = b.Sub(
                b.Current(ha::BitColumn(3, bit)),
                EmitChoice(b, b.Current(ha::BitColumn(0, bit)),
                           b.Current(ha::BitColumn(1, bit)),
                           b.Current(ha::BitColumn(2, bit))));
            b.Mul(b.Current(sel + 5), residual);
        });
        AppendAuto(out, E, [bit](ProgramBuilder& b) {
            const uint32_t residual = b.Sub(
                b.Current(ha::BitColumn(3, bit)),
                EmitMajority(b, b.Current(ha::BitColumn(0, bit)),
                             b.Current(ha::BitColumn(1, bit)),
                             b.Current(ha::BitColumn(2, bit))));
            b.Mul(b.Current(sel + 6), residual);
        });
    }
    // -- sigma S-boxes (selectors 7..10), which outer, bit inner. --
    for (uint32_t which = 0; which < 4; ++which) {
        const std::array<ha::BitTransform, 3> transforms =
            SigmaTransforms(which);
        for (uint32_t bit = 0; bit < 32; ++bit) {
            AppendAuto(out, E, [which, bit, transforms](ProgramBuilder& b) {
                const uint32_t residual = b.Sub(
                    b.Current(ha::BitColumn(1, bit)),
                    EmitXor3(
                        b,
                        EmitTransformBit(b, bit, transforms[0].kind,
                                         transforms[0].amount),
                        EmitTransformBit(b, bit, transforms[1].kind,
                                         transforms[1].amount),
                        EmitTransformBit(b, bit, transforms[2].kind,
                                         transforms[2].amount)));
                b.Mul(b.Current(sel + 7 + which), residual);
            });
        }
    }
    // -- word slot 3 unused unless choice/majority. --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        const uint32_t use_word3 =
            b.Add(b.Current(sel + 5), b.Current(sel + 6));
        b.Mul(b.Sub(b.Constant(Fp3::One()), use_word3),
              b.Current(ha::ValueColumn(3)));
    });
    // -- word slot 2 unused on the sigma S-boxes. --
    AppendAuto(out, E, [](ProgramBuilder& b) {
        uint32_t selected = b.Current(sel + 7);
        for (uint32_t i = 8; i <= 10; ++i) {
            selected = b.Add(selected, b.Current(sel + i));
        }
        b.Mul(selected, b.Current(ha::ValueColumn(2)));
    });
    return Finalize(out, why);
}

bool BuildRCStage3HashKernelOutputProgramTable(
    RCStage3RelationRole role,
    cb::ProgramTable& out,
    std::string* why)
{
    if (!BuildRCStage3CoupledHashKernelProgramTable(
            role, out, why)) {
        return false;
    }
    static_assert(
        ha::kFixedProgramColumns ==
        kRCStage3HashKernelOutputColumnV1);
    out.current_width =
        kRCStage3HashKernelOutputColumnV1 + 1U;
    out.next_width = out.current_width;
    for (auto& program : out.programs) {
        program.current_width = out.current_width;
        program.next_width = out.next_width;
    }
    AppendAuto(out, aq::AirKind::kEverywhere,
        [](ProgramBuilder& b) {
            const uint32_t selector =
                ha::kFixedProgramSelectorBase;
            uint32_t selected = b.Constant(Fp3::Zero());
            for (uint32_t opcode = 0; opcode <= 4; ++opcode) {
                selected = b.Add(
                    selected,
                    b.Mul(
                        b.Current(selector + opcode),
                        b.Current(ha::ValueColumn(2))));
            }
            for (uint32_t opcode = 5; opcode <= 6; ++opcode) {
                selected = b.Add(
                    selected,
                    b.Mul(
                        b.Current(selector + opcode),
                        b.Current(ha::ValueColumn(3))));
            }
            for (uint32_t opcode = 7; opcode <= 10; ++opcode) {
                selected = b.Add(
                    selected,
                    b.Mul(
                        b.Current(selector + opcode),
                        b.Current(ha::ValueColumn(1))));
            }
            b.Sub(
                b.Current(
                    kRCStage3HashKernelOutputColumnV1),
                selected);
        });
    return Finalize(out, why);
}

} // namespace matmul::v4::rc
