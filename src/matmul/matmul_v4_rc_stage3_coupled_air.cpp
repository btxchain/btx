// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_air.h>

#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace cb = constraint_bytecode;
using gf::Fp3;
using CS = aq::AirConstraintSystem<Fp3>;

constexpr std::array<RCStage3RelationRole, 8> COUPLED_ROLES{
    RCStage3RelationRole::CoupledBank,
    RCStage3RelationRole::CoupledGemm,
    RCStage3RelationRole::CoupledExchange,
    RCStage3RelationRole::CoupledPermutation,
    RCStage3RelationRole::CoupledMix,
    RCStage3RelationRole::CoupledExtract,
    RCStage3RelationRole::CoupledBarrier,
    RCStage3RelationRole::CoupledDigest,
};

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:coupled_air:" + message;
    return false;
}

class ProgramBuilder {
public:
    ProgramBuilder(RCStage3RelationRole role,
                   uint32_t ordinal,
                   aq::AirKind kind,
                   uint32_t degree,
                   uint32_t width)
    {
        m_program.role = role;
        m_program.constraint_ordinal = ordinal;
        m_program.kind = kind;
        m_program.declared_degree = degree;
        m_program.current_width = width;
        m_program.next_width = width;
    }

    uint32_t Current(uint32_t column)
    {
        return Push({cb::Opcode::Current, column, 0, Fp3::Zero()});
    }
    uint32_t Next(uint32_t column)
    {
        return Push({cb::Opcode::Next, column, 0, Fp3::Zero()});
    }
    uint32_t Constant(const Fp3& value)
    {
        return Push({cb::Opcode::Constant, 0, 0, value});
    }
    uint32_t Add(uint32_t lhs, uint32_t rhs)
    {
        return Push({cb::Opcode::Add, lhs, rhs, Fp3::Zero()});
    }
    uint32_t Sub(uint32_t lhs, uint32_t rhs)
    {
        return Push({cb::Opcode::Sub, lhs, rhs, Fp3::Zero()});
    }
    uint32_t Mul(uint32_t lhs, uint32_t rhs)
    {
        return Push({cb::Opcode::Mul, lhs, rhs, Fp3::Zero()});
    }
    cb::Program Take() { return std::move(m_program); }

private:
    uint32_t Push(cb::Instruction instruction)
    {
        const uint32_t out =
            static_cast<uint32_t>(m_program.instructions.size());
        m_program.instructions.push_back(std::move(instruction));
        return out;
    }
    cb::Program m_program;
};

template <typename Fn>
void Append(cb::ProgramTable& table,
            aq::AirKind kind,
            uint32_t degree,
            Fn&& build)
{
    ProgramBuilder builder(
        table.role,
        static_cast<uint32_t>(table.programs.size()),
        kind, degree, table.current_width);
    build(builder);
    table.programs.push_back(builder.Take());
}

void AppendBoolean(cb::ProgramTable& table, uint32_t column)
{
    Append(table, aq::AirKind::kEverywhere, 2,
           [column](ProgramBuilder& b) {
               const uint32_t value = b.Current(column);
               const uint32_t one = b.Constant(Fp3::One());
               const uint32_t minus_one = b.Sub(value, one);
               b.Mul(value, minus_one);
           });
}

uint32_t SelectNibbleTable(
    ProgramBuilder& b,
    uint32_t bits_base,
    const std::array<int64_t, 16>& table)
{
    uint32_t value = b.Constant(Fp3::Zero());
    for (uint32_t entry = 0; entry < 16; ++entry) {
        uint32_t selector = b.Constant(Fp3::One());
        for (uint32_t bit = 0; bit < 4; ++bit) {
            const uint32_t cell = b.Current(bits_base + bit);
            uint32_t factor = cell;
            if (((entry >> bit) & 1U) == 0) {
                const uint32_t one = b.Constant(Fp3::One());
                factor = b.Sub(one, cell);
            }
            selector = b.Mul(selector, factor);
        }
        const uint32_t coefficient =
            b.Constant(gf::FromSigned3(table[entry]));
        const uint32_t term = b.Mul(selector, coefficient);
        value = b.Add(value, term);
    }
    return value;
}

uint32_t NextPow2(uint32_t value)
{
    uint32_t result = 2;
    while (result < value && result <= std::numeric_limits<uint32_t>::max() / 2U) {
        result <<= 1;
    }
    return result;
}

CS BuildCanonicalKernel(RCStage3RelationRole role, uint32_t n_rows)
{
    cb::ProgramTable table;
    CS cs;
    if (!BuildRCStage3CoupledLocalKernelProgramTable(role, table) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, n_rows, cs)) {
        return {};
    }
    return cs;
}

CS BuildGemmKernel(uint32_t inner)
{
    using namespace coupled_air_col;
    CS cs = BuildCanonicalKernel(
        RCStage3RelationRole::CoupledGemm,
        NextPow2(inner));
    if (cs.n_columns != GEMM_NUM_COLS) return {};
    cs.preprocessed_pin_ood = true;
    std::vector<Fp3> active(cs.n_rows, Fp3::Zero());
    for (uint32_t row = 0; row < inner; ++row) active[row] = Fp3::One();
    cs.preprocessed.push_back({GEMM_ACTIVE, std::move(active)});
    return cs;
}

CS BuildCopyKernel(RCStage3RelationRole role)
{
    return BuildCanonicalKernel(role, 2);
}

uint32_t MixBitColumn(uint32_t limb, uint32_t bit)
{
    return coupled_air_col::MIX_BITS + limb * 16U + bit;
}

CS BuildMixKernel()
{
    return BuildCanonicalKernel(
        RCStage3RelationRole::CoupledMix, 2);
}

void Gap(RCStage3CoupledAirEntry& out, RCStage3CoupledAirGapCode code,
         const char* detail)
{
    out.gaps.push_back({code, detail});
}

bool SameCounts(const RCStage3CoupledRelationCounts& a,
                const RCStage3CoupledRelationCounts& b)
{
    return a.primary == b.primary && a.secondary == b.secondary;
}

} // namespace

bool BuildRCStage3CoupledLocalKernelProgramTable(
    RCStage3RelationRole role,
    cb::ProgramTable& out,
    std::string* why)
{
    using namespace coupled_air_col;
    out = {};
    out.role = role;
    switch (role) {
    case RCStage3RelationRole::CoupledBank:
        out.current_width = BANK_NUM_COLS;
        break;
    case RCStage3RelationRole::CoupledGemm:
        out.current_width = GEMM_NUM_COLS;
        break;
    case RCStage3RelationRole::CoupledExchange:
    case RCStage3RelationRole::CoupledPermutation:
        out.current_width = COPY_NUM_COLS;
        break;
    case RCStage3RelationRole::CoupledMix:
        out.current_width = MIX_NUM_COLS;
        break;
    case RCStage3RelationRole::CoupledExtract:
        // Full RcSampler local kernel as bytecode. scale_e=0 is the canonical
        // wired default; the C_rho-assembling lane calls the scale_e-
        // parameterized builder directly for other public exponents.
        return BuildRCStage3CoupledExtractLocalKernelProgramTable(
            0, out, why);
    case RCStage3RelationRole::CoupledBarrier:
    case RCStage3RelationRole::CoupledDigest:
        // SHA-256 compression fixed-program AIR as bytecode (shared by both
        // DirectSha256d roles; the committed table role differs).
        return BuildRCStage3CoupledHashKernelProgramTable(role, out, why);
    default:
        return Fail(why, "bytecode_role");
    }
    out.next_width = out.current_width;

    if (role == RCStage3RelationRole::CoupledBank) {
        for (uint32_t bit = 0; bit < 4; ++bit) {
            AppendBoolean(out, BANK_NB0 + bit);
        }
        AppendBoolean(out, BANK_E0);
        AppendBoolean(out, BANK_E1);
        Append(out, aq::AirKind::kEverywhere, 1,
               [](ProgramBuilder& b) {
                   const uint32_t target = b.Current(BANK_NIB);
                   uint32_t value = b.Constant(Fp3::Zero());
                   for (uint32_t bit = 0; bit < 4; ++bit) {
                       const uint32_t coefficient =
                           b.Constant(U(1U << bit));
                       const uint32_t cell =
                           b.Current(BANK_NB0 + bit);
                       value = b.Add(
                           value, b.Mul(coefficient, cell));
                   }
                   b.Sub(target, value);
               });
        const gkr_air::TableTM tm;
        std::array<int64_t, 16> acc{};
        std::array<int64_t, 16> mu{};
        for (uint32_t i = 0; i < 16; ++i) {
            acc[i] = tm.acc[i];
            mu[i] = tm.mu[i];
        }
        Append(out, aq::AirKind::kEverywhere, 4,
               [acc](ProgramBuilder& b) {
                   const uint32_t target = b.Current(BANK_ACC);
                   b.Sub(
                       target,
                       SelectNibbleTable(
                           b, BANK_NB0, acc));
               });
        Append(out, aq::AirKind::kEverywhere, 4,
               [mu](ProgramBuilder& b) {
                   const uint32_t target = b.Current(BANK_MU);
                   b.Sub(
                       target,
                       SelectNibbleTable(
                           b, BANK_NB0, mu));
               });
        Append(out, aq::AirKind::kEverywhere, 3,
               [](ProgramBuilder& b) {
                   const uint32_t target = b.Current(BANK_OUT);
                   const uint32_t mu = b.Current(BANK_MU);
                   const uint32_t e0 = b.Current(BANK_E0);
                   const uint32_t e1 = b.Current(BANK_E1);
                   const uint32_t one0 = b.Constant(Fp3::One());
                   const uint32_t one1 = b.Constant(Fp3::One());
                   const uint32_t three = b.Constant(U(3));
                   const uint32_t left = b.Add(one0, e0);
                   const uint32_t right =
                       b.Add(one1, b.Mul(three, e1));
                   const uint32_t scale = b.Mul(left, right);
                   b.Sub(target, b.Mul(mu, scale));
               });
    } else if (role == RCStage3RelationRole::CoupledGemm) {
        for (uint32_t column : {GEMM_A, GEMM_B}) {
            Append(out, aq::AirKind::kEverywhere, 2,
                   [column](ProgramBuilder& b) {
                       const uint32_t one =
                           b.Constant(Fp3::One());
                       const uint32_t active =
                           b.Current(GEMM_ACTIVE);
                       const uint32_t value =
                           b.Current(column);
                       b.Mul(b.Sub(one, active), value);
                   });
        }
        Append(out, aq::AirKind::kFirstRow, 2,
               [](ProgramBuilder& b) {
                   const uint32_t acc = b.Current(GEMM_ACC);
                   const uint32_t a = b.Current(GEMM_A);
                   const uint32_t operand = b.Current(GEMM_B);
                   b.Sub(acc, b.Mul(a, operand));
               });
        Append(out, aq::AirKind::kTransition, 3,
               [](ProgramBuilder& b) {
                   const uint32_t next_acc = b.Next(GEMM_ACC);
                   const uint32_t acc = b.Current(GEMM_ACC);
                   const uint32_t active = b.Next(GEMM_ACTIVE);
                   const uint32_t a = b.Next(GEMM_A);
                   const uint32_t operand = b.Next(GEMM_B);
                   const uint32_t product = b.Mul(a, operand);
                   const uint32_t term = b.Mul(active, product);
                   b.Sub(next_acc, b.Add(acc, term));
               });
        Append(out, aq::AirKind::kTransition, 1,
               [](ProgramBuilder& b) {
                   const uint32_t next_out = b.Next(GEMM_OUT);
                   const uint32_t out = b.Current(GEMM_OUT);
                   b.Sub(next_out, out);
               });
        Append(out, aq::AirKind::kLastRow, 1,
               [](ProgramBuilder& b) {
                   const uint32_t acc = b.Current(GEMM_ACC);
                   const uint32_t out = b.Current(GEMM_OUT);
                   b.Sub(acc, out);
               });
    } else if (role == RCStage3RelationRole::CoupledExchange ||
               role == RCStage3RelationRole::CoupledPermutation) {
        Append(out, aq::AirKind::kEverywhere, 1,
               [](ProgramBuilder& b) {
                   const uint32_t output =
                       b.Current(COPY_OUTPUT);
                   const uint32_t input =
                       b.Current(COPY_INPUT);
                   b.Sub(output, input);
               });
    } else if (role == RCStage3RelationRole::CoupledMix) {
        // Each arithmetic limb is reconstructed from 16 boolean cells. This
        // prevents Goldilocks-field wrap from masquerading as uint64 wrap.
        for (uint32_t limb = 0; limb < 16; ++limb) {
            for (uint32_t bit = 0; bit < 16; ++bit) {
                AppendBoolean(out, MixBitColumn(limb, bit));
            }
            Append(out, aq::AirKind::kEverywhere, 1,
                   [limb](ProgramBuilder& b) {
                       const uint32_t target = b.Current(limb);
                       uint32_t value = b.Constant(Fp3::Zero());
                       for (uint32_t bit = 0; bit < 16; ++bit) {
                           const uint32_t coefficient =
                               b.Constant(U(1U << bit));
                           const uint32_t cell =
                               b.Current(MixBitColumn(limb, bit));
                           value = b.Add(
                               value,
                               b.Mul(coefficient, cell));
                       }
                       b.Sub(target, value);
                   });
        }
        for (uint32_t limb = 0; limb < 4; ++limb) {
            AppendBoolean(out, MIX_CARRY + limb);
            AppendBoolean(out, MIX_BORROW + limb);
            Append(out, aq::AirKind::kEverywhere, 1,
                   [limb](ProgramBuilder& b) {
                       const uint32_t a =
                           b.Current(MIX_A_LIMB + limb);
                       const uint32_t operand =
                           b.Current(MIX_B_LIMB + limb);
                       uint32_t lhs = b.Add(a, operand);
                       if (limb != 0) {
                           lhs = b.Add(
                               lhs,
                               b.Current(
                                   MIX_CARRY + limb - 1U));
                       }
                       const uint32_t sum =
                           b.Current(MIX_SUM_LIMB + limb);
                       const uint32_t base =
                           b.Constant(U(1U << 16));
                       const uint32_t carry =
                           b.Current(MIX_CARRY + limb);
                       const uint32_t rhs =
                           b.Add(sum, b.Mul(base, carry));
                       b.Sub(lhs, rhs);
                   });
            Append(out, aq::AirKind::kEverywhere, 1,
                   [limb](ProgramBuilder& b) {
                       const uint32_t operand =
                           b.Current(MIX_B_LIMB + limb);
                       const uint32_t a =
                           b.Current(MIX_A_LIMB + limb);
                       uint32_t relation = b.Sub(operand, a);
                       if (limb != 0) {
                           relation = b.Sub(
                               relation,
                               b.Current(
                                   MIX_BORROW + limb - 1U));
                       }
                       const uint32_t base =
                           b.Constant(U(1U << 16));
                       const uint32_t borrow =
                           b.Current(MIX_BORROW + limb);
                       relation = b.Add(
                           relation, b.Mul(base, borrow));
                       const uint32_t difference =
                           b.Current(MIX_DIFF_LIMB + limb);
                       b.Sub(relation, difference);
                   });
        }
    }
    return cb::ValidateProgramTable(out, why);
}

bool ResolveRCStage3CoupledAir(const RCStage3CoupledAirRequest& request,
                               RCStage3CoupledAirEntry& out,
                               std::string* why)
{
    out = {};
    out.role = request.role;
    const auto counts =
        ExpectedRCStage3CoupledRelationCounts(request.role, request.shape, why);
    if (!counts.has_value()) return false;
    if (request.extract_scale_e > 3) return Fail(why, "extract_scale_e");
    out.coverage.required = *counts;

    switch (request.role) {
    case RCStage3RelationRole::CoupledBank:
        out.constraints = BuildCanonicalKernel(
            RCStage3RelationRole::CoupledBank, 2);
        out.constraint_system_available = true;
        out.local_kernel_complete = true;
        out.coverage.kernel = *counts;
        if (!kRCStage3CoupledBankSeedXofPrototypeExecuted) {
            Gap(out, RCStage3CoupledAirGapCode::BankSeedXof,
                "bank nibble/scale columns are not yet bound to the page seed SHA-XOF");
        }
        if (!kRCStage3CoupledBankPageInclusionPrototypeExecuted) {
            Gap(out, RCStage3CoupledAirGapCode::BankPageInclusion,
                "selected page cells are not yet opened against the canonical bank root");
        }
        break;
    case RCStage3RelationRole::CoupledGemm:
        out.constraints = BuildGemmKernel(request.shape.lobe_width);
        out.constraint_system_available = true;
        out.local_kernel_complete = true;
        out.coverage.kernel = *counts;
        break;
    case RCStage3RelationRole::CoupledExchange:
        out.constraints = BuildCopyKernel(
            RCStage3RelationRole::CoupledExchange);
        out.constraint_system_available = true;
        out.local_kernel_complete = true;
        out.coverage.kernel = *counts;
        if (!kRCStage3CoupledExchangeSchedulePrototypeExecuted) {
            Gap(out, RCStage3CoupledAirGapCode::PublicScheduleBinding,
                "fixed segment and material-exchange row indices lack proof-bound schedule columns");
        }
        if (request.shape.exchange_rounds != 0 &&
            !kRCStage3CoupledMaterialExchangeHashXofPrototypeExecuted) {
            Gap(out, RCStage3CoupledAirGapCode::MaterialExchangeHashXof,
                "dependency-linked exchange seed SHA-XOF and XOR rounds lack an AIR");
        }
        break;
    case RCStage3RelationRole::CoupledPermutation:
        out.constraints = BuildCopyKernel(
            RCStage3RelationRole::CoupledPermutation);
        out.constraint_system_available = true;
        out.local_kernel_complete = true;
        out.coverage.kernel = *counts;
        if (!kRCStage3CoupledPermutationSchedulePrototypeExecuted) {
            Gap(out, RCStage3CoupledAirGapCode::PublicScheduleBinding,
                "bit-affine source/destination index evaluation is not pinned into this AIR");
        }
        break;
    case RCStage3RelationRole::CoupledMix:
        out.constraints = BuildMixKernel();
        out.constraint_system_available = true;
        out.local_kernel_complete = true;
        out.coverage.kernel = *counts;
        if (!kRCStage3CoupledMixSchedulePrototypeExecuted) {
            Gap(out, RCStage3CoupledAirGapCode::PublicScheduleBinding,
                "butterfly stage pairing, rotate-mask indices, and pattern order are not proof-bound");
        }
        break;
    case RCStage3RelationRole::CoupledExtract: {
        const gkr_air::TableTM tm;
        out.constraints = aq::BuildRcSamplerConstraintSystem<Fp3>(
            gkr_air::kAirSlotBudget, request.gamma, request.alpha,
            request.extract_scale_e, tm);
        out.constraint_system_available = true;
        out.local_kernel_complete = false;
        out.coverage.kernel = *counts;
        Gap(out, RCStage3CoupledAirGapCode::ExtractChaChaAndScaleSha,
            "sampler keystream and scale exponent are not connected to committed ChaCha/SHA AIR columns");
        Gap(out, RCStage3CoupledAirGapCode::ExtractInt64AndRangeLookups,
            "C-E7/C-E8 int64 embedding plus T_X/T_R16 proof-bound lookup columns remain absent");
        break;
    }
    case RCStage3RelationRole::CoupledBarrier:
        Gap(out, RCStage3CoupledAirGapCode::BarrierSha256d,
            "generic committed-cell SHA checker has no immutable AirConstraintSystem resolver");
        break;
    case RCStage3RelationRole::CoupledDigest:
        Gap(out, RCStage3CoupledAirGapCode::DigestSha256d,
            "bank/barrier root SHA256d closure has no immutable AirConstraintSystem resolver");
        break;
    default:
        return Fail(why, "role");
    }

    if (out.constraint_system_available) {
        Gap(out, RCStage3CoupledAirGapCode::CommitmentOpeningBridge,
            "AIR trace columns are not yet opened against the Stage-3 input/output/trace roots");
    }
    Gap(out, RCStage3CoupledAirGapCode::RecursiveAggregation,
        "complete scheduled AIR instances are not yet closed under bounded-width recursion");

    out.proof_only_complete =
        out.constraint_system_available && out.local_kernel_complete &&
        SameCounts(out.coverage.required, out.coverage.kernel) && out.gaps.empty();
    if (why != nullptr) {
        *why = out.proof_only_complete ? "stage3:coupled_air:ok"
                                      : "stage3:coupled_air:residual_gaps";
    }
    return true;
}

std::vector<RCStage3CoupledAirEntry>
AssessRCStage3CoupledAirRegistry(const RCStage3CoupledShape& shape,
                                 const Fp3& gamma,
                                 const Fp3& alpha,
                                 uint8_t extract_scale_e)
{
    std::vector<RCStage3CoupledAirEntry> result;
    result.reserve(COUPLED_ROLES.size());
    for (RCStage3RelationRole role : COUPLED_ROLES) {
        RCStage3CoupledAirEntry entry;
        std::string ignored;
        if (!ResolveRCStage3CoupledAir(
                {role, shape, gamma, alpha, extract_scale_e}, entry, &ignored)) {
            entry = {};
            entry.role = role;
        }
        result.push_back(std::move(entry));
    }
    return result;
}

bool RCStage3CoupledAirRegistryReady(const RCStage3CoupledShape& shape,
                                     const Fp3& gamma,
                                     const Fp3& alpha,
                                     std::string* why)
{
    const auto entries =
        AssessRCStage3CoupledAirRegistry(shape, gamma, alpha);
    if (entries.size() != COUPLED_ROLES.size()) return Fail(why, "registry_size");
    for (const auto& entry : entries) {
        if (!entry.proof_only_complete) {
            return Fail(why, std::string(RCStage3RelationRoleName(entry.role)) +
                                 ":residual_gaps");
        }
    }
    if (why != nullptr) *why = "stage3:coupled_air:ok";
    return true;
}

} // namespace matmul::v4::rc
