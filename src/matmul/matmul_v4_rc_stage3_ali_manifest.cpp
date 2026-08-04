// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_ali_manifest.h>

#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_stage3_family_vm.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <string_view>

namespace matmul::v4::rc::stage3_ali_manifest {

namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace topo = universal_topology;
namespace vm = stage3_family_vm;

constexpr gf::Fp kOmega2_32 =
    UINT64_C(0x185629dcda58878c);
constexpr std::string_view kCommitmentDomain =
    "BTX_RC_STAGE3_PRODUCTION_ALI_MANIFEST_V1";
constexpr std::string_view kAssessmentCommitmentDomainV2 =
    "BTX_RC_STAGE3_PRODUCTION_ALI_ASSESSMENT_V2";

bool Fail(std::string* why, const char* reason)
{
    if (why != nullptr) {
        *why = std::string{"stage3:ali_manifest:"} + reason;
    }
    return false;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 &&
        (value & (value - 1U)) == 0;
}

gf::Fp PowBase(gf::Fp base, uint64_t exponent)
{
    gf::Fp out = 1;
    base = gf::Canonical(base);
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

gf::Fp OmegaForSize(uint32_t size)
{
    if (!IsPowerOfTwo(size)) return 0;
    uint32_t log_size = 0;
    for (uint32_t remaining = size;
         remaining > 1;
         remaining >>= 1) {
        ++log_size;
    }
    if (log_size > 32) return 0;
    return PowBase(
        kOmega2_32,
        UINT64_C(1) << (32 - log_size));
}

bool DigestCanonical(const ah::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp limb) {
            return limb < gf::kP;
        });
}

bool DigestZero(const ah::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp limb) {
            return limb == 0;
        });
}

void AppendU32(std::vector<gf::Fp>& preimage, uint32_t value)
{
    preimage.push_back(static_cast<gf::Fp>(value));
}

void AppendU64(std::vector<gf::Fp>& preimage, uint64_t value)
{
    // Never absorb an arbitrary uint64_t as one field element: x and x+p
    // would be the same Goldilocks lane. Two u32 lanes are injective.
    AppendU32(preimage, static_cast<uint32_t>(value));
    AppendU32(
        preimage,
        static_cast<uint32_t>(value >> 32));
}

void AppendBool(std::vector<gf::Fp>& preimage, bool value)
{
    AppendU32(preimage, value ? 1U : 0U);
}

void AppendBytes(
    std::vector<gf::Fp>& preimage,
    std::string_view bytes)
{
    AppendU64(preimage, bytes.size());
    for (size_t cursor = 0; cursor < bytes.size(); cursor += 4) {
        uint32_t word = 0;
        for (uint32_t byte = 0;
             byte < 4 && cursor + byte < bytes.size();
             ++byte) {
            word |=
                static_cast<uint32_t>(
                    static_cast<unsigned char>(
                        bytes[cursor + byte]))
                << (8 * byte);
        }
        AppendU32(preimage, word);
    }
}

bool AppendDigest(
    std::vector<gf::Fp>& preimage,
    const ah::Digest& digest)
{
    if (!DigestCanonical(digest)) return false;
    for (const gf::Fp limb : digest) {
        AppendU64(preimage, limb);
    }
    return true;
}

bool CheckedU32(size_t value, uint32_t& out)
{
    if (value > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    out = static_cast<uint32_t>(value);
    return true;
}

struct TableInventory {
    uint32_t constraints{0};
    uint32_t instructions{0};
    uint32_t challenge_loads{0};
    uint32_t maximum_degree{0};
    uint64_t maximum_composed_degree{0};
    uint32_t quotient_len{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    bool challenge_degree_checked{false};
};

bool AuditChallengeDegreeClass(
    const cb::ProgramTable& table,
    uint32_t& challenge_loads,
    std::string* why)
{
    challenge_loads = 0;
    for (const cb::Program& program : table.programs) {
        std::vector<uint32_t> degrees;
        degrees.reserve(program.instructions.size());
        for (uint32_t index = 0;
             index < program.instructions.size();
             ++index) {
            const cb::Instruction& instruction =
                program.instructions[index];
            switch (instruction.opcode) {
            case cb::Opcode::Current:
            case cb::Opcode::Next:
                degrees.push_back(1);
                break;
            case cb::Opcode::Challenge:
                if (instruction.lhs >=
                        program.challenge_width ||
                    challenge_loads ==
                        std::numeric_limits<uint32_t>::max()) {
                    return Fail(
                        why, "challenge_class_index");
                }
                ++challenge_loads;
                // Challenge values are verifier-owned but are still
                // algebraic variables of degree one in the ALI identity.
                degrees.push_back(1);
                break;
            case cb::Opcode::Constant:
                degrees.push_back(0);
                break;
            case cb::Opcode::Add:
            case cb::Opcode::Sub:
            case cb::Opcode::Mul:
                if (instruction.lhs >= index ||
                    instruction.rhs >= index) {
                    return Fail(
                        why, "challenge_class_register");
                }
                if (instruction.opcode == cb::Opcode::Mul) {
                    const uint64_t degree =
                        uint64_t{degrees[instruction.lhs]} +
                        degrees[instruction.rhs];
                    if (degree >
                        std::numeric_limits<uint32_t>::max()) {
                        return Fail(
                            why,
                            "challenge_class_degree_overflow");
                    }
                    degrees.push_back(
                        static_cast<uint32_t>(degree));
                } else {
                    degrees.push_back(std::max(
                        degrees[instruction.lhs],
                        degrees[instruction.rhs]));
                }
                break;
            default:
                return Fail(
                    why, "challenge_class_opcode");
            }
        }
        if (degrees.empty() ||
            degrees.back() != program.declared_degree) {
            return Fail(
                why, "challenge_class_declared_degree");
        }
    }
    return true;
}

bool DeriveTableInventory(
    const cb::ProgramTable& table,
    TableInventory& out,
    std::string* why)
{
    out = {};
    if (!cb::ValidateProgramTable(table, why) ||
        !CheckedU32(table.programs.size(), out.constraints)) {
        return Fail(why, "program_table");
    }
    uint64_t instruction_count = 0;
    for (const cb::Program& program : table.programs) {
        instruction_count += program.instructions.size();
        if (instruction_count >
            std::numeric_limits<uint32_t>::max()) {
            return Fail(why, "instruction_count");
        }
        out.maximum_degree =
            std::max(
                out.maximum_degree,
                program.declared_degree);
    }
    out.instructions =
        static_cast<uint32_t>(instruction_count);
    if (!AuditChallengeDegreeClass(
            table, out.challenge_loads, why)) {
        return false;
    }
    out.challenge_degree_checked = true;

    std::vector<gf::Fp3> challenges(
        table.challenge_width,
        gf::Fp3::Zero());
    aq::AirConstraintSystem<gf::Fp3> cs;
    if (!cb::BuildAirConstraintSystemFromProgramTable(
            table,
            kProductionAliPaddedQueryRowsV1,
            challenges, cs, why)) {
        return Fail(why, "constraint_system");
    }
    out.maximum_composed_degree =
        cs.MaxComposedDegreeBound();
    out.quotient_len = cs.QuotientLen();
    out.n_coeffs = FriNextPow2(std::max(
        kProductionAliPaddedQueryRowsV1,
        out.quotient_len));
    if (out.n_coeffs == 0 ||
        out.n_coeffs >
            std::numeric_limits<uint32_t>::max() /
                kRCFriBlowup) {
        return Fail(why, "lde_overflow");
    }
    out.n_lde = out.n_coeffs * kRCFriBlowup;
    return true;
}

bool StructuralStub(
    const topo::ProductionFamilyProgramSourceV1& source)
{
    if (source.semantic_relation_complete ||
        !source.semantic_endpoints.empty() ||
        source.program.current_width != 1 ||
        source.program.next_width != 1 ||
        source.program.challenge_width != 0 ||
        source.program.programs.size() != 1) {
        return false;
    }
    const cb::Program& program =
        source.program.programs.front();
    return
        program.instructions.size() == 1 &&
        program.instructions.front().opcode ==
            cb::Opcode::Current;
}

bool DeriveFamily(
    const topo::ProductionFamilyProgramSourceV1& source,
    ProductionAliFamilyV1& out,
    std::string* why)
{
    out = {};
    out.family_index = source.family_index;
    out.kind = source.kind;
    out.role = source.role;
    out.semantic_endpoints =
        source.semantic_endpoints;
    out.semantic_relation_complete =
        source.semantic_relation_complete;

    out.source_program_key =
        cb::CommitProgramTableAlgHash(source.program);
    out.source_current_width =
        source.program.current_width;
    out.source_next_width =
        source.program.next_width;
    out.source_challenge_width =
        source.program.challenge_width;

    TableInventory source_inventory;
    if (!DeriveTableInventory(
            source.program, source_inventory, why) ||
        DigestZero(out.source_program_key) ||
        !DigestCanonical(out.source_program_key)) {
        return Fail(why, "source_inventory");
    }
    out.source_constraint_count =
        source_inventory.constraints;
    out.source_instruction_count =
        source_inventory.instructions;
    out.source_challenge_loads =
        source_inventory.challenge_loads;
    out.source_max_degree =
        source_inventory.maximum_degree;
    out.source_max_composed_degree =
        source_inventory.maximum_composed_degree;
    out.source_quotient_len =
        source_inventory.quotient_len;
    out.source_n_coeffs =
        source_inventory.n_coeffs;
    out.source_n_lde =
        source_inventory.n_lde;

    rba::QuotientDomainV1 domain;
    if (!BuildProductionAliSourceDomainV1(
            source.program, domain, why)) {
        return false;
    }
    const cw::CompiledQuotientProgramV1 compiled =
        cw::CompileConstantWidthQuotientProgramV1(
            source.program,
            out.source_program_key,
            domain,
            kProductionAliQueriesV1);
    if (!compiled.valid) {
        return Fail(why, "compile");
    }
    TableInventory compiled_inventory;
    if (!DeriveTableInventory(
            compiled.compiled_table,
            compiled_inventory, why)) {
        return false;
    }
    out.compiled_program_key =
        compiled.compiled_program_key;
    if (DigestZero(out.compiled_program_key) ||
        !DigestCanonical(out.compiled_program_key) ||
        out.compiled_program_key !=
            cb::CommitProgramTableAlgHash(
                compiled.compiled_table)) {
        return Fail(why, "compiled_key");
    }
    out.compiled_current_width =
        compiled.compiled_table.current_width;
    out.compiled_next_width =
        compiled.compiled_table.next_width;
    out.compiled_challenge_width =
        compiled.compiled_table.challenge_width;
    out.compiled_constraint_count =
        compiled_inventory.constraints;
    out.compiled_instruction_count =
        compiled_inventory.instructions;
    out.compiled_challenge_loads =
        compiled_inventory.challenge_loads;
    out.compiled_max_degree =
        compiled_inventory.maximum_degree;
    out.compiled_max_composed_degree =
        compiled_inventory.maximum_composed_degree;
    out.compiled_quotient_len =
        compiled_inventory.quotient_len;
    out.compiled_n_coeffs =
        compiled_inventory.n_coeffs;
    out.compiled_n_lde =
        compiled_inventory.n_lde;
    out.compiled_physical_columns =
        compiled.physical_columns;

    const cw::VerticalVmCapacityV1 capacity =
        cw::AssessVerticalVmCapacityV1(
            source.program,
            out.source_program_key,
            domain,
            kProductionAliQueriesV1);
    if (!capacity.valid) {
        return Fail(why, "capacity");
    }
    out.semantic_rows = compiled.semantic_rows;
    out.padded_source_rows = compiled.padded_rows;
    out.vertical_logical_rows =
        capacity.logical_vertical_rows;
    out.vertical_padded_rows =
        capacity.padded_vertical_rows;
    out.coefficient_cap =
        capacity.coefficient_cap;
    out.minimum_vm_segments =
        capacity.minimum_vm_segments;

    out.source_table_canonical =
        cb::ValidateProgramTable(source.program);
    out.source_table_non_stub =
        !StructuralStub(source);
    out.challenge_class_degree_checked =
        source_inventory.challenge_degree_checked &&
        compiled_inventory.challenge_degree_checked;
    out.compiled_table_canonical =
        cb::ValidateProgramTable(
            compiled.compiled_table);
    out.exact_q192_rows =
        compiled.semantic_rows ==
            kProductionAliQueriesV1 &&
        compiled.padded_rows ==
            kProductionAliPaddedQueryRowsV1 &&
        capacity.semantic_rows ==
            kProductionAliQueriesV1 &&
        capacity.padded_source_rows ==
            kProductionAliPaddedQueryRowsV1;
    out.quotient_and_lde_bounds_derived =
        out.source_quotient_len != 0 &&
        out.source_n_coeffs != 0 &&
        out.source_n_lde ==
            out.source_n_coeffs * kRCFriBlowup &&
        out.compiled_quotient_len != 0 &&
        out.compiled_n_coeffs != 0 &&
        out.compiled_n_lde ==
            out.compiled_n_coeffs * kRCFriBlowup;
    out.within_coefficient_cap =
        capacity.fits_unsegmented_split_rap &&
        capacity.minimum_vm_segments == 1 &&
        capacity.padded_vertical_rows <=
            capacity.coefficient_cap;
    out.constant_width_53 =
        compiled.physical_columns ==
            kProductionAliCompiledColumnsV1 &&
        compiled.physical_columns ==
            vm::kFamilyVmExecutableColumnsV1 &&
        compiled.constant_physical_width;
    return true;
}

void AccumulateMaxima(
    ProductionAliManifestV1& out,
    const ProductionAliFamilyV1& family)
{
    out.maximum_source_width =
        std::max(
            out.maximum_source_width,
            family.source_current_width);
    out.maximum_source_challenge_width =
        std::max(
            out.maximum_source_challenge_width,
            family.source_challenge_width);
    out.maximum_source_constraints =
        std::max(
            out.maximum_source_constraints,
            family.source_constraint_count);
    out.maximum_source_instructions =
        std::max(
            out.maximum_source_instructions,
            family.source_instruction_count);
    out.maximum_source_degree =
        std::max(
            out.maximum_source_degree,
            family.source_max_degree);
    out.maximum_source_quotient_len =
        std::max(
            out.maximum_source_quotient_len,
            family.source_quotient_len);
    out.maximum_source_n_lde =
        std::max(
            out.maximum_source_n_lde,
            family.source_n_lde);
    out.maximum_compiled_constraints =
        std::max(
            out.maximum_compiled_constraints,
            family.compiled_constraint_count);
    out.maximum_compiled_instructions =
        std::max(
            out.maximum_compiled_instructions,
            family.compiled_instruction_count);
    out.maximum_compiled_degree =
        std::max(
            out.maximum_compiled_degree,
            family.compiled_max_degree);
    out.maximum_compiled_quotient_len =
        std::max(
            out.maximum_compiled_quotient_len,
            family.compiled_quotient_len);
    out.maximum_compiled_n_lde =
        std::max(
            out.maximum_compiled_n_lde,
            family.compiled_n_lde);
    out.maximum_vertical_logical_rows =
        std::max(
            out.maximum_vertical_logical_rows,
            family.vertical_logical_rows);
    out.maximum_vertical_padded_rows =
        std::max(
            out.maximum_vertical_padded_rows,
            family.vertical_padded_rows);
    out.maximum_minimum_vm_segments =
        std::max(
            out.maximum_minimum_vm_segments,
            family.minimum_vm_segments);
    out.total_source_constraints +=
        family.source_constraint_count;
    out.total_source_instructions +=
        family.source_instruction_count;
    out.total_compiled_constraints +=
        family.compiled_constraint_count;
    out.total_compiled_instructions +=
        family.compiled_instruction_count;
    if (family.semantic_relation_complete) {
        ++out.semantic_complete_families;
    } else {
        ++out.semantic_partial_families;
    }
    if (family.source_challenge_loads != 0) {
        ++out.families_with_challenge_loads;
    }
}

template <typename Member>
bool Every(
    const std::vector<ProductionAliFamilyV1>& families,
    Member member)
{
    return std::all_of(
        families.begin(), families.end(),
        [member](const ProductionAliFamilyV1& family) {
            return family.*member;
        });
}

} // namespace

bool BuildProductionAliSourceDomainV1(
    const cb::ProgramTable& source,
    rba::QuotientDomainV1& out,
    std::string* why)
{
    out = {};
    TableInventory inventory;
    if (!DeriveTableInventory(
            source, inventory, why) ||
        !IsPowerOfTwo(inventory.n_lde) ||
        inventory.n_lde <
            kProductionAliPaddedQueryRowsV1) {
        return Fail(why, "source_domain_inventory");
    }
    const gf::Fp trace_omega =
        OmegaForSize(kProductionAliPaddedQueryRowsV1);
    const gf::Fp evaluation_omega =
        OmegaForSize(inventory.n_lde);
    if (trace_omega == 0 ||
        evaluation_omega == 0) {
        return Fail(why, "source_domain_root");
    }
    out.trace_rows =
        kProductionAliPaddedQueryRowsV1;
    out.trace_omega =
        gf::Fp3::FromFp(trace_omega);
    out.evaluation_rows = inventory.n_lde;
    out.evaluation_omega =
        gf::Fp3::FromFp(evaluation_omega);
    out.coset_shift =
        gf::Fp3::FromFp(7);
    return true;
}

ProductionAliManifestV1
BuildProductionAliManifestV1()
{
    ProductionAliManifestV1 out;
    const sites::ProductionProofSiteManifest site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    const std::vector<
        topo::ProductionFamilyProgramSourceV1> sources =
        topo::BuildProductionFamilyProgramSourcesV1(
            site_manifest);
    std::string why;
    if (!BuildProductionAliManifestFromSourcesV1(
            site_manifest, sources, out, &why)) {
        out.note =
            "stage3:ali_manifest:canonical_sources:" +
            why;
    }
    return out;
}

bool BuildProductionAliManifestFromSourcesV1(
    const sites::ProductionProofSiteManifest& site_manifest,
    const std::vector<topo::ProductionFamilyProgramSourceV1>& sources,
    ProductionAliManifestV1& out,
    std::string* why)
{
    out = {};
    std::string local_why;
    if (!sites::ValidateProductionProofSiteManifest(
            site_manifest, &local_why) ||
        site_manifest.entries.size() !=
            kProductionAliFamilyCountV1 ||
        sources.size() !=
            kProductionAliFamilyCountV1) {
        return Fail(why, "source_set_shape");
    }

    std::array<bool, kProductionAliFamilyCountV1> seen{};
    for (uint32_t index = 0; index < sources.size(); ++index) {
        const auto& source = sources[index];
        const auto& site = site_manifest.entries[index];
        if (source.family_index >= seen.size() ||
            seen[source.family_index] ||
            source.family_index != index ||
            source.kind != site.kind ||
            source.role != site.role ||
            source.program.role != source.role ||
            static_cast<uint32_t>(source.kind) != index + 1U) {
            return Fail(why, "source_identity_or_duplicate");
        }
        seen[source.family_index] = true;
        if (!cb::ValidateProgramTable(
                source.program, &local_why)) {
            if (why != nullptr) {
                *why =
                    "stage3:ali_manifest:source_program_" +
                    std::to_string(index) + ":" + local_why;
            }
            return false;
        }
        if (StructuralStub(source)) {
            return Fail(why, "source_structural_stub");
        }
    }
    if (!topo::ValidateProductionFamilyProgramSourcesV1(
            site_manifest, sources, &local_why)) {
        if (why != nullptr) {
            *why =
                "stage3:ali_manifest:source_transplant:" +
                local_why;
        }
        return false;
    }

    out.families.reserve(sources.size());
    for (uint32_t index = 0; index < sources.size(); ++index) {
        ProductionAliFamilyV1 family;
        if (!DeriveFamily(sources[index], family, &local_why)) {
            if (why != nullptr) {
                *why =
                    "stage3:ali_manifest:family:" +
                    std::to_string(index) + ":" + local_why;
            }
            out = {};
            return false;
        }
        AccumulateMaxima(out, family);
        out.families.push_back(std::move(family));
    }

    out.exact_28_family_order =
        out.families.size() ==
            kProductionAliFamilyCountV1;
    out.every_source_key_derived =
        std::all_of(
            out.families.begin(), out.families.end(),
            [](const ProductionAliFamilyV1& family) {
                return
                    DigestCanonical(
                        family.source_program_key) &&
                    !DigestZero(
                        family.source_program_key);
            });
    out.every_compiled_key_derived =
        std::all_of(
            out.families.begin(), out.families.end(),
            [](const ProductionAliFamilyV1& family) {
                return
                    DigestCanonical(
                        family.compiled_program_key) &&
                    !DigestZero(
                        family.compiled_program_key);
            });
    out.every_source_non_stub =
        Every(
            out.families,
            &ProductionAliFamilyV1::
                source_table_non_stub);
    out.every_challenge_degree_checked =
        Every(
            out.families,
            &ProductionAliFamilyV1::
                challenge_class_degree_checked);
    out.every_q192_row_bound_exact =
        Every(
            out.families,
            &ProductionAliFamilyV1::
                exact_q192_rows);
    out.every_quotient_lde_bound_derived =
        Every(
            out.families,
            &ProductionAliFamilyV1::
                quotient_and_lde_bounds_derived);
    out.every_compiled_program_53_columns =
        Every(
            out.families,
            &ProductionAliFamilyV1::
                constant_width_53);
    out.every_family_within_cap =
        Every(
            out.families,
            &ProductionAliFamilyV1::
                within_coefficient_cap);
    out.canonical_u32_injective_commitment =
        out.every_source_key_derived &&
        out.every_compiled_key_derived;
    out.local_manifest_complete =
        out.exact_28_family_order &&
        out.every_source_key_derived &&
        out.every_compiled_key_derived &&
        out.every_source_non_stub &&
        out.every_challenge_degree_checked &&
        out.every_q192_row_bound_exact &&
        out.every_quotient_lde_bound_derived &&
        out.every_compiled_program_53_columns &&
        out.every_family_within_cap &&
        out.canonical_u32_injective_commitment;
    out.recursive_root_consumed =
        kProductionAliManifestRecursiveRootConsumedV1;
    out.production_authority =
        kProductionAliManifestAuthorityV1;
    out.note = out.local_manifest_complete
        ? "stage3:ali_manifest:exact_28_family_local_inventory;"
          "14_partial_semantic_families_and_recursive_root_pending"
        : "stage3:ali_manifest:local_inventory_incomplete";
    out.commitment =
        ComputeProductionAliManifestCommitmentV1(out);
    if (DigestZero(out.commitment)) {
        out.canonical_u32_injective_commitment = false;
        out.local_manifest_complete = false;
        out.note =
            "stage3:ali_manifest:commitment";
        return Fail(why, "commitment");
    }
    if (!out.local_manifest_complete) {
        return Fail(why, "local_inventory");
    }
    if (why != nullptr) {
        *why =
            "stage3:ali_manifest:canonical_non_stub_sources";
    }
    return true;
}

ah::Digest
ComputeProductionAliManifestCommitmentV1(
    const ProductionAliManifestV1& manifest)
{
    if (manifest.version !=
            kProductionAliManifestVersionV1 ||
        manifest.families.size() !=
            kProductionAliFamilyCountV1) {
        return {};
    }
    std::vector<gf::Fp> preimage;
    preimage.reserve(64 + manifest.families.size() * 96);
    AppendBytes(preimage, kCommitmentDomain);
    AppendU32(preimage, manifest.version);
    AppendU32(
        preimage,
        static_cast<uint32_t>(
            manifest.families.size()));
    for (const ProductionAliFamilyV1& family :
         manifest.families) {
        AppendU32(preimage, family.family_index);
        AppendU32(
            preimage,
            static_cast<uint32_t>(family.kind));
        AppendU32(
            preimage,
            static_cast<uint32_t>(family.role));
        AppendU32(
            preimage,
            static_cast<uint32_t>(
                family.semantic_endpoints.size()));
        for (const uint16_t endpoint :
             family.semantic_endpoints) {
            AppendU32(preimage, endpoint);
        }
        AppendBool(
            preimage,
            family.semantic_relation_complete);
        if (!AppendDigest(
                preimage, family.source_program_key)) {
            return {};
        }
        AppendU32(preimage, family.source_current_width);
        AppendU32(preimage, family.source_next_width);
        AppendU32(preimage, family.source_challenge_width);
        AppendU32(preimage, family.source_constraint_count);
        AppendU32(preimage, family.source_instruction_count);
        AppendU32(preimage, family.source_challenge_loads);
        AppendU32(preimage, family.source_max_degree);
        AppendU64(
            preimage,
            family.source_max_composed_degree);
        AppendU32(preimage, family.source_quotient_len);
        AppendU32(preimage, family.source_n_coeffs);
        AppendU32(preimage, family.source_n_lde);
        if (!AppendDigest(
                preimage,
                family.compiled_program_key)) {
            return {};
        }
        AppendU32(preimage, family.compiled_current_width);
        AppendU32(preimage, family.compiled_next_width);
        AppendU32(
            preimage,
            family.compiled_challenge_width);
        AppendU32(
            preimage,
            family.compiled_constraint_count);
        AppendU32(
            preimage,
            family.compiled_instruction_count);
        AppendU32(
            preimage,
            family.compiled_challenge_loads);
        AppendU32(preimage, family.compiled_max_degree);
        AppendU64(
            preimage,
            family.compiled_max_composed_degree);
        AppendU32(preimage, family.compiled_quotient_len);
        AppendU32(preimage, family.compiled_n_coeffs);
        AppendU32(preimage, family.compiled_n_lde);
        AppendU32(
            preimage,
            family.compiled_physical_columns);
        AppendU32(preimage, family.semantic_rows);
        AppendU32(preimage, family.padded_source_rows);
        AppendU64(preimage, family.vertical_logical_rows);
        AppendU64(preimage, family.vertical_padded_rows);
        AppendU64(preimage, family.coefficient_cap);
        AppendU32(preimage, family.minimum_vm_segments);
        AppendBool(preimage, family.source_table_canonical);
        AppendBool(preimage, family.source_table_non_stub);
        AppendBool(
            preimage,
            family.challenge_class_degree_checked);
        AppendBool(
            preimage,
            family.compiled_table_canonical);
        AppendBool(preimage, family.exact_q192_rows);
        AppendBool(
            preimage,
            family.quotient_and_lde_bounds_derived);
        AppendBool(
            preimage,
            family.within_coefficient_cap);
        AppendBool(preimage, family.constant_width_53);
    }

    AppendU32(preimage, manifest.maximum_source_width);
    AppendU32(
        preimage,
        manifest.maximum_source_challenge_width);
    AppendU32(
        preimage,
        manifest.maximum_source_constraints);
    AppendU32(
        preimage,
        manifest.maximum_source_instructions);
    AppendU32(
        preimage,
        manifest.maximum_source_degree);
    AppendU32(
        preimage,
        manifest.maximum_source_quotient_len);
    AppendU32(preimage, manifest.maximum_source_n_lde);
    AppendU32(
        preimage,
        manifest.maximum_compiled_constraints);
    AppendU32(
        preimage,
        manifest.maximum_compiled_instructions);
    AppendU32(
        preimage,
        manifest.maximum_compiled_degree);
    AppendU32(
        preimage,
        manifest.maximum_compiled_quotient_len);
    AppendU32(preimage, manifest.maximum_compiled_n_lde);
    AppendU64(
        preimage,
        manifest.maximum_vertical_logical_rows);
    AppendU64(
        preimage,
        manifest.maximum_vertical_padded_rows);
    AppendU32(
        preimage,
        manifest.maximum_minimum_vm_segments);
    AppendU64(
        preimage,
        manifest.total_source_constraints);
    AppendU64(
        preimage,
        manifest.total_source_instructions);
    AppendU64(
        preimage,
        manifest.total_compiled_constraints);
    AppendU64(
        preimage,
        manifest.total_compiled_instructions);
    AppendU32(
        preimage,
        manifest.semantic_complete_families);
    AppendU32(
        preimage,
        manifest.semantic_partial_families);
    AppendU32(
        preimage,
        manifest.families_with_challenge_loads);
    AppendBool(preimage, manifest.exact_28_family_order);
    AppendBool(preimage, manifest.every_source_key_derived);
    AppendBool(preimage, manifest.every_compiled_key_derived);
    AppendBool(preimage, manifest.every_source_non_stub);
    AppendBool(
        preimage,
        manifest.every_challenge_degree_checked);
    AppendBool(
        preimage,
        manifest.every_q192_row_bound_exact);
    AppendBool(
        preimage,
        manifest.every_quotient_lde_bound_derived);
    AppendBool(
        preimage,
        manifest.every_compiled_program_53_columns);
    AppendBool(preimage, manifest.every_family_within_cap);
    AppendBool(
        preimage,
        manifest.canonical_u32_injective_commitment);
    AppendBool(preimage, manifest.local_manifest_complete);
    AppendBool(preimage, manifest.recursive_root_consumed);
    AppendBool(preimage, manifest.production_authority);
    return ah::SpongeHashFp(preimage);
}

bool ValidateProductionAliManifestV1(
    const ProductionAliManifestV1& manifest,
    std::string* why)
{
    const ProductionAliManifestV1 expected =
        BuildProductionAliManifestV1();
    if (!expected.local_manifest_complete ||
        expected.recursive_root_consumed ||
        expected.production_authority ||
        DigestZero(expected.commitment)) {
        return Fail(why, "canonical_build");
    }
    if (!(manifest == expected)) {
        return Fail(why, "canonical_equality");
    }
    if (manifest.commitment !=
        ComputeProductionAliManifestCommitmentV1(
            manifest)) {
        return Fail(why, "commitment");
    }
    return true;
}

bool BuildProductionAliAssessmentFromSourcesV2(
    const sites::ProductionProofSiteManifest& site_manifest,
    const std::vector<topo::ProductionFamilyProgramSourceV1>& sources,
    ProductionAliAssessmentV2& out,
    std::string* why)
{
    out = {};
    ProductionAliManifestV1 families;
    std::string local_why;
    if (!BuildProductionAliManifestFromSourcesV1(
            site_manifest, sources, families, &local_why)) {
        if (why != nullptr) {
            *why =
                "stage3:ali_assessment_v2:families:" +
                local_why;
        }
        return false;
    }
    const auto migration =
        topo::AssessProductionFamilyProgramMigrationV1(
            sources);
    out.family_manifest_commitment =
        families.commitment;
    out.family_count =
        static_cast<uint32_t>(families.families.size());
    out.semantic_complete_families =
        families.semantic_complete_families;
    out.semantic_partial_families =
        families.semantic_partial_families;
    out.source_constraints =
        families.total_source_constraints;
    out.source_instructions =
        families.total_source_instructions;
    out.compiled_constraints =
        families.total_compiled_constraints;
    out.compiled_instructions =
        families.total_compiled_instructions;
    out.partial_family_residuals =
        migration.partial_residuals;

    const auto& role_order = RCStage3UnifiedRoleOrder();
    out.roles.reserve(role_order.size());
    for (const RCStage3RelationRole role : role_order) {
        ProductionAliRoleAssessmentV2 summary;
        summary.role = role;
        const auto& required =
            RequiredRCStage3RelationEndpoints(role);
        summary.required_semantic_endpoints =
            static_cast<uint32_t>(required.size());
        std::set<uint16_t> complete_endpoints;
        summary.every_table_non_stub = true;
        summary.every_degree_bound_derived = true;
        for (const auto& family : families.families) {
            if (family.role != role) continue;
            ++summary.family_count;
            summary.semantic_complete_families +=
                family.semantic_relation_complete;
            summary.semantic_partial_families +=
                !family.semantic_relation_complete;
            summary.source_constraints +=
                family.source_constraint_count;
            summary.source_instructions +=
                family.source_instruction_count;
            summary.compiled_constraints +=
                family.compiled_constraint_count;
            summary.compiled_instructions +=
                family.compiled_instruction_count;
            summary.maximum_source_degree =
                std::max(
                    summary.maximum_source_degree,
                    family.source_max_degree);
            summary.maximum_source_composed_degree =
                std::max(
                    summary.maximum_source_composed_degree,
                    family.source_max_composed_degree);
            summary.maximum_source_n_lde =
                std::max(
                    summary.maximum_source_n_lde,
                    family.source_n_lde);
            summary.maximum_compiled_degree =
                std::max(
                    summary.maximum_compiled_degree,
                    family.compiled_max_degree);
            summary.maximum_compiled_composed_degree =
                std::max(
                    summary.maximum_compiled_composed_degree,
                    family.compiled_max_composed_degree);
            summary.maximum_compiled_n_lde =
                std::max(
                    summary.maximum_compiled_n_lde,
                    family.compiled_n_lde);
            summary.every_table_non_stub =
                summary.every_table_non_stub &&
                family.source_table_non_stub &&
                family.source_table_canonical &&
                family.compiled_table_canonical;
            summary.every_degree_bound_derived =
                summary.every_degree_bound_derived &&
                family.challenge_class_degree_checked &&
                family.quotient_and_lde_bounds_derived;
            if (family.semantic_relation_complete) {
                for (const uint16_t endpoint :
                     family.semantic_endpoints) {
                    const bool registered =
                        std::any_of(
                            required.begin(), required.end(),
                            [endpoint](const auto candidate) {
                                return
                                    static_cast<uint16_t>(
                                        candidate) ==
                                    endpoint;
                            });
                    if (!registered ||
                        !complete_endpoints.insert(
                            endpoint).second) {
                        return Fail(
                            why,
                            "v2_endpoint_coverage_registry");
                    }
                }
            }
            if (!family.semantic_relation_complete) {
                const auto residual = std::find_if(
                    migration.partial_residuals.begin(),
                    migration.partial_residuals.end(),
                    [&family](const auto& item) {
                        return item.kind == family.kind;
                    });
                if (residual ==
                    migration.partial_residuals.end()) {
                    return Fail(
                        why,
                        "v2_partial_family_without_residual");
                }
                summary.residual_obligations_or |=
                    residual->missing_obligations;
            }
        }
        if (summary.family_count == 0) {
            summary.every_table_non_stub = false;
            summary.every_degree_bound_derived = false;
        }
        summary.locally_complete_semantic_endpoints =
            static_cast<uint32_t>(
                complete_endpoints.size());
        summary.every_family_locally_complete =
            summary.family_count != 0 &&
            summary.semantic_partial_families == 0 &&
            summary.residual_obligations_or == 0;
        summary.complete_endpoint_coverage =
            summary.every_family_locally_complete &&
            summary.locally_complete_semantic_endpoints ==
                summary.required_semantic_endpoints;
        out.fully_semantic_roles +=
            summary.complete_endpoint_coverage;
        out.required_semantic_endpoints +=
            summary.required_semantic_endpoints;
        out.locally_complete_semantic_endpoints +=
            summary.locally_complete_semantic_endpoints;
        out.roles.push_back(std::move(summary));
    }

    out.role_count =
        static_cast<uint32_t>(out.roles.size());
    out.exact_28_family_registry =
        families.exact_28_family_order &&
        out.family_count ==
            kProductionAliFamilyCountV1;
    out.exact_14_role_order =
        out.roles.size() ==
            kRCStage3UnifiedRoleCount;
    if (out.exact_14_role_order) {
        for (uint32_t index = 0;
             index < out.roles.size(); ++index) {
            if (out.roles[index].role != role_order[index]) {
                out.exact_14_role_order = false;
                break;
            }
        }
    }
    out.every_registered_role_has_program =
        out.exact_14_role_order &&
        std::all_of(
            out.roles.begin(), out.roles.end(),
            [](const auto& role) {
                return role.family_count != 0;
            });
    out.every_program_table_non_stub =
        families.every_source_non_stub &&
        std::all_of(
            out.roles.begin(), out.roles.end(),
            [](const auto& role) {
                return role.every_table_non_stub;
            });
    out.every_degree_bound_derived =
        families.every_challenge_degree_checked &&
        families.every_quotient_lde_bound_derived &&
        std::all_of(
            out.roles.begin(), out.roles.end(),
            [](const auto& role) {
                return role.every_degree_bound_derived;
            });
    out.local_ali_assessment_complete =
        families.local_manifest_complete &&
        out.exact_28_family_registry &&
        out.exact_14_role_order &&
        out.every_registered_role_has_program &&
        out.every_program_table_non_stub &&
        out.every_degree_bound_derived;
    out.semantic_relation_manifest_complete =
        out.local_ali_assessment_complete &&
        out.semantic_complete_families ==
            kProductionAliFamilyCountV1 &&
        out.semantic_partial_families == 0 &&
        out.partial_family_residuals.empty() &&
        out.fully_semantic_roles ==
            kRCStage3UnifiedRoleCount &&
        out.required_semantic_endpoints ==
            kRCStage3RelationClosureEndpointCount &&
        out.locally_complete_semantic_endpoints ==
            out.required_semantic_endpoints;
    out.recursive_root_consumed = false;
    out.production_authority = false;
    out.note =
        out.semantic_relation_manifest_complete
        ? "stage3:ali_assessment_v2:semantic_manifest_complete;"
          "recursive_root_pending"
        : "stage3:ali_assessment_v2:local_bytecode_and_degree_manifest_"
          "complete;14_of_28_families_partial;14_of_52_semantic_"
          "endpoints_locally_covered;0_of_14_roles_endpoint_complete;"
          "recursive_root_pending";
    out.commitment =
        ComputeProductionAliAssessmentCommitmentV2(out);
    if (DigestZero(out.commitment)) {
        out.local_ali_assessment_complete = false;
        return Fail(why, "v2_commitment");
    }
    if (!out.local_ali_assessment_complete) {
        return Fail(why, "v2_local_assessment");
    }
    if (why != nullptr) {
        *why = out.note;
    }
    return true;
}

ProductionAliAssessmentV2
BuildProductionAliAssessmentV2()
{
    ProductionAliAssessmentV2 out;
    const auto site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    const auto sources =
        topo::BuildProductionFamilyProgramSourcesV1(
            site_manifest);
    std::string why;
    if (!BuildProductionAliAssessmentFromSourcesV2(
            site_manifest, sources, out, &why)) {
        out.note =
            "stage3:ali_assessment_v2:canonical_build:" +
            why;
    }
    return out;
}

ah::Digest ComputeProductionAliAssessmentCommitmentV2(
    const ProductionAliAssessmentV2& assessment)
{
    if (assessment.version !=
            kProductionAliAssessmentVersionV2 ||
        assessment.roles.size() !=
            kRCStage3UnifiedRoleCount ||
        assessment.partial_family_residuals.size() >
            kProductionAliFamilyCountV1 ||
        !DigestCanonical(
            assessment.family_manifest_commitment) ||
        DigestZero(
            assessment.family_manifest_commitment)) {
        return {};
    }
    std::vector<gf::Fp> preimage;
    preimage.reserve(
        64 + assessment.roles.size() * 32 +
        assessment.partial_family_residuals.size() * 2);
    AppendBytes(preimage, kAssessmentCommitmentDomainV2);
    AppendU32(preimage, assessment.version);
    if (!AppendDigest(
            preimage,
            assessment.family_manifest_commitment)) {
        return {};
    }
    AppendU32(
        preimage,
        static_cast<uint32_t>(assessment.roles.size()));
    for (const auto& role : assessment.roles) {
        AppendU32(
            preimage,
            static_cast<uint32_t>(role.role));
        AppendU32(preimage, role.family_count);
        AppendU32(
            preimage,
            role.semantic_complete_families);
        AppendU32(
            preimage,
            role.semantic_partial_families);
        AppendU32(
            preimage,
            role.required_semantic_endpoints);
        AppendU32(
            preimage,
            role.locally_complete_semantic_endpoints);
        AppendU64(preimage, role.source_constraints);
        AppendU64(preimage, role.source_instructions);
        AppendU64(preimage, role.compiled_constraints);
        AppendU64(preimage, role.compiled_instructions);
        AppendU32(preimage, role.maximum_source_degree);
        AppendU64(
            preimage,
            role.maximum_source_composed_degree);
        AppendU32(preimage, role.maximum_source_n_lde);
        AppendU32(preimage, role.maximum_compiled_degree);
        AppendU64(
            preimage,
            role.maximum_compiled_composed_degree);
        AppendU32(preimage, role.maximum_compiled_n_lde);
        AppendU32(
            preimage,
            role.residual_obligations_or);
        AppendBool(preimage, role.every_table_non_stub);
        AppendBool(
            preimage,
            role.every_degree_bound_derived);
        AppendBool(
            preimage,
            role.every_family_locally_complete);
        AppendBool(
            preimage,
            role.complete_endpoint_coverage);
    }
    AppendU32(
        preimage,
        static_cast<uint32_t>(
            assessment.partial_family_residuals.size()));
    for (const auto& residual :
         assessment.partial_family_residuals) {
        AppendU32(
            preimage,
            static_cast<uint32_t>(residual.kind));
        AppendU32(
            preimage,
            residual.missing_obligations);
    }
    AppendU32(preimage, assessment.family_count);
    AppendU32(preimage, assessment.role_count);
    AppendU32(
        preimage,
        assessment.semantic_complete_families);
    AppendU32(
        preimage,
        assessment.semantic_partial_families);
    AppendU32(preimage, assessment.fully_semantic_roles);
    AppendU32(
        preimage,
        assessment.required_semantic_endpoints);
    AppendU32(
        preimage,
        assessment.locally_complete_semantic_endpoints);
    AppendU64(preimage, assessment.source_constraints);
    AppendU64(preimage, assessment.source_instructions);
    AppendU64(preimage, assessment.compiled_constraints);
    AppendU64(preimage, assessment.compiled_instructions);
    AppendBool(
        preimage,
        assessment.exact_28_family_registry);
    AppendBool(preimage, assessment.exact_14_role_order);
    AppendBool(
        preimage,
        assessment.every_registered_role_has_program);
    AppendBool(
        preimage,
        assessment.every_program_table_non_stub);
    AppendBool(
        preimage,
        assessment.every_degree_bound_derived);
    AppendBool(
        preimage,
        assessment.local_ali_assessment_complete);
    AppendBool(
        preimage,
        assessment.semantic_relation_manifest_complete);
    AppendBool(
        preimage,
        assessment.recursive_root_consumed);
    AppendBool(preimage, assessment.production_authority);
    AppendBytes(preimage, assessment.note);
    return ah::SpongeHashFp(preimage);
}

bool ValidateProductionAliAssessmentV2(
    const ProductionAliAssessmentV2& assessment,
    std::string* why)
{
    const ProductionAliAssessmentV2 expected =
        BuildProductionAliAssessmentV2();
    if (!expected.local_ali_assessment_complete ||
        expected.semantic_relation_manifest_complete ||
        expected.recursive_root_consumed ||
        expected.production_authority ||
        DigestZero(expected.commitment)) {
        return Fail(why, "v2_canonical_build");
    }
    if (!(assessment == expected)) {
        return Fail(why, "v2_canonical_equality");
    }
    if (assessment.commitment !=
        ComputeProductionAliAssessmentCommitmentV2(
            assessment)) {
        return Fail(why, "v2_commitment");
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_ali_manifest
