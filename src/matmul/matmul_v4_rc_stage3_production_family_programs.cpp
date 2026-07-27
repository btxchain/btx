// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>

#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <algorithm>
#include <set>

namespace matmul::v4::rc::universal_topology {
namespace {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;
namespace sites = soundness_scenarios;
using gf::Fp3;

/** The exact structural stub the tests used (matmul_v4_rc_stage3_universal_
 * topology_tests.cpp OneColumnProgram), reproduced here so the honest
 * production path never depends on a *_tests.cpp translation unit. Unlike
 * that helper, callers below never mark this complete. */
cb::ProgramTable OneColumnStubProgram(RCStage3RelationRole role)
{
    cb::ProgramTable table;
    table.role = role;
    table.current_width = 1;
    table.next_width = 1;
    cb::Program program;
    program.role = role;
    program.kind = aq::AirKind::kEverywhere;
    program.declared_degree = 1;
    program.current_width = 1;
    program.next_width = 1;
    program.instructions.push_back(
        {cb::Opcode::Current, 0, 0, Fp3::Zero()});
    table.programs.push_back(std::move(program));
    return table;
}

ProductionFamilyProgramSourceV1 StubSource(
    const sites::ProductionProofSiteEntry& site, uint32_t family_index)
{
    ProductionFamilyProgramSourceV1 source;
    source.family_index = family_index;
    source.kind = site.kind;
    source.role = site.role;
    source.program = OneColumnStubProgram(site.role);
    source.public_input_schema = {
        static_cast<unsigned char>(family_index),
        static_cast<unsigned char>(static_cast<uint16_t>(site.role))};
    // Deliberately empty/false: a 1-column program proves nothing about the
    // relation this site names, so it must not claim any endpoint or
    // completeness. This is the honest counterpart of the *_tests.cpp
    // OneColumnProgram helper, which claims every role endpoint complete.
    source.semantic_endpoints.clear();
    source.semantic_relation_complete = false;
    return source;
}

/** One real, already-unit-tested bytecode program plus the exact single
 * endpoint it closes. Returns false (leave the site a stub) when this
 * session did not reach that site's role. */
bool RealFamilyFor(
    sites::ProductionProofSiteKind kind,
    RCStage3RelationRole role,
    cb::ProgramTable& program,
    RCStage3RelationEndpoint& endpoint,
    std::string* why)
{
    switch (kind) {
    case sites::ProductionProofSiteKind::EpisodeBuilderCounterXof:
        if (role != RCStage3RelationRole::EpisodeDeterministicBuilder) {
            return false;
        }
        if (!BuildRCStage3EpisodeBuilderTraceProgramTable(program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::EpisodeBuilderTrace;
        return true;
    case sites::ProductionProofSiteKind::EpisodeDigestSha256d:
        if (role != RCStage3RelationRole::EpisodeDigest) return false;
        if (!BuildRCStage3EpisodePowProgramTable(program, why)) return false;
        endpoint = RCStage3RelationEndpoint::EpisodeDigestPow;
        return true;
    case sites::ProductionProofSiteKind::EpisodeTileTreeSha256d:
        if (role != RCStage3RelationRole::EpisodeTileTree) return false;
        if (!BuildRCStage3EpisodeTileTreeByteBridgeProgramTable(
                program, why)) {
            return false;
        }
        endpoint = RCStage3RelationEndpoint::EpisodeTileTreeStream;
        return true;
    default:
        return false;
    }
}

} // namespace

std::vector<ProductionFamilyProgramSourceV1>
BuildProductionFamilyProgramSourcesV1(
    const sites::ProductionProofSiteManifest& manifest)
{
    std::vector<ProductionFamilyProgramSourceV1> out;
    out.reserve(manifest.entries.size());
    for (size_t i = 0; i < manifest.entries.size(); ++i) {
        const auto& site = manifest.entries[i];
        ProductionFamilyProgramSourceV1 source =
            StubSource(site, static_cast<uint32_t>(i));

        cb::ProgramTable real;
        RCStage3RelationEndpoint endpoint{};
        std::string why;
        if (RealFamilyFor(site.kind, site.role, real, endpoint, &why) &&
            cb::ValidateProgramTable(real, &why)) {
            source.program = std::move(real);
            source.semantic_endpoints = {
                static_cast<uint16_t>(endpoint)};
            source.semantic_relation_complete = true;
        }
        out.push_back(std::move(source));
    }
    return out;
}

ProductionFamilyProgramMigrationStatusV1
AssessProductionFamilyProgramMigrationV1(
    const std::vector<ProductionFamilyProgramSourceV1>& sources)
{
    ProductionFamilyProgramMigrationStatusV1 out;
    out.families_total = static_cast<uint32_t>(sources.size());
    std::set<RCStage3RelationRole> roles;
    std::set<uint16_t> endpoints;
    for (const auto& source : sources) {
        if (!source.semantic_relation_complete ||
            source.semantic_endpoints.empty()) {
            continue;
        }
        ++out.families_real;
        roles.insert(source.role);
        endpoints.insert(
            source.semantic_endpoints.begin(),
            source.semantic_endpoints.end());
    }
    out.roles_with_real_program = static_cast<uint32_t>(roles.size());
    out.real_roles.assign(roles.begin(), roles.end());
    out.real_endpoints.assign(endpoints.begin(), endpoints.end());
    return out;
}

} // namespace matmul::v4::rc::universal_topology
