// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_hash_semantic.h>

#include <hash.h>

#include <limits>

namespace matmul::v4::rc::stage3_hash_semantic {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) *why = "stage3:hash_semantic:" + detail;
    return false;
}

bool IsRegisteredEndpoint(RCStage3RelationEndpoint endpoint)
{
    const uint16_t id = static_cast<uint16_t>(endpoint);
    return id >= 1 && id <= kRCStage3RelationClosureEndpointCount;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    if (value <= 2) return 2;
    --value;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    return value + 1;
}

bool VerifyAdapted(
    RCStage3RelationEndpoint endpoint,
    const hash_air::FixedProgram& program,
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    const uint256& manifest_commitment,
    const FlatBoundaryProofBundle& bundle,
    std::string* why)
{
    if (bundle.endpoint != endpoint) {
        return Fail(why, "endpoint");
    }
    return VerifyFlatBoundaryProofBundle(
        program, boundaries, manifest_commitment, bundle, why);
}

} // namespace

uint256 ComputeBoundaryProofSeed(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    uint32_t boundary_index,
    uint32_t boundary_count)
{
    HashWriter hash;
    hash << std::string{"BTX_RC_STAGE3_HASH_SEMANTIC_BOUNDARY_V1"};
    hash << static_cast<uint16_t>(endpoint);
    hash << statement_commitment;
    hash << manifest_commitment;
    hash << boundary_index;
    hash << boundary_count;
    return hash.GetHash();
}

bool ProveFlatBoundaryProofBundle(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    const hash_air::FixedProgram& program,
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    FlatBoundaryProofBundle& out,
    std::string* why)
{
    out = {};
    if (!IsRegisteredEndpoint(endpoint) ||
        statement_commitment.IsNull() ||
        manifest_commitment.IsNull() ||
        boundaries.empty() ||
        boundaries.size() > kMaxFlatBoundaryProofs) {
        return Fail(why, "prove_bundle_shape");
    }
    std::string program_why;
    if (!hash_air::ValidateCanonicalProgram(program, &program_why)) {
        return Fail(why, "prove_program:" + program_why);
    }
    out.endpoint = endpoint;
    out.statement_commitment = statement_commitment;
    out.manifest_commitment = manifest_commitment;
    out.proofs.resize(boundaries.size());
    const uint32_t count = static_cast<uint32_t>(boundaries.size());
    for (uint32_t i = 0; i < count; ++i) {
        const auto& boundary = boundaries[i];
        if (boundary.external_values.empty() ||
            boundary.final_words.empty()) {
            out = {};
            return Fail(why, "prove_empty_boundary");
        }
        hash_air::ProgramWitness witness;
        if (!hash_air::BuildProgramWitness(
                program, boundary.external_values, witness, why)) {
            out = {};
            return Fail(
                why, "prove_witness_" + std::to_string(i));
        }
        const uint256 seed = ComputeBoundaryProofSeed(
            endpoint, statement_commitment, manifest_commitment,
            i, count);
        if (!hash_air::ProveFixedProgramProvenanceAir(
                program, witness, boundary.external_values,
                boundary.final_words, seed, out.proofs[i], why)) {
            out = {};
            return Fail(
                why, "prove_boundary_" + std::to_string(i));
        }
    }
    if (!VerifyFlatBoundaryProofBundle(
            program, boundaries, manifest_commitment, out, why)) {
        out = {};
        return Fail(why, "prove_self_verify");
    }
    return true;
}

bool VerifyFlatBoundaryProofBundle(
    const hash_air::FixedProgram& program,
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    const uint256& expected_manifest_commitment,
    const FlatBoundaryProofBundle& bundle,
    std::string* why)
{
    if (bundle.version != kFlatBundleVersion ||
        !IsRegisteredEndpoint(bundle.endpoint) ||
        bundle.statement_commitment.IsNull() ||
        expected_manifest_commitment.IsNull() ||
        bundle.manifest_commitment != expected_manifest_commitment ||
        boundaries.empty() ||
        boundaries.size() > kMaxFlatBoundaryProofs ||
        boundaries.size() != bundle.proofs.size()) {
        return Fail(why, "bundle_shape");
    }
    std::string program_why;
    if (!hash_air::ValidateCanonicalProgram(program, &program_why)) {
        return Fail(why, "program:" + program_why);
    }
    const uint32_t count = static_cast<uint32_t>(boundaries.size());
    for (uint32_t i = 0; i < count; ++i) {
        const auto& boundary = boundaries[i];
        if (boundary.external_values.empty() ||
            boundary.final_words.empty()) {
            return Fail(why, "empty_boundary");
        }
        const uint256 seed = ComputeBoundaryProofSeed(
            bundle.endpoint, bundle.statement_commitment,
            bundle.manifest_commitment, i, count);
        std::string proof_why;
        if (!hash_air::VerifyFixedProgramProvenanceAir(
                program, boundary.external_values,
                boundary.final_words, seed, bundle.proofs[i],
                &proof_why)) {
            return Fail(
                why, "boundary_" + std::to_string(i) + ":" + proof_why);
        }
    }
    if (why != nullptr) *why = "stage3:hash_semantic:all_boundaries_ok";
    return true;
}

namespace {

uint256 ComputeVerticalBoundaryProofSeed(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    uint32_t chunk_index,
    uint32_t chunk_count,
    uint32_t boundary_begin,
    uint32_t boundary_count,
    uint32_t total_boundaries)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_HASH_SEMANTIC_VERTICAL_BOUNDARY_V1"};
    hash << static_cast<uint16_t>(endpoint);
    hash << statement_commitment;
    hash << manifest_commitment;
    hash << chunk_index;
    hash << chunk_count;
    hash << boundary_begin;
    hash << boundary_count;
    hash << total_boundaries;
    return hash.GetHash();
}

} // namespace

bool ProveVerticalBoundaryProofBundle(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    const hash_air::FixedProgram& program,
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    VerticalBoundaryProofBundle& out,
    std::string* why)
{
    out = {};
    if (!IsRegisteredEndpoint(endpoint) ||
        statement_commitment.IsNull() ||
        manifest_commitment.IsNull() ||
        boundaries.empty() ||
        boundaries.size() > kMaxFlatBoundaryProofs ||
        boundaries.size() >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "prove_vertical_shape");
    }
    std::string program_why;
    if (!hash_air::ValidateCanonicalProgram(
            program, &program_why)) {
        return Fail(
            why, "prove_vertical_program:" + program_why);
    }
    for (const auto& boundary : boundaries) {
        if (boundary.external_values.empty() ||
            boundary.final_words.empty()) {
            return Fail(why, "prove_vertical_empty_boundary");
        }
    }
    out.endpoint = endpoint;
    out.statement_commitment = statement_commitment;
    out.manifest_commitment = manifest_commitment;
    out.boundary_count =
        static_cast<uint32_t>(boundaries.size());
    const uint32_t width =
        hash_air::kFixedProgramVerticalSemanticInstances;
    const uint32_t chunks =
        (out.boundary_count + width - 1U) / width;
    out.proofs.resize(chunks);
    for (uint32_t chunk = 0; chunk < chunks; ++chunk) {
        const uint32_t begin = chunk * width;
        const uint32_t count =
            std::min(width, out.boundary_count - begin);
        std::vector<hash_air::FixedProgramBoundaryInstance>
            chunk_boundaries(
                boundaries.begin() + begin,
                boundaries.begin() + begin + count);
        const uint256 seed =
            ComputeVerticalBoundaryProofSeed(
                endpoint, statement_commitment,
                manifest_commitment, chunk, chunks,
                begin, count, out.boundary_count);
        if (!hash_air::ProveFixedProgramVerticalProvenanceAir(
                program, chunk_boundaries, seed,
                out.proofs[chunk], why)) {
            out = {};
            return Fail(
                why, "prove_vertical_chunk_" +
                    std::to_string(chunk));
        }
    }
    if (!VerifyVerticalBoundaryProofBundle(
            program, boundaries, manifest_commitment,
            out, why)) {
        out = {};
        return Fail(why, "prove_vertical_self_verify");
    }
    return true;
}

bool VerifyVerticalBoundaryProofBundle(
    const hash_air::FixedProgram& program,
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    const uint256& expected_manifest_commitment,
    const VerticalBoundaryProofBundle& bundle,
    std::string* why)
{
    if (bundle.version != kFlatBundleVersion ||
        !IsRegisteredEndpoint(bundle.endpoint) ||
        bundle.statement_commitment.IsNull() ||
        expected_manifest_commitment.IsNull() ||
        bundle.manifest_commitment !=
            expected_manifest_commitment ||
        boundaries.empty() ||
        boundaries.size() > kMaxFlatBoundaryProofs ||
        boundaries.size() != bundle.boundary_count) {
        return Fail(why, "vertical_bundle_shape");
    }
    std::string program_why;
    if (!hash_air::ValidateCanonicalProgram(
            program, &program_why)) {
        return Fail(why, "vertical_program:" + program_why);
    }
    const uint32_t width =
        hash_air::kFixedProgramVerticalSemanticInstances;
    const uint32_t chunks =
        (bundle.boundary_count + width - 1U) / width;
    if (bundle.proofs.size() != chunks) {
        return Fail(why, "vertical_chunk_count");
    }
    for (uint32_t chunk = 0; chunk < chunks; ++chunk) {
        const uint32_t begin = chunk * width;
        const uint32_t count =
            std::min(width, bundle.boundary_count - begin);
        std::vector<hash_air::FixedProgramBoundaryInstance>
            chunk_boundaries(
                boundaries.begin() + begin,
                boundaries.begin() + begin + count);
        const uint256 seed =
            ComputeVerticalBoundaryProofSeed(
                bundle.endpoint,
                bundle.statement_commitment,
                bundle.manifest_commitment,
                chunk, chunks, begin, count,
                bundle.boundary_count);
        std::string proof_why;
        if (!hash_air::VerifyFixedProgramVerticalProvenanceAir(
                program, chunk_boundaries, seed,
                bundle.proofs[chunk], &proof_why)) {
            return Fail(
                why, "vertical_chunk_" +
                    std::to_string(chunk) + ":" + proof_why);
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:hash_semantic:"
            "all_vertical_boundaries_ok";
    }
    return true;
}

bool BuildCanonicalBoundaryValues(
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    BoundaryPort port,
    std::vector<Fp3>& out,
    std::string* why)
{
    out.clear();
    if (boundaries.empty() ||
        (port != BoundaryPort::External &&
         port != BoundaryPort::Final &&
         port != BoundaryPort::ExternalThenFinal)) {
        return Fail(why, "value_port");
    }
    uint64_t words = 0;
    for (const auto& boundary : boundaries) {
        if (boundary.external_values.empty() ||
            boundary.final_words.empty()) {
            return Fail(why, "value_boundary");
        }
        if (port == BoundaryPort::External ||
            port == BoundaryPort::ExternalThenFinal) {
            words += boundary.external_values.size();
        }
        if (port == BoundaryPort::Final ||
            port == BoundaryPort::ExternalThenFinal) {
            words += boundary.final_words.size();
        }
    }
    if (words == 0 ||
        words > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "value_count");
    }
    out.reserve(static_cast<size_t>(words));
    for (const auto& boundary : boundaries) {
        if (port == BoundaryPort::External ||
            port == BoundaryPort::ExternalThenFinal) {
            for (uint32_t word : boundary.external_values) {
                out.push_back(Fp3::FromFp(word));
            }
        }
        if (port == BoundaryPort::Final ||
            port == BoundaryPort::ExternalThenFinal) {
            for (uint32_t word : boundary.final_words) {
                out.push_back(Fp3::FromFp(word));
            }
        }
    }
    return true;
}

bool ComputeCanonicalBoundaryValueRoot(
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    BoundaryPort port,
    uint256& root,
    uint32_t& logical_rows,
    uint32_t& n_rows,
    std::string* why)
{
    root.SetNull();
    logical_rows = 0;
    n_rows = 0;
    std::vector<Fp3> values;
    if (!BuildCanonicalBoundaryValues(boundaries, port, values, why) ||
        values.size() > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    logical_rows = static_cast<uint32_t>(values.size());
    n_rows = NextPowerOfTwo(logical_rows);
    values.resize(n_rows, Fp3::Zero());
    root = aq::AirCommittedValuesRoot<Fp3>(values, n_rows);
    if (root.IsNull()) return Fail(why, "null_value_root");
    return true;
}

bool VerifyShaManifestBundle(
    RCStage3RelationEndpoint endpoint,
    const hash_air::ShaManifest& manifest,
    const FlatBoundaryProofBundle& bundle,
    std::string* why)
{
    std::vector<hash_air::FixedProgramBoundaryInstance> boundaries;
    if (!hash_air::BuildShaManifestBoundaryInstances(
            manifest, boundaries, why)) {
        return Fail(why, "sha_manifest");
    }
    return VerifyAdapted(
        endpoint,
        hash_air::BuildCanonicalProgram(
            hash_air::ProgramKind::Sha256Compression),
        boundaries, manifest.commitment, bundle, why);
}

bool VerifyCounterXofManifestBundle(
    RCStage3RelationEndpoint endpoint,
    const hash_air::CounterXofManifest& manifest,
    const FlatBoundaryProofBundle& bundle,
    std::string* why)
{
    std::vector<hash_air::FixedProgramBoundaryInstance> boundaries;
    if (!hash_air::BuildCounterXofManifestBoundaryInstances(
            manifest, boundaries, why)) {
        return Fail(why, "counter_xof_manifest");
    }
    return VerifyAdapted(
        endpoint,
        hash_air::BuildCanonicalProgram(
            hash_air::ProgramKind::Sha256Compression),
        boundaries, manifest.commitment, bundle, why);
}

bool VerifyChaChaManifestBundle(
    RCStage3RelationEndpoint endpoint,
    const hash_air::ChaChaConsumptionManifest& manifest,
    const FlatBoundaryProofBundle& bundle,
    std::string* why)
{
    std::vector<hash_air::FixedProgramBoundaryInstance> boundaries;
    if (!hash_air::BuildChaChaManifestBoundaryInstances(
            manifest, boundaries, why)) {
        return Fail(why, "chacha_manifest");
    }
    return VerifyAdapted(
        endpoint,
        hash_air::BuildCanonicalProgram(
            hash_air::ProgramKind::ChaCha20Block),
        boundaries, manifest.commitment, bundle, why);
}

bool VerifyTileTreeManifestBundle(
    RCStage3RelationEndpoint endpoint,
    const hash_air::TileTreeManifest& manifest,
    const FlatBoundaryProofBundle& bundle,
    std::string* why)
{
    std::vector<hash_air::FixedProgramBoundaryInstance> boundaries;
    if (!hash_air::BuildTileTreeManifestBoundaryInstances(
            manifest, boundaries, why)) {
        return Fail(why, "tile_tree_manifest");
    }
    return VerifyAdapted(
        endpoint,
        hash_air::BuildCanonicalProgram(
            hash_air::ProgramKind::Sha256Compression),
        boundaries, manifest.commitment, bundle, why);
}

bool VerifyDirectSha256dManifestBundle(
    RCStage3RelationEndpoint endpoint,
    const hash_air::DirectSha256dManifest& manifest,
    const FlatBoundaryProofBundle& bundle,
    std::string* why)
{
    std::vector<hash_air::FixedProgramBoundaryInstance> boundaries;
    if (!hash_air::BuildDirectSha256dManifestBoundaryInstances(
            manifest, boundaries, why)) {
        return Fail(why, "direct_sha256d_manifest");
    }
    return VerifyAdapted(
        endpoint,
        hash_air::BuildCanonicalProgram(
            hash_air::ProgramKind::Sha256Compression),
        boundaries, manifest.commitment, bundle, why);
}

} // namespace matmul::v4::rc::stage3_hash_semantic
