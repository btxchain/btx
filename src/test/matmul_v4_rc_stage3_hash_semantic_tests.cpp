// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_hash_semantic.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <vector>

namespace hs = matmul::v4::rc::stage3_hash_semantic;
namespace ha = matmul::v4::rc::stage3_hash_air;
using matmul::v4::rc::RCStage3RelationEndpoint;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_hash_semantic_tests,
                         BasicTestingSetup)

namespace {

uint256 Tagged(uint8_t first)
{
    uint256 out;
    for (uint32_t i = 0; i < 32; ++i) {
        out.begin()[i] = static_cast<uint8_t>(first + i);
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(canonical_boundary_values_are_ordered_and_committed)
{
    ha::ShaManifest manifest;
    std::string why;
    BOOST_REQUIRE(ha::BuildShaManifest(
        std::vector<uint8_t>{0x62, 0x74, 0x78},
        ha::ShaMode::Single, manifest, &why));
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    BOOST_REQUIRE(ha::BuildShaManifestBoundaryInstances(
        manifest, boundaries, &why));
    BOOST_REQUIRE_EQUAL(boundaries.size(), 1U);

    std::vector<matmul::v4::rc::gkr_field::Fp3> external;
    std::vector<matmul::v4::rc::gkr_field::Fp3> final;
    BOOST_REQUIRE(hs::BuildCanonicalBoundaryValues(
        boundaries, hs::BoundaryPort::External, external, &why));
    BOOST_REQUIRE(hs::BuildCanonicalBoundaryValues(
        boundaries, hs::BoundaryPort::Final, final, &why));
    BOOST_CHECK_EQUAL(external.size(), 88U);
    BOOST_CHECK_EQUAL(final.size(), 8U);

    uint256 root;
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    BOOST_REQUIRE(hs::ComputeCanonicalBoundaryValueRoot(
        boundaries, hs::BoundaryPort::ExternalThenFinal,
        root, logical_rows, n_rows, &why));
    BOOST_CHECK(!root.IsNull());
    BOOST_CHECK_EQUAL(logical_rows, 96U);
    BOOST_CHECK_EQUAL(n_rows, 128U);

    auto changed = boundaries;
    ++changed.front().final_words.front();
    uint256 changed_root;
    uint32_t changed_logical{0};
    uint32_t changed_rows{0};
    BOOST_REQUIRE(hs::ComputeCanonicalBoundaryValueRoot(
        changed, hs::BoundaryPort::ExternalThenFinal,
        changed_root, changed_logical, changed_rows, &why));
    BOOST_CHECK(root != changed_root);
}

BOOST_AUTO_TEST_CASE(flat_bundle_is_exact_count_and_manifest_bound)
{
    ha::ShaManifest manifest;
    std::string why;
    BOOST_REQUIRE(ha::BuildShaManifest(
        std::vector<uint8_t>{0x01}, ha::ShaMode::Single,
        manifest, &why));
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    BOOST_REQUIRE(ha::BuildShaManifestBoundaryInstances(
        manifest, boundaries, &why));

    hs::FlatBoundaryProofBundle bundle;
    bundle.endpoint =
        RCStage3RelationEndpoint::EpisodeBuilderSeedChain;
    bundle.statement_commitment = Tagged(11);
    bundle.manifest_commitment = manifest.commitment;
    BOOST_CHECK(!hs::VerifyFlatBoundaryProofBundle(
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression),
        boundaries, manifest.commitment, bundle, &why));

    bundle.proofs.resize(2);
    BOOST_CHECK(!hs::VerifyFlatBoundaryProofBundle(
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression),
        boundaries, manifest.commitment, bundle, &why));
}

BOOST_AUTO_TEST_CASE(flat_sha_bundle_executes_every_provenance_proof)
{
    if (std::getenv("BTX_RUN_STAGE3_HASH_SEMANTIC_PROVE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_HASH_SEMANTIC_PROVE=1 for the "
            "full fixed-program provenance quotient round trip");
        return;
    }

    ha::ShaManifest manifest;
    std::string why;
    BOOST_REQUIRE(ha::BuildShaManifest(
        std::vector<uint8_t>{0x42}, ha::ShaMode::Single,
        manifest, &why));
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    BOOST_REQUIRE(ha::BuildShaManifestBoundaryInstances(
        manifest, boundaries, &why));
    BOOST_REQUIRE_EQUAL(boundaries.size(), 1U);

    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::Sha256Compression);
    hs::FlatBoundaryProofBundle bundle;
    BOOST_REQUIRE_MESSAGE(
        hs::ProveFlatBoundaryProofBundle(
            RCStage3RelationEndpoint::EpisodeBuilderSeedChain,
            Tagged(17), manifest.commitment, program, boundaries,
            bundle, &why),
        why);
    BOOST_CHECK_MESSAGE(
        hs::VerifyShaManifestBundle(
            bundle.endpoint, manifest, bundle, &why),
        why);

    auto wrong_manifest = bundle;
    wrong_manifest.manifest_commitment = Tagged(99);
    BOOST_CHECK(!hs::VerifyShaManifestBundle(
        wrong_manifest.endpoint, manifest, wrong_manifest, &why));

    auto wrong_statement = bundle;
    wrong_statement.statement_commitment = Tagged(33);
    BOOST_CHECK(!hs::VerifyShaManifestBundle(
        wrong_statement.endpoint, manifest, wrong_statement, &why));
}

BOOST_AUTO_TEST_CASE(vertical_bundle_executes_canonical_chunks_optional)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_HASH_VERTICAL_PROVE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_HASH_VERTICAL_PROVE=1 for "
            "the 63-active vertical boundary bundle");
        return;
    }
    ha::ShaManifest manifest;
    std::string why;
    BOOST_REQUIRE(ha::BuildShaManifest(
        std::vector<uint8_t>{0x24}, ha::ShaMode::Single,
        manifest, &why));
    std::vector<ha::FixedProgramBoundaryInstance> one;
    BOOST_REQUIRE(ha::BuildShaManifestBoundaryInstances(
        manifest, one, &why));
    std::vector<ha::FixedProgramBoundaryInstance> boundaries(
        64, one.front());
    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::Sha256Compression);
    hs::VerticalBoundaryProofBundle bundle;
    BOOST_REQUIRE_MESSAGE(
        hs::ProveVerticalBoundaryProofBundle(
            RCStage3RelationEndpoint::EpisodeExtractScale,
            Tagged(0x31), manifest.commitment, program,
            boundaries, bundle, &why),
        why);
    BOOST_REQUIRE_EQUAL(bundle.proofs.size(), 2U);
    BOOST_REQUIRE(!bundle.proofs[0].quotient.batch.column_len.empty());
    BOOST_REQUIRE(!bundle.proofs[1].quotient.batch.column_len.empty());
    BOOST_CHECK_EQUAL(
        bundle.proofs[0].quotient.batch.column_len[0],
        1024U * ha::kFixedProgramVerticalScheduledInstances);
    BOOST_CHECK_EQUAL(
        bundle.proofs[1].quotient.batch.column_len[0], 2U * 1024U);
    BOOST_CHECK_MESSAGE(
        hs::VerifyVerticalBoundaryProofBundle(
            program, boundaries, manifest.commitment,
            bundle, &why),
        why);

    auto omitted = boundaries;
    omitted.pop_back();
    BOOST_CHECK(!hs::VerifyVerticalBoundaryProofBundle(
        program, omitted, manifest.commitment, bundle, &why));
    auto changed = boundaries;
    ++changed[62].final_words[0];
    BOOST_CHECK(!hs::VerifyVerticalBoundaryProofBundle(
        program, changed, manifest.commitment, bundle, &why));
    auto reordered = boundaries;
    reordered[1].external_values[0] ^= 1U;
    BOOST_CHECK(!hs::VerifyVerticalBoundaryProofBundle(
        program, reordered, manifest.commitment, bundle, &why));
}

BOOST_AUTO_TEST_SUITE_END()
