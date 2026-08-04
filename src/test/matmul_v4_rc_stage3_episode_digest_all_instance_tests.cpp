// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_episode_digest_all_instance.h>

#include <algorithm>
#include <cstdlib>
#include <utility>

namespace rc = matmul::v4::rc;
namespace digest = rc::episode_digest_all_instance;
namespace fp = rc::recursive_fixedpoint;
namespace gf = rc::gkr_field;
namespace ha = rc::stage3_hash_air;
namespace sites = rc::soundness_scenarios;
namespace tape = rc::stage3_multirow_v13_proof_tape_air;

namespace {

uint256 Root(uint8_t byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

ha::EpisodeDigestManifest Manifest()
{
    const auto params = rc::MakeDatacenterRCEpisodeParams();
    std::vector<uint256> round_roots;
    round_roots.reserve(params.rounds);
    for (uint32_t round = 0; round < params.rounds; ++round) {
        round_roots.push_back(
            Root(static_cast<uint8_t>(0x40 + round)));
    }
    ha::EpisodeDigestManifest out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildEpisodeDigestManifest(
            params.rounds, round_roots, out, &why),
        why);
    return out;
}

rc::RCStage3SuccinctProof Statement(
    const uint256& episode_digest)
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Episode;
    auto& public_inputs = out.public_inputs;
    public_inputs.height = 91;
    public_inputs.n_bits = 0x207fffffU;
    public_inputs.episode_profile = 2;
    public_inputs.transcript_version = rc::ENC_RC_V4;
    public_inputs.header_commitment = Root(0x11);
    public_inputs.params_commitment = Root(0x22);
    public_inputs.sigma = Root(0x33);
    public_inputs.target = Root(0xff);
    public_inputs.episode_digest = episode_digest;
    public_inputs.final_digest = episode_digest;
    public_inputs.program_consensus_pin.recursive_alg_hash_root =
        Root(0x08);
    public_inputs.program_consensus_pin.external_sha256d_audit_root =
        Root(0x09);
    public_inputs.program_consensus_pin.registry_binding =
        Root(0x0a);
    return out;
}

digest::TapeChallengeContextV1 TapeContext()
{
    digest::TapeChallengeContextV1 out;
    out.shape.trace_rows = 2;
    out.shape.trace_columns = 2;
    out.shape.quotient_len = 2;
    out.shape.n_coeffs = 2;
    out.shape.base_column_indices = {0};
    out.binding.program_root = Root(0x71);
    out.binding.statement_root = Root(0x72);
    out.binding.public_fs_seed = Root(0x73);
    out.binding.proof_wire_root = Root(0x74);
    out.binding.tape_root = {1, 2, 3, 4};
    out.source_inventory_root =
        tape::ComputeShardSourceInventoryRootV2(
            out.shape, out.binding);
    out.shard_count =
        static_cast<uint32_t>(
            tape::BuildShardPlansV2(
                out.shape, out.binding).size());
    return out;
}

bool RebindProof(
    digest::ProductV1& product,
    fp::AlgAirProof proof,
    std::string* why)
{
    auto& site = product.sites.at(0);
    if (!rc::SerializeAirQuotientProofAlg(
            proof, site.proof_bytes, why)) {
        return false;
    }
    site.proof_commitment =
        fp::ComputeNormalizedAlgAirProofCommitment(proof);
    site.proof_wire_root =
        digest::CommitProofWireV1(site.proof_bytes);
    product.product_commitment =
        digest::CommitProductV1(product);
    return !site.proof_commitment.IsNull() &&
        !site.proof_wire_root.IsNull() &&
        !product.product_commitment.IsNull();
}

fp::AlgAirProof Decode(
    const digest::ProductV1& product)
{
    std::string why;
    const auto proof =
        rc::DeserializeAirQuotientProofAlg(
            product.sites.at(0).proof_bytes, &why);
    BOOST_REQUIRE_MESSAGE(proof.has_value(), why);
    return *proof;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_digest_all_instance_tests)

BOOST_AUTO_TEST_CASE(
    production_inventory_is_exactly_six_boundaries_one_site)
{
    const auto manifest = Manifest();
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildDirectSha256dManifestBoundaryInstances(
            manifest.direct, boundaries, &why),
        why);
    BOOST_CHECK_EQUAL(
        rc::MakeDatacenterRCEpisodeParams().rounds, 8U);
    BOOST_CHECK_EQUAL(boundaries.size(), 6U);

    const auto site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    const auto found = std::find_if(
        site_manifest.entries.begin(),
        site_manifest.entries.end(),
        [](const auto& entry) {
            return entry.kind ==
                sites::ProductionProofSiteKind::
                    EpisodeDigestSha256d;
        });
    BOOST_REQUIRE(found != site_manifest.entries.end());
    BOOST_CHECK_EQUAL(found->logical_units, boundaries.size());
    BOOST_CHECK_EQUAL(
        found->units_per_site,
        digest::kBoundariesPerProofSiteV1);
    BOOST_CHECK_EQUAL(found->proof_sites, 1U);
}

BOOST_AUTO_TEST_CASE(
    complete_family_proof_roundtrip_and_attacks)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_EPISODE_DIGEST_ALL_INSTANCE") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_EPISODE_DIGEST_ALL_INSTANCE=1 "
            "to execute the complete ordinary AlgAir proof");
        return;
    }

    const auto manifest = Manifest();
    const auto statement =
        Statement(manifest.direct.digest);
    const auto tape_context = TapeContext();
    BOOST_REQUIRE(!tape_context.source_inventory_root.IsNull());
    BOOST_REQUIRE_GT(tape_context.shard_count, 0U);

    digest::ProductV1 product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        digest::ProveProductV1(
            statement, manifest, tape_context,
            product, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        digest::VerifyProductV1(
            statement, tape_context,
            product, &why),
        why);
    BOOST_REQUIRE_EQUAL(product.sites.size(), 1U);
    BOOST_CHECK_EQUAL(product.boundary_count, 6U);
    BOOST_CHECK_EQUAL(product.leaf_site_count, 1U);
    BOOST_CHECK(product.endpoint_root_chain_verified);
    BOOST_CHECK(!product.endpoint_binding_root.IsNull());
    BOOST_CHECK(!product.normalized_recursive_consumed);
    BOOST_CHECK(!product.production_authority);

    std::vector<digest::RecursiveChildInputV1> children;
    BOOST_REQUIRE_MESSAGE(
        digest::BuildRecursiveChildInputsV1(
            statement, tape_context,
            product, children, &why),
        why);
    BOOST_REQUIRE_EQUAL(children.size(), 1U);
    const bool child_verified =
        rc::air_quotient::AirQuotientVerify<
            gf::Fp3,
            rc::air_quotient::AirFriBackendAlg<gf::Fp3>>(
            children[0].cs, children[0].proof,
            children[0].public_fs_seed, &why);
    BOOST_CHECK_MESSAGE(child_verified, why);

    auto omitted = product;
    omitted.sites.clear();
    omitted.product_commitment =
        digest::CommitProductV1(omitted);
    BOOST_CHECK(
        !digest::VerifyProductV1(
            statement, tape_context, omitted, &why));

    auto duplicated = product;
    duplicated.sites.push_back(duplicated.sites.front());
    duplicated.product_commitment =
        digest::CommitProductV1(duplicated);
    BOOST_CHECK(
        !digest::VerifyProductV1(
            statement, tape_context, duplicated, &why));

    auto manifest_substitution = product;
    std::swap(
        manifest_substitution.manifest.round_roots[0],
        manifest_substitution.manifest.round_roots[1]);
    manifest_substitution.product_commitment =
        digest::CommitProductV1(manifest_substitution);
    BOOST_CHECK(
        !digest::VerifyProductV1(
            statement, tape_context,
            manifest_substitution, &why));

    auto tape_substitution = tape_context;
    tape_substitution.binding.tape_root[0] =
        gf::Add(
            tape_substitution.binding.tape_root[0],
            gf::FromU64(1));
    tape_substitution.source_inventory_root =
        tape::ComputeShardSourceInventoryRootV2(
            tape_substitution.shape,
            tape_substitution.binding);
    BOOST_CHECK(
        !digest::VerifyProductV1(
            statement, tape_substitution,
            product, &why));

    auto endpoint_forgery = product;
    BOOST_REQUIRE(
        !endpoint_forgery.endpoint_root_chain.
            digest_proof.quotient.batch.queries.empty());
    BOOST_REQUIRE(
        !endpoint_forgery.endpoint_root_chain.
            digest_proof.quotient.batch.queries[0].
                columns.empty());
    endpoint_forgery.endpoint_root_chain.
        digest_proof.quotient.batch.queries[0].
            columns[0].value =
        gf::Add(
            endpoint_forgery.endpoint_root_chain.
                digest_proof.quotient.batch.queries[0].
                    columns[0].value,
            gf::Fp3::One());
    endpoint_forgery.product_commitment =
        digest::CommitProductV1(endpoint_forgery);
    BOOST_CHECK(
        !digest::VerifyProductV1(
            statement, tape_context,
            endpoint_forgery, &why));
    BOOST_CHECK(
        why.find("endpoint_root_chain") !=
        std::string::npos);

    auto opening_forgery = product;
    auto forged_proof = Decode(opening_forgery);
    BOOST_REQUIRE(
        !forged_proof.batch.queries.empty());
    BOOST_REQUIRE(
        !forged_proof.batch.queries[0].
            row.values.empty());
    forged_proof.batch.queries[0].row.values[0] =
        gf::Add(
            forged_proof.batch.queries[0].
                row.values[0],
            gf::Fp3::One());
    BOOST_REQUIRE(
        RebindProof(
            opening_forgery,
            std::move(forged_proof), &why));
    BOOST_CHECK(
        !digest::VerifyProductV1(
            statement, tape_context,
            opening_forgery, &why));
    BOOST_CHECK(
        why.find("site_proof_") !=
        std::string::npos);

    auto query_reorder = product;
    auto reordered_proof = Decode(query_reorder);
    BOOST_REQUIRE_GE(
        reordered_proof.batch.queries.size(), 2U);
    std::swap(
        reordered_proof.batch.queries[0],
        reordered_proof.batch.queries[1]);
    BOOST_REQUIRE(
        RebindProof(
            query_reorder,
            std::move(reordered_proof), &why));
    BOOST_CHECK(
        !digest::VerifyProductV1(
            statement, tape_context,
            query_reorder, &why));
    BOOST_CHECK(
        why.find("site_proof_") !=
        std::string::npos);

    auto query_duplicate = product;
    auto duplicated_proof = Decode(query_duplicate);
    BOOST_REQUIRE_GE(
        duplicated_proof.batch.queries.size(), 2U);
    duplicated_proof.batch.queries[1] =
        duplicated_proof.batch.queries[0];
    BOOST_REQUIRE(
        RebindProof(
            query_duplicate,
            std::move(duplicated_proof), &why));
    BOOST_CHECK(
        !digest::VerifyProductV1(
            statement, tape_context,
            query_duplicate, &why));
    BOOST_CHECK(
        why.find("site_proof_") !=
        std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
