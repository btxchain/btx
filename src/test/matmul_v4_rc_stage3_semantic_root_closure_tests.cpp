// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_semantic_root_closure.h>

#include <chrono>

namespace closure =
    matmul::v4::rc::semantic_root_closure;
namespace rc = matmul::v4::rc;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_semantic_root_closure_tests)

namespace {

rc::RCStage3CoupledShape Shape()
{
    return rc::MakeRCStage3CoupledShape(
        rc::MakeMediumV3RCCoupParams(),
        rc::MakeMediumV4RCCoupOptions());
}

closure::SemanticRootClosureManifestV1 Manifest()
{
    return closure::BuildSemanticRootClosureManifestV1(
        Shape(),
        gf::Fp3::FromFp(7),
        gf::Fp3::FromFp(11),
        1);
}

uint256 Seed(uint32_t value)
{
    uint256 out;
    for (uint32_t i = 0; i < out.size(); ++i) {
        out.begin()[i] =
            static_cast<unsigned char>(
                (value + 19U * i) & 0xffU);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

std::array<uint32_t, closure::kSemanticRootU32WordsV1>
Words(uint32_t seed)
{
    std::array<
        uint32_t,
        closure::kSemanticRootU32WordsV1> out{};
    for (uint32_t i = 0; i < out.size(); ++i) {
        out[i] =
            seed * 0x9e3779b1U +
            i * 0x01020305U + 1U;
    }
    return out;
}

closure::SemanticRootReceiptStatementV1 Receipt(
    const closure::SemanticRootClosureManifestV1& manifest)
{
    closure::SemanticRootReceiptStatementV1 out;
    out.closure_manifest_commitment =
        manifest.closure_commitment;
    out.all_sources_available =
        manifest.recursive_semantic_closure_complete;
    out.recursively_consumable =
        manifest.recursive_semantic_closure_complete;
    out.production_authority =
        manifest.production_authority;
    out.endpoints.reserve(manifest.endpoints.size());
    for (uint32_t index = 0;
         index < manifest.endpoints.size(); ++index) {
        const auto& expected = manifest.endpoints[index];
        closure::SemanticEndpointReceiptStatementV1 endpoint;
        endpoint.endpoint = expected.endpoint;
        endpoint.role = expected.role;
        endpoint.family_index = expected.family_index;
        endpoint.program_recursive_alg_hash_words =
            expected.program_recursive_alg_hash_words;
        endpoint.relation_semantic_root_words =
            Words(index + 1U);
        endpoint.provenance_root_words =
            endpoint.relation_semantic_root_words;
        endpoint.receipt_semantic_root_words =
            endpoint.relation_semantic_root_words;
        if (expected.ctl.relation_value_same_trace) {
            endpoint.ctl_schedule_commitment_words =
                Words(0x100U + index);
            endpoint.ctl_challenge_commitment_words =
                Words(0x200U + index);
            for (uint32_t word = 0;
                 word < endpoint.ctl_terminal_words.size();
                 ++word) {
                endpoint.ctl_terminal_words[word] =
                    0x300U + 17U * index + word;
            }
        }
        endpoint.ctl_rational_identity_acceptance =
            expected.ctl
                .recursive_rational_identity_consumed;
        endpoint.child_acceptance =
            expected.child_receipt_acceptance_cell;
        out.endpoints.push_back(std::move(endpoint));
    }
    out.statement_commitment =
        closure::
            ComputeSemanticRootReceiptStatementCommitmentV1(
                out);
    return out;
}

void Recommit(
    closure::SemanticRootClosureManifestV1& manifest)
{
    manifest.closure_commitment =
        closure::ComputeSemanticRootClosureCommitmentV1(
            manifest);
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_52_by_14_manifest_reports_real_missing_sources)
{
    const auto manifest = Manifest();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        closure::ValidateSemanticRootClosureManifestV1(
            manifest, Shape(),
            gf::Fp3::FromFp(7),
            gf::Fp3::FromFp(11),
            1, false, &why),
        why);
    BOOST_CHECK_EQUAL(manifest.roles.size(), 14U);
    BOOST_CHECK_EQUAL(manifest.endpoints.size(), 52U);
    BOOST_CHECK_EQUAL(
        manifest.exact_program_endpoints, 14U);
    BOOST_CHECK_EQUAL(
        manifest.relation_proof_cell_endpoints, 22U);
    BOOST_CHECK_EQUAL(
        manifest.same_trace_ctl_value_endpoints, 21U);
    BOOST_CHECK_EQUAL(
        manifest.semantic_complete_endpoints, 2U);
    BOOST_CHECK_EQUAL(
        manifest.recursive_provenance_endpoints, 0U);
    BOOST_CHECK_EQUAL(
        manifest.child_receipt_acceptance_endpoints, 0U);
    BOOST_CHECK_EQUAL(
        manifest.recursively_consumed_endpoints, 0U);
    BOOST_CHECK_EQUAL(manifest.complete_roles, 0U);
    BOOST_CHECK(manifest.exact_role_order);
    BOOST_CHECK(manifest.exact_endpoint_order);
    BOOST_CHECK(manifest.production_registry_canonical);
    BOOST_CHECK(manifest.no_structural_stub_claims);
    BOOST_CHECK(manifest.canonical_u32_commitment);
    BOOST_CHECK(manifest.local_inventory_complete);
    BOOST_CHECK(
        !manifest.recursive_semantic_closure_complete);
    BOOST_CHECK(!manifest.production_authority);
    BOOST_CHECK_EQUAL(manifest.residuals.size(), 52U);

    for (uint32_t index = 0;
         index < manifest.endpoints.size(); ++index) {
        const auto& endpoint = manifest.endpoints[index];
        BOOST_CHECK_EQUAL(
            static_cast<uint16_t>(endpoint.endpoint),
            index + 1U);
        BOOST_CHECK(
            endpoint.missing_sources &
            closure::
                MissingRecursiveCtlRationalIdentityV1);
        BOOST_CHECK(
            endpoint.missing_sources &
            closure::
                MissingChildReceiptAcceptanceCellV1);
        BOOST_CHECK(
            !endpoint.ctl
                 .recursive_rational_identity_consumed);
        if (endpoint.ctl.relation_value_same_trace) {
            BOOST_CHECK(
                endpoint.ctl.tuple_columns_owned);
            BOOST_CHECK(
                endpoint.ctl
                    .ordered_schedule_and_multiplicity_pinned);
            BOOST_CHECK(
                endpoint.ctl
                    .post_commit_challenges_bound);
            BOOST_CHECK(
                endpoint.ctl
                    .denominators_nonzero_constrained);
            BOOST_CHECK(
                !endpoint.ctl
                     .global_terminal_zero_consumed);
        }
    }
}

BOOST_AUTO_TEST_CASE(
    omission_reorder_duplicate_stub_and_cross_role_reject)
{
    const auto honest = Manifest();
    const auto validate =
        [](const auto& candidate) {
            return closure::
                ValidateSemanticRootClosureManifestV1(
                    candidate, Shape(),
                    gf::Fp3::FromFp(7),
                    gf::Fp3::FromFp(11),
                    1);
        };
    {
        auto attack = honest;
        attack.endpoints.erase(
            attack.endpoints.begin() + 7);
        Recommit(attack);
        BOOST_CHECK(!validate(attack));
    }
    {
        auto attack = honest;
        std::swap(
            attack.endpoints[9],
            attack.endpoints[10]);
        Recommit(attack);
        BOOST_CHECK(!validate(attack));
    }
    {
        auto attack = honest;
        attack.endpoints[12] =
            attack.endpoints[11];
        Recommit(attack);
        BOOST_CHECK(!validate(attack));
    }
    {
        auto attack = honest;
        const auto found = std::find_if(
            attack.endpoints.begin(),
            attack.endpoints.end(),
            [](const auto& endpoint) {
                return endpoint.exact_program_table;
            });
        BOOST_REQUIRE(
            found != attack.endpoints.end());
        found->exact_program_table = false;
        found->family_index =
            closure::kSemanticRootNoFamilyV1;
        found->program_external_sha256d_words = {};
        found->program_recursive_alg_hash_words = {};
        found->missing_sources |=
            closure::MissingExactProgramTableV1;
        Recommit(attack);
        BOOST_CHECK(!validate(attack));
    }
    {
        auto attack = honest;
        attack.endpoints[29].role =
            rc::RCStage3RelationRole::CoupledBank;
        Recommit(attack);
        BOOST_CHECK(!validate(attack));
    }
}

BOOST_AUTO_TEST_CASE(
    exact_receipt_statement_is_binding_only_and_fail_closed)
{
    const auto manifest = Manifest();
    const auto honest = Receipt(manifest);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        closure::ValidateSemanticRootReceiptStatementV1(
            manifest, honest, &why),
        why);
    BOOST_CHECK(!honest.all_sources_available);
    BOOST_CHECK(!honest.recursively_consumable);
    BOOST_CHECK(!honest.production_authority);
    for (const auto& endpoint : honest.endpoints) {
        BOOST_CHECK_EQUAL(endpoint.child_acceptance, 0U);
        BOOST_CHECK_EQUAL(
            endpoint.ctl_rational_identity_acceptance,
            0U);
    }

    {
        auto attack = honest;
        attack.endpoints.pop_back();
        attack.statement_commitment =
            closure::
                ComputeSemanticRootReceiptStatementCommitmentV1(
                    attack);
        BOOST_CHECK(
            !closure::
                ValidateSemanticRootReceiptStatementV1(
                    manifest, attack));
    }
    {
        auto attack = honest;
        std::swap(
            attack.endpoints[4],
            attack.endpoints[5]);
        attack.statement_commitment =
            closure::
                ComputeSemanticRootReceiptStatementCommitmentV1(
                    attack);
        BOOST_CHECK(
            !closure::
                ValidateSemanticRootReceiptStatementV1(
                    manifest, attack));
    }
    {
        auto attack = honest;
        attack.endpoints[8]
            .provenance_root_words[3] ^= 1U;
        attack.statement_commitment =
            closure::
                ComputeSemanticRootReceiptStatementCommitmentV1(
                    attack);
        BOOST_CHECK(
            !closure::
                ValidateSemanticRootReceiptStatementV1(
                    manifest, attack));
    }
    {
        auto attack = honest;
        attack.endpoints[0].role =
            rc::RCStage3RelationRole::EpisodeGemm;
        attack.statement_commitment =
            closure::
                ComputeSemanticRootReceiptStatementCommitmentV1(
                    attack);
        BOOST_CHECK(
            !closure::
                ValidateSemanticRootReceiptStatementV1(
                    manifest, attack));
    }
    {
        auto attack = honest;
        attack.endpoints[0].child_acceptance = 1;
        attack.statement_commitment =
            closure::
                ComputeSemanticRootReceiptStatementCommitmentV1(
                    attack);
        BOOST_CHECK(
            !closure::
                ValidateSemanticRootReceiptStatementV1(
                    manifest, attack));
    }
    {
        auto attack = honest;
        const auto found = std::find_if(
            manifest.endpoints.begin(),
            manifest.endpoints.end(),
            [](const auto& endpoint) {
                return !endpoint.ctl
                            .relation_value_same_trace;
            });
        BOOST_REQUIRE(
            found != manifest.endpoints.end());
        const size_t index = std::distance(
            manifest.endpoints.begin(), found);
        attack.endpoints[index]
            .ctl_terminal_words[0] = 1;
        attack.statement_commitment =
            closure::
                ComputeSemanticRootReceiptStatementCommitmentV1(
                    attack);
        BOOST_CHECK(
            !closure::
                ValidateSemanticRootReceiptStatementV1(
                    manifest, attack));
    }
}

BOOST_AUTO_TEST_CASE(
    u32_decoder_rejects_goldilocks_alias_and_extensions)
{
    uint32_t decoded = 0;
    BOOST_CHECK(
        closure::DecodeCanonicalSemanticU32CellV1(
            gf::Fp3::FromFp(
                gf::FromU64(0xffffffffULL)),
            decoded));
    BOOST_CHECK_EQUAL(decoded, 0xffffffffU);
    BOOST_CHECK(
        !closure::DecodeCanonicalSemanticU32CellV1(
            gf::Fp3{gf::kP, 0, 0}, decoded));
    BOOST_CHECK(
        !closure::DecodeCanonicalSemanticU32CellV1(
            gf::Fp3{
                uint64_t{1} << 32, 0, 0},
            decoded));
    BOOST_CHECK(
        !closure::DecodeCanonicalSemanticU32CellV1(
            gf::Fp3{0, 1, 0}, decoded));
}

BOOST_AUTO_TEST_CASE(
    inventory_air_proof_roundtrip_and_proof_tamper_reject)
{
    const auto manifest = Manifest();
    const auto product =
        closure::BuildSemanticRootClosureAirV1(
            manifest);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.cs.n_rows, 64U);
    BOOST_CHECK_EQUAL(product.active_rows, 52U);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.exact_manifest_pinned);
    BOOST_CHECK(product.values_are_ordinary_witness);
    BOOST_CHECK(
        product.only_expected_schedule_preprocessed);
    BOOST_CHECK(
        !product.recursive_semantic_closure_complete);
    BOOST_CHECK(!product.production_authority);

    const uint256 seed = Seed(0x52);
    const auto prove_begin =
        std::chrono::steady_clock::now();
    const auto proved = aq::AirQuotientProveRows(
        product.cs, product.columns, seed);
    const auto prove_end =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    std::string why;
    const auto verify_begin =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            product.cs, proved.proof, seed, &why),
        why);
    const auto verify_end =
        std::chrono::steady_clock::now();

    rc::AirQuotientProofAlg canonical;
    canonical.batch = proved.proof.batch;
    canonical.next_openings =
        proved.proof.next_openings;
    canonical.trace_commit =
        proved.proof.trace_commit;
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE_MESSAGE(
        rc::SerializeAirQuotientProofAlg(
            canonical, bytes, &why),
        why);
    BOOST_TEST_MESSAGE(
        "SEMANTIC_ROOT_INVENTORY_PROOF measured_bytes="
        << bytes.size()
        << " prove_us="
        << std::chrono::duration_cast<
               std::chrono::microseconds>(
               prove_end - prove_begin).count()
        << " verify_us="
        << std::chrono::duration_cast<
               std::chrono::microseconds>(
               verify_end - verify_begin).count()
        << " rows=" << product.cs.n_rows
        << " cols=" << product.cs.n_columns
        << " constraints="
        << product.cs.constraints.size());

    auto tampered = proved.proof;
    BOOST_REQUIRE(!tampered.batch.queries.empty());
    BOOST_REQUIRE_GT(
        tampered.batch.queries[0].row.values.size(),
        product.layout.claimed_missing_sources);
    tampered.batch.queries[0]
        .row.values[
            product.layout.claimed_missing_sources] =
        gf::Add(
            tampered.batch.queries[0]
                .row.values[
                    product.layout
                        .claimed_missing_sources],
            gf::Fp3::One());
    std::string reject_why;
    BOOST_CHECK_MESSAGE(
        !aq::AirQuotientVerifyRows(
            product.cs, tampered, seed,
            &reject_why),
        "proof-level semantic inventory tamper accepted");
    BOOST_TEST_MESSAGE(
        "SEMANTIC_ROOT_INVENTORY_REJECT why=\""
        << reject_why << "\"");

    auto pin_tampered_cs = product.cs;
    const auto pin = std::find_if(
        pin_tampered_cs.preprocessed.begin(),
        pin_tampered_cs.preprocessed.end(),
        [&product](const auto& entry) {
            return entry.first ==
                product.layout.expected_endpoint;
        });
    BOOST_REQUIRE(
        pin != pin_tampered_cs.preprocessed.end());
    BOOST_REQUIRE(!pin->second.empty());
    pin->second[0] =
        gf::Add(pin->second[0], gf::Fp3::One());
    std::string pin_reject_why;
    BOOST_CHECK_MESSAGE(
        !aq::AirQuotientVerifyRows(
            pin_tampered_cs, proved.proof, seed,
            &pin_reject_why),
        "proof-level preprocessed schedule-pin "
        "tamper accepted");
    BOOST_TEST_MESSAGE(
        "SEMANTIC_ROOT_PIN_REJECT why=\""
        << pin_reject_why << "\"");
}

BOOST_AUTO_TEST_SUITE_END()
