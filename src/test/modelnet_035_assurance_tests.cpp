// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_assurance.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_assurance_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(arch_004_profiles_are_one_implementation)
{
    const modelnet::DeploymentProfile profiles[] = {
        modelnet::DeploymentProfile::PUBLIC_PARTICIPANT,
        modelnet::DeploymentProfile::PRIVATE_PERSONAL,
        modelnet::DeploymentProfile::COMMUNITY_REALM,
        modelnet::DeploymentProfile::ENTERPRISE_INGRESS,
        modelnet::DeploymentProfile::ENTERPRISE_SITE,
        modelnet::DeploymentProfile::OFFLINE_SITE,
    };
    const char* names[] = {
        "PUBLIC_PARTICIPANT",
        "PRIVATE_PERSONAL",
        "COMMUNITY_REALM",
        "ENTERPRISE_INGRESS",
        "ENTERPRISE_SITE",
        "OFFLINE_SITE",
    };
    std::string implementation;
    for (size_t i = 0; i < 6; ++i) {
        const modelnet::ProfileConfig cfg = modelnet::MakeProfile(profiles[i]);
        BOOST_CHECK(cfg.profile == profiles[i]);
        BOOST_CHECK_EQUAL(std::string(modelnet::ProfileName(profiles[i])), std::string(names[i]));
        if (implementation.empty()) implementation = cfg.implementation;
        BOOST_CHECK_EQUAL(cfg.implementation, implementation);
        BOOST_CHECK_EQUAL(cfg.implementation, modelnet::kOneImplementation);
    }

    const modelnet::ProfileConfig participant = modelnet::MakeProfile(modelnet::DeploymentProfile::PUBLIC_PARTICIPANT);
    modelnet::ProfileConfig personal = modelnet::MakeProfile(modelnet::DeploymentProfile::PRIVATE_PERSONAL);
    BOOST_CHECK(participant.public_connectivity);
    BOOST_CHECK(participant.publication_authority);
    BOOST_CHECK(!personal.public_connectivity);
    BOOST_CHECK(!personal.publication_authority);

    modelnet::ProfileConfig connectivity = participant;
    const modelnet::ScopeDecision cut = modelnet::SetPublicConnectivity(connectivity, false);
    BOOST_CHECK(cut.ok);
    BOOST_CHECK(!connectivity.public_connectivity);
    BOOST_CHECK(connectivity.publication_authority);

    modelnet::ProfileConfig community = modelnet::MakeProfile(modelnet::DeploymentProfile::COMMUNITY_REALM);
    BOOST_CHECK(community.public_connectivity);
    BOOST_CHECK(!community.publication_authority);
    const modelnet::ScopeDecision explicit_pub = modelnet::SetPublicationAuthority(community, true, true);
    BOOST_CHECK(explicit_pub.ok);
    BOOST_CHECK(community.publication_authority);
    BOOST_CHECK(community.public_connectivity);
    BOOST_CHECK(community.profile == modelnet::DeploymentProfile::COMMUNITY_REALM);

    modelnet::ProfileConfig ingress = modelnet::MakeProfile(modelnet::DeploymentProfile::ENTERPRISE_INGRESS);
    BOOST_CHECK(ingress.public_connectivity);
    BOOST_CHECK(!ingress.publication_authority);
    BOOST_CHECK(ingress.profile != modelnet::DeploymentProfile::PUBLIC_PARTICIPANT);
    const modelnet::ScopeDecision implied = modelnet::SetPublicationAuthority(ingress, true, false);
    BOOST_CHECK(!implied.ok);
    BOOST_CHECK_EQUAL(implied.code, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!ingress.publication_authority);

    const modelnet::ScopeDecision implicit = modelnet::EnableImplicitPublicExport(personal);
    BOOST_CHECK(!implicit.ok);
    BOOST_CHECK_EQUAL(implicit.code, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!personal.publication_authority);

    modelnet::ProfileConfig offline = modelnet::MakeProfile(modelnet::DeploymentProfile::OFFLINE_SITE);
    BOOST_CHECK(!offline.public_connectivity);
    const modelnet::ScopeDecision online = modelnet::SetPublicConnectivity(offline, true);
    BOOST_CHECK(!online.ok);
    BOOST_CHECK_EQUAL(online.code, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!offline.public_connectivity);

    const modelnet::ProfileConfig site = modelnet::MakeProfile(modelnet::DeploymentProfile::ENTERPRISE_SITE);
    BOOST_CHECK(!site.public_connectivity);
    BOOST_CHECK(!site.wallet_enabled);
    BOOST_CHECK(!site.mining_enabled);
    BOOST_CHECK(modelnet::EnterpriseWorksWithWalletMiningDisabled(site));
    ingress.public_connectivity = false;
    BOOST_CHECK(!ingress.wallet_enabled);
    BOOST_CHECK(!ingress.mining_enabled);
    BOOST_CHECK(modelnet::EnterpriseWorksWithWalletMiningDisabled(ingress));
}

BOOST_AUTO_TEST_CASE(arch_002_scheduler_marketplace_and_swarm_leader_stay_off)
{
    modelnet::NetworkTrainingPolicy policy;
    BOOST_CHECK(!policy.network_training_scheduler_enabled);
    const modelnet::ScopeDecision denied = modelnet::SetNetworkTrainingSchedulerEnabled(policy, true);
    BOOST_CHECK(!denied.ok);
    BOOST_CHECK_EQUAL(denied.code, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!policy.network_training_scheduler_enabled);
    const modelnet::ScopeDecision kept = modelnet::SetNetworkTrainingSchedulerEnabled(policy, false);
    BOOST_CHECK(kept.ok);
    BOOST_CHECK(!policy.network_training_scheduler_enabled);

    const modelnet::ScopeDecision market = modelnet::EnableMarketplace();
    BOOST_CHECK(!market.ok);
    BOOST_CHECK_EQUAL(market.code, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!modelnet::MarketplaceEnabled());
    const modelnet::ScopeDecision swarm = modelnet::EnableSwarmLeader();
    BOOST_CHECK(!swarm.ok);
    BOOST_CHECK_EQUAL(swarm.code, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!modelnet::SwarmLeaderEnabled());
}

BOOST_AUTO_TEST_CASE(arch_001_secret_placement_and_boundary)
{
    const modelnet::ScopeDecision placed = modelnet::SecretPlacement(false, false, false);
    BOOST_CHECK(placed.ok);
    BOOST_CHECK(placed.code.empty());
    const modelnet::ScopeDecision signing = modelnet::SecretPlacement(true, false, false);
    const modelnet::ScopeDecision wallet = modelnet::SecretPlacement(false, true, false);
    const modelnet::ScopeDecision policy = modelnet::SecretPlacement(false, false, true);
    const modelnet::ScopeDecision all = modelnet::SecretPlacement(true, true, true);
    for (const modelnet::ScopeDecision& decision : {signing, wallet, policy, all}) {
        BOOST_CHECK(!decision.ok);
        BOOST_CHECK_EQUAL(decision.code, "BTX035_SCOPE_DENIED");
    }

    const std::string same_host = modelnet::AdvertiseActualBoundary(true, true, false);
    BOOST_CHECK(same_host.find("process") != std::string::npos);
    BOOST_CHECK(same_host.find("hardware") == std::string::npos);
    const std::string wrapped = modelnet::AdvertiseActualBoundary(false, true, true);
    BOOST_CHECK(wrapped.find("process") != std::string::npos);
    BOOST_CHECK(wrapped.find("hardware") == std::string::npos);
    const std::string proven = modelnet::AdvertiseActualBoundary(false, true, false);
    BOOST_CHECK(proven.find("hardware") != std::string::npos);
    BOOST_CHECK(proven.find("process") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(arch_003_model_plane_does_not_own_cs_main)
{
    // Locked false: ModelPlaneLockOwnsCsMain() must not start returning true.
    BOOST_CHECK(!modelnet::ModelPlaneLockOwnsCsMain());
}

BOOST_AUTO_TEST_CASE(sec_001_assurance_dimensions_stay_separate)
{
    modelnet::AssuranceReport report;
    report.source_authenticity = true;
    const std::string text = modelnet::FormatReport(report);
    BOOST_CHECK(text.find("byte_integrity=false") != std::string::npos);
    BOOST_CHECK(text.find("source_authenticity=true") != std::string::npos);
    BOOST_CHECK(text.find("authorization=false") != std::string::npos);
    BOOST_CHECK(text.find("transport_confidentiality=false") != std::string::npos);
    BOOST_CHECK(text.find("training_reproducibility=false") != std::string::npos);
    BOOST_CHECK(text.find("evaluator_independence=false") != std::string::npos);
    BOOST_CHECK(text.find("behavioral_evaluation=false") != std::string::npos);
    BOOST_CHECK(text.find("runtime_containment=false") != std::string::npos);
    BOOST_CHECK(text.find("distribution_approval=false") != std::string::npos);
    BOOST_CHECK(text.find("local_check=false") != std::string::npos);
    BOOST_CHECK(text.find("delegated_to_selected_attestor=false") != std::string::npos);
    BOOST_CHECK(text.find("trusted") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(sec_002_network_executor_message)
{
    const std::string id(96, 'a');
    BOOST_CHECK(modelnet::IsBuildManifestId(id));
    BOOST_CHECK_EQUAL(modelnet::InstalledAdapterId(id), id);
    BOOST_CHECK(modelnet::RejectNetworkExecutorMessage(id).empty());

    const std::string upper(96, 'A');
    BOOST_CHECK(!modelnet::IsBuildManifestId(upper));
    BOOST_CHECK_EQUAL(modelnet::RejectNetworkExecutorMessage(upper), "BTX035_SCOPE_DENIED");
    BOOST_CHECK(modelnet::InstalledAdapterId(upper).empty());

    const std::string shell = "echo hi; id";
    BOOST_CHECK(modelnet::MessageHasShellMetacharacter(shell));
    BOOST_CHECK_EQUAL(modelnet::RejectNetworkExecutorMessage(shell), "BTX035_SCOPE_DENIED");

    const std::string env = "PATH=/tmp/ignored";
    BOOST_CHECK(modelnet::MessageHasEnvAssignment(env));
    BOOST_CHECK_EQUAL(modelnet::RejectNetworkExecutorMessage(env), "BTX035_SCOPE_DENIED");

    const std::string path = "/usr/bin/python3";
    BOOST_CHECK(modelnet::MessageHasAbsoluteExecutablePath(path));
    BOOST_CHECK_EQUAL(modelnet::RejectNetworkExecutorMessage(path), "BTX035_SCOPE_DENIED");
    BOOST_CHECK(modelnet::InstalledAdapterId("/usr/bin/" + id).empty());
    BOOST_CHECK(modelnet::MessageHasAbsoluteExecutablePath("C:\\Windows\\system32\\cmd.exe"));
    BOOST_CHECK(!modelnet::IsBuildManifestId(path));
}

BOOST_AUTO_TEST_CASE(sec_003_redaction_and_public_metadata)
{
    const std::string raw =
        "GET https://user:pass@example.com/obj?token=abc&sig=deadbeef Authorization: Bearer eyJhbGci.secret";
    const std::string redacted = modelnet::RedactLog(raw);
    BOOST_CHECK(redacted.find("user:pass@") == std::string::npos);
    BOOST_CHECK(redacted.find("eyJhbGci") == std::string::npos);
    BOOST_CHECK(redacted.find("token=abc") == std::string::npos);
    BOOST_CHECK(redacted.find("sig=deadbeef") == std::string::npos);
    BOOST_CHECK(redacted.find("example.com") != std::string::npos);
    BOOST_CHECK(redacted.find("[redacted]") != std::string::npos);

    modelnet::MetadataRow row;
    row.is_private = true;
    row.signature = true;
    row.selected = false;
    BOOST_CHECK(!modelnet::PublicMetadata(row));
    row.selected = true;
    BOOST_CHECK(!modelnet::PublicMetadata(row));
    row.is_private = false;
    row.signature = true;
    row.selected = false;
    BOOST_CHECK(!modelnet::PublicMetadata(row));
    row.selected = true;
    BOOST_CHECK(modelnet::PublicMetadata(row));
}

BOOST_AUTO_TEST_CASE(sec_004_independent_operators)
{
    std::string property;
    BOOST_CHECK(!modelnet::IndependentOperators({}, "", false, true, 0, property));
    BOOST_CHECK(property.empty());
    BOOST_CHECK(!modelnet::IndependentOperators({}, "", false, false, 1000, property));
    BOOST_CHECK(property.empty());
    BOOST_CHECK(!modelnet::IndependentOperators({"root-a", "root-b"}, "many keys", true, false, 0, property));
    BOOST_CHECK(property.empty());
    BOOST_CHECK(!modelnet::IndependentOperators({"root-a", "root-a"}, "evaluators", true, false, 0, property));
    BOOST_CHECK(!modelnet::IndependentOperators({"root-a", "root-b"}, "evaluators", false, false, 0, property));
    BOOST_CHECK(property.empty());

    BOOST_CHECK(modelnet::IndependentOperators({"root-a", "root-b", "root-a"}, "evaluators", true, false, 1000, property));
    BOOST_CHECK_EQUAL(property, "evaluators");
}

BOOST_AUTO_TEST_CASE(core_002_monetary_terms_untouched)
{
    BOOST_CHECK(modelnet::MonetaryTermsUntouched());
    const modelnet::ScopeDecision applied = modelnet::ApplyResearchRecordToConsensus();
    BOOST_CHECK(!applied.ok);
    BOOST_CHECK_EQUAL(applied.code, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!modelnet::PromptAuthorizesDeployment("deploy the research record"));
    BOOST_CHECK(!modelnet::PromptAuthorizesDeployment(""));
}

BOOST_AUTO_TEST_CASE(core_003_fork_choice_rejects_model_records)
{
    const char* kinds[] = {
        "research_record",
        "vote",
        "promotion",
        "rollout_receipt",
        "admission_decision",
    };
    for (const char* kind : kinds) {
        const modelnet::ScopeDecision decision = modelnet::ApplyToForkChoice(kind);
        BOOST_CHECK(!decision.ok);
        BOOST_CHECK_EQUAL(decision.code, "BTX035_SCOPE_DENIED");
    }
}

BOOST_AUTO_TEST_CASE(core_005_claims_name_the_dimension)
{
    const std::string bytes = modelnet::ClaimText("byte_integrity");
    const std::string runtime = modelnet::ClaimText("runtime_containment");
    BOOST_CHECK(bytes.find("byte_integrity") != std::string::npos);
    BOOST_CHECK(runtime.find("runtime_containment") != std::string::npos);
    BOOST_CHECK(bytes.find("runtime_containment") == std::string::npos);
    const modelnet::ScopeDecision trusted = modelnet::EvaluateClaim("trusted");
    BOOST_CHECK(!trusted.ok);
    BOOST_CHECK_EQUAL(trusted.code, "BTX035_CLAIM");
    const modelnet::ScopeDecision named = modelnet::EvaluateClaim(bytes);
    BOOST_CHECK(named.ok);
    BOOST_CHECK(named.code.empty());
    const modelnet::ScopeDecision first = modelnet::EvaluateClaim("BTX is the world's first");
    BOOST_CHECK(!first.ok);
    BOOST_CHECK_EQUAL(first.code, "BTX035_CLAIM");
}

BOOST_AUTO_TEST_CASE(run_002_protected_profile_defaults_and_bypass)
{
    const modelnet::ProtectedProfile profile = modelnet::DefaultProtectedProfile();
    BOOST_CHECK(!profile.external_network);
    BOOST_CHECK(!profile.ambient_credentials);
    BOOST_CHECK(profile.input_volume.read_only);
    BOOST_CHECK(modelnet::ProtectedDefaultsHold(profile));
    modelnet::ProtectedProfile opened = profile;
    opened.external_network = true;
    BOOST_CHECK(!modelnet::ProtectedDefaultsHold(opened));

    const char* channels[] = {"shell", "raw socket", "mounted secret", "git helper", "local service", "child process"};
    for (const char* channel : channels) {
        BOOST_CHECK_EQUAL(modelnet::BypassDeniedTool(channel), "BTX035_SCOPE_DENIED");
    }
}

BOOST_AUTO_TEST_CASE(econ_002_pay_with_compute_is_not_a_marketplace)
{
    modelnet::ComputeAccounting accounting;
    BOOST_CHECK(!accounting.PayWithComputeEnabled());
    BOOST_CHECK(!accounting.marketplace);
    BOOST_CHECK(!accounting.ResearchMaySpend());
    BOOST_CHECK(modelnet::EnablePayWithCompute(accounting));
    BOOST_CHECK(accounting.PayWithComputeEnabled());
    BOOST_CHECK(!accounting.marketplace);
    BOOST_CHECK(!accounting.ResearchMaySpend());
}

BOOST_AUTO_TEST_SUITE_END()
