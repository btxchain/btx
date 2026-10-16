// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_gateway.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_gateway_tests, BasicTestingSetup)

namespace {

std::string OpenApiPath()
{
    const char* spec = std::getenv("BTX035_SPEC");
    if (spec == nullptr || spec[0] == '\0') return {};
    return std::string(spec) + "/api/openapi.json";
}

bool SpecConfigured()
{
    return std::getenv("BTX035_SPEC") != nullptr;
}

const std::string kSession = "session-1";
const std::string kRealm = "realm-1";
const std::string kResource = "resource-1";
const std::string kIdem = "idempotency-key-1";
const std::string kState = "expected-state-1";

modelnet::HostedGateway LoadSpec()
{
    modelnet::HostedGateway gateway;
    std::string err;
    const std::string openapi = OpenApiPath();
    BOOST_REQUIRE_MESSAGE(!openapi.empty(), "set BTX035_SPEC to the v1.1 specification root");
    BOOST_REQUIRE(gateway.Load(openapi, err));
    BOOST_CHECK(err.empty());
    return gateway;
}

modelnet::AuditEvent SampleAudit(std::string value, std::string classification)
{
    modelnet::AuditEvent event;
    event.event_type = "inventory.export";
    event.realm_id = "realm-1";
    event.resource_id = "resource-1";
    event.field = "access_token";
    event.value = std::move(value);
    event.classification = std::move(classification);
    return event;
}

} // namespace

static_assert(!modelnet::GeneralMethodRouterEnabled());

BOOST_AUTO_TEST_CASE(hosted_routes_match_openapi_allowlist)
{
    if (!SpecConfigured()) {
        BOOST_TEST_MESSAGE("BTX035_SPEC is unset; skipping hosted_routes_match_openapi_allowlist");
        return;
    }
    const modelnet::HostedGateway gateway = LoadSpec();
    BOOST_REQUIRE_EQUAL(gateway.Routes().size(), 45);
    bool saw_mutation = false;
    bool saw_read = false;
    for (const modelnet::HostedGateway::Route& route : gateway.Routes()) {
        BOOST_CHECK(gateway.HostedRouteAllowed(route.http_method, route.path));
        BOOST_CHECK(gateway.HostedRouteAllowed("post", route.path));
        BOOST_CHECK(!gateway.HostedRouteAllowed("GET", route.path));
        std::string err;
        BOOST_CHECK(gateway.CheckRoute(route.http_method, route.path, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(gateway.CheckOperationId(route.operation_id, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(gateway.IsMutation(route.operation_id), route.mutation);
        saw_mutation = saw_mutation || route.mutation;
        saw_read = saw_read || !route.mutation;
    }
    BOOST_CHECK(saw_mutation);
    BOOST_CHECK(saw_read);
    BOOST_CHECK(gateway.HostedRouteAllowed("POST", "/v1/lab/info"));
    BOOST_CHECK(gateway.HostedRouteAllowed("POST", "/v1/lab/economy_refs"));
    BOOST_CHECK(gateway.HostedRouteAllowed("POST", "/v1/lab/state_get"));
    BOOST_CHECK(!gateway.IsMutation("info"));
    BOOST_CHECK(!gateway.IsMutation("lab.state_get"));
    BOOST_CHECK(gateway.IsMutation("record_import"));
    BOOST_CHECK(gateway.IsMutation("model_host"));

    std::string err;
    BOOST_CHECK(gateway.CheckOperationId("lab.state_get", err));
    BOOST_CHECK(gateway.CheckOperationId("lab.rollout_endpoints", err));
    BOOST_CHECK(!gateway.CheckOperationId("state_get", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROUTE");
}

BOOST_AUTO_TEST_CASE(rpc_shell_wallet_and_unknown_methods_are_rejected)
{
    if (!SpecConfigured()) {
        BOOST_TEST_MESSAGE("BTX035_SPEC is unset; skipping rpc_shell_wallet_and_unknown_methods_are_rejected");
        return;
    }
    const modelnet::HostedGateway gateway = LoadSpec();
    const std::string rejected_paths[] = {
        "/rpc",
        "/rpc/",
        "/RPC",
        "/bin/sh",
        "/bin/bash",
        "/home/user/private",
        "/tmp/local-path",
        "/v1/lab/shell",
        "/v1/wallet/send",
        "/v1/lab/sendtoaddress",
        "/v1/lab/git_register",
        "/v1/lab/workspace_create",
        "/v1/lab/bundle_import",
        "/v1/lab/bundle_export",
    };
    for (const std::string& path : rejected_paths) {
        BOOST_CHECK(!gateway.HostedRouteAllowed("POST", path));
        std::string err;
        BOOST_CHECK(!gateway.CheckRoute("POST", path, err));
        BOOST_CHECK_EQUAL(err, "BTX035_ROUTE");
        BOOST_CHECK(!gateway.CheckMutation("POST", path, kSession, kRealm, kResource, kIdem, kState, err));
        BOOST_CHECK_EQUAL(err, "BTX035_ROUTE");
    }

    const std::string rejected_ids[] = {
        "sendtoaddress",
        "walletpassphrase",
        "getbalance",
        "dumpprivkey",
        "bash",
        "sh",
        "/rpc",
        "POST /rpc",
        "git_register",
        "workspace_create",
        "bundle_import",
        "not_listed",
        "",
    };
    for (const std::string& operation_id : rejected_ids) {
        std::string err = "stale";
        BOOST_CHECK(!gateway.CheckOperationId(operation_id, err));
        BOOST_CHECK_EQUAL(err, "BTX035_ROUTE");
    }

    modelnet::HostedGateway missing;
    std::string err;
    BOOST_CHECK(!missing.Load("spec/BTX035_v1_1/api/missing-openapi.json", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(missing.Routes().empty());
}

BOOST_AUTO_TEST_CASE(mutation_requires_session_realm_resource_idempotency_and_state)
{
    if (!SpecConfigured()) {
        BOOST_TEST_MESSAGE("BTX035_SPEC is unset; skipping mutation_requires_session_realm_resource_idempotency_and_state");
        return;
    }
    const modelnet::HostedGateway gateway = LoadSpec();
    std::string err;
    BOOST_CHECK(gateway.CheckMutation("POST", "/v1/lab/record_import", kSession, kRealm, kResource, kIdem, kState, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gateway.CheckMutation("POST", "/v1/lab/model_host", kSession, kRealm, kResource, kIdem, "null", err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!gateway.CheckMutation("POST", "/v1/lab/record_import", "", kRealm, kResource, kIdem, kState, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(!gateway.CheckMutation("POST", "/v1/lab/record_import", kSession, "", kResource, kIdem, kState, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(!gateway.CheckMutation("POST", "/v1/lab/record_import", kSession, kRealm, "  ", kIdem, kState, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(!gateway.CheckMutation("POST", "/v1/lab/record_import", kSession, kRealm, kResource, "", kState, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(!gateway.CheckMutation("POST", "/v1/lab/record_import", kSession, kRealm, kResource, kIdem, "", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");

    BOOST_CHECK(gateway.CheckMutation("POST", "/v1/lab/info", "", "", "", "", "", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(bearer_alone_is_not_a_mutation_authority)
{
    std::string err;
    BOOST_CHECK(!modelnet::MutationAuthorizedByBearer("bearer-token-only", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(!modelnet::MutationAuthorizedByBearer("", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(!modelnet::GeneralMethodRouterEnabled());
}

BOOST_AUTO_TEST_CASE(inventory_keeps_desired_observed_unknown_separate)
{
    UniValue out;
    std::string err;
    const std::vector<std::string> desired{"desired-a"};
    const std::vector<std::string> observed{"observed-a"};
    const std::vector<std::string> unknown{"unknown-a"};
    BOOST_REQUIRE(modelnet::InventoryExport(desired, observed, unknown, 1712345678901LL, "gen-42", out, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(out.exists("desired"));
    BOOST_REQUIRE(out.exists("observed"));
    BOOST_REQUIRE(out.exists("unknown"));
    BOOST_CHECK(out["desired"].isArray());
    BOOST_CHECK(out["observed"].isArray());
    BOOST_CHECK(out["unknown"].isArray());
    BOOST_CHECK_EQUAL(out["desired"][0].get_str(), "desired-a");
    BOOST_CHECK_EQUAL(out["observed"][0].get_str(), "observed-a");
    BOOST_CHECK_EQUAL(out["unknown"][0].get_str(), "unknown-a");
    BOOST_CHECK_EQUAL(out["observed_ms"].getInt<int64_t>(), 1712345678901LL);
    BOOST_CHECK_EQUAL(out["deployment_generation"].get_str(), "gen-42");
    BOOST_REQUIRE(out.exists("runtime_receipt"));
    BOOST_CHECK_EQUAL(out["runtime_receipt"]["observed_ms"].getInt<int64_t>(), 1712345678901LL);
    BOOST_CHECK_EQUAL(out["runtime_receipt"]["deployment_generation"].get_str(), "gen-42");
}

BOOST_AUTO_TEST_CASE(omitted_observed_fails)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("observed", UniValue{"stale"});
    std::string err;
    BOOST_CHECK(!modelnet::InventoryExport({"desired-a"}, std::nullopt, {"unknown-a"}, 10, "gen-1", out, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(!out.exists("observed"));
    BOOST_CHECK(!out.exists("desired"));
}

BOOST_AUTO_TEST_CASE(runtime_receipt_includes_observation_and_generation)
{
    UniValue receipt;
    std::string err;
    BOOST_REQUIRE(modelnet::RuntimeReceipt(99, "generation-7", receipt, err));
    BOOST_CHECK(receipt.exists("observed_ms"));
    BOOST_CHECK(receipt.exists("deployment_generation"));
    BOOST_CHECK_EQUAL(receipt["observed_ms"].getInt<int64_t>(), 99);
    BOOST_CHECK_EQUAL(receipt["deployment_generation"].get_str(), "generation-7");
    BOOST_CHECK(!modelnet::RuntimeReceipt(1, "", receipt, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(!receipt.exists("deployment_generation"));
    BOOST_CHECK(!modelnet::RuntimeReceipt(-1, "generation-7", receipt, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
}

BOOST_AUTO_TEST_CASE(audit_event_ids_are_stable_and_secrets_are_redacted)
{
    const modelnet::AuditEvent secret = SampleAudit("PLAINTEXT-AUDIT-TOKEN", "secret");
    const std::string first = modelnet::AuditEventId(secret);
    const std::string second = modelnet::AuditEventId(secret);
    BOOST_CHECK_EQUAL(first, second);
    BOOST_CHECK_EQUAL(first.size(), 64);

    modelnet::AuditEvent changed = secret;
    changed.value += "-other";
    BOOST_CHECK(modelnet::AuditEventId(changed) != first);

    UniValue exported;
    std::string err;
    BOOST_REQUIRE(modelnet::ExportAuditEvent(secret, exported, err));
    BOOST_CHECK_EQUAL(exported["id"].get_str(), first);
    BOOST_CHECK_EQUAL(exported["value"].get_str(), "REDACTED");
    BOOST_CHECK(exported.write().find("PLAINTEXT-AUDIT-TOKEN") == std::string::npos);
    BOOST_CHECK_EQUAL(modelnet::ExportAuditEvent(secret, exported, err), true);
    BOOST_CHECK_EQUAL(exported["id"].get_str(), second);

    const modelnet::AuditEvent pub = SampleAudit("gap", "public");
    modelnet::AuditEvent pub_field = pub;
    pub_field.field = "coverage";
    BOOST_REQUIRE(modelnet::ExportAuditEvent(pub_field, exported, err));
    BOOST_CHECK_EQUAL(exported["value"].get_str(), "gap");
    BOOST_CHECK_EQUAL(exported["id"].get_str(), modelnet::AuditEventId(pub_field));
}

BOOST_AUTO_TEST_CASE(private_admission_is_not_a_public_advertisement)
{
    BOOST_CHECK(!modelnet::PrivateAdmissionAdvertisesPublic());
    BOOST_CHECK_EQUAL(modelnet::DashboardAssurance("PRIVATE_REBUILDABLE"), "PRIVATE_REBUILDABLE");
    BOOST_CHECK_EQUAL(modelnet::DashboardAssurance("DELEGATED_POLICY_ATTESTED"), "DELEGATED_POLICY_ATTESTED");
    BOOST_CHECK(modelnet::DashboardAssurance("PRIVATE_REBUILDABLE") != "trusted");
    BOOST_CHECK(modelnet::DashboardAssurance("DELEGATED_POLICY_ATTESTED") != "trusted");

    std::string err;
    BOOST_CHECK(!modelnet::ExportPublic(false, "closure-public-1", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!modelnet::ExportPublic(true, "", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!modelnet::ExportPublic(true, "   ", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!modelnet::ExportPublic(false, "", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(modelnet::ExportPublic(true, "closure-public-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!modelnet::PrivateAdmissionAdvertisesPublic());
}

BOOST_AUTO_TEST_CASE(host_paths_use_strict_admission_and_quarantine_wins)
{
    const std::string gated[] = {
        "hostmodel",
        "importmodel",
        "importmodel-publish",
        "seedmodel",
        "demand-seed",
        "peer-follow",
        "cloud-mirror",
        "encrypted-reveal",
        "bundle-import",
        "package-install",
        "prefix-HostModel-suffix",
    };
    for (const std::string& path : gated) {
        BOOST_CHECK(modelnet::HostPathRequiresAdmission(path));
    }
    BOOST_CHECK(!modelnet::HostPathRequiresAdmission("research_query"));
    BOOST_CHECK(!modelnet::HostPathRequiresAdmission("info"));
    BOOST_CHECK(!modelnet::HostPathRequiresAdmission("unregistered-legacy-id"));
    BOOST_CHECK(!modelnet::HostPathRequiresAdmission("economy_refs"));

    BOOST_CHECK(modelnet::AdmissionDecision(true, false));
    BOOST_CHECK(!modelnet::AdmissionDecision(true, true));
    BOOST_CHECK(!modelnet::AdmissionDecision(false, false));
    BOOST_CHECK(!modelnet::AdmissionDecision(false, true));
}

BOOST_AUTO_TEST_SUITE_END()
