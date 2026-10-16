#include <modelnet/lab_api.h>
#include <modelnet/research_rpc.h>
#include <univalue.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_lab_api_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(every_lab_method_is_implemented)
{
    modelnet::ResetLabApi();
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.info", R"json({})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.info was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.record_get", R"json({"record_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.record_get was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.record_import", R"json({"envelope": {"record_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "body": {"envelope_version": 2}, "signature_hex": "ab"}, "publish": false, "idempotency_key": "idempotency-key-03", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.record_import was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.record_verify", R"json({"envelope": {"record_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "body": {"envelope_version": 2}, "signature_hex": "ab"}})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.record_verify was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.identity_inspect", R"json({"principal_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.identity_inspect was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.identity_create", R"json({"label": "l", "recovery_key_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "recovery_threshold": 1, "recovery_delay_ms": "1", "idempotency_key": "idempotency-key-06", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.identity_create was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.identity_sign", R"json({"record_type": "r", "payload": {}, "realm_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "delegation_id": null, "expires_ms": "1", "idempotency_key": "idempotency-key-07", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.identity_sign was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.identity_transition", R"json({"transition_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "approval_set_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "idempotency_key": "idempotency-key-08", "expected_state": null, "new_key_proof_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "observation_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "identity_state_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.identity_transition was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.identity_revoke", R"json({"revocation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "idempotency_key": "idempotency-key-09", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.identity_revoke was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.grant_evaluate", R"json({"grant_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "audience_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "permission": {"record_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "body": {"envelope_version": 2}, "signature_hex": "ab"}, "release_id": null, "now_ms": "1"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.grant_evaluate was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.git_register", R"json({"repository_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "origins": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "required_commit": {"record_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "body": {"envelope_version": 2}, "signature_hex": "ab"}, "workspace_allowed": false, "idempotency_key": "idempotency-key-11", "expected_state": null, "repository_genesis_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.git_register was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.git_snapshot", R"json({"repository_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "commit": {"record_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "body": {"envelope_version": 2}, "signature_hex": "ab"}, "dependency_lock_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "history_required": false, "idempotency_key": "idempotency-key-12", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.git_snapshot was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.git_attest", R"json({"snapshot_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "purpose": "p", "build_closure_id": null, "idempotency_key": "idempotency-key-13", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.git_attest was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.git_publish_ref", R"json({"update_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "approval_set_id": null, "idempotency_key": "idempotency-key-14", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.git_publish_ref was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.git_refs", R"json({"repository_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "namespace": "n", "after_cursor": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.git_refs was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.git_fetch_ticket", R"json({"repository_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "operation": "o", "ref_update_id": null, "max_bytes": "1", "idempotency_key": "idempotency-key-16", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.git_fetch_ticket was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.workspace_create", R"json({"snapshot_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "backend": "b", "adapter_id": null, "storage_limit": "1", "idempotency_key": "idempotency-key-17", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.workspace_create was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.workspace_snapshot", R"json({"workspace_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "generation": "1", "publishable": false, "idempotency_key": "idempotency-key-18", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.workspace_snapshot was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.workspace_restore", R"json({"workspace_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "checkpoint_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "new_generation": "1", "idempotency_key": "idempotency-key-19", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.workspace_restore was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.workspace_operation", R"json({"workspace_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "event": {"record_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "body": {"envelope_version": 2}, "signature_hex": "ab"}, "idempotency_key": "idempotency-key-20", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.workspace_operation was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.workspace_reconcile", R"json({"workspace_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "parent_checkpoint_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "resolution_snapshot_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "idempotency_key": "idempotency-key-21", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.workspace_reconcile was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.workspace_hydrate", R"json({"workspace_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "generation": "1", "paths": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "max_bytes": "1", "idempotency_key": "idempotency-key-22", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.workspace_hydrate was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.source_query", R"json({"snapshot_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "query_kind": "q", "query": "q", "limit": 1})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.source_query was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.research_query", R"json({"scope": "s", "topics": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "kinds": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "after_cursor": null, "limit": 1})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.research_query was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.research_context", R"json({"root_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "relations": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "max_depth": 1, "max_records": 1})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.research_context was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.research_frontier", R"json({"objective_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "view": "v", "limit": 1, "cursor": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.research_frontier was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.research_subscribe", R"json({"topic_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "principal_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "expires_ms": "1", "scope": "s", "idempotency_key": "idempotency-key-27", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.research_subscribe was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.research_unsubscribe", R"json({"subscription_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "idempotency_key": "idempotency-key-28", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.research_unsubscribe was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.research_publish", R"json({"record_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "topic_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "visibility": "v", "idempotency_key": "idempotency-key-29", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.research_publish was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.research_events", R"json({"subscription_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "after_sequence": "1", "wait_ms": "1"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.research_events was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.capsule_resolve", R"json({"capsule_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "purpose": "INSPECT", "max_bytes": "1"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.capsule_resolve was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.artifact_acquire", R"json({"resource": {}, "origin_policy_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "max_bytes": "1", "destination_class": "d", "idempotency_key": "idempotency-key-32", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.artifact_acquire was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.operation_get", R"json({"operation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.operation_get was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.operation_cancel", R"json({"operation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "idempotency_key": "idempotency-key-34", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.operation_cancel was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.audit_coverage", R"json({"trajectory_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.audit_coverage was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.admission_evaluate", R"json({"model_ref": {}, "policy_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "evidence_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "idempotency_key": "idempotency-key-36", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.admission_evaluate was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.model_host", R"json({"model_ref": {}, "admission_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "storage_limit_bytes": "1", "idempotency_key": "idempotency-key-37", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.model_host was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.model_unhost", R"json({"model_ref": {}, "idempotency_key": "idempotency-key-38", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.model_unhost was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.agent_lineage", R"json({"release_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "max_depth": 1, "cursor": null, "limit": 1})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.agent_lineage was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.agent_adopt", R"json({"release_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "prior_release_id": null, "grant_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "evaluation_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "idempotency_key": "idempotency-key-40", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.agent_adopt was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.runtime_bind", R"json({"release_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "environment_ref": {}, "requested_grants": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "assurance": "a", "idempotency_key": "idempotency-key-41", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.runtime_bind was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.action_prepare", R"json({"intent_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "idempotency_key": "idempotency-key-42", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.action_prepare was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.action_execute", R"json({"decision_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "one_use_permit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "idempotency_key": "idempotency-key-43", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.action_execute was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.runtime_pause", R"json({"runtime_binding_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "reason": "r", "idempotency_key": "idempotency-key-44", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.runtime_pause was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.runtime_resume", R"json({"runtime_binding_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "new_grant_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "idempotency_key": "idempotency-key-45", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.runtime_resume was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.journal_checkpoint", R"json({"stream_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "through_sequence": "1", "retention_until_ms": "1", "idempotency_key": "idempotency-key-46", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.journal_checkpoint was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.journal_proof", R"json({"checkpoint_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sequence": "1"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.journal_proof was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.journal_witness", R"json({"checkpoint_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "retained_until_ms": "1", "idempotency_key": "idempotency-key-48", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.journal_witness was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.incident_publish", R"json({"incident_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "audience": "a", "idempotency_key": "idempotency-key-49", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.incident_publish was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.realm_create", R"json({"name": "n", "nonce": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "policy_template": "p", "idempotency_key": "idempotency-key-50", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.realm_create was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.realm_policy_apply", R"json({"policy_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "approval_set_id": null, "idempotency_key": "idempotency-key-51", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.realm_policy_apply was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.realm_status", R"json({"realm_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.realm_status was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.promotion_prepare", R"json({"source_realm_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "destination_realm_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "resource_refs": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "policy_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "review_ref": {}, "idempotency_key": "idempotency-key-53", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.promotion_prepare was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.promotion_attest", R"json({"promotion_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "checks_ref": {}, "valid_until_ms": "1", "idempotency_key": "idempotency-key-54", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.promotion_attest was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.promotion_verify", R"json({"promotion_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "attestation_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "policy_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.promotion_verify was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.channel_publish", R"json({"update_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "approval_set_id": null, "idempotency_key": "idempotency-key-56", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.channel_publish was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.channel_get", R"json({"realm_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "channel": "c"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.channel_get was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.rollout_start", R"json({"plan_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "approval_set_id": null, "idempotency_key": "idempotency-key-58", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.rollout_start was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.rollout_status", R"json({"plan_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.rollout_status was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.rollout_pause", R"json({"plan_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "reason": "r", "idempotency_key": "idempotency-key-60", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.rollout_pause was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.rollout_rollback", R"json({"plan_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "new_channel_update_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "idempotency_key": "idempotency-key-61", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.rollout_rollback was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.deployment_observe", R"json({"receipt_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "idempotency_key": "idempotency-key-62", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.deployment_observe was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.bundle_export", R"json({"bundle_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "local_destination": "l", "idempotency_key": "idempotency-key-63", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.bundle_export was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.bundle_import", R"json({"local_source": "l", "destination_realm_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "minimum_policy_epoch": "1", "idempotency_key": "idempotency-key-64", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.bundle_import was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.migration_plan", R"json({"target_version": "t", "include_private": false})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.migration_plan was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.migration_apply", R"json({"plan_ref": {}, "backup_ref": {}, "idempotency_key": "idempotency-key-66", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.migration_apply was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.migration_verify", R"json({"migration_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.migration_verify was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.economy_refs", R"json({"subject_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.economy_refs was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.state_get", R"json({"target_kind": "t", "target_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.state_get was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.rollout_endpoints", R"json({"plan_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "filter": "f", "cursor": null, "limit": 1})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.rollout_endpoints was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.repository_create", R"json({"label": "l", "nonce": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "object_format": "o", "project_genesis_id": null, "default_ref": "d", "idempotency_key": "idempotency-key-71", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.repository_create was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.git_push_authorize", R"json({"batch_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "approval_set_id": null, "push_session_nonce": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "idempotency_key": "idempotency-key-72", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.git_push_authorize was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.identity_refresh", R"json({"principal_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "challenge_nonce": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "idempotency_key": "idempotency-key-73", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.identity_refresh was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.research_execute", R"json({"input_capsule_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "recipe_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "runtime_binding_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "research_grant_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "local_capability_grant_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "idempotency_key": "idempotency-key-74", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.research_execute was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
    {
        std::string response, err;
        const bool ok = modelnet::DispatchLab035("lab.trust_reconcile", R"json({"anchor_record_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "identity_state_ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], "owner_approval_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "idempotency_key": "idempotency-key-75", "expected_state": null})json", response, err);
        BOOST_CHECK_MESSAGE(err != "BTX035_NOT_IMPLEMENTED", "lab.trust_reconcile was not implemented");
        if (ok) {
            UniValue parsed;
            BOOST_CHECK(parsed.read(response));
            BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
        }
    }
}

BOOST_AUTO_TEST_CASE(auto_pay_is_rejected)
{
    std::string response, err;
    BOOST_CHECK(!modelnet::DispatchLab035("lab.info", "{\"auto_pay\":true}", response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(response.empty());
}

BOOST_AUTO_TEST_CASE(idempotent_replay_returns_the_same_result)
{
    modelnet::ResetLabApi();
    const char* request = R"json({"label":"lab","recovery_key_ids":[],"recovery_threshold":1,"recovery_delay_ms":"1","idempotency_key":"idempotency-replay","expected_state":null})json";
    std::string first, second, err;
    BOOST_REQUIRE(modelnet::DispatchLab035("lab.identity_create", request, first, err));
    BOOST_REQUIRE(modelnet::DispatchLab035("lab.identity_create", request, second, err));
    BOOST_CHECK_EQUAL(first, second);
    BOOST_CHECK(!modelnet::DispatchLab035("lab.identity_create", R"json({"label":"other","recovery_key_ids":[],"recovery_threshold":1,"recovery_delay_ms":"1","idempotency_key":"idempotency-replay","expected_state":null})json", second, err));
    BOOST_CHECK_EQUAL(err, "BTX035_IDEMPOTENCY");
}

BOOST_AUTO_TEST_CASE(unknown_parameter_is_rejected)
{
    std::string response, err;
    BOOST_CHECK(!modelnet::DispatchLab035("lab.info", R"json({"extra":true})json", response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(response.empty());
}

BOOST_AUTO_TEST_CASE(unknown_lab_method_stays_unimplemented)
{
    std::string response = "x", err;
    BOOST_CHECK(!modelnet::DispatchLab035("lab.not_a_method", "{}", response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_IMPLEMENTED");
    BOOST_CHECK(response.empty());
}

BOOST_AUTO_TEST_CASE(economy_refs_cannot_spend)
{
    modelnet::ResetLabApi();
    std::string response, err;
    BOOST_REQUIRE(modelnet::DispatchLab035("lab.economy_refs", R"json({"subject_id":"subject-1"})json", response, err));
    UniValue parsed;
    BOOST_REQUIRE(parsed.read(response));
    BOOST_CHECK(!parsed["result"]["spend_authorized"].get_bool());
    BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
}

static UniValue LabResult(const char* method, const UniValue& request)
{
    std::string response, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchLab035(method, request.write(), response, err), std::string(method) + " " + err);
    UniValue parsed;
    BOOST_REQUIRE(parsed.read(response));
    BOOST_CHECK_EQUAL(parsed["automatic_spend_atoms"].get_str(), "0");
    return parsed["result"];
}

BOOST_AUTO_TEST_CASE(lab_methods_keep_state_and_reject_bad_transitions)
{
    modelnet::ResetLabApi();
    const std::string hex_a(96, 'a');
    const std::string hex_b(96, 'b');
    const std::string hex_c(96, 'c');

    UniValue created = LabResult("lab.identity_create", [] {
        UniValue req(UniValue::VOBJ);
        req.pushKV("label", "behavior");
        req.pushKV("recovery_key_ids", UniValue(UniValue::VARR));
        req.pushKV("recovery_threshold", 1);
        req.pushKV("recovery_delay_ms", "1");
        req.pushKV("idempotency_key", "idempotency-behavior");
        req.pushKV("expected_state", UniValue());
        return req;
    }());
    BOOST_CHECK_EQUAL(created["state"].get_str(), "ACTIVE");
    BOOST_CHECK_EQUAL(created["record_id"].get_str().size(), 96U);

    UniValue inspected(UniValue::VOBJ);
    inspected.pushKV("principal_id", created["record_id"].get_str());
    UniValue identity = LabResult("lab.identity_inspect", inspected);
    BOOST_CHECK_EQUAL(identity["state"].get_str(), "ACTIVE");
    BOOST_CHECK_EQUAL(identity["epoch"].get_str(), "0");
    BOOST_CHECK_EQUAL(identity["active_key_id"].get_str().size(), 96U);

    auto channel = [&](const char* sequence, const char* idem) {
        UniValue payload(UniValue::VOBJ);
        payload.pushKV("realm_id", hex_a);
        payload.pushKV("channel", "model");
        payload.pushKV("epoch", "0");
        payload.pushKV("sequence", sequence);
        payload.pushKV("previous_update_id", UniValue());
        payload.pushKV("promotion_id", UniValue());
        payload.pushKV("trust_attestation_ids", UniValue(UniValue::VARR));
        payload.pushKV("desired_closure_root", hex_b);
        payload.pushKV("policy_id", hex_c);
        payload.pushKV("valid_until_ms", "4102444800000");
        payload.pushKV("rollback_of", UniValue());
        payload.pushKV("conflict_resolution_id", UniValue());
        UniValue sign(UniValue::VOBJ);
        sign.pushKV("record_type", "ChannelUpdate");
        sign.pushKV("payload", payload);
        sign.pushKV("realm_id", hex_a);
        sign.pushKV("delegation_id", UniValue());
        sign.pushKV("expires_ms", "10");
        sign.pushKV("idempotency_key", idem);
        sign.pushKV("expected_state", UniValue());
        UniValue signed_result = LabResult("lab.identity_sign", sign);
        UniValue import_req(UniValue::VOBJ);
        import_req.pushKV("envelope", signed_result["envelope"]);
        import_req.pushKV("publish", true);
        import_req.pushKV("idempotency_key", std::string("import-") + idem);
        import_req.pushKV("expected_state", UniValue());
        UniValue imported = LabResult("lab.record_import", import_req);
        BOOST_CHECK_EQUAL(imported["state"].get_str(), "PUBLISHED");
        UniValue verify(UniValue::VOBJ);
        verify.pushKV("envelope", signed_result["envelope"]);
        UniValue verified = LabResult("lab.record_verify", verify);
        BOOST_CHECK(verified["valid"].get_bool());
        return signed_result["envelope"]["record_id"].get_str();
    };

    const std::string first = channel("0", "idempotency-sign-0");
    UniValue publish(UniValue::VOBJ);
    publish.pushKV("update_id", first);
    publish.pushKV("approval_set_id", UniValue());
    publish.pushKV("idempotency_key", "idempotency-chan-0");
    publish.pushKV("expected_state", UniValue());
    BOOST_CHECK_EQUAL(LabResult("lab.channel_publish", publish)["state"].get_str(), "PUBLISHED");
    UniValue get(UniValue::VOBJ);
    get.pushKV("realm_id", hex_a);
    get.pushKV("channel", "model");
    UniValue current = LabResult("lab.channel_get", get);
    BOOST_CHECK_EQUAL(current["state"].get_str(), "CURRENT");
    BOOST_CHECK_EQUAL(current["sequence"].get_str(), "0");
    BOOST_CHECK_EQUAL(current["update_id"].get_str(), first);

    const std::string replayed = channel("0", "idempotency-sign-replay");
    publish.pushKV("update_id", replayed);
    publish.pushKV("idempotency_key", "idempotency-chan-replay");
    std::string response, err;
    BOOST_CHECK(!modelnet::DispatchLab035("lab.channel_publish", publish.write(), response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_STALE");

    const std::string second = channel("1", "idempotency-sign-1");
    publish.pushKV("update_id", second);
    publish.pushKV("idempotency_key", "idempotency-chan-1");
    BOOST_CHECK_EQUAL(LabResult("lab.channel_publish", publish)["state"].get_str(), "PUBLISHED");
    current = LabResult("lab.channel_get", get);
    BOOST_CHECK_EQUAL(current["sequence"].get_str(), "1");
    BOOST_CHECK_EQUAL(current["update_id"].get_str(), second);

    UniValue prepare(UniValue::VOBJ);
    prepare.pushKV("intent_id", hex_a);
    prepare.pushKV("idempotency_key", "idempotency-prepare");
    prepare.pushKV("expected_state", UniValue());
    const UniValue prepared = LabResult("lab.action_prepare", prepare);
    const std::string permit = prepared["one_use_permit"].get_str();
    BOOST_CHECK_NE(permit, prepared["record_id"].get_str());
    BOOST_CHECK_EQUAL(prepared["record_id"].get_str(), prepared["permit_commitment"].get_str());
    UniValue execute(UniValue::VOBJ);
    execute.pushKV("decision_id", hex_b);
    execute.pushKV("one_use_permit", permit);
    execute.pushKV("idempotency_key", "idempotency-execute");
    execute.pushKV("expected_state", UniValue());
    BOOST_CHECK_EQUAL(LabResult("lab.action_execute", execute)["state"].get_str(), "EXECUTED");
    execute.pushKV("idempotency_key", "idempotency-execute-2");
    BOOST_CHECK(!modelnet::DispatchLab035("lab.action_execute", execute.write(), response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REPLAY");

    UniValue bind(UniValue::VOBJ);
    bind.pushKV("release_id", hex_b);
    bind.pushKV("environment_ref", UniValue(UniValue::VOBJ));
    bind.pushKV("requested_grants", UniValue(UniValue::VARR));
    bind.pushKV("assurance", "LOCAL");
    bind.pushKV("idempotency_key", "idempotency-bind");
    bind.pushKV("expected_state", UniValue());
    const std::string binding = LabResult("lab.runtime_bind", bind)["record_id"].get_str();
    prepare.pushKV("intent_id", hex_b);
    prepare.pushKV("idempotency_key", "idempotency-prepare-2");
    const UniValue prepared2 = LabResult("lab.action_prepare", prepare);
    const std::string permit2 = prepared2["one_use_permit"].get_str();
    BOOST_CHECK_NE(permit2, prepared2["record_id"].get_str());
    UniValue pause(UniValue::VOBJ);
    pause.pushKV("runtime_binding_id", binding);
    pause.pushKV("reason", "operator");
    pause.pushKV("idempotency_key", "idempotency-pause");
    pause.pushKV("expected_state", UniValue());
    BOOST_CHECK_EQUAL(LabResult("lab.runtime_pause", pause)["state"].get_str(), "PAUSED");
    execute.pushKV("one_use_permit", permit2);
    execute.pushKV("idempotency_key", "idempotency-paused");
    BOOST_CHECK(!modelnet::DispatchLab035("lab.action_execute", execute.write(), response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PAUSED");
    UniValue resume(UniValue::VOBJ);
    resume.pushKV("runtime_binding_id", binding);
    resume.pushKV("new_grant_id", hex_b);
    resume.pushKV("idempotency_key", "idempotency-resume");
    resume.pushKV("expected_state", UniValue());
    BOOST_CHECK_EQUAL(LabResult("lab.runtime_resume", resume)["state"].get_str(), "RESUMED");
    execute.pushKV("idempotency_key", "idempotency-after-resume");
    BOOST_CHECK_EQUAL(LabResult("lab.action_execute", execute)["state"].get_str(), "EXECUTED");

    UniValue ws(UniValue::VOBJ);
    ws.pushKV("snapshot_id", hex_a);
    ws.pushKV("backend", "OPERATION_JOURNAL");
    ws.pushKV("adapter_id", UniValue());
    ws.pushKV("storage_limit", "1");
    ws.pushKV("idempotency_key", "idempotency-workspace");
    ws.pushKV("expected_state", UniValue());
    const std::string workspace = LabResult("lab.workspace_create", ws)["workspace_id"].get_str();
    UniValue op(UniValue::VOBJ);
    op.pushKV("workspace_id", workspace);
    op.pushKV("event", UniValue(UniValue::VOBJ));
    op.pushKV("idempotency_key", "idempotency-ws-1");
    op.pushKV("expected_state", UniValue());
    BOOST_CHECK_EQUAL(LabResult("lab.workspace_operation", op)["sequence"].get_str(), "1");
    op.pushKV("idempotency_key", "idempotency-ws-2");
    BOOST_CHECK_EQUAL(LabResult("lab.workspace_operation", op)["sequence"].get_str(), "2");

    UniValue admit(UniValue::VOBJ);
    admit.pushKV("model_ref", UniValue(UniValue::VOBJ));
    admit.pushKV("policy_id", hex_c);
    UniValue evidence(UniValue::VARR);
    evidence.push_back(hex_a);
    admit.pushKV("evidence_ids", evidence);
    admit.pushKV("idempotency_key", "idempotency-admit");
    admit.pushKV("expected_state", UniValue());
    const std::string admission = LabResult("lab.admission_evaluate", admit)["operation_id"].get_str();
    BOOST_CHECK_EQUAL(LabResult("lab.admission_evaluate", admit)["state"].get_str(), "FAILED");
    UniValue host(UniValue::VOBJ);
    host.pushKV("model_ref", UniValue(UniValue::VOBJ));
    host.pushKV("admission_id", admission);
    host.pushKV("storage_limit_bytes", "1");
    host.pushKV("idempotency_key", "idempotency-host");
    host.pushKV("expected_state", UniValue());
    BOOST_CHECK(!modelnet::DispatchLab035("lab.model_host", host.write(), response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ADMISSION");
    UniValue follow(UniValue::VOBJ);
    follow.pushKV("operation_id", admission);
    UniValue followed = LabResult("lab.operation_get", follow);
    BOOST_CHECK_EQUAL(followed["state"].get_str(), "FAILED");
    BOOST_CHECK_EQUAL(followed["physical_disposition"].get_str(), "STOPPED_QUIESCENT");

    UniValue repo(UniValue::VOBJ);
    repo.pushKV("label", "lab");
    repo.pushKV("nonce", "1");
    repo.pushKV("object_format", "git");
    repo.pushKV("project_genesis_id", UniValue());
    repo.pushKV("default_ref", "refs/heads/main");
    repo.pushKV("idempotency_key", "idempotency-repo");
    repo.pushKV("expected_state", UniValue());
    const std::string repository = LabResult("lab.repository_create", repo)["repository_id"].get_str();
    UniValue reg(UniValue::VOBJ);
    reg.pushKV("repository_id", repository);
    reg.pushKV("origins", UniValue(UniValue::VARR));
    reg.pushKV("required_commit", UniValue(UniValue::VOBJ));
    reg.pushKV("workspace_allowed", false);
    reg.pushKV("idempotency_key", "idempotency-register");
    reg.pushKV("expected_state", UniValue());
    reg.pushKV("repository_genesis_id", hex_a);
    BOOST_CHECK_EQUAL(LabResult("lab.git_register", reg)["state"].get_str(), "COMPLETE");
    UniValue ticket(UniValue::VOBJ);
    ticket.pushKV("repository_id", repository);
    ticket.pushKV("operation", "fetch");
    ticket.pushKV("ref_update_id", UniValue());
    ticket.pushKV("max_bytes", "1");
    ticket.pushKV("idempotency_key", "idempotency-ticket");
    ticket.pushKV("expected_state", UniValue());
    BOOST_CHECK_EQUAL(LabResult("lab.git_fetch_ticket", ticket)["ticket"].get_str().size(), 64U);

    UniValue roll(UniValue::VOBJ);
    roll.pushKV("plan_id", hex_c);
    roll.pushKV("approval_set_id", UniValue());
    roll.pushKV("idempotency_key", "idempotency-roll");
    roll.pushKV("expected_state", UniValue());
    BOOST_CHECK_EQUAL(LabResult("lab.rollout_start", roll)["state"].get_str(), "COMPLETE");
    UniValue status(UniValue::VOBJ);
    status.pushKV("plan_id", hex_c);
    BOOST_CHECK_EQUAL(LabResult("lab.rollout_status", status)["state"].get_str(), "PLANNED");
    UniValue roll_pause(UniValue::VOBJ);
    roll_pause.pushKV("plan_id", hex_c);
    roll_pause.pushKV("reason", "operator");
    roll_pause.pushKV("idempotency_key", "idempotency-roll-pause");
    roll_pause.pushKV("expected_state", UniValue());
    UniValue paused = LabResult("lab.rollout_pause", roll_pause);
    BOOST_CHECK(paused["paused"].get_bool());
    BOOST_CHECK_EQUAL(paused["endpoint_query_method"].get_str(), "lab.rollout_endpoints");
    BOOST_CHECK_EQUAL(LabResult("lab.rollout_status", status)["state"].get_str(), "PAUSED");
}

BOOST_AUTO_TEST_CASE(git_publish_ref_rejects_stale_old_target)
{
    modelnet::ResetLabApi();
    const std::string realm(96, 'a');
    const std::string stale_target(96, 'd');

    UniValue identity(UniValue::VOBJ);
    identity.pushKV("label", "ref");
    identity.pushKV("recovery_key_ids", UniValue(UniValue::VARR));
    identity.pushKV("recovery_threshold", 1);
    identity.pushKV("recovery_delay_ms", "1");
    identity.pushKV("idempotency_key", "idempotency-stale-id");
    identity.pushKV("expected_state", UniValue());
    BOOST_CHECK_EQUAL(LabResult("lab.identity_create", identity)["state"].get_str(), "ACTIVE");

    UniValue repo(UniValue::VOBJ);
    repo.pushKV("label", "refs");
    repo.pushKV("nonce", "stale-nonce");
    repo.pushKV("object_format", "git");
    repo.pushKV("project_genesis_id", UniValue());
    repo.pushKV("default_ref", "refs/heads/main");
    repo.pushKV("idempotency_key", "idempotency-stale-repo");
    repo.pushKV("expected_state", UniValue());
    const UniValue created = LabResult("lab.repository_create", repo);
    const std::string repository = created["repository_id"].get_str();
    const std::string genesis = created["repository_genesis_id"].get_str();
    BOOST_CHECK_NE(stale_target, genesis);

    auto SignAndStore = [&](const UniValue& payload, const char* idem) {
        UniValue sign(UniValue::VOBJ);
        sign.pushKV("record_type", "GitRefUpdate");
        sign.pushKV("payload", payload);
        sign.pushKV("realm_id", realm);
        sign.pushKV("delegation_id", UniValue());
        sign.pushKV("expires_ms", "10");
        sign.pushKV("idempotency_key", idem);
        sign.pushKV("expected_state", UniValue());
        const UniValue signed_result = LabResult("lab.identity_sign", sign);
        UniValue import_req(UniValue::VOBJ);
        import_req.pushKV("envelope", signed_result["envelope"]);
        import_req.pushKV("publish", false);
        import_req.pushKV("idempotency_key", std::string("import-") + idem);
        import_req.pushKV("expected_state", UniValue());
        const UniValue imported = LabResult("lab.record_import", import_req);
        BOOST_CHECK_EQUAL(imported["state"].get_str(), "STORED");
        return signed_result["envelope"]["record_id"].get_str();
    };

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("repository_id", repository);
    payload.pushKV("ref_name", "refs/heads/main");
    payload.pushKV("old_target", stale_target);
    payload.pushKV("new_target", std::string(96, 'e'));
    payload.pushKV("snapshot_id", UniValue());
    payload.pushKV("sequence", "0");
    payload.pushKV("previous_update_id", UniValue());
    payload.pushKV("policy_id", UniValue());
    payload.pushKV("force", false);
    const std::string update_id = SignAndStore(payload, "idempotency-stale-sign");

    UniValue publish(UniValue::VOBJ);
    publish.pushKV("update_id", update_id);
    publish.pushKV("approval_set_id", UniValue());
    publish.pushKV("idempotency_key", "idempotency-stale-pub");
    publish.pushKV("expected_state", UniValue());
    std::string response, err;
    BOOST_CHECK(!modelnet::DispatchLab035("lab.git_publish_ref", publish.write(), response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_STALE");
    BOOST_CHECK(response.empty());

    UniValue refs(UniValue::VOBJ);
    refs.pushKV("repository_id", repository);
    refs.pushKV("namespace", "refs/heads");
    refs.pushKV("after_cursor", UniValue());
    const UniValue listed = LabResult("lab.git_refs", refs);
    BOOST_REQUIRE_EQUAL(listed["record_ids"].size(), 1U);
    BOOST_CHECK_EQUAL(listed["record_ids"][0].get_str(), genesis);
}

BOOST_AUTO_TEST_CASE(concurrent_calls_keep_the_store_consistent)
{
    // Mutating lab methods share one process-global store. Parallel callers
    // must all succeed once that store is serialized.
    modelnet::ResetLabApi();
    constexpr int THREADS{8};
    constexpr int CALLS{40};
    std::atomic<int> failure_count{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([t, &failure_count] {
            for (int k = 0; k < CALLS; ++k) {
                const std::string id{std::to_string(t) + "-" + std::to_string(k)};
                UniValue req(UniValue::VOBJ);
                req.pushKV("name", "realm-" + id);
                req.pushKV("nonce", std::to_string(k));
                req.pushKV("policy_template", "default");
                req.pushKV("idempotency_key", "concurrent-realm-" + id);
                req.pushKV("expected_state", UniValue());
                std::string response, err;
                if (!modelnet::DispatchLab035("lab.realm_create", req.write(), response, err)) ++failure_count;
            }
        });
    }
    for (auto& thread : threads) thread.join();
    const int failures = failure_count.load();
    BOOST_CHECK_EQUAL(failures, 0);
    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_SUITE_END()
