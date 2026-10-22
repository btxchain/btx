// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/git_snapshot.h>
#include <modelnet/lab_api.h>
#include <modelnet/lab_exchange.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/random.h>
#include <univalue.h>
#include <util/check.h>
#include <util/time.h>

#include <cstdint>
#include <cstdlib>
#include <exception>
#include <string>
#include <vector>

namespace {

const std::vector<std::string> GIT_KINDS{
    "blob", "tree", "commit", "tag", "research", "train", "lineage", "model", "piece", "replay",
};

// Every lab.* method except the three that dial a loopback port or write
// under the working directory (snapshot_pull, bundle_export, bundle_import).
const std::vector<std::string> LAB_METHODS{
    "lab.info", "lab.record_get", "lab.record_import", "lab.record_verify", "lab.identity_inspect",
    "lab.identity_create", "lab.identity_sign", "lab.identity_transition", "lab.identity_revoke",
    "lab.grant_evaluate", "lab.git_register", "lab.git_snapshot", "lab.git_attest", "lab.git_publish_ref",
    "lab.git_refs", "lab.git_fetch_ticket", "lab.workspace_create", "lab.workspace_snapshot",
    "lab.workspace_restore", "lab.workspace_operation", "lab.workspace_reconcile", "lab.workspace_hydrate",
    "lab.source_query", "lab.research_query", "lab.research_context", "lab.research_frontier",
    "lab.research_subscribe", "lab.research_unsubscribe", "lab.research_publish", "lab.research_events",
    "lab.capsule_resolve", "lab.artifact_acquire", "lab.operation_get", "lab.operation_cancel",
    "lab.audit_coverage", "lab.admission_evaluate", "lab.model_host", "lab.model_unhost", "lab.agent_lineage",
    "lab.agent_adopt", "lab.runtime_bind", "lab.action_prepare", "lab.action_execute", "lab.runtime_pause",
    "lab.runtime_resume", "lab.journal_checkpoint", "lab.journal_proof", "lab.journal_witness",
    "lab.incident_publish", "lab.realm_create", "lab.realm_policy_apply", "lab.realm_status",
    "lab.promotion_prepare", "lab.promotion_attest", "lab.promotion_verify", "lab.channel_publish",
    "lab.channel_get", "lab.rollout_start", "lab.rollout_status", "lab.rollout_pause", "lab.rollout_rollback",
    "lab.deployment_observe", "lab.migration_plan", "lab.migration_apply", "lab.migration_verify",
    "lab.economy_refs", "lab.state_get", "lab.rollout_endpoints", "lab.repository_create",
    "lab.git_push_authorize", "lab.identity_refresh", "lab.research_execute", "lab.trust_reconcile",
    "lab.snapshot_export", "lab.snapshot_import",
};

const std::vector<std::string> PEER_ROUTES{
    "hello", "auth", "records/get", "records/announce", "research/query", "subscriptions/poll",
    "git/tunnel", "artifacts/manifest", "artifacts/piece", "trust/state", "channels/get",
};

void initialize_modelnet_lab()
{
    // Keep the lab in process memory: no loopback peers, no guard daemon,
    // no lab or bundle directory.
    for (const char* name : {"BTX035_LAB_PEER", "BTX035_LAB_PEERS", "BTX_GUARD_PORT", "BTX035_LAB_DIR", "BTX035_BUNDLE_DIR"}) {
        unsetenv(name);
    }
}

void ResetLab()
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    SetMockTime(1700000000);
    modelnet::ResetLabApi();
}

/** lab035 RPC: the RPC server turns a thrown std::exception into an error reply. */
void LabCall(const std::string& method, const std::string& request)
{
    std::string response;
    std::string err;
    try {
        if (modelnet::DispatchLabApi(method, request, response, err)) {
            UniValue parsed;
            Assert(parsed.read(response));
        } else {
            Assert(response.empty());
            Assert(!err.empty());
        }
    } catch (const std::exception&) {
    }
}

/** `/btx-model/3/`: no RPC credentials and no catch around the handler. */
void PeerCall(const std::string& route, const std::string& request)
{
    std::string response;
    std::string err;
    if (modelnet::ServeLabPeer(route, request, response, err)) {
        Assert(err.empty());
        UniValue parsed;
        Assert(parsed.read(response));
    } else {
        Assert(response.empty());
    }
}

void FuzzedCalls(FuzzedDataProvider& fdp, unsigned max_calls)
{
    LIMITED_WHILE(fdp.remaining_bytes() > 0, max_calls)
    {
        if (fdp.ConsumeBool()) {
            const std::string& method = LAB_METHODS[fdp.ConsumeIntegralInRange<size_t>(0, LAB_METHODS.size() - 1)];
            LabCall(method, fdp.ConsumeRandomLengthString(4096));
        } else {
            const std::string& route = PEER_ROUTES[fdp.ConsumeIntegralInRange<size_t>(0, PEER_ROUTES.size() - 1)];
            PeerCall(route, fdp.ConsumeRandomLengthString(4096));
        }
    }
}

} // namespace

// Exchange manifest reader with its object-count and object-size caps.
FUZZ_TARGET(modelnet_exchange_manifest)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const size_t max_objects = fdp.ConsumeIntegralInRange<size_t>(1, modelnet::MAX_EXCHANGE_OBJECTS);
    const size_t max_bytes = fdp.ConsumeIntegralInRange<size_t>(0, modelnet::MAX_EXCHANGE_OBJECT_BYTES);
    const std::string manifest = fdp.ConsumeRemainingBytesAsString();

    std::vector<modelnet::ExchangeObject> objects;
    std::string err;
    if (!modelnet::VerifyExchangeManifest(manifest, objects, err, max_objects, max_bytes)) {
        Assert(!err.empty());
        return;
    }
    Assert(err.empty());
    Assert(!objects.empty() && objects.size() <= max_objects);
    for (const modelnet::ExchangeObject& object : objects) Assert(object.content.size() <= max_bytes);

    std::string rewritten;
    Assert(modelnet::WriteExchangeManifest(objects, rewritten, err));
    std::vector<modelnet::ExchangeObject> again;
    Assert(modelnet::VerifyExchangeManifest(rewritten, again, err, max_objects, max_bytes));
    Assert(again.size() == objects.size());
    for (size_t i = 0; i < again.size(); ++i) {
        Assert(again[i].kind == objects[i].kind);
        Assert(again[i].digest == objects[i].digest);
        Assert(again[i].content == objects[i].content);
    }
}

// lab.snapshot_import with a manifest whose digests are correct, so the
// research, train (replay), lineage, model and piece readers behind the
// digest check see the fuzzed object contents. Then serve the result.
FUZZ_TARGET(modelnet_lab_snapshot_import, .init = initialize_modelnet_lab)
{
    ResetLab();
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    std::vector<modelnet::ExchangeObject> objects;
    LIMITED_WHILE(fdp.remaining_bytes() > 0 && fdp.ConsumeBool(), 32)
    {
        modelnet::ExchangeObject object;
        object.kind = GIT_KINDS[fdp.ConsumeIntegralInRange<size_t>(0, GIT_KINDS.size() - 1)];
        object.content = fdp.ConsumeRandomLengthString(1 << 14);
        const std::vector<unsigned char> raw(object.content.begin(), object.content.end());
        std::string err;
        Assert(modelnet::GitObjectDigest(object.kind, raw, object.digest, err));
        objects.push_back(std::move(object));
    }
    if (objects.empty()) return;
    std::string manifest;
    std::string err;
    Assert(modelnet::WriteExchangeManifest(objects, manifest, err));

    UniValue request(UniValue::VOBJ);
    request.pushKV("manifest", manifest);
    request.pushKV("idempotency_key", "fuzz-snapshot-import-0001");
    request.pushKV("expected_state", UniValue{});
    LabCall("lab.snapshot_import", request.write());
    FuzzedCalls(fdp, 8);
}

// Any sequence of lab.* calls and peer routes against one in-memory lab.
FUZZ_TARGET(modelnet_lab_api, .init = initialize_modelnet_lab)
{
    ResetLab();
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    FuzzedCalls(fdp, 16);
}
