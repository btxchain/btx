// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/git_snapshot.h>
#include <modelnet/guard_machine.h>
#include <modelnet/lab_api.h>
#include <modelnet/lab_exchange.h>
#include <modelnet/research_rpc.h>
#include <modelnet/training_integer.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_disk_tests, BasicTestingSetup)

namespace {

struct TempTree {
    explicit TempTree(fs::path path_in) : path(std::move(path_in))
    {
        std::error_code ec;
        fs::remove_all(path, ec);
        fs::create_directories(path);
    }
    ~TempTree()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    fs::path path;
};

struct LabDirEnv {
    explicit LabDirEnv(const fs::path& dir) { Point(dir); }
    void Point(const fs::path& dir)
    {
        const std::string text = PathToString(dir);
        ::setenv("BTX035_LAB_DIR", text.c_str(), 1);
    }
    ~LabDirEnv() { ::unsetenv("BTX035_LAB_DIR"); }
};

bool LabCall(const char* method, const UniValue& request, UniValue& result, std::string& err)
{
    std::string response;
    if (!modelnet::DispatchLab035(method, request.write(), response, err)) return false;
    UniValue envelope;
    if (!envelope.read(response) || !envelope.isObject() || !envelope.exists("automatic_spend_atoms") ||
        !envelope["automatic_spend_atoms"].isStr() || envelope["automatic_spend_atoms"].get_str() != "0" ||
        !envelope.exists("result") || !envelope["result"].isObject()) {
        err = "BTX035_SCHEMA";
        return false;
    }
    result = envelope["result"];
    err.clear();
    return true;
}

UniValue ContributionPayload(const char* kind, const UniValue& physical, const UniValue& informed)
{
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("objective_id", std::string(96, 'b'));
    payload.pushKV("kind", kind);
    payload.pushKV("source_snapshot_id", std::string(96, 'c'));
    payload.pushKV("physical_parent_ids", physical);
    payload.pushKV("informed_by", informed);
    payload.pushKV("capsule_id", UniValue());
    payload.pushKV("claim_refs", UniValue(UniValue::VARR));
    payload.pushKV("evidence_refs", UniValue(UniValue::VARR));
    payload.pushKV("summary", "local");
    return payload;
}

std::string SignAndStore(const char* record_type, const UniValue& payload, const char* idem)
{
    UniValue sign(UniValue::VOBJ);
    sign.pushKV("record_type", record_type);
    sign.pushKV("payload", payload);
    sign.pushKV("realm_id", std::string(96, 'a'));
    sign.pushKV("delegation_id", UniValue());
    sign.pushKV("expires_ms", "10");
    sign.pushKV("idempotency_key", idem);
    sign.pushKV("expected_state", UniValue());
    UniValue signed_result;
    std::string err;
    BOOST_REQUIRE(LabCall("lab.identity_sign", sign, signed_result, err));
    BOOST_REQUIRE(signed_result["envelope"].isObject());
    const std::string record_id = signed_result["envelope"]["record_id"].get_str();
    BOOST_REQUIRE_EQUAL(record_id.size(), 96U);
    UniValue import_req(UniValue::VOBJ);
    import_req.pushKV("envelope", signed_result["envelope"]);
    import_req.pushKV("publish", false);
    import_req.pushKV("idempotency_key", std::string("import-") + idem);
    import_req.pushKV("expected_state", UniValue());
    UniValue imported;
    BOOST_REQUIRE(LabCall("lab.record_import", import_req, imported, err));
    BOOST_CHECK_EQUAL(imported["record_id"].get_str(), record_id);
    BOOST_CHECK_EQUAL(imported["state"].get_str(), "STORED");
    return record_id;
}

void PublishStored(const std::string& record_id, const char* idem)
{
    UniValue topics(UniValue::VARR);
    topics.push_back(std::string(96, 'b'));
    UniValue req(UniValue::VOBJ);
    req.pushKV("record_id", record_id);
    req.pushKV("topic_ids", topics);
    req.pushKV("visibility", "PUBLIC");
    req.pushKV("idempotency_key", idem);
    req.pushKV("expected_state", UniValue());
    UniValue published;
    std::string err;
    BOOST_REQUIRE(LabCall("lab.research_publish", req, published, err));
    BOOST_CHECK_EQUAL(published["state"].get_str(), "PUBLISHED");
    BOOST_CHECK_EQUAL(published["record_id"].get_str(), record_id);
}

void ExpectLinkedContext(const std::string& later, const std::string& earlier, const std::string& announcement, const std::string& unknown)
{
    UniValue roots(UniValue::VARR);
    roots.push_back(later);
    UniValue req(UniValue::VOBJ);
    req.pushKV("root_ids", roots);
    req.pushKV("relations", UniValue(UniValue::VARR));
    req.pushKV("max_depth", 8);
    req.pushKV("max_records", 16);
    UniValue result;
    std::string err;
    BOOST_REQUIRE(LabCall("lab.research_context", req, result, err));
    const UniValue& ids = result["record_ids"];
    BOOST_REQUIRE_EQUAL(ids.size(), 2U);
    BOOST_CHECK_EQUAL(ids[0].get_str(), later);
    BOOST_CHECK_EQUAL(ids[1].get_str(), earlier);
    for (size_t i = 0; i < ids.size(); ++i) {
        BOOST_CHECK(ids[i].get_str() != announcement);
        BOOST_CHECK(ids[i].get_str() != unknown);
    }
    const UniValue& coverage = result["coverage"];
    BOOST_REQUIRE(coverage.exists("selection_is_proof"));
    BOOST_CHECK(coverage["selection_is_proof"].isFalse());
    BOOST_CHECK_EQUAL(coverage["physical_edges"].get_str(), "1");
    BOOST_CHECK_EQUAL(coverage["informed_edges"].get_str(), "0");
}

} // namespace

BOOST_AUTO_TEST_CASE(guard_line_is_one_use_and_refuses_spend)
{
    using namespace modelnet;
    GuardTable table;
    const std::string fingerprint(96, 'a');
    const std::string prepared = GuardHandleLine(table, "PREPARE research.run " + fingerprint + " 1", 1000);
    std::istringstream in(prepared);
    std::string verb;
    std::string secret;
    std::string commitment;
    int64_t not_after = 0;
    in >> verb >> secret >> commitment >> not_after;
    BOOST_CHECK_EQUAL(verb, "PERMIT");
    BOOST_CHECK_EQUAL(commitment, GuardCommitment(secret));
    BOOST_CHECK_EQUAL(not_after, int64_t{1000} + GuardTable::kPermitTtlMs);

    const std::string executed = GuardHandleLine(table, "EXECUTE " + secret, 1000);
    BOOST_CHECK(executed.rfind("RECEIPT ", 0) == 0);
    BOOST_CHECK(executed.size() > std::string("RECEIPT ").size());
    BOOST_CHECK_EQUAL(executed.substr(executed.size() - std::string(" PERMIT_CONSUMED NOT_DISPATCHED").size()), " PERMIT_CONSUMED NOT_DISPATCHED");

    BOOST_CHECK_EQUAL(GuardHandleLine(table, "EXECUTE " + secret, 1000), "ERR BTX035_REPLAY");
    BOOST_CHECK_EQUAL(GuardHandleLine(table, "PREPARE spend " + std::string(96, 'b') + " 1", 1000), "ERR BTX035_SCOPE_DENIED");
    BOOST_CHECK_EQUAL(GuardHandleLine(table, "PAUSE", 1000), "OK");
    BOOST_CHECK(table.Paused());
    BOOST_CHECK_EQUAL(GuardHandleLine(table, "RESUME", 1000), "OK");
    BOOST_CHECK(!table.Paused());
}

BOOST_AUTO_TEST_CASE(lab_directory_reloads_a_realm_and_a_second_directory_does_not)
{
    BOOST_REQUIRE(!m_path_root.empty());
    ::unsetenv("BTX035_LAB_DIR");
    modelnet::ResetLabApi();

    TempTree first{m_path_root / "btx035-lab-disk" / "a"};
    TempTree second{m_path_root / "btx035-lab-disk" / "b"};
    LabDirEnv env(first.path);
    modelnet::ResetLabApi();

    UniValue create(UniValue::VOBJ);
    create.pushKV("name", "durable");
    create.pushKV("nonce", "nonce-durable-1");
    create.pushKV("policy_template", "local");
    create.pushKV("idempotency_key", "idempotency-disk-realm");
    create.pushKV("expected_state", UniValue());
    UniValue created;
    std::string err;
    BOOST_REQUIRE(LabCall("lab.realm_create", create, created, err));
    const std::string realm = created["realm_id"].get_str();
    const std::string policy = created["policy_id"].get_str();
    BOOST_REQUIRE_EQUAL(realm.size(), 96U);

    UniValue identity(UniValue::VOBJ);
    identity.pushKV("label", "disk");
    identity.pushKV("recovery_key_ids", UniValue(UniValue::VARR));
    identity.pushKV("recovery_threshold", 1);
    identity.pushKV("recovery_delay_ms", "1");
    identity.pushKV("idempotency_key", "idempotency-disk-id");
    identity.pushKV("expected_state", UniValue());
    UniValue identified;
    BOOST_REQUIRE(LabCall("lab.identity_create", identity, identified, err));

    std::ifstream input(PathToString(first.path / "lab.json"));
    std::stringstream buffer;
    buffer << input.rdbuf();
    const std::string body = buffer.str();
    UniValue disk;
    BOOST_REQUIRE(disk.read(body));
    BOOST_CHECK(!disk.exists("identity_sk"));
    BOOST_CHECK(body.find("identity_sk") == std::string::npos);
    BOOST_REQUIRE(disk["automatic_spend_atoms"].isStr());
    BOOST_CHECK_EQUAL(disk["automatic_spend_atoms"].get_str(), "0");
    BOOST_CHECK(disk["realms"].exists(realm));
    BOOST_REQUIRE(disk["identity_pk"].isObject());
    BOOST_CHECK(!disk["identity_pk"].getKeys().empty());

    modelnet::ReloadLabFromDisk();
    UniValue status_req(UniValue::VOBJ);
    status_req.pushKV("realm_id", realm);
    UniValue status;
    BOOST_REQUIRE(LabCall("lab.realm_status", status_req, status, err));
    BOOST_CHECK_EQUAL(status["policy_id"].get_str(), policy);

    env.Point(second.path);
    modelnet::ReloadLabFromDisk();
    std::string missing;
    BOOST_CHECK(!modelnet::DispatchLab035("lab.realm_status", status_req.write(), missing, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");
    BOOST_CHECK(fs::exists(first.path / "lab.json"));
    BOOST_CHECK(!fs::exists(second.path / "lab.json"));

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(snapshot_carries_a_public_negative_row_and_drops_a_private_row)
{
    ::unsetenv("BTX035_LAB_DIR");
    modelnet::ResetLabApi();
    std::string err;
    UniValue identity(UniValue::VOBJ);
    identity.pushKV("label", "research");
    identity.pushKV("recovery_key_ids", UniValue(UniValue::VARR));
    identity.pushKV("recovery_threshold", 1);
    identity.pushKV("recovery_delay_ms", "1");
    identity.pushKV("idempotency_key", "idempotency-disk-research-id");
    identity.pushKV("expected_state", UniValue());
    UniValue identified;
    BOOST_REQUIRE(LabCall("lab.identity_create", identity, identified, err));

    const std::string negative_id(96, 'a');
    const std::string private_id(96, 'c');
    const std::string topic(96, 'b');
    UniValue topics(UniValue::VARR);
    topics.push_back(topic);

    UniValue negative(UniValue::VOBJ);
    negative.pushKV("record_id", negative_id);
    negative.pushKV("topic_ids", topics);
    negative.pushKV("visibility", "NEGATIVE");
    negative.pushKV("idempotency_key", "idempotency-disk-negative");
    negative.pushKV("expected_state", UniValue());
    UniValue published;
    BOOST_REQUIRE(LabCall("lab.research_publish", negative, published, err));

    UniValue hidden(UniValue::VOBJ);
    hidden.pushKV("record_id", private_id);
    hidden.pushKV("topic_ids", topics);
    hidden.pushKV("visibility", "PRIVATE");
    hidden.pushKV("idempotency_key", "idempotency-disk-private");
    hidden.pushKV("expected_state", UniValue());
    BOOST_REQUIRE(LabCall("lab.research_publish", hidden, published, err));

    UniValue repo(UniValue::VOBJ);
    repo.pushKV("label", "source");
    repo.pushKV("nonce", "disk-nonce");
    repo.pushKV("object_format", "git");
    repo.pushKV("project_genesis_id", UniValue());
    repo.pushKV("default_ref", "refs/heads/main");
    repo.pushKV("idempotency_key", "idempotency-disk-repo");
    repo.pushKV("expected_state", UniValue());
    UniValue created;
    BOOST_REQUIRE(LabCall("lab.repository_create", repo, created, err));
    const std::string repository = created["repository_id"].get_str();

    UniValue commit(UniValue::VOBJ);
    commit.pushKV("tree", "independent source\n");
    UniValue snap(UniValue::VOBJ);
    snap.pushKV("repository_id", repository);
    snap.pushKV("commit", commit);
    snap.pushKV("dependency_lock_id", std::string(96, 'd'));
    snap.pushKV("history_required", false);
    snap.pushKV("idempotency_key", "idempotency-disk-snap");
    snap.pushKV("expected_state", UniValue());
    BOOST_REQUIRE(LabCall("lab.git_snapshot", snap, created, err));

    UniValue exp(UniValue::VOBJ);
    exp.pushKV("repository_id", repository);
    exp.pushKV("idempotency_key", "idempotency-disk-export");
    exp.pushKV("expected_state", UniValue());
    UniValue exported;
    BOOST_REQUIRE(LabCall("lab.snapshot_export", exp, exported, err));
    BOOST_CHECK_EQUAL(exported["object_count"].getInt<int>(), 2);
    const std::string manifest = exported["manifest"].get_str();
    BOOST_CHECK(manifest.find(private_id) == std::string::npos);

    std::vector<modelnet::ExchangeObject> objects;
    BOOST_REQUIRE(modelnet::VerifyExchangeManifest(manifest, objects, err));
    int research_rows = 0;
    std::string line;
    std::string digest;
    for (const modelnet::ExchangeObject& object : objects) {
        if (object.kind != "research") continue;
        ++research_rows;
        line = object.content;
        digest = object.digest;
    }
    BOOST_CHECK_EQUAL(research_rows, 1);
    BOOST_CHECK(line.find('\n') == std::string::npos);
    BOOST_CHECK(line.rfind("v1|", 0) == 0);
    BOOST_CHECK(line.find(negative_id) != std::string::npos);
    BOOST_CHECK(line.find(private_id) == std::string::npos);
    BOOST_CHECK_EQUAL(line.substr(line.size() - 8), "|1|1|0|0");
    const std::vector<unsigned char> bytes(line.begin(), line.end());
    std::string expect;
    BOOST_REQUIRE(modelnet::GitObjectDigest("research", Span<const unsigned char>{bytes.data(), bytes.size()}, expect, err));
    BOOST_CHECK_EQUAL(digest, expect);

    modelnet::ResetLabApi();
    UniValue import(UniValue::VOBJ);
    import.pushKV("manifest", manifest);
    import.pushKV("idempotency_key", "idempotency-disk-import");
    import.pushKV("expected_state", UniValue());
    UniValue imported;
    BOOST_REQUIRE(LabCall("lab.snapshot_import", import, imported, err));

    UniValue frontier_req(UniValue::VOBJ);
    frontier_req.pushKV("objective_id", std::string(96, 'e'));
    frontier_req.pushKV("view", "RECENT");
    frontier_req.pushKV("limit", 10);
    frontier_req.pushKV("cursor", UniValue());
    UniValue frontier;
    BOOST_REQUIRE(LabCall("lab.research_frontier", frontier_req, frontier, err));
    BOOST_REQUIRE_EQUAL(frontier["record_ids"].size(), 1U);
    BOOST_CHECK_EQUAL(frontier["record_ids"][0].get_str(), negative_id);

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(integer_train_survives_reload_and_snapshot)
{
    BOOST_REQUIRE(!m_path_root.empty());
    ::unsetenv("BTX035_LAB_DIR");
    ::unsetenv("BTX_GUARD_PORT");
    modelnet::ResetLabApi();

    TempTree dir{m_path_root / "btx035-lab-disk" / "train"};
    LabDirEnv env(dir.path);
    modelnet::ResetLabApi();

    std::string err;
    UniValue identity(UniValue::VOBJ);
    identity.pushKV("label", "train");
    identity.pushKV("recovery_key_ids", UniValue(UniValue::VARR));
    identity.pushKV("recovery_threshold", 1);
    identity.pushKV("recovery_delay_ms", "1");
    identity.pushKV("idempotency_key", "idempotency-disk-train-id");
    identity.pushKV("expected_state", UniValue());
    UniValue identified;
    BOOST_REQUIRE(LabCall("lab.identity_create", identity, identified, err));

    const std::string negative_id(96, 'a');
    const std::string private_id(96, 'c');
    const std::string topic(96, 'b');
    UniValue topics(UniValue::VARR);
    topics.push_back(topic);

    UniValue negative(UniValue::VOBJ);
    negative.pushKV("record_id", negative_id);
    negative.pushKV("topic_ids", topics);
    negative.pushKV("visibility", "NEGATIVE");
    negative.pushKV("idempotency_key", "idempotency-disk-train-neg");
    negative.pushKV("expected_state", UniValue());
    UniValue published;
    BOOST_REQUIRE(LabCall("lab.research_publish", negative, published, err));

    UniValue hidden(UniValue::VOBJ);
    hidden.pushKV("record_id", private_id);
    hidden.pushKV("topic_ids", topics);
    hidden.pushKV("visibility", "PRIVATE");
    hidden.pushKV("idempotency_key", "idempotency-disk-train-priv");
    hidden.pushKV("expected_state", UniValue());
    BOOST_REQUIRE(LabCall("lab.research_publish", hidden, published, err));

    UniValue repo(UniValue::VOBJ);
    repo.pushKV("label", "train-source");
    repo.pushKV("nonce", "train-nonce");
    repo.pushKV("object_format", "git");
    repo.pushKV("project_genesis_id", UniValue());
    repo.pushKV("default_ref", "refs/heads/main");
    repo.pushKV("idempotency_key", "idempotency-disk-train-repo");
    repo.pushKV("expected_state", UniValue());
    UniValue created;
    BOOST_REQUIRE(LabCall("lab.repository_create", repo, created, err));
    const std::string repository = created["repository_id"].get_str();

    UniValue commit(UniValue::VOBJ);
    commit.pushKV("tree", "integer source\n");
    UniValue snap(UniValue::VOBJ);
    snap.pushKV("repository_id", repository);
    snap.pushKV("commit", commit);
    snap.pushKV("dependency_lock_id", std::string(96, 'd'));
    snap.pushKV("history_required", false);
    snap.pushKV("idempotency_key", "idempotency-disk-train-snap");
    snap.pushKV("expected_state", UniValue());
    BOOST_REQUIRE(LabCall("lab.git_snapshot", snap, created, err));

    const std::string intent(96, '1');
    UniValue prepare(UniValue::VOBJ);
    prepare.pushKV("intent_id", intent);
    prepare.pushKV("idempotency_key", "idempotency-disk-train-prep");
    prepare.pushKV("expected_state", UniValue());
    UniValue prepared;
    BOOST_REQUIRE(LabCall("lab.action_prepare", prepare, prepared, err));

    UniValue exec(UniValue::VOBJ);
    exec.pushKV("input_capsule_id", std::string(96, '2'));
    exec.pushKV("recipe_id", "INTEGER_LINEAR");
    exec.pushKV("runtime_binding_id", std::string(96, '3'));
    exec.pushKV("research_grant_id", std::string(96, '4'));
    exec.pushKV("local_capability_grant_id", intent);
    exec.pushKV("idempotency_key", "idempotency-disk-train-exec");
    exec.pushKV("expected_state", UniValue());
    UniValue ran;
    BOOST_REQUIRE(LabCall("lab.research_execute", exec, ran, err));
    BOOST_REQUIRE_EQUAL(ran["state"].get_str(), "COMPLETE");
    const std::string trajectory = ran["operation_id"].get_str();
    BOOST_REQUIRE_EQUAL(trajectory.size(), 96U);

    std::ifstream input(PathToString(dir.path / "lab.json"));
    std::stringstream buffer;
    buffer << input.rdbuf();
    const std::string body = buffer.str();
    UniValue disk;
    BOOST_REQUIRE(disk.read(body));
    BOOST_CHECK(body.find("identity_sk") == std::string::npos);
    BOOST_REQUIRE(disk["automatic_spend_atoms"].isStr());
    BOOST_CHECK_EQUAL(disk["automatic_spend_atoms"].get_str(), "0");
    BOOST_REQUIRE(disk["trains"].isObject());
    BOOST_REQUIRE(disk["trains"].exists(trajectory));
    const UniValue& saved = disk["trains"][trajectory];
    BOOST_CHECK_EQUAL(saved["weight"].get_str(), "2");
    BOOST_CHECK_EQUAL(saved["bias"].get_str(), "0");
    BOOST_CHECK_EQUAL(saved["momentum_w"].get_str(), "0");
    BOOST_CHECK_EQUAL(saved["momentum_b"].get_str(), "0");
    BOOST_CHECK_EQUAL(saved["cursor"].get_str(), "8");
    BOOST_CHECK_EQUAL(saved["step"].get_str(), "8");
    const std::string state_hash = saved["state_hash"].get_str();
    BOOST_CHECK_EQUAL(state_hash.size(), 96U);

    UniValue exp(UniValue::VOBJ);
    exp.pushKV("repository_id", repository);
    exp.pushKV("idempotency_key", "idempotency-disk-train-export");
    exp.pushKV("expected_state", UniValue());
    UniValue exported;
    BOOST_REQUIRE(LabCall("lab.snapshot_export", exp, exported, err));
    BOOST_CHECK_EQUAL(exported["object_count"].getInt<int>(), 4);
    const std::string manifest = exported["manifest"].get_str();
    BOOST_CHECK(manifest.find(private_id) == std::string::npos);
    BOOST_CHECK(manifest.find(negative_id) != std::string::npos);

    std::vector<modelnet::ExchangeObject> objects;
    BOOST_REQUIRE(modelnet::VerifyExchangeManifest(manifest, objects, err));
    int research_rows = 0;
    int train_rows = 0;
    int replay_rows = 0;
    int model_rows = 0;
    std::string train_line;
    std::string train_digest;
    std::string replay_line;
    for (const modelnet::ExchangeObject& object : objects) {
        if (object.kind == "research") ++research_rows;
        if (object.kind == "replay") {
            ++replay_rows;
            replay_line = object.content;
        }
        if (object.kind == "model" || object.kind == "piece") ++model_rows;
        if (object.kind != "train") continue;
        ++train_rows;
        train_line = object.content;
        train_digest = object.digest;
    }
    BOOST_CHECK_EQUAL(research_rows, 1);
    BOOST_CHECK_EQUAL(train_rows, 1);
    BOOST_CHECK_EQUAL(replay_rows, 1);
    BOOST_CHECK_EQUAL(model_rows, 0);
    BOOST_CHECK_EQUAL(replay_line, "v1|" + trajectory + "|" + identified["record_id"].get_str());
    const std::string canonical = "v1|" + trajectory + "|2|0|0|0|8|8|" + state_hash;
    BOOST_CHECK_EQUAL(train_line, canonical);
    BOOST_CHECK(train_line.find('\n') == std::string::npos);
    BOOST_CHECK(train_line.find('\r') == std::string::npos);
    const std::vector<unsigned char> bytes(train_line.begin(), train_line.end());
    std::string expect;
    BOOST_REQUIRE(modelnet::GitObjectDigest("train", Span<const unsigned char>{bytes.data(), bytes.size()}, expect, err));
    BOOST_CHECK_EQUAL(train_digest, expect);

    modelnet::ReloadLabFromDisk();
    UniValue audit_req(UniValue::VOBJ);
    audit_req.pushKV("trajectory_id", trajectory);
    audit_req.pushKV("policy_id", std::string(96, 'e'));
    UniValue coverage;
    BOOST_REQUIRE(LabCall("lab.audit_coverage", audit_req, coverage, err));
    BOOST_CHECK(coverage["complete_path"].isTrue());

    modelnet::ResetLabApi();
    UniValue import(UniValue::VOBJ);
    import.pushKV("manifest", manifest);
    import.pushKV("idempotency_key", "idempotency-disk-train-import");
    import.pushKV("expected_state", UniValue());
    UniValue imported;
    BOOST_REQUIRE(LabCall("lab.snapshot_import", import, imported, err));
    BOOST_REQUIRE(LabCall("lab.audit_coverage", audit_req, coverage, err));
    BOOST_CHECK(coverage["complete_path"].isTrue());

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(contribution_links_survive_reload_and_snapshot)
{
    BOOST_REQUIRE(!m_path_root.empty());
    ::unsetenv("BTX035_LAB_DIR");
    ::unsetenv("BTX_GUARD_PORT");
    modelnet::ResetLabApi();

    TempTree dir{m_path_root / "btx035-lab-disk" / "contrib"};
    LabDirEnv env(dir.path);
    modelnet::ResetLabApi();

    std::string err;
    UniValue identity(UniValue::VOBJ);
    identity.pushKV("label", "links");
    identity.pushKV("recovery_key_ids", UniValue(UniValue::VARR));
    identity.pushKV("recovery_threshold", 1);
    identity.pushKV("recovery_delay_ms", "1");
    identity.pushKV("idempotency_key", "idempotency-link-id");
    identity.pushKV("expected_state", UniValue());
    UniValue identified;
    BOOST_REQUIRE(LabCall("lab.identity_create", identity, identified, err));

    const std::string unknown(96, 'e');
    const std::string earlier = SignAndStore("ResearchContribution", ContributionPayload("NEGATIVE_RESULT", UniValue(UniValue::VARR), UniValue(UniValue::VARR)), "idempotency-link-sign-neg");
    PublishStored(earlier, "idempotency-link-pub-neg");

    UniValue physical(UniValue::VARR);
    physical.push_back(earlier);
    UniValue informed(UniValue::VARR);
    informed.push_back(unknown);
    const std::string later = SignAndStore("ResearchContribution", ContributionPayload("EXPERIMENT", physical, informed), "idempotency-link-sign-exp");
    PublishStored(later, "idempotency-link-pub-exp");

    UniValue announcement_payload(UniValue::VOBJ);
    announcement_payload.pushKV("objective_id", std::string(96, 'b'));
    announcement_payload.pushKV("base_contribution_ids", UniValue(UniValue::VARR));
    announcement_payload.pushKV("intent", "notice");
    announcement_payload.pushKV("expires_ms", "10");
    announcement_payload.pushKV("collaboration", false);
    announcement_payload.pushKV("contact_binding_id", std::string(96, 'd'));
    const std::string announcement = SignAndStore("ActivityAnnouncement", announcement_payload, "idempotency-link-sign-ann");
    PublishStored(announcement, "idempotency-link-pub-ann");

    UniValue repo(UniValue::VOBJ);
    repo.pushKV("label", "links");
    repo.pushKV("nonce", "link-nonce");
    repo.pushKV("object_format", "git");
    repo.pushKV("project_genesis_id", UniValue());
    repo.pushKV("default_ref", "refs/heads/main");
    repo.pushKV("idempotency_key", "idempotency-link-repo");
    repo.pushKV("expected_state", UniValue());
    UniValue created;
    BOOST_REQUIRE(LabCall("lab.repository_create", repo, created, err));
    const std::string repository = created["repository_id"].get_str();
    UniValue commit(UniValue::VOBJ);
    commit.pushKV("tree", "contribution source\n");
    UniValue snap(UniValue::VOBJ);
    snap.pushKV("repository_id", repository);
    snap.pushKV("commit", commit);
    snap.pushKV("dependency_lock_id", std::string(96, 'd'));
    snap.pushKV("history_required", false);
    snap.pushKV("idempotency_key", "idempotency-link-snap");
    snap.pushKV("expected_state", UniValue());
    BOOST_REQUIRE(LabCall("lab.git_snapshot", snap, created, err));

    std::ifstream input(PathToString(dir.path / "lab.json"));
    std::stringstream buffer;
    buffer << input.rdbuf();
    const std::string body = buffer.str();
    UniValue disk;
    BOOST_REQUIRE(disk.read(body));
    BOOST_CHECK(body.find("identity_sk") == std::string::npos);
    BOOST_CHECK(!disk.exists("identity_sk"));
    BOOST_REQUIRE(disk["automatic_spend_atoms"].isStr());
    BOOST_CHECK_EQUAL(disk["automatic_spend_atoms"].get_str(), "0");
    BOOST_REQUIRE(disk["records"].exists(later));
    const std::string stored_later = disk["records"][later].get_str();
    BOOST_CHECK(stored_later.find("ResearchContribution") != std::string::npos);
    BOOST_CHECK(stored_later.find("idempotency_key") == std::string::npos);
    BOOST_CHECK(disk["records"][announcement].get_str().find("ActivityAnnouncement") != std::string::npos);

    int negative_rows = 0;
    int later_rows = 0;
    int announcement_rows = 0;
    const UniValue& saved_rows = disk["observations"];
    BOOST_REQUIRE(saved_rows.isArray());
    for (size_t i = 0; i < saved_rows.size(); ++i) {
        const UniValue& row = saved_rows[i];
        const std::string id = row["record_id"].get_str();
        if (id == announcement) ++announcement_rows;
        if (id == earlier) {
            ++negative_rows;
            BOOST_CHECK_EQUAL(row["kind"].get_str(), "NEGATIVE_RESULT");
            BOOST_CHECK(row["negative"].isTrue());
            BOOST_CHECK(row["is_private"].isFalse());
            BOOST_CHECK_EQUAL(row["physical_parent_ids"].size(), 0U);
            BOOST_CHECK_EQUAL(row["informed_by"].size(), 0U);
        }
        if (id == later) {
            ++later_rows;
            BOOST_CHECK_EQUAL(row["kind"].get_str(), "EXPERIMENT");
            BOOST_CHECK(row["negative"].isFalse());
            BOOST_REQUIRE_EQUAL(row["physical_parent_ids"].size(), 1U);
            BOOST_CHECK_EQUAL(row["physical_parent_ids"][0].get_str(), earlier);
            BOOST_REQUIRE_EQUAL(row["informed_by"].size(), 1U);
            BOOST_CHECK_EQUAL(row["informed_by"][0].get_str(), unknown);
        }
    }
    BOOST_CHECK_EQUAL(negative_rows, 1);
    BOOST_CHECK_EQUAL(later_rows, 1);
    BOOST_CHECK_EQUAL(announcement_rows, 0);

    modelnet::ReloadLabFromDisk();
    ExpectLinkedContext(later, earlier, announcement, unknown);

    UniValue exp(UniValue::VOBJ);
    exp.pushKV("repository_id", repository);
    exp.pushKV("idempotency_key", "idempotency-link-export");
    exp.pushKV("expected_state", UniValue());
    UniValue exported;
    BOOST_REQUIRE(LabCall("lab.snapshot_export", exp, exported, err));
    BOOST_CHECK_EQUAL(exported["object_count"].getInt<int>(), 5);
    const std::string manifest = exported["manifest"].get_str();
    const std::string negative_line = "v1|" + earlier + "|NEGATIVE_RESULT||";
    const std::string later_line = "v1|" + later + "|EXPERIMENT|" + earlier + "|" + unknown;
    BOOST_CHECK(manifest.find(negative_line) != std::string::npos);
    BOOST_CHECK(manifest.find(later_line) != std::string::npos);
    BOOST_CHECK(manifest.find(announcement) == std::string::npos);

    std::vector<modelnet::ExchangeObject> objects;
    BOOST_REQUIRE(modelnet::VerifyExchangeManifest(manifest, objects, err));
    int research_rows = 0;
    int lineage_rows = 0;
    for (const modelnet::ExchangeObject& object : objects) {
        if (object.kind == "research") {
            ++research_rows;
            BOOST_CHECK(object.content.find("NEGATIVE_RESULT") == std::string::npos);
            BOOST_CHECK(object.content.find('\n') == std::string::npos);
        }
        if (object.kind != "lineage") continue;
        ++lineage_rows;
        BOOST_CHECK(object.content.find(' ') == std::string::npos);
        BOOST_CHECK(object.content.find('\n') == std::string::npos);
        BOOST_CHECK(object.content.find('\r') == std::string::npos);
        const std::vector<unsigned char> bytes(object.content.begin(), object.content.end());
        std::string digest;
        BOOST_REQUIRE(modelnet::GitObjectDigest("lineage", Span<const unsigned char>{bytes.data(), bytes.size()}, digest, err));
        BOOST_CHECK_EQUAL(object.digest, digest);
    }
    BOOST_CHECK_EQUAL(research_rows, 2);
    BOOST_CHECK_EQUAL(lineage_rows, 2);

    modelnet::ResetLabApi();
    UniValue import(UniValue::VOBJ);
    import.pushKV("manifest", manifest);
    import.pushKV("idempotency_key", "idempotency-link-import");
    import.pushKV("expected_state", UniValue());
    UniValue imported;
    BOOST_REQUIRE(LabCall("lab.snapshot_import", import, imported, err));
    ExpectLinkedContext(later, earlier, announcement, unknown);

    modelnet::ResetLabApi();
}

UniValue HexList(const std::string& id)
{
    UniValue list(UniValue::VARR);
    list.push_back(id);
    return list;
}

UniValue Nullable()
{
    return UniValue();
}

BOOST_AUTO_TEST_CASE(model_pieces_survive_reload_and_need_two_roots)
{
    BOOST_REQUIRE(!m_path_root.empty());
    ::unsetenv("BTX035_LAB_DIR");
    ::unsetenv("BTX_GUARD_PORT");
    ::unsetenv("BTX035_LAB_PEER");
    ::unsetenv("BTX035_LAB_PEER_USER");
    ::unsetenv("BTX035_LAB_PEER_PASSWORD");
    modelnet::ResetLabApi();

    TempTree dir{m_path_root / "btx035-lab-disk" / "pieces"};
    LabDirEnv env(dir.path);
    modelnet::ResetLabApi();

    std::string err;
    UniValue identity(UniValue::VOBJ);
    identity.pushKV("label", "author-a");
    identity.pushKV("recovery_key_ids", UniValue(UniValue::VARR));
    identity.pushKV("recovery_threshold", 1);
    identity.pushKV("recovery_delay_ms", "1");
    identity.pushKV("idempotency_key", "idempotency-piece-id-a");
    identity.pushKV("expected_state", Nullable());
    UniValue identified;
    BOOST_REQUIRE(LabCall("lab.identity_create", identity, identified, err));
    const std::string author_a = identified["record_id"].get_str();

    UniValue repo(UniValue::VOBJ);
    repo.pushKV("label", "piece-source");
    repo.pushKV("nonce", "piece-nonce");
    repo.pushKV("object_format", "git");
    repo.pushKV("project_genesis_id", Nullable());
    repo.pushKV("default_ref", "refs/heads/main");
    repo.pushKV("idempotency_key", "idempotency-piece-repo");
    repo.pushKV("expected_state", Nullable());
    UniValue created;
    BOOST_REQUIRE(LabCall("lab.repository_create", repo, created, err));
    const std::string repository = created["repository_id"].get_str();

    UniValue commit(UniValue::VOBJ);
    commit.pushKV("tree", "integer model source\n");
    UniValue snap(UniValue::VOBJ);
    snap.pushKV("repository_id", repository);
    snap.pushKV("commit", commit);
    snap.pushKV("dependency_lock_id", std::string(96, 'd'));
    snap.pushKV("history_required", false);
    snap.pushKV("idempotency_key", "idempotency-piece-snap");
    snap.pushKV("expected_state", Nullable());
    BOOST_REQUIRE(LabCall("lab.git_snapshot", snap, created, err));
    const std::string snapshot_id = created["operation_id"].get_str();

    const std::string intent_a(96, '1');
    UniValue prepare(UniValue::VOBJ);
    prepare.pushKV("intent_id", intent_a);
    prepare.pushKV("idempotency_key", "idempotency-piece-prep-a");
    prepare.pushKV("expected_state", Nullable());
    UniValue prepared;
    BOOST_REQUIRE(LabCall("lab.action_prepare", prepare, prepared, err));

    UniValue exec(UniValue::VOBJ);
    exec.pushKV("input_capsule_id", std::string(96, '2'));
    exec.pushKV("recipe_id", "INTEGER_MODEL");
    exec.pushKV("runtime_binding_id", std::string(96, '3'));
    exec.pushKV("research_grant_id", std::string(96, '4'));
    exec.pushKV("local_capability_grant_id", intent_a);
    exec.pushKV("idempotency_key", "idempotency-piece-exec-a");
    exec.pushKV("expected_state", Nullable());
    UniValue ran;
    BOOST_REQUIRE(LabCall("lab.research_execute", exec, ran, err));
    BOOST_CHECK_EQUAL(ran["state"].get_str(), "COMPLETE");
    const std::string trajectory_a = ran["operation_id"].get_str();
    const std::string digest = ran["artifact_digest"].get_str();
    BOOST_CHECK_EQUAL(digest.size(), 96U);

    UniValue resource(UniValue::VOBJ);
    resource.pushKV("digest", digest);
    resource.pushKV("repository_id", repository);
    UniValue acquire(UniValue::VOBJ);
    acquire.pushKV("resource", resource);
    acquire.pushKV("origin_policy_id", std::string(96, 'e'));
    acquire.pushKV("max_bytes", "1000000");
    acquire.pushKV("destination_class", "LOCAL");
    acquire.pushKV("idempotency_key", "idempotency-piece-acquire");
    acquire.pushKV("expected_state", Nullable());
    UniValue acquired;
    BOOST_REQUIRE(LabCall("lab.artifact_acquire", acquire, acquired, err));
    BOOST_CHECK_EQUAL(acquired["state"].get_str(), "COMPLETE");
    BOOST_CHECK_EQUAL(acquired["artifact_digest"].get_str(), digest);
    BOOST_CHECK(acquired["byte_size"].get_str() != "0");
    BOOST_CHECK(fs::exists(dir.path / "pieces"));
    UniValue capsule(UniValue::VOBJ);
    capsule.pushKV("capsule_id", digest);
    capsule.pushKV("purpose", "REPLAY");
    capsule.pushKV("max_bytes", "1000000");
    UniValue resolved;
    BOOST_REQUIRE(LabCall("lab.capsule_resolve", capsule, resolved, err));
    BOOST_CHECK(resolved["missing_refs"].getValues().empty());
    BOOST_CHECK_EQUAL(resolved["estimated_bytes"].get_str(), acquired["byte_size"].get_str());

    modelnet::ReloadLabFromDisk();
    acquire.pushKV("idempotency_key", "idempotency-piece-acquire2");
    BOOST_REQUIRE(LabCall("lab.artifact_acquire", acquire, acquired, err));
    BOOST_CHECK_EQUAL(acquired["state"].get_str(), "COMPLETE");
    BOOST_CHECK_EQUAL(acquired["artifact_digest"].get_str(), digest);
    UniValue follow(UniValue::VOBJ);
    follow.pushKV("operation_id", trajectory_a);
    UniValue followed;
    BOOST_REQUIRE(LabCall("lab.operation_get", follow, followed, err));
    BOOST_CHECK_EQUAL(followed["state"].get_str(), "COMPLETE");
    BOOST_CHECK_EQUAL(followed["physical_disposition"].get_str(), "STOPPED_QUIESCENT");

    identity.pushKV("label", "author-b");
    identity.pushKV("idempotency_key", "idempotency-piece-id-b");
    BOOST_REQUIRE(LabCall("lab.identity_create", identity, identified, err));
    const std::string author_b = identified["record_id"].get_str();
    BOOST_CHECK(author_a != author_b);

    const std::string intent_b(96, '5');
    prepare.pushKV("intent_id", intent_b);
    prepare.pushKV("idempotency_key", "idempotency-piece-prep-b");
    BOOST_REQUIRE(LabCall("lab.action_prepare", prepare, prepared, err));
    exec.pushKV("local_capability_grant_id", intent_b);
    exec.pushKV("idempotency_key", "idempotency-piece-exec-b");
    BOOST_REQUIRE(LabCall("lab.research_execute", exec, ran, err));
    BOOST_CHECK_EQUAL(ran["state"].get_str(), "COMPLETE");
    BOOST_CHECK_EQUAL(ran["artifact_digest"].get_str(), digest);
    const std::string trajectory_b = ran["operation_id"].get_str();

    UniValue model_ref(UniValue::VOBJ);
    model_ref.pushKV("digest", digest);
    UniValue admit(UniValue::VOBJ);
    admit.pushKV("model_ref", model_ref);
    admit.pushKV("policy_id", std::string(96, 'e'));
    admit.pushKV("evidence_ids", HexList(trajectory_a));
    admit.pushKV("idempotency_key", "idempotency-piece-admit-1");
    admit.pushKV("expected_state", Nullable());
    UniValue admitted;
    BOOST_REQUIRE(LabCall("lab.admission_evaluate", admit, admitted, err));
    BOOST_CHECK_EQUAL(admitted["state"].get_str(), "FAILED");

    UniValue both(UniValue::VARR);
    both.push_back(trajectory_a);
    both.push_back(trajectory_b);
    admit.pushKV("evidence_ids", both);
    admit.pushKV("idempotency_key", "idempotency-piece-admit-2");
    BOOST_REQUIRE(LabCall("lab.admission_evaluate", admit, admitted, err));
    BOOST_CHECK_EQUAL(admitted["state"].get_str(), "COMPLETE");
    const std::string admission = admitted["operation_id"].get_str();

    UniValue host(UniValue::VOBJ);
    host.pushKV("model_ref", model_ref);
    host.pushKV("admission_id", admission);
    host.pushKV("storage_limit_bytes", "1000000");
    host.pushKV("idempotency_key", "idempotency-piece-host");
    host.pushKV("expected_state", Nullable());
    UniValue hosted;
    BOOST_REQUIRE(LabCall("lab.model_host", host, hosted, err));
    BOOST_CHECK(hosted["hosted"].get_bool());

    UniValue exp(UniValue::VOBJ);
    exp.pushKV("repository_id", repository);
    exp.pushKV("idempotency_key", "idempotency-piece-export");
    exp.pushKV("expected_state", Nullable());
    UniValue exported;
    BOOST_REQUIRE(LabCall("lab.snapshot_export", exp, exported, err));
    const std::string manifest = exported["manifest"].get_str();
    std::vector<modelnet::ExchangeObject> objects;
    BOOST_REQUIRE(modelnet::VerifyExchangeManifest(manifest, objects, err));
    int train_rows = 0;
    int replay_rows = 0;
    int model_rows = 0;
    int piece_rows = 0;
    for (const modelnet::ExchangeObject& object : objects) {
        if (object.kind == "train") ++train_rows;
        if (object.kind == "replay") ++replay_rows;
        if (object.kind == "model") ++model_rows;
        if (object.kind == "piece") ++piece_rows;
    }
    BOOST_CHECK_EQUAL(train_rows, 2);
    BOOST_CHECK_EQUAL(replay_rows, 2);
    BOOST_CHECK_EQUAL(model_rows, 1);
    BOOST_CHECK(piece_rows >= 1);

    UniValue source(UniValue::VOBJ);
    source.pushKV("name", "source");
    source.pushKV("nonce", "piece-source-nonce");
    source.pushKV("policy_template", "local");
    source.pushKV("idempotency_key", "idempotency-piece-realm-s");
    source.pushKV("expected_state", Nullable());
    UniValue destination(UniValue::VOBJ);
    destination.pushKV("name", "destination");
    destination.pushKV("nonce", "piece-dest-nonce");
    destination.pushKV("policy_template", "local");
    destination.pushKV("idempotency_key", "idempotency-piece-realm-d");
    destination.pushKV("expected_state", Nullable());
    UniValue realm;
    BOOST_REQUIRE(LabCall("lab.realm_create", source, realm, err));
    const std::string source_id = realm["realm_id"].get_str();
    BOOST_REQUIRE(LabCall("lab.realm_create", destination, realm, err));
    const std::string destination_id = realm["realm_id"].get_str();
    const std::string policy_id = realm["policy_id"].get_str();

    UniValue promo(UniValue::VOBJ);
    promo.pushKV("source_realm_id", source_id);
    promo.pushKV("destination_realm_id", destination_id);
    promo.pushKV("resource_refs", HexList(digest));
    promo.pushKV("policy_id", policy_id);
    promo.pushKV("review_ref", UniValue(UniValue::VOBJ));
    promo.pushKV("idempotency_key", "idempotency-piece-promo");
    promo.pushKV("expected_state", Nullable());
    UniValue prepared_promo;
    BOOST_REQUIRE(LabCall("lab.promotion_prepare", promo, prepared_promo, err));
    const std::string promotion = prepared_promo["record_id"].get_str();
    UniValue checks(UniValue::VOBJ);
    checks.pushKV("closure", "checked");
    checks.pushKV("realm_id", destination_id);
    UniValue attest(UniValue::VOBJ);
    attest.pushKV("promotion_id", promotion);
    attest.pushKV("checks_ref", checks);
    attest.pushKV("valid_until_ms", "10");
    attest.pushKV("idempotency_key", "idempotency-piece-att-1");
    attest.pushKV("expected_state", Nullable());
    UniValue attested;
    BOOST_REQUIRE(LabCall("lab.promotion_attest", attest, attested, err));
    const std::string pin_a = attested["record_id"].get_str();
    checks.pushKV("policy", "checked");
    attest.pushKV("checks_ref", checks);
    attest.pushKV("idempotency_key", "idempotency-piece-att-2");
    BOOST_REQUIRE(LabCall("lab.promotion_attest", attest, attested, err));
    const std::string pin_b = attested["record_id"].get_str();
    BOOST_CHECK(pin_a != pin_b);
    UniValue wrong(UniValue::VOBJ);
    wrong.pushKV("closure", "checked");
    wrong.pushKV("realm_id", source_id);
    attest.pushKV("checks_ref", wrong);
    attest.pushKV("idempotency_key", "idempotency-piece-att-x");
    BOOST_CHECK(!LabCall("lab.promotion_attest", attest, attested, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REALM");
    UniValue pins(UniValue::VARR);
    pins.push_back(pin_a);
    pins.push_back(pin_b);
    UniValue verify(UniValue::VOBJ);
    verify.pushKV("promotion_id", promotion);
    verify.pushKV("attestation_ids", pins);
    verify.pushKV("policy_id", policy_id);
    UniValue verified;
    BOOST_REQUIRE(LabCall("lab.promotion_verify", verify, verified, err));
    BOOST_CHECK_EQUAL(verified["state"].get_str(), "COMPLETE");
    BOOST_CHECK_EQUAL(verified["threshold"].get_str(), "2");
    UniValue repeated(UniValue::VARR);
    repeated.push_back(pin_a);
    repeated.push_back(pin_a);
    UniValue again(UniValue::VOBJ);
    again.pushKV("promotion_id", promotion);
    again.pushKV("attestation_ids", repeated);
    again.pushKV("policy_id", policy_id);
    UniValue duplicated;
    BOOST_REQUIRE(LabCall("lab.promotion_verify", again, duplicated, err));
    BOOST_CHECK_EQUAL(duplicated["state"].get_str(), "FAILED");

    UniValue revoke_checks(UniValue::VOBJ);
    revoke_checks.pushKV("revoke_attestor", pin_a);
    revoke_checks.pushKV("realm_id", destination_id);
    attest.pushKV("checks_ref", revoke_checks);
    attest.pushKV("idempotency_key", "idempotency-piece-revoke");
    BOOST_REQUIRE(LabCall("lab.promotion_attest", attest, attested, err));
    BOOST_CHECK_EQUAL(attested["state"].get_str(), "REVOKED");
    BOOST_CHECK_EQUAL(attested["threshold"].get_str(), "2");
    UniValue status_req(UniValue::VOBJ);
    status_req.pushKV("realm_id", destination_id);
    UniValue status;
    BOOST_REQUIRE(LabCall("lab.realm_status", status_req, status, err));
    BOOST_CHECK_EQUAL(status["threshold"].get_str(), "2");

    UniValue channel(UniValue::VOBJ);
    channel.pushKV("realm_id", destination_id);
    channel.pushKV("channel", "model");
    channel.pushKV("epoch", "0");
    channel.pushKV("sequence", "0");
    channel.pushKV("previous_update_id", Nullable());
    channel.pushKV("promotion_id", Nullable());
    channel.pushKV("trust_attestation_ids", UniValue(UniValue::VARR));
    channel.pushKV("desired_closure_root", digest);
    channel.pushKV("policy_id", policy_id);
    channel.pushKV("valid_until_ms", "10");
    channel.pushKV("rollback_of", Nullable());
    channel.pushKV("conflict_resolution_id", Nullable());
    const std::string expired = SignAndStore("ChannelUpdate", channel, "idem-piece-chan-exp");
    UniValue expired_publish(UniValue::VOBJ);
    expired_publish.pushKV("update_id", expired);
    expired_publish.pushKV("approval_set_id", Nullable());
    expired_publish.pushKV("idempotency_key", "idempotency-piece-pub-exp");
    expired_publish.pushKV("expected_state", Nullable());
    UniValue expired_result;
    BOOST_CHECK(!LabCall("lab.channel_publish", expired_publish, expired_result, err));
    BOOST_CHECK_EQUAL(err, "BTX035_EXPIRED");
    channel.pushKV("valid_until_ms", "4102444800000");
    const std::string update_0 = SignAndStore("ChannelUpdate", channel, "idem-piece-chan-0");
    UniValue publish(UniValue::VOBJ);
    publish.pushKV("update_id", update_0);
    publish.pushKV("approval_set_id", Nullable());
    publish.pushKV("idempotency_key", "idempotency-piece-pub-0");
    publish.pushKV("expected_state", Nullable());
    UniValue published;
    BOOST_REQUIRE(LabCall("lab.channel_publish", publish, published, err));
    BOOST_CHECK_EQUAL(published["state"].get_str(), "PUBLISHED");

    UniValue rings(UniValue::VARR);
    rings.push_back("canary");
    rings.push_back("rest");
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("channel_update_id", update_0);
    plan.pushKV("fleet_policy_id", policy_id);
    plan.pushKV("rings", rings);
    plan.pushKV("activation", "ATOMIC");
    plan.pushKV("deadline_ms", "10");
    plan.pushKV("rollback_update_id", Nullable());
    plan.pushKV("bandwidth_limit_bytes_s", "1");
    const std::string plan_id = SignAndStore("RolloutPlan", plan, "idem-piece-plan-01");
    UniValue roll(UniValue::VOBJ);
    roll.pushKV("plan_id", plan_id);
    roll.pushKV("approval_set_id", Nullable());
    roll.pushKV("idempotency_key", "idempotency-piece-roll");
    roll.pushKV("expected_state", Nullable());
    UniValue rolled;
    BOOST_REQUIRE(LabCall("lab.rollout_start", roll, rolled, err));
    BOOST_CHECK_EQUAL(rolled["state"].get_str(), "COMPLETE");
    UniValue roll_status(UniValue::VOBJ);
    roll_status.pushKV("plan_id", plan_id);
    BOOST_REQUIRE(LabCall("lab.rollout_status", roll_status, status, err));
    BOOST_CHECK_EQUAL(status["state"].get_str(), "STAGED");

    auto receipt = [&](const char* device, const char* ring, const char* state, const char* idem, const UniValue& authorization) {
        UniValue payload(UniValue::VOBJ);
        payload.pushKV("rollout_id", plan_id);
        payload.pushKV("channel_update_id", update_0);
        payload.pushKV("device_id", device);
        payload.pushKV("ring_id", ring);
        payload.pushKV("state", state);
        payload.pushKV("observed_closure_root", digest);
        payload.pushKV("local_generation", "1");
        payload.pushKV("health_evidence_id", Nullable());
        payload.pushKV("last_observed_ms", "1");
        payload.pushKV("observation_epoch", "0");
        payload.pushKV("receipt_sequence", "1");
        payload.pushKV("previous_receipt_id", Nullable());
        payload.pushKV("controller_pause_epoch", "0");
        payload.pushKV("activation_authorization_id", authorization);
        payload.pushKV("observer_key_id", Nullable());
        const std::string receipt_id = SignAndStore("DeploymentReceipt", payload, idem);
        UniValue observe(UniValue::VOBJ);
        observe.pushKV("receipt_id", receipt_id);
        observe.pushKV("idempotency_key", std::string("idempotency-") + idem);
        observe.pushKV("expected_state", Nullable());
        UniValue observed;
        BOOST_REQUIRE(LabCall("lab.deployment_observe", observe, observed, err));
        BOOST_CHECK_EQUAL(observed["state"].get_str(), "OBSERVED");
        return observed;
    };
    UniValue approval(UniValue::VOBJ);
    approval.pushKV("proposal_id", plan_id);
    approval.pushKV("policy_id", policy_id);
    approval.pushKV("decision", "APPROVE");
    approval.pushKV("decision_context", plan_id);
    const std::string authorization = SignAndStore("GovernanceApproval", approval, "idem-piece-owner-auth");
    UniValue auth_id(authorization);
    UniValue first = receipt("device-a", "canary", "ACTIVE", "idem-piece-rec-a", Nullable());
    BOOST_CHECK_EQUAL(first["endpoint_state"].get_str(), "ACTIVE");
    BOOST_REQUIRE(LabCall("lab.rollout_status", roll_status, status, err));
    BOOST_CHECK_EQUAL(status["state"].get_str(), "CANARY");
    UniValue held = receipt("device-b", "rest", "ACTIVE", "idem-piece-rec-hold", Nullable());
    BOOST_CHECK_EQUAL(held["endpoint_state"].get_str(), "ACTIVE");
    BOOST_REQUIRE(LabCall("lab.rollout_status", roll_status, status, err));
    BOOST_CHECK_EQUAL(status["state"].get_str(), "CANARY");
    BOOST_CHECK(status["active_generation"].get_str().empty());
    UniValue second = receipt("device-b", "rest", "ACTIVE", "idem-piece-rec-b", auth_id);
    BOOST_CHECK_EQUAL(second["endpoint_state"].get_str(), "ACTIVE");
    BOOST_REQUIRE(LabCall("lab.rollout_status", roll_status, status, err));
    BOOST_CHECK_EQUAL(status["state"].get_str(), "ACTIVE");
    BOOST_CHECK_EQUAL(status["active_generation"].get_str(), plan_id);
    UniValue offline = receipt("device-c", "rest", "UNKNOWN", "idem-piece-rec-c", Nullable());
    BOOST_CHECK_EQUAL(offline["endpoint_state"].get_str(), "UNKNOWN");
    BOOST_REQUIRE(LabCall("lab.rollout_status", roll_status, status, err));
    BOOST_CHECK(std::stoi(status["counts"]["unknown"].get_str()) >= 1);

    channel.pushKV("sequence", "1");
    channel.pushKV("previous_update_id", update_0);
    const std::string update_1 = SignAndStore("ChannelUpdate", channel, "idem-piece-chan-1");
    UniValue back(UniValue::VOBJ);
    back.pushKV("plan_id", plan_id);
    back.pushKV("new_channel_update_id", update_1);
    back.pushKV("idempotency_key", "idempotency-piece-rollback");
    back.pushKV("expected_state", Nullable());
    BOOST_REQUIRE(LabCall("lab.rollout_rollback", back, rolled, err));
    BOOST_CHECK_EQUAL(rolled["state"].get_str(), "COMPLETE");
    BOOST_REQUIRE(LabCall("lab.rollout_status", roll_status, status, err));
    BOOST_CHECK_EQUAL(status["state"].get_str(), "ROLLED_BACK");
    BOOST_CHECK_EQUAL(status["active_generation"].get_str(), plan_id);
    back.pushKV("idempotency_key", "idempotency-piece-back-2");
    BOOST_CHECK(!LabCall("lab.rollout_rollback", back, rolled, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    UniValue checkpoint_req(UniValue::VOBJ);
    checkpoint_req.pushKV("stream_id", std::string(96, '7'));
    checkpoint_req.pushKV("through_sequence", "1");
    checkpoint_req.pushKV("retention_until_ms", "10");
    checkpoint_req.pushKV("idempotency_key", "idempotency-piece-checkpoint");
    checkpoint_req.pushKV("expected_state", Nullable());
    UniValue checkpoint;
    BOOST_REQUIRE(LabCall("lab.journal_checkpoint", checkpoint_req, checkpoint, err));
    const std::string checkpoint_id = checkpoint["record_id"].get_str();
    UniValue ws(UniValue::VOBJ);
    ws.pushKV("snapshot_id", snapshot_id);
    ws.pushKV("backend", "OPERATION_JOURNAL");
    ws.pushKV("adapter_id", Nullable());
    ws.pushKV("storage_limit", "1000000");
    ws.pushKV("idempotency_key", "idempotency-piece-ws");
    ws.pushKV("expected_state", Nullable());
    UniValue workspace;
    BOOST_REQUIRE(LabCall("lab.workspace_create", ws, workspace, err));
    const std::string workspace_id = workspace["workspace_id"].get_str();
    UniValue event(UniValue::VOBJ);
    event.pushKV("path", "model");
    UniValue op(UniValue::VOBJ);
    op.pushKV("workspace_id", workspace_id);
    op.pushKV("event", event);
    op.pushKV("idempotency_key", "idempotency-piece-wsop");
    op.pushKV("expected_state", Nullable());
    UniValue operated;
    BOOST_REQUIRE(LabCall("lab.workspace_operation", op, operated, err));

    modelnet::ReloadLabFromDisk();
    UniValue channel_get(UniValue::VOBJ);
    channel_get.pushKV("realm_id", destination_id);
    channel_get.pushKV("channel", "model");
    UniValue current;
    BOOST_REQUIRE(LabCall("lab.channel_get", channel_get, current, err));
    BOOST_CHECK_EQUAL(current["sequence"].get_str(), "1");
    BOOST_CHECK_EQUAL(current["update_id"].get_str(), update_1);
    BOOST_CHECK_EQUAL(current["state"].get_str(), "CURRENT");
    UniValue proof(UniValue::VOBJ);
    proof.pushKV("checkpoint_id", checkpoint_id);
    proof.pushKV("sequence", "1");
    UniValue proved;
    BOOST_REQUIRE(LabCall("lab.journal_proof", proof, proved, err));
    BOOST_CHECK(proved["event_ref"].isObject());
    BOOST_CHECK_EQUAL(proved["event_ref"]["digest48"].get_str(), std::string(96, '7'));
    UniValue witness_req(UniValue::VOBJ);
    witness_req.pushKV("checkpoint_id", checkpoint_id);
    witness_req.pushKV("retained_until_ms", "10");
    witness_req.pushKV("idempotency_key", "idempotency-piece-witness");
    witness_req.pushKV("expected_state", Nullable());
    UniValue witnessed;
    BOOST_REQUIRE(LabCall("lab.journal_witness", witness_req, witnessed, err));
    BOOST_CHECK_EQUAL(witnessed["state"].get_str(), "WITNESSED");
    op.pushKV("idempotency_key", "idempotency-piece-wsop-2");
    BOOST_REQUIRE(LabCall("lab.workspace_operation", op, operated, err));
    BOOST_CHECK_EQUAL(operated["sequence"].get_str(), "2");
    BOOST_REQUIRE(LabCall("lab.realm_status", status_req, status, err));
    BOOST_CHECK_EQUAL(status["threshold"].get_str(), "2");
    BOOST_REQUIRE(LabCall("lab.rollout_status", roll_status, status, err));
    BOOST_CHECK_EQUAL(status["state"].get_str(), "ROLLED_BACK");
    publish.pushKV("idempotency_key", "idempotency-piece-pub-stale");
    BOOST_CHECK(!LabCall("lab.channel_publish", publish, published, err));
    BOOST_CHECK(err == "BTX035_STALE" || err == "BTX035_ROLLBACK");
    UniValue foreign(UniValue::VARR);
    foreign.push_back(pin_a);
    foreign.push_back(promotion);
    verify.pushKV("attestation_ids", foreign);
    BOOST_REQUIRE(LabCall("lab.promotion_verify", verify, verified, err));
    BOOST_CHECK_EQUAL(verified["state"].get_str(), "FAILED");
    BOOST_REQUIRE(LabCall("lab.realm_status", status_req, status, err));
    BOOST_CHECK_EQUAL(status["threshold"].get_str(), "2");
    admit.pushKV("idempotency_key", "idempotency-piece-admit-3");
    BOOST_REQUIRE(LabCall("lab.admission_evaluate", admit, admitted, err));
    BOOST_CHECK_EQUAL(admitted["state"].get_str(), "COMPLETE");

    modelnet::ResetLabApi();
    UniValue import(UniValue::VOBJ);
    import.pushKV("manifest", manifest);
    import.pushKV("idempotency_key", "idempotency-piece-import");
    import.pushKV("expected_state", Nullable());
    UniValue imported;
    BOOST_REQUIRE(LabCall("lab.snapshot_import", import, imported, err));
    admit.pushKV("idempotency_key", "idempotency-piece-admit-4");
    BOOST_REQUIRE(LabCall("lab.admission_evaluate", admit, admitted, err));
    BOOST_CHECK_EQUAL(admitted["state"].get_str(), "COMPLETE");
    host.pushKV("admission_id", admitted["operation_id"].get_str());
    host.pushKV("idempotency_key", "idempotency-piece-host-2");
    BOOST_REQUIRE(LabCall("lab.model_host", host, hosted, err));
    BOOST_CHECK(hosted["hosted"].get_bool());
    acquire.pushKV("idempotency_key", "idempotency-piece-acquire3");
    BOOST_REQUIRE(LabCall("lab.artifact_acquire", acquire, acquired, err));
    BOOST_CHECK_EQUAL(acquired["artifact_digest"].get_str(), digest);

    bool flipped = false;
    for (modelnet::ExchangeObject& object : objects) {
        if (object.kind != "piece" || object.content.empty()) continue;
        char& last = object.content.back();
        last = last == 'a' ? 'b' : 'a';
        const std::vector<unsigned char> bytes(object.content.begin(), object.content.end());
        BOOST_REQUIRE(modelnet::GitObjectDigest("piece", Span<const unsigned char>{bytes.data(), bytes.size()}, object.digest, err));
        flipped = true;
        break;
    }
    BOOST_REQUIRE(flipped);
    std::string bad_manifest;
    BOOST_REQUIRE(modelnet::WriteExchangeManifest(objects, bad_manifest, err));
    modelnet::ResetLabApi();
    import.pushKV("manifest", bad_manifest);
    import.pushKV("idempotency_key", "idempotency-piece-import-bad");
    BOOST_CHECK(!LabCall("lab.snapshot_import", import, imported, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ID_MISMATCH");

    modelnet::ResetLabApi();
    UniValue query(UniValue::VOBJ);
    query.pushKV("scope", "PEERS");
    query.pushKV("topics", HexList(std::string(96, 'b')));
    query.pushKV("kinds", HexList(std::string(96, 'c')));
    query.pushKV("after_cursor", Nullable());
    query.pushKV("limit", 4);
    UniValue queried;
    BOOST_REQUIRE(LabCall("lab.research_query", query, queried, err));
    BOOST_CHECK(queried["coverage"]["complete"].isFalse());
    BOOST_CHECK_EQUAL(queried["coverage"]["queried_peers"].get_str(), "0");
    BOOST_CHECK_EQUAL(queried["coverage"]["omissions"][0].get_str(), "BTX035_SCOPE_DENIED");

    ::setenv("BTX035_LAB_PEER", "10.1.2.3:9", 1);
    ::setenv("BTX035_LAB_PEER_USER", "lab", 1);
    ::setenv("BTX035_LAB_PEER_PASSWORD", "lab-pass-0001", 1);
    BOOST_CHECK(!LabCall("lab.research_query", query, queried, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    ::unsetenv("BTX035_LAB_PEER");
    ::unsetenv("BTX035_LAB_PEER_USER");
    ::unsetenv("BTX035_LAB_PEER_PASSWORD");
    modelnet::ResetLabApi();
}

namespace {

modelnet::ExchangeObject DigestedObject(const std::string& kind, const std::string& content)
{
    modelnet::ExchangeObject object;
    object.kind = kind;
    object.content = content;
    std::string err;
    const std::vector<unsigned char> bytes(content.begin(), content.end());
    BOOST_REQUIRE(modelnet::GitObjectDigest(kind, Span<const unsigned char>{bytes.data(), bytes.size()}, object.digest, err));
    return object;
}

modelnet::ExchangeObject PieceObject(const std::string& model_digest, const std::string& index, const std::string& hex)
{
    return DigestedObject("piece", "v1|" + model_digest + "|" + index + "|" + hex);
}

bool ImportObjects(const std::vector<modelnet::ExchangeObject>& objects, const std::string& idem, std::string& err)
{
    std::string manifest;
    BOOST_REQUIRE(modelnet::WriteExchangeManifest(objects, manifest, err));
    UniValue import(UniValue::VOBJ);
    import.pushKV("manifest", manifest);
    import.pushKV("idempotency_key", idem);
    import.pushKV("expected_state", UniValue());
    UniValue imported;
    return LabCall("lab.snapshot_import", import, imported, err);
}

UniValue DiskRow(const std::string& kind, const std::string& digest, const std::string& content)
{
    UniValue row(UniValue::VOBJ);
    row.pushKV("kind", kind);
    row.pushKV("digest", digest);
    row.pushKV("content", content);
    return row;
}

UniValue ReadLabJson(const fs::path& dir)
{
    std::ifstream input(PathToString(dir / "lab.json"));
    std::stringstream buffer;
    buffer << input.rdbuf();
    UniValue disk;
    BOOST_REQUIRE(disk.read(buffer.str()));
    return disk;
}

void WriteLabJson(const fs::path& dir, const UniValue& disk)
{
    std::ofstream output(PathToString(dir / "lab.json"), std::ios::binary | std::ios::trunc);
    output << disk.write();
    BOOST_REQUIRE(output.good());
}

/** Ask the loopback peer route for one stored piece. Returns "OK" or the error code. */
std::string PeerPiece(const std::string& manifest_id, const std::string& model_digest, const std::string& index)
{
    UniValue resource(UniValue::VOBJ);
    resource.pushKV("kind", "MODEL");
    resource.pushKV("digest48", model_digest);
    UniValue req(UniValue::VOBJ);
    req.pushKV("resource", resource);
    req.pushKV("manifest_id", manifest_id);
    req.pushKV("piece_index", index);
    req.pushKV("maximum_bytes", "64");
    std::string response;
    std::string err;
    if (modelnet::ServeLabPeer("artifacts/piece", req.write(), response, err)) return "OK";
    return err;
}

std::string IntegerTrainLine(const std::string& trajectory_id, const modelnet::IntegerState& state)
{
    return "v1|" + trajectory_id + "|" + util::ToString(state.weight) + "|" + util::ToString(state.bias) + "|" +
           util::ToString(state.momentum_w) + "|" + util::ToString(state.momentum_b) + "|" +
           util::ToString(state.cursor) + "|" + util::ToString(state.step) + "|" + state.state_hash;
}

/** True when lab.audit_coverage finds a complete replay path. `first_gap` is its first gap code. */
bool AuditComplete(const std::string& trajectory_id, std::string& first_gap)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("trajectory_id", trajectory_id);
    req.pushKV("policy_id", std::string(96, 'e'));
    UniValue coverage;
    std::string err;
    BOOST_REQUIRE(LabCall("lab.audit_coverage", req, coverage, err));
    first_gap = coverage["gaps"].empty() ? std::string() : coverage["gaps"][0].get_str();
    return coverage["complete_path"].isTrue();
}

} // namespace

BOOST_AUTO_TEST_CASE(piece_index_past_the_cap_or_after_a_gap_is_refused)
{
    BOOST_REQUIRE(!m_path_root.empty());
    ::unsetenv("BTX035_LAB_DIR");
    ::unsetenv("BTX_GUARD_PORT");
    modelnet::ResetLabApi();

    const std::string last = util::ToString(modelnet::MODEL_MAX_PIECES - 1);
    const std::string cap = util::ToString(modelnet::MODEL_MAX_PIECES);
    const std::string cap_plus_one = util::ToString(modelnet::MODEL_MAX_PIECES + 1);
    const std::string model_a(96, '1');
    const std::string model_b(96, '2');
    const std::string model_c(96, '3');
    const std::string model_d(96, '4');
    std::string err;

    // Pieces in index order still import.
    BOOST_CHECK(ImportObjects({PieceObject(model_a, "0", "aa"), PieceObject(model_a, "1", "bb")}, "idempotency-bound-piece-ok", err));
    BOOST_CHECK(err.empty());

    // An index at or past MODEL_MAX_PIECES is refused before anything is stored.
    BOOST_CHECK(!ImportObjects({PieceObject(model_b, cap, "aa")}, "idempotency-bound-piece-cap", err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(!ImportObjects({PieceObject(model_b, cap_plus_one, "aa")}, "idempotency-bound-piece-cap-1", err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");

    // The last valid index passes the cap, and is then refused as a gap on an empty model.
    BOOST_CHECK(!ImportObjects({PieceObject(model_c, last, "aa")}, "idempotency-bound-piece-last", err));
    BOOST_CHECK_EQUAL(err, "BTX035_GAP");
    BOOST_CHECK(!ImportObjects({PieceObject(model_c, "0", "aa"), PieceObject(model_c, "2", "cc")}, "idempotency-bound-piece-gap", err));
    BOOST_CHECK_EQUAL(err, "BTX035_GAP");

    // The reload path skips the same rows from lab.json.
    TempTree dir{m_path_root / "btx035-lab-disk" / "piece-bounds"};
    LabDirEnv env(dir.path);
    modelnet::ResetLabApi();
    const modelnet::ExchangeObject blob = DigestedObject("blob", "piece bounds manifest\n");
    BOOST_REQUIRE(ImportObjects({blob, PieceObject(model_a, "0", "aa")}, "idempotency-bound-piece-disk", err));
    UniValue disk = ReadLabJson(dir.path);
    BOOST_REQUIRE(disk["repo_objects"].isObject());
    UniValue repos = disk["repo_objects"];
    const modelnet::ExchangeObject over_cap = PieceObject(model_b, cap, "aa");
    UniValue rows(UniValue::VARR);
    rows.push_back(DiskRow("piece", over_cap.digest, over_cap.content));
    rows.push_back(DiskRow("piece", model_c, cap + ":c"));
    rows.push_back(DiskRow("piece", model_d, "0:d"));
    rows.push_back(DiskRow("piece", model_d, "2:e"));
    repos.pushKV("model-bytes", rows);
    disk.pushKV("repo_objects", repos);
    WriteLabJson(dir.path, disk);

    modelnet::ReloadLabFromDisk();
    BOOST_CHECK_EQUAL(PeerPiece(blob.digest, model_a, "0"), "OK");
    BOOST_CHECK_EQUAL(PeerPiece(blob.digest, model_b, cap), "BTX035_NOT_FOUND");
    BOOST_CHECK_EQUAL(PeerPiece(blob.digest, model_c, cap), "BTX035_NOT_FOUND");
    BOOST_CHECK_EQUAL(PeerPiece(blob.digest, model_d, "0"), "OK");
    BOOST_CHECK_EQUAL(PeerPiece(blob.digest, model_d, "2"), "BTX035_NOT_FOUND");

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(manifest_pieces_out_of_index_order_are_a_gap)
{
    BOOST_REQUIRE(!m_path_root.empty());
    ::unsetenv("BTX035_LAB_DIR");
    ::unsetenv("BTX_GUARD_PORT");
    modelnet::ResetLabApi();

    const std::string model_e(96, '5');
    const std::string model_f(96, '6');
    std::string err;

    // An export lists a model's pieces in index order from 0. A complete set in another order is refused
    // at the first piece past the next index.
    BOOST_CHECK(!ImportObjects({PieceObject(model_e, "1", "bb"), PieceObject(model_e, "0", "aa")}, "idempotency-piece-order-reversed", err));
    BOOST_CHECK_EQUAL(err, "BTX035_GAP");

    // The same pieces in index order import.
    BOOST_CHECK(ImportObjects({PieceObject(model_f, "0", "aa"), PieceObject(model_f, "1", "bb")}, "idempotency-piece-order-ok", err));
    BOOST_CHECK(err.empty());

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(integer_train_record_past_the_step_cap_is_refused)
{
    BOOST_REQUIRE(!m_path_root.empty());
    ::unsetenv("BTX035_LAB_DIR");
    ::unsetenv("BTX_GUARD_PORT");
    modelnet::ResetLabApi();
    using modelnet::INTEGER_MAX_STEPS;

    std::string err;
    std::string gap;
    modelnet::IntegerTrainer at_cap;
    BOOST_REQUIRE(at_cap.Run(INTEGER_MAX_STEPS, err));
    const std::string cap_id(96, '5');
    BOOST_CHECK(ImportObjects({DigestedObject("train", IntegerTrainLine(cap_id, at_cap.State()))}, "idempotency-bound-train-cap", err));
    BOOST_CHECK(AuditComplete(cap_id, gap));

    // One step past the cap is refused while the line is decoded, before any replay.
    modelnet::IntegerState over = at_cap.State();
    over.step = INTEGER_MAX_STEPS + 1;
    over.cursor = INTEGER_MAX_STEPS + 1;
    const std::string over_id(96, '6');
    BOOST_CHECK(!ImportObjects({DigestedObject("train", IntegerTrainLine(over_id, over))}, "idempotency-bound-train-over", err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(!AuditComplete(over_id, gap));
    BOOST_CHECK_EQUAL(gap, "BTX035_NOT_FOUND");

    // lab.json with a train step past the cap is refused as a whole, as ReadLaunch does past 4096.
    TempTree dir{m_path_root / "btx035-lab-disk" / "train-bounds"};
    LabDirEnv env(dir.path);
    modelnet::ResetLabApi();
    modelnet::IntegerTrainer lab_run;
    BOOST_REQUIRE(lab_run.Run(modelnet::IntegerDataset().size(), err));
    const std::string disk_id(96, '7');
    BOOST_REQUIRE(ImportObjects({DigestedObject("train", IntegerTrainLine(disk_id, lab_run.State()))}, "idempotency-bound-train-disk", err));
    modelnet::ReloadLabFromDisk();
    BOOST_CHECK(AuditComplete(disk_id, gap));

    UniValue disk = ReadLabJson(dir.path);
    BOOST_REQUIRE(disk["trains"].isObject());
    BOOST_REQUIRE(disk["trains"].exists(disk_id));
    UniValue trains = disk["trains"];
    UniValue row = trains[disk_id];
    BOOST_CHECK_EQUAL(row["step"].get_str(), "8");
    row.pushKV("step", util::ToString(INTEGER_MAX_STEPS + 1));
    trains.pushKV(disk_id, row);
    disk.pushKV("trains", trains);
    WriteLabJson(dir.path, disk);
    modelnet::ReloadLabFromDisk();
    BOOST_CHECK(!AuditComplete(disk_id, gap));
    BOOST_CHECK_EQUAL(gap, "BTX035_NOT_FOUND");

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_SUITE_END()
