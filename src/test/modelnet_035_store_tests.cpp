// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_store.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <system_error>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_store_tests, BasicTestingSetup)

namespace {

bool Hex96(const std::string& text)
{
    if (text.size() != 96) return false;
    for (unsigned char c : text) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
}

struct TempTree {
    explicit TempTree(fs::path path_in) : path(std::move(path_in))
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    ~TempTree()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    fs::path path;
};

fs::path StoreDir(const fs::path& root, const char* name)
{
    const fs::path base = root.empty() ? fs::path{"lab-store-test"} : root / "lab-store-test";
    return base / name;
}

modelnet::LabRecord SampleRecord(const std::string& id, bool is_private)
{
    modelnet::LabRecord row;
    row.record_id = id;
    row.type = "note";
    row.principal = "principal-a";
    row.realm = "realm-a";
    row.bytes_ref = "bytes-a";
    row.accepted_at = "10";
    row.auth_state = "accepted";
    row.is_private = is_private;
    return row;
}

modelnet::LabStateFields SampleState()
{
    modelnet::LabStateFields fields;
    fields.realm_id = "realm-a";
    fields.owner_scope = "owner-a";
    fields.target_kind = "record";
    fields.target_key = "target-a";
    fields.generation = "1";
    fields.value_id = "value-a";
    fields.policy_epoch = "2";
    return fields;
}

modelnet::LabStateKey KeyOf(const modelnet::LabStateFields& fields)
{
    modelnet::LabStateKey key;
    key.realm_id = fields.realm_id;
    key.owner_scope = fields.owner_scope;
    key.target_kind = fields.target_kind;
    key.target_key = fields.target_key;
    return key;
}

modelnet::LabIdempotency SampleIdem()
{
    modelnet::LabIdempotency scope;
    scope.caller = "caller-a";
    scope.realm = "realm-a";
    scope.method = "lab.state_get";
    scope.key = "idem-key-0001";
    return scope;
}

} // namespace

BOOST_AUTO_TEST_CASE(state_token_changes_with_every_field)
{
    const modelnet::LabStateFields base = SampleState();
    const std::string token = modelnet::StateToken(base);
    BOOST_CHECK(Hex96(token));
    BOOST_CHECK_EQUAL(modelnet::StateToken(base), token);

    modelnet::LabStateFields realm = base;
    realm.realm_id = "realm-b";
    modelnet::LabStateFields owner = base;
    owner.owner_scope = "owner-b";
    modelnet::LabStateFields kind = base;
    kind.target_kind = "ref";
    modelnet::LabStateFields target = base;
    target.target_key = "target-b";
    modelnet::LabStateFields generation = base;
    generation.generation = "3";
    modelnet::LabStateFields value = base;
    value.value_id = "value-b";
    modelnet::LabStateFields missing = base;
    missing.value_id.reset();
    modelnet::LabStateFields epoch = base;
    epoch.policy_epoch = "4";

    BOOST_CHECK(modelnet::StateToken(realm) != token);
    BOOST_CHECK(modelnet::StateToken(owner) != token);
    BOOST_CHECK(modelnet::StateToken(kind) != token);
    BOOST_CHECK(modelnet::StateToken(target) != token);
    BOOST_CHECK(modelnet::StateToken(generation) != token);
    BOOST_CHECK(modelnet::StateToken(value) != token);
    BOOST_CHECK(modelnet::StateToken(missing) != token);
    BOOST_CHECK(modelnet::StateToken(epoch) != token);
    BOOST_CHECK(modelnet::StateToken(realm) != modelnet::StateToken(owner));
}

BOOST_AUTO_TEST_CASE(reopen_keeps_rows_and_replays_idempotency)
{
    TempTree tmp{StoreDir(m_path_root, "reopen")};
    const modelnet::LabRecord record = SampleRecord("rec-1", false);
    modelnet::LabRef ref;
    ref.repository = "repo-a";
    ref.name_space = "ns-a";
    ref.name = "main";
    ref.sequence = "1";
    ref.update_id = "upd-1";
    ref.target = "rec-1";
    modelnet::LabIdentityEpoch epoch;
    epoch.root = "root-a";
    epoch.epoch = "1";
    epoch.transition = "genesis";
    epoch.key = "key-a";
    epoch.status = "active";
    modelnet::LabRevocation revocation;
    revocation.issuer = "issuer-a";
    revocation.epoch = "1";
    revocation.target = "key-b";
    const modelnet::LabStateFields fields = SampleState();
    const modelnet::LabStateKey key = KeyOf(fields);
    const modelnet::LabIdempotency scope = SampleIdem();
    const std::string request = "canonical-request-v1";
    const std::string body = "stable-response-body";

    {
        modelnet::LabStore store(tmp.path);
        std::string err;
        BOOST_REQUIRE(store.Open(err));
        BOOST_CHECK(!store.RequiresWallet());
        BOOST_CHECK(store.SignatureRequired());
        BOOST_CHECK(!store.BackendReady());
        BOOST_REQUIRE(store.InsertRecord(record, err));
        BOOST_REQUIRE(store.InsertRef(ref, err));
        BOOST_REQUIRE(store.InsertIdentityEpoch(epoch, err));
        BOOST_REQUIRE(store.InsertRevocation(revocation, err));
        BOOST_REQUIRE(store.PutState(fields, err));
        modelnet::LabStateView view;
        BOOST_REQUIRE(store.StateGet(key, view, err));
        BOOST_CHECK(view.exists);
        BOOST_CHECK_EQUAL(view.generation, "1");
        BOOST_REQUIRE(view.value_id);
        BOOST_CHECK_EQUAL(*view.value_id, "value-a");
        BOOST_CHECK_EQUAL(view.policy_epoch, "2");
        BOOST_REQUIRE(view.state_token);
        BOOST_CHECK_EQUAL(*view.state_token, modelnet::StateToken(fields));

        bool replayed = true;
        std::string response = "stale";
        BOOST_REQUIRE(store.Reserve(scope, request, *view.state_token, key, replayed, response, err));
        BOOST_CHECK(!replayed);
        BOOST_CHECK(response.empty());
        BOOST_REQUIRE(store.Commit(scope, request, body, err));
    }

    modelnet::LabStore store(tmp.path);
    std::string err;
    BOOST_REQUIRE(store.Open(err));
    modelnet::LabRecord got_record;
    BOOST_REQUIRE(store.GetRecord(record.record_id, got_record, err));
    BOOST_CHECK_EQUAL(got_record.type, record.type);
    BOOST_CHECK_EQUAL(got_record.principal, record.principal);
    BOOST_CHECK_EQUAL(got_record.realm, record.realm);
    BOOST_CHECK_EQUAL(got_record.bytes_ref, record.bytes_ref);
    BOOST_CHECK_EQUAL(got_record.accepted_at, record.accepted_at);
    BOOST_CHECK_EQUAL(got_record.auth_state, record.auth_state);
    modelnet::LabRef got_ref;
    BOOST_REQUIRE(store.GetRef(ref.repository, ref.name_space, ref.name, ref.sequence, got_ref, err));
    BOOST_CHECK_EQUAL(got_ref.update_id, ref.update_id);
    BOOST_CHECK_EQUAL(got_ref.target, ref.target);
    modelnet::LabIdentityEpoch got_epoch;
    BOOST_REQUIRE(store.GetIdentityEpoch(epoch.root, epoch.epoch, got_epoch, err));
    BOOST_CHECK_EQUAL(got_epoch.transition, epoch.transition);
    BOOST_CHECK_EQUAL(got_epoch.key, epoch.key);
    BOOST_CHECK_EQUAL(got_epoch.status, epoch.status);
    modelnet::LabRevocation got_revocation;
    BOOST_REQUIRE(store.GetRevocation(revocation.issuer, revocation.epoch, revocation.target, got_revocation, err));
    BOOST_CHECK(!got_revocation.is_private);

    bool replayed = false;
    std::string response;
    BOOST_REQUIRE(store.Reserve(scope, request, "not-the-stored-token", key, replayed, response, err));
    BOOST_CHECK(replayed);
    BOOST_CHECK_EQUAL(response, body);

    replayed = true;
    response = "replaced";
    BOOST_CHECK(!store.Reserve(scope, "canonical-request-v2", modelnet::StateToken(fields), key, replayed, response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_IDEMPOTENCY");
    BOOST_CHECK(response.empty());

    replayed = false;
    response.clear();
    BOOST_REQUIRE(store.Reserve(scope, request, "", key, replayed, response, err));
    BOOST_CHECK(replayed);
    BOOST_CHECK_EQUAL(response, body);
}

BOOST_AUTO_TEST_CASE(record_conflict_keeps_first_row)
{
    TempTree tmp{StoreDir(m_path_root, "conflict")};
    modelnet::LabStore store(tmp.path);
    std::string err;
    BOOST_REQUIRE(store.Open(err));
    const modelnet::LabRecord first = SampleRecord("rec-1", false);
    BOOST_REQUIRE(store.InsertRecord(first, err));

    modelnet::LabRecord second = first;
    second.type = "other";
    second.bytes_ref = "bytes-b";
    BOOST_CHECK(!store.InsertRecord(second, err));
    BOOST_CHECK_EQUAL(err, "BTX035_CONFLICT");

    modelnet::LabRecord got;
    BOOST_REQUIRE(store.GetRecord(first.record_id, got, err));
    BOOST_CHECK_EQUAL(got.type, first.type);
    BOOST_CHECK_EQUAL(got.bytes_ref, first.bytes_ref);
    BOOST_CHECK_EQUAL(got.principal, first.principal);
    BOOST_CHECK_EQUAL(got.auth_state, first.auth_state);

    modelnet::LabStore again(tmp.path);
    BOOST_REQUIRE(again.Open(err));
    modelnet::LabRecord persisted;
    BOOST_REQUIRE(again.GetRecord(first.record_id, persisted, err));
    BOOST_CHECK_EQUAL(persisted.type, first.type);
    BOOST_CHECK_EQUAL(persisted.bytes_ref, first.bytes_ref);
}

BOOST_AUTO_TEST_CASE(state_mismatch_does_not_commit)
{
    TempTree tmp{StoreDir(m_path_root, "state")};
    modelnet::LabStore store(tmp.path);
    std::string err;
    BOOST_REQUIRE(store.Open(err));
    const modelnet::LabStateFields fields = SampleState();
    const modelnet::LabStateKey key = KeyOf(fields);
    BOOST_REQUIRE(store.PutState(fields, err));
    modelnet::LabStateView absent;
    modelnet::LabStateKey other = key;
    other.target_key = "target-missing";
    BOOST_REQUIRE(store.StateGet(other, absent, err));
    BOOST_CHECK(!absent.exists);
    BOOST_CHECK_EQUAL(absent.generation, "0");
    BOOST_CHECK(!absent.value_id);
    BOOST_CHECK_EQUAL(absent.policy_epoch, "0");
    BOOST_CHECK(!absent.state_token);

    const modelnet::LabIdempotency scope = SampleIdem();
    const std::string request = "canonical-request-v1";
    bool replayed = true;
    std::string response = "stale";
    BOOST_CHECK(!store.Reserve(scope, request, "deadbeef", key, replayed, response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_STATE");
    BOOST_CHECK(!replayed);
    BOOST_CHECK(response.empty());

    modelnet::LabStateView view;
    BOOST_REQUIRE(store.StateGet(key, view, err));
    BOOST_REQUIRE(view.state_token);
    BOOST_REQUIRE(store.Reserve(scope, request, *view.state_token, key, replayed, response, err));
    BOOST_CHECK(!replayed);

    modelnet::LabStateFields moved = fields;
    moved.generation = "2";
    BOOST_REQUIRE(store.PutState(moved, err));
    BOOST_CHECK(!store.Commit(scope, request, "should-not-store", err));
    BOOST_CHECK_EQUAL(err, "BTX035_STATE");

    BOOST_REQUIRE(store.PutState(fields, err));
    BOOST_REQUIRE(store.Commit(scope, request, "stable-response-body", err));
    BOOST_CHECK(!store.Reserve(scope, "canonical-request-v2", *view.state_token, key, replayed, response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_IDEMPOTENCY");
    BOOST_REQUIRE(store.Reserve(scope, request, "ignored-after-commit", key, replayed, response, err));
    BOOST_CHECK(replayed);
    BOOST_CHECK_EQUAL(response, "stable-response-body");
}

BOOST_AUTO_TEST_CASE(limit_keeps_signature_and_does_not_ready_empty_backend)
{
    TempTree empty_dir{StoreDir(m_path_root, "limit-empty")};
    {
        modelnet::LabStore store(empty_dir.path);
        std::string err;
        BOOST_REQUIRE(store.Open(err));
        BOOST_REQUIRE(store.SetLimits(0, 1000000, err));
        BOOST_CHECK(!store.InsertRecord(SampleRecord("rec-1", false), err));
        BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
        BOOST_CHECK(store.SignatureRequired());
        BOOST_CHECK(!store.BackendReady());
        BOOST_CHECK(!store.MarkBackendReady(err));
        BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_REQUIRED");
        BOOST_CHECK(store.SignatureRequired());
        BOOST_CHECK(!store.BackendReady());
        modelnet::LabRecord gone;
        BOOST_CHECK(!store.GetRecord("rec-1", gone, err));
    }

    TempTree capped{StoreDir(m_path_root, "limit-cap")};
    modelnet::LabStore store(capped.path);
    std::string err;
    BOOST_REQUIRE(store.Open(err));
    BOOST_REQUIRE(store.SetLimits(1, 1000000, err));
    const modelnet::LabRecord first = SampleRecord("rec-1", false);
    BOOST_REQUIRE(store.InsertRecord(first, err));
    BOOST_REQUIRE(store.MarkBackendReady(err));
    BOOST_CHECK(store.BackendReady());
    BOOST_CHECK(!store.InsertRecord(SampleRecord("rec-2", false), err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(store.SignatureRequired());
    BOOST_CHECK(store.BackendReady());
    modelnet::LabRecord got;
    BOOST_REQUIRE(store.GetRecord(first.record_id, got, err));
    BOOST_CHECK_EQUAL(got.bytes_ref, first.bytes_ref);
    BOOST_CHECK(!store.GetRecord("rec-2", got, err));

    BOOST_REQUIRE(store.SetLimits(10, 4, err));
    modelnet::LabRecord wide = SampleRecord("rec-wide", false);
    wide.bytes_ref = "this-field-is-longer-than-four-bytes";
    BOOST_CHECK(!store.InsertRecord(wide, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(store.SignatureRequired());
    BOOST_CHECK(store.BackendReady());
    BOOST_CHECK(!store.GetRecord("rec-wide", got, err));
    BOOST_REQUIRE(store.GetRecord(first.record_id, got, err));
    BOOST_CHECK_EQUAL(got.type, first.type);
}

BOOST_AUTO_TEST_CASE(public_export_omits_private_rows)
{
    TempTree tmp{StoreDir(m_path_root, "private")};
    const std::string secret_record = "PRIVREC-7c2e";
    const std::string secret_ref = "PRIVREF-7c2e";
    const std::string secret_epoch = "PRIVEPOCH-7c2e";
    const std::string secret_revocation = "PRIVREV-7c2e";
    modelnet::LabRecord pub = SampleRecord("PUBREC-7c2e", false);
    modelnet::LabRecord priv = SampleRecord(secret_record, true);
    priv.bytes_ref = secret_record;
    modelnet::LabRef pub_ref;
    pub_ref.repository = "PUBREF-7c2e";
    pub_ref.name_space = "ns";
    pub_ref.name = "main";
    pub_ref.sequence = "1";
    pub_ref.update_id = "upd-pub";
    pub_ref.target = "PUBREC-7c2e";
    modelnet::LabRef priv_ref = pub_ref;
    priv_ref.repository = secret_ref;
    priv_ref.target = secret_record;
    priv_ref.is_private = true;
    modelnet::LabIdentityEpoch pub_epoch;
    pub_epoch.root = "PUBEPOCH-7c2e";
    pub_epoch.epoch = "1";
    pub_epoch.transition = "genesis";
    pub_epoch.key = "key-pub";
    pub_epoch.status = "active";
    modelnet::LabIdentityEpoch priv_epoch = pub_epoch;
    priv_epoch.root = secret_epoch;
    priv_epoch.status = secret_epoch;
    priv_epoch.is_private = true;
    modelnet::LabRevocation pub_revocation;
    pub_revocation.issuer = "PUBREV-7c2e";
    pub_revocation.epoch = "1";
    pub_revocation.target = "key-pub";
    modelnet::LabRevocation priv_revocation = pub_revocation;
    priv_revocation.issuer = secret_revocation;
    priv_revocation.target = secret_revocation;
    priv_revocation.is_private = true;

    std::string exported;
    {
        modelnet::LabStore store(tmp.path);
        std::string err;
        BOOST_REQUIRE(store.Open(err));
        BOOST_REQUIRE(store.InsertRecord(pub, err));
        BOOST_REQUIRE(store.InsertRecord(priv, err));
        BOOST_REQUIRE(store.InsertRef(pub_ref, err));
        BOOST_REQUIRE(store.InsertRef(priv_ref, err));
        BOOST_REQUIRE(store.InsertIdentityEpoch(pub_epoch, err));
        BOOST_REQUIRE(store.InsertIdentityEpoch(priv_epoch, err));
        BOOST_REQUIRE(store.InsertRevocation(pub_revocation, err));
        BOOST_REQUIRE(store.InsertRevocation(priv_revocation, err));
        BOOST_REQUIRE(store.PublicExport(exported, err));
        modelnet::LabRecord still_private;
        BOOST_REQUIRE(store.GetRecord(secret_record, still_private, err));
        BOOST_CHECK(still_private.is_private);
    }

    BOOST_CHECK(exported.find("PUBREC-7c2e") != std::string::npos);
    BOOST_CHECK(exported.find("PUBREF-7c2e") != std::string::npos);
    BOOST_CHECK(exported.find("PUBEPOCH-7c2e") != std::string::npos);
    BOOST_CHECK(exported.find("PUBREV-7c2e") != std::string::npos);
    BOOST_CHECK(exported.find(secret_record) == std::string::npos);
    BOOST_CHECK(exported.find(secret_ref) == std::string::npos);
    BOOST_CHECK(exported.find(secret_epoch) == std::string::npos);
    BOOST_CHECK(exported.find(secret_revocation) == std::string::npos);

    modelnet::LabStore store(tmp.path);
    std::string err;
    BOOST_REQUIRE(store.Open(err));
    std::string again;
    BOOST_REQUIRE(store.PublicExport(again, err));
    BOOST_CHECK_EQUAL(again, exported);
    BOOST_CHECK(again.find(secret_record) == std::string::npos);
    BOOST_CHECK(again.find(secret_ref) == std::string::npos);
    BOOST_CHECK(again.find(secret_epoch) == std::string::npos);
    BOOST_CHECK(again.find(secret_revocation) == std::string::npos);
    modelnet::LabRecord persisted_private;
    BOOST_REQUIRE(store.GetRecord(secret_record, persisted_private, err));
    BOOST_CHECK(persisted_private.is_private);
    BOOST_CHECK_EQUAL(persisted_private.bytes_ref, secret_record);
}

BOOST_AUTO_TEST_SUITE_END()
