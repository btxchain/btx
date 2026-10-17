// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/git_snapshot.h>
#include <modelnet/guard_machine.h>
#include <modelnet/lab_api.h>
#include <modelnet/lab_exchange.h>
#include <modelnet/research_rpc.h>
#include <modelnet/research_views.h>
#include <modelnet/training_integer.h>
#include <span.h>
#include <univalue.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_complete_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(integer_profile_replays_and_rejects_a_changed_cursor)
{
    using namespace modelnet;
    IntegerTrainer trainer;
    std::string err;
    BOOST_REQUIRE(trainer.Run(IntegerDataset().size(), err));
    const IntegerState published = trainer.State();
    BOOST_REQUIRE(published.step == IntegerDataset().size());
    BOOST_REQUIRE(published.weight != 0);
    IntegerTrainer again;
    BOOST_CHECK(again.ReplayMatches(published, err));

    IntegerState cursor = published;
    cursor.cursor += 1;
    BOOST_CHECK(!IntegerTrainer::CheckState(cursor, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RNG");

    IntegerState weights = published;
    weights.weight += 1;
    BOOST_CHECK(!IntegerTrainer::CheckState(weights, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ID_MISMATCH");

    IntegerTrainer resumed;
    BOOST_CHECK(!resumed.Resume(IntegerState{}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_RESUMABLE");
    IntegerTrainer prefix;
    BOOST_REQUIRE(prefix.Run(4, err));
    BOOST_CHECK(resumed.Resume(prefix.State(), err));
    BOOST_CHECK(resumed.Run(IntegerDataset().size() - 4, err));
    BOOST_CHECK_EQUAL(resumed.State().state_hash, published.state_hash);
}

BOOST_AUTO_TEST_CASE(integer_trainer_refuses_steps_past_the_cap)
{
    using namespace modelnet;
    std::string err;
    IntegerTrainer over;
    BOOST_CHECK(!over.Run(INTEGER_MAX_STEPS + 1, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK_EQUAL(over.State().step, uint64_t{0});
    BOOST_CHECK(over.Intervals().empty());

    IntegerTrainer at_cap;
    BOOST_REQUIRE(at_cap.Run(INTEGER_MAX_STEPS, err));
    BOOST_CHECK_EQUAL(at_cap.State().step, INTEGER_MAX_STEPS);
    BOOST_CHECK(IntegerTrainer::CheckState(at_cap.State(), err));

    // The cap counts the steps already taken.
    BOOST_CHECK(!at_cap.Run(1, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK_EQUAL(at_cap.State().step, INTEGER_MAX_STEPS);

    // A published state past the cap is refused before any replay.
    IntegerState published = at_cap.State();
    published.step = INTEGER_MAX_STEPS + 1;
    BOOST_CHECK(!IntegerTrainer::CheckState(published, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
}

BOOST_AUTO_TEST_CASE(research_views_keep_negatives_and_drop_private_rows)
{
    using namespace modelnet;
    std::vector<ResearchObservation> rows(3);
    rows[0].record_id = std::string(96, 'a');
    rows[0].sequence = 1;
    rows[0].negative = true;
    rows[1].record_id = std::string(96, 'b');
    rows[1].sequence = 2;
    rows[1].reproduction_count = 3;
    rows[1].content_hash = "same";
    rows[2].record_id = std::string(96, 'c');
    rows[2].sequence = 3;
    rows[2].is_private = true;
    rows[2].content_hash = "same";
    rows[2].reproduction_count = 9;
    ResearchView view;
    std::string err;
    BOOST_REQUIRE(ParseResearchView("RECENT", view, err));
    std::vector<std::string> ids;
    BOOST_REQUIRE(SortResearchView(view, rows, true, ids, err));
    BOOST_REQUIRE_EQUAL(ids.size(), 2U);
    BOOST_CHECK_EQUAL(ids[0], rows[1].record_id);
    BOOST_CHECK_EQUAL(ids[1], rows[0].record_id);
    BOOST_REQUIRE(ParseResearchView("NEGLECTED", view, err));
    BOOST_REQUIRE(SortResearchView(view, rows, true, ids, err));
    BOOST_CHECK_EQUAL(ids[0], rows[0].record_id);
}

BOOST_AUTO_TEST_CASE(exchange_rejects_a_replaced_blob)
{
    using namespace modelnet;
    std::vector<ExchangeObject> objects(1);
    objects[0].kind = "blob";
    objects[0].content = "hello";
    std::string err;
    const std::vector<unsigned char> bytes(objects[0].content.begin(), objects[0].content.end());
    BOOST_REQUIRE(GitObjectDigest(objects[0].kind, Span<const unsigned char>{bytes.data(), bytes.size()}, objects[0].digest, err));
    std::string manifest;
    BOOST_REQUIRE(WriteExchangeManifest(objects, manifest, err));
    std::vector<ExchangeObject> verified;
    BOOST_REQUIRE(VerifyExchangeManifest(manifest, verified, err));
    BOOST_CHECK_EQUAL(verified[0].digest, objects[0].digest);

    objects[0].content = "goodbye";
    BOOST_CHECK(!WriteExchangeManifest(objects, manifest, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ID_MISMATCH");
    BOOST_CHECK(!PullExchangeLoopback("10.0.0.8", 1, "u", "p", "repo", manifest, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
}

BOOST_AUTO_TEST_CASE(exchange_manifest_refuses_too_many_or_too_large_objects)
{
    using namespace modelnet;
    const auto blob = [](const std::string& content) {
        ExchangeObject object;
        object.kind = "blob";
        object.content = content;
        std::string digest_err;
        const std::vector<unsigned char> bytes(content.begin(), content.end());
        BOOST_REQUIRE(GitObjectDigest("blob", Span<const unsigned char>{bytes.data(), bytes.size()}, object.digest, digest_err));
        return object;
    };
    std::string err;
    std::string manifest;
    std::vector<ExchangeObject> verified;
    BOOST_REQUIRE(WriteExchangeManifest({blob("a"), blob("b"), blob("c")}, manifest, err));
    BOOST_CHECK(VerifyExchangeManifest(manifest, verified, err));
    BOOST_CHECK_EQUAL(verified.size(), 3U);

    // Small caps passed in, so the count check needs only three objects.
    BOOST_CHECK(VerifyExchangeManifest(manifest, verified, err, 3, 1));
    BOOST_CHECK(!VerifyExchangeManifest(manifest, verified, err, 2, 1));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_REQUIRE(WriteExchangeManifest({blob("ab")}, manifest, err));
    BOOST_CHECK(!VerifyExchangeManifest(manifest, verified, err, 3, 1));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");

    // The default object cap, at and one byte past MAX_EXCHANGE_OBJECT_BYTES.
    BOOST_REQUIRE(WriteExchangeManifest({blob(std::string(MAX_EXCHANGE_OBJECT_BYTES, 'x'))}, manifest, err));
    BOOST_CHECK(VerifyExchangeManifest(manifest, verified, err));
    BOOST_REQUIRE(WriteExchangeManifest({blob(std::string(MAX_EXCHANGE_OBJECT_BYTES + 1, 'x'))}, manifest, err));
    BOOST_CHECK(!VerifyExchangeManifest(manifest, verified, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
}

BOOST_AUTO_TEST_CASE(guard_permit_is_one_use_and_thirty_seconds)
{
    using namespace modelnet;
    GuardTable table;
    GuardPermit permit;
    std::string err;
    BOOST_REQUIRE(table.Prepare("research.run", std::string(96, 'a'), 1, 1000, permit, err));
    BOOST_CHECK_EQUAL(permit.not_after_ms - 1000, GuardTable::kPermitTtlMs);
    BOOST_CHECK_EQUAL(permit.commitment, GuardCommitment(permit.secret));
    std::string receipt;
    BOOST_CHECK(table.Execute(permit.secret, 1000, receipt, err));
    BOOST_CHECK(!receipt.empty());
    BOOST_CHECK(!table.Execute(permit.secret, 1000, receipt, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REPLAY");
    GuardPermit spend;
    BOOST_CHECK(!table.Prepare("wallet.spend", std::string(96, 'b'), 1, 1000, spend, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    table.Pause();
    BOOST_CHECK(!table.Prepare("research.run", std::string(96, 'c'), 1, 1000, spend, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PAUSED");
}

BOOST_AUTO_TEST_CASE(fetch_ticket_exports_once_and_source_query_reads_the_bytes)
{
    modelnet::ResetLabApi();
    UniValue repo(UniValue::VOBJ);
    repo.pushKV("label", "source");
    repo.pushKV("nonce", "ticket-nonce");
    repo.pushKV("object_format", "git");
    repo.pushKV("project_genesis_id", UniValue());
    repo.pushKV("default_ref", "refs/heads/main");
    repo.pushKV("idempotency_key", "idempotency-ticket-repo");
    repo.pushKV("expected_state", UniValue());
    std::string response, err;
    BOOST_REQUIRE(modelnet::DispatchLab035("lab.repository_create", repo.write(), response, err));
    UniValue created;
    BOOST_REQUIRE(created.read(response));
    const std::string repository = created["result"]["repository_id"].get_str();

    UniValue commit(UniValue::VOBJ);
    commit.pushKV("tree", "independent source\n");
    UniValue snap(UniValue::VOBJ);
    snap.pushKV("repository_id", repository);
    snap.pushKV("commit", commit);
    snap.pushKV("dependency_lock_id", std::string(96, 'd'));
    snap.pushKV("history_required", false);
    snap.pushKV("idempotency_key", "idempotency-ticket-snap");
    snap.pushKV("expected_state", UniValue());
    BOOST_REQUIRE(modelnet::DispatchLab035("lab.git_snapshot", snap.write(), response, err));

    UniValue ticket_req(UniValue::VOBJ);
    ticket_req.pushKV("repository_id", repository);
    ticket_req.pushKV("operation", "fetch");
    ticket_req.pushKV("ref_update_id", UniValue());
    ticket_req.pushKV("max_bytes", "1000000");
    ticket_req.pushKV("idempotency_key", "idempotency-ticket-issue");
    ticket_req.pushKV("expected_state", UniValue());
    BOOST_REQUIRE(modelnet::DispatchLab035("lab.git_fetch_ticket", ticket_req.write(), response, err));
    UniValue issued;
    BOOST_REQUIRE(issued.read(response));
    const std::string ticket = issued["result"]["ticket"].get_str();
    BOOST_CHECK_EQUAL(ticket.size(), 64U);
    BOOST_CHECK_EQUAL(issued["result"]["transport"].get_str(), "lab.snapshot_export");
    BOOST_CHECK(!issued["result"].exists("socket_path"));

    UniValue ids(UniValue::VARR);
    ids.push_back(repository);
    UniValue query(UniValue::VOBJ);
    query.pushKV("snapshot_ids", ids);
    query.pushKV("query_kind", "text");
    query.pushKV("query", "independent source");
    query.pushKV("limit", 5);
    BOOST_REQUIRE(modelnet::DispatchLab035("lab.source_query", query.write(), response, err));
    UniValue found;
    BOOST_REQUIRE(found.read(response));
    BOOST_REQUIRE_EQUAL(found["result"]["matches"].size(), 1U);
    const std::string digest = found["result"]["matches"][0].get_str();

    UniValue acquire(UniValue::VOBJ);
    UniValue resource(UniValue::VOBJ);
    resource.pushKV("digest", digest);
    acquire.pushKV("resource", resource);
    acquire.pushKV("origin_policy_id", std::string(96, 'e'));
    acquire.pushKV("max_bytes", "1000000");
    acquire.pushKV("destination_class", "local");
    acquire.pushKV("idempotency_key", "idempotency-ticket-acquire");
    acquire.pushKV("expected_state", UniValue());
    BOOST_REQUIRE(modelnet::DispatchLab035("lab.artifact_acquire", acquire.write(), response, err));
    UniValue acquired;
    BOOST_REQUIRE(acquired.read(response));
    BOOST_CHECK_EQUAL(acquired["result"]["state"].get_str(), "COMPLETE");

    UniValue empty_resource(UniValue::VOBJ);
    acquire.pushKV("resource", empty_resource);
    acquire.pushKV("idempotency_key", "idempotency-ticket-acquire-miss");
    BOOST_REQUIRE(modelnet::DispatchLab035("lab.artifact_acquire", acquire.write(), response, err));
    UniValue missed;
    BOOST_REQUIRE(missed.read(response));
    BOOST_CHECK_EQUAL(missed["result"]["state"].get_str(), "FAILED");

    UniValue exp(UniValue::VOBJ);
    exp.pushKV("repository_id", repository);
    exp.pushKV("fetch_ticket", ticket);
    exp.pushKV("idempotency_key", "idempotency-ticket-export");
    exp.pushKV("expected_state", UniValue());
    BOOST_REQUIRE(modelnet::DispatchLab035("lab.snapshot_export", exp.write(), response, err));
    exp.pushKV("idempotency_key", "idempotency-ticket-export-2");
    BOOST_CHECK(!modelnet::DispatchLab035("lab.snapshot_export", exp.write(), response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REPLAY");
}

BOOST_AUTO_TEST_SUITE_END()
