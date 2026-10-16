// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_remaining.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

std::string Id(char fill)
{
    return std::string(96, fill);
}

modelnet::RetainedSource Object(char id, const char* visibility, const char* tenant, const std::string& bytes)
{
    modelnet::RetainedSource row;
    row.object_id = Id(id);
    row.visibility = visibility;
    row.tenant = tenant;
    row.bytes = bytes;
    row.research_record_id = Id('b');
    return row;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_035_remaining_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(res004_query_rebuild_and_private_isolation)
{
    using namespace modelnet;
    SourceIndex index;
    std::string err;
    const std::string bytes = "fn main() {}";
    BOOST_REQUIRE(index.Add(Object('a', "PUBLIC", "tenant-a", bytes), err));
    BOOST_REQUIRE(index.Add(Object('c', "PRIVATE", "tenant-b", bytes), err));
    BOOST_CHECK(!index.Rebuild("s3://original-account", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!index.Rebuilt());

    std::string file;
    std::string record;
    BOOST_REQUIRE(index.QueryFile(Id('a'), file, record, err));
    BOOST_CHECK_EQUAL(file, bytes);
    BOOST_CHECK_EQUAL(record, Id('b'));
    std::string diff;
    BOOST_REQUIRE(index.QueryDiff(Id('a'), Id('c'), diff, err));
    BOOST_CHECK_EQUAL(diff, "equal");
    BOOST_CHECK(!index.QuerySemantic(Id('a'), err));
    BOOST_CHECK_EQUAL(err, "BTX035_PARSER_ABSENT");
    BOOST_CHECK(!index.Cloned());
    BOOST_CHECK(!index.SemanticFabricated());

    BOOST_REQUIRE(index.DeleteDerived());
    std::vector<std::string> ids;
    BOOST_CHECK(!index.QueryPublic(SourceContentHash(bytes), "tenant-a", ids, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");
    BOOST_REQUIRE(index.Rebuild("", err));
    BOOST_REQUIRE(index.QueryPublic(SourceContentHash(bytes), "tenant-a", ids, err));
    BOOST_REQUIRE_EQUAL(ids.size(), 1U);
    BOOST_CHECK_EQUAL(ids[0], Id('a'));
    BOOST_REQUIRE(index.QueryPublic(SourceContentHash(bytes), "tenant-b", ids, err));
    BOOST_CHECK(ids.empty());
}

BOOST_AUTO_TEST_CASE(run004_witness_before_success)
{
    using namespace modelnet;
    WitnessLog log;
    std::string err;
    BOOST_REQUIRE(log.Record("act-1", "edit-file", "ALLOW", "wrote", "because the prompt said so", err));
    BOOST_CHECK(!log.Expose("act-1", err));
    BOOST_CHECK_EQUAL(err, "BTX035_WITNESS");
    BOOST_CHECK(!log.Witness("act-1", "PUBLISHER", err));
    BOOST_CHECK_EQUAL(err, "BTX035_AUTHORITY");
    BOOST_CHECK(!log.Exposed("act-1"));
    BOOST_REQUIRE(log.Witness("act-1", "WITNESS", err));
    BOOST_CHECK(!log.Expose("act-1", err));
    BOOST_CHECK_EQUAL(err, "BTX035_WITNESS");
    std::string checkpoint;
    BOOST_REQUIRE(log.Checkpoint(checkpoint, err));
    BOOST_CHECK_EQUAL(checkpoint.size(), 96U);
    BOOST_REQUIRE(log.Expose("act-1", err));
    BOOST_CHECK(log.Exposed("act-1"));
    const std::string text = log.EvidenceText("act-1");
    BOOST_CHECK(text.find("intent=edit-file") != std::string::npos);
    BOOST_CHECK(text.find("decision=ALLOW") != std::string::npos);
    BOOST_CHECK(text.find("outcome=wrote") != std::string::npos);
    BOOST_CHECK(text.find("rationale_not_proof=") != std::string::npos);
    BOOST_CHECK(text.find("faithful") == std::string::npos);
    BOOST_REQUIRE(log.DeleteCheckpoint(err));
    BOOST_CHECK(log.CheckpointMissing());
    BOOST_CHECK(!log.Exposed("act-1"));
}

BOOST_AUTO_TEST_CASE(rev002_package_authenticates_only_after_owner_pin)
{
    using namespace modelnet;
    PackageGate package;
    std::string err;
    BOOST_CHECK(!package.HasProductionSignature());
    BOOST_CHECK(!package.AppointedPerson());
    BOOST_CHECK(!package.AppointPersonFromPackage("any person", err));
    BOOST_CHECK_EQUAL(err, "BTX035_AUTHORITY");
    BOOST_REQUIRE(package.AddFile("MARKDOWN", "spec-bytes", err));
    BOOST_REQUIRE(package.AddFile("SCHEMAS", "schema-bytes", err));
    BOOST_CHECK(!package.Authenticate("", package.InventoryDigest(), err));
    BOOST_CHECK_EQUAL(err, "BTX035_RELEASE_UNSIGNED");
    BOOST_CHECK(!package.Authenticated());
    BOOST_CHECK(!package.Authenticate("operator-pin-0001", std::string(96, 'a'), err));
    BOOST_CHECK_EQUAL(err, "BTX035_RELEASE_UNSIGNED");
    BOOST_CHECK(!package.Authenticated());
    BOOST_REQUIRE(package.Authenticate("operator-pin-0001", package.InventoryDigest(), err));
    BOOST_CHECK(package.Authenticated());
    BOOST_REQUIRE(package.InterruptAfterPersist(err));
    BOOST_CHECK(package.Partial());
    BOOST_CHECK(!package.Authenticated());
    BOOST_REQUIRE(package.Recover(err));
    BOOST_CHECK(!package.Authenticated());
    BOOST_CHECK(package.Partial());
}

BOOST_AUTO_TEST_CASE(core001_and_dev003_reject_unresolved_release)
{
    using namespace modelnet;
    ReleaseGate gate;
    std::string err;
    std::vector<ReleaseCase> rows = {
        {"RES-004-A", "PASS", true},
        {"BUILD-002-A", "BLOCKED", true},
        {"OLD-001-A", "NOT_RUN", true},
    };
    BOOST_REQUIRE(gate.SetCases(rows, err));
    BOOST_CHECK(!gate.ClaimComplete(true, err));
    BOOST_CHECK_EQUAL(err, "BTX035_CLAIM");
    BOOST_CHECK(!gate.Complete());
    BOOST_CHECK(!gate.ClaimComplete(false, err));
    BOOST_CHECK(!gate.Complete());
    BOOST_REQUIRE(gate.Restore(err));
    BOOST_CHECK_EQUAL(gate.StateOf("OLD-001-A"), "NOT_RUN");
    BOOST_CHECK(!gate.Complete());

    BOOST_CHECK(!gate.NoteJourney("e2e", "", err));
    BOOST_REQUIRE(gate.NoteJourney("e2e", "test_btx", err));
    BOOST_REQUIRE(gate.NoteJourney("journey", "test_btx", err));
    BOOST_CHECK(gate.JourneysReady());
    BOOST_CHECK(!gate.ClaimComplete(false, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RELEASE");

    std::vector<ReleaseCase> ready = {{"RES-004-A", "PASS", true}};
    BOOST_REQUIRE(gate.SetCases(ready, err));
    BOOST_REQUIRE(gate.NoteJourney("e2e", "test_btx", err));
    BOOST_REQUIRE(gate.NoteJourney("journey", "test_btx", err));
    BOOST_REQUIRE(gate.ClaimComplete(false, err));
    BOOST_CHECK(gate.Complete());
    BOOST_REQUIRE(gate.Stop());
    BOOST_CHECK(gate.RestartKeepsStopped());
    BOOST_CHECK(!gate.Complete());
}

BOOST_AUTO_TEST_SUITE_END()
