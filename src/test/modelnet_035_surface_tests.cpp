// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/action_authority.h>
#include <modelnet/canonical_codec.h>
#include <modelnet/identity.h>
#include <modelnet/migrate_035.h>
#include <modelnet/model_admission.h>
#include <modelnet/model_panel.h>
#include <modelnet/realm_channel.h>
#include <modelnet/research_graph.h>
#include <modelnet/research_rpc.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_surface_tests, BasicTestingSetup)

namespace {

UniValue DispatchOk(const std::string& method, const UniValue& request)
{
    std::string response;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchLab035(method, request.write(), response, err), err);
    UniValue parsed;
    BOOST_REQUIRE(parsed.read(response));
    BOOST_REQUIRE(parsed.isObject());
    BOOST_REQUIRE(!parsed.empty());
    return parsed;
}

UniValue IntervalJson(uint64_t start, uint64_t end, const std::string& ancestry)
{
    UniValue interval(UniValue::VOBJ);
    interval.pushKV("start_inclusive", start);
    interval.pushKV("end_exclusive", end);
    interval.pushKV("start_state", "S0");
    interval.pushKV("end_state", "SF");
    interval.pushKV("ancestry", ancestry);
    interval.pushKV("publisher_only", false);
    return interval;
}

UniValue AdmitJson(const std::string& assurance, bool owner_authorized, const std::vector<std::string>& roots)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("assurance", assurance);
    req.pushKV("byte_hash_matches", true);
    req.pushKV("total", uint64_t{8});
    req.pushKV("start_state", "S0");
    req.pushKV("final_state", "SF");
    req.pushKV("owner_authorized", owner_authorized);
    UniValue intervals(UniValue::VARR);
    if (roots.size() >= 2) {
        intervals.push_back(IntervalJson(0, 8, roots[0]));
        intervals.push_back(IntervalJson(0, 8, roots[1]));
    }
    req.pushKV("intervals", intervals);
    UniValue root_json(UniValue::VARR);
    for (const std::string& root : roots) root_json.push_back(root);
    req.pushKV("independent_roots", root_json);
    return req;
}

} // namespace

BOOST_AUTO_TEST_CASE(unknown_method_is_not_implemented)
{
    std::string response = "{\"ok\":true}";
    std::string err = "stale";
    BOOST_CHECK(!modelnet::DispatchLab035("lab035.unknown", "{}", response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_IMPLEMENTED");
    BOOST_CHECK(response.empty());

    response = "{\"ok\":true}";
    BOOST_CHECK(!modelnet::DispatchLab035("lab035.admit.extra", "{}", response, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_IMPLEMENTED");
    BOOST_CHECK(response.empty());

    const char* argv[] = {"lab035", "lab035.nope", "{}"};
    std::string out = "{\"ok\":true}";
    BOOST_CHECK(!modelnet::Lab035Cli(3, argv, out, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_IMPLEMENTED");
    BOOST_CHECK(out.empty());
}

BOOST_AUTO_TEST_CASE(version_1_migration_fails)
{
    UniValue body(UniValue::VOBJ);
    body.pushKV("envelope_version", 1);
    body.pushKV("network_id", std::string(64, 'a'));
    body.pushKV("realm_id", std::string(96, 'b'));

    modelnet::Digest48 id;
    id.data[0] = 0xab;
    id.data[47] = 0xcd;
    std::string err;
    BOOST_CHECK(!modelnet::MigrateEnvelope(body, id, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ENVELOPE_VERSION");
    BOOST_CHECK_EQUAL(id.data[0], static_cast<unsigned char>(0xab));
    BOOST_CHECK_EQUAL(id.data[47], static_cast<unsigned char>(0xcd));
    BOOST_CHECK_EQUAL(id.data[1], static_cast<unsigned char>(0));
}

BOOST_AUTO_TEST_CASE(version_2_migration_calls_record_id)
{
    UniValue body(UniValue::VOBJ);
    body.pushKV("envelope_version", 2);
    body.pushKV("network_id", std::string(64, 'a'));
    body.pushKV("realm_id", std::string(96, 'b'));

    modelnet::Digest48 migrated;
    modelnet::Digest48 direct;
    std::string err;
    BOOST_REQUIRE(modelnet::MigrateEnvelope(body, migrated, err));
    BOOST_REQUIRE(modelnet::RecordIdV11(body, direct, err));
    BOOST_CHECK(migrated == direct);
    BOOST_CHECK(!migrated.IsNull());
}

BOOST_AUTO_TEST_CASE(research_only_panel_serve_not_allowed)
{
    const modelnet::AdmissionResult research = modelnet::Admit(
        modelnet::Assurance::RESEARCH_ONLY, true, {}, 8, "S0", "SF", {}, true);
    BOOST_CHECK(research.research_execution_permit);
    BOOST_CHECK(!research.admitted);
    BOOST_CHECK(!research.ServeAllowed());

    modelnet::RealmRollout rollout;
    std::string err;
    BOOST_REQUIRE(rollout.PublishChannel("lab", 0, "h0", err));
    BOOST_REQUIRE(rollout.PublishChannel("lab", 1, "h1", err));

    modelnet::ActionGate gate;
    gate.ReportPhysical("op", "PRESENT");
    gate.CancelLogical("op");

    const modelnet::PanelSnapshot snap = modelnet::CapturePanel(research, rollout, "lab", gate, "op");
    BOOST_CHECK(!snap.serve_allowed);
    BOOST_CHECK_EQUAL(snap.admission_code, research.code);
    BOOST_CHECK_EQUAL(snap.realm, "lab");
    BOOST_CHECK_EQUAL(snap.channel_sequence, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(snap.logical_state, "CANCELLED");
    BOOST_CHECK_EQUAL(snap.physical_state, "PRESENT");
}

BOOST_AUTO_TEST_CASE(dispatch_calls_real_apis)
{
    std::vector<unsigned char> pk;
    std::vector<unsigned char> sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    UniValue identity(UniValue::VOBJ);
    identity.pushKV("pubkey_hex", HexStr(pk));
    const UniValue created = DispatchOk("lab035.identity.create", identity);
    BOOST_CHECK_EQUAL(created["root_id"].get_str(), modelnet::ResearchIdentityId(Span<const unsigned char>{pk.data(), pk.size()}).Hex());
    BOOST_CHECK_EQUAL(created["epoch"].getInt<uint64_t>(), uint64_t{0});
    BOOST_CHECK(created["wallet_spend"].isFalse());

    UniValue git(UniValue::VOBJ);
    git.pushKV("kind", "blob");
    git.pushKV("content", "a");
    const UniValue digested = DispatchOk("lab035.git.digest", git);
    BOOST_CHECK_EQUAL(digested["digest"].get_str(), "1adcbf5aea2ca919b25776a05ac40948173bbd72b7e324942ccebf7c67480423246df9a4a07e58fea1f4523705eab508");

    std::string failed = "{\"digest\":\"pretend\"}";
    BOOST_CHECK(!modelnet::DispatchLab035("lab035.git.digest", "{\"kind\":\"BLOB\",\"content\":\"a\"}", failed, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GIT_TYPE");
    BOOST_CHECK(failed.empty());

    modelnet::Digest48 contribution;
    contribution.data[0] = 7;
    modelnet::Digest48 author;
    author.data[0] = 9;
    UniValue research(UniValue::VOBJ);
    research.pushKV("topic", "lab-topic");
    research.pushKV("contribution_id", contribution.Hex());
    research.pushKV("author_id", author.Hex());
    research.pushKV("negative", true);
    research.pushKV("summary", "no gain");
    const UniValue published = DispatchOk("lab035.research.publish", research);
    BOOST_CHECK(published["negative"].isTrue());
    BOOST_CHECK_EQUAL(published["summary"].get_str(), "no gain");
    BOOST_CHECK(published["peer"].isTrue());
    modelnet::Digest48 topic;
    BOOST_REQUIRE(modelnet::TopicId("lab-topic", topic, err));
    BOOST_CHECK_EQUAL(published["topic"].get_str(), topic.Hex());

    const UniValue admitted = DispatchOk("lab035.admit", AdmitJson("PUBLIC_STRICT", false, {"root-a", "root-b"}));
    BOOST_CHECK(admitted["admitted"].isTrue());
    BOOST_CHECK(admitted["serve_allowed"].isTrue());
    BOOST_CHECK(admitted["code"].get_str().empty());

    const UniValue research_only = DispatchOk("lab035.admit", AdmitJson("RESEARCH_ONLY", true, {}));
    BOOST_CHECK(research_only["research_execution_permit"].isTrue());
    BOOST_CHECK(research_only["serve_allowed"].isFalse());

    UniValue wan(UniValue::VOBJ);
    wan.pushKV("realm", "alpha");
    wan.pushKV("threshold", 2);
    UniValue pinned(UniValue::VARR);
    pinned.push_back("a");
    pinned.push_back("b");
    pinned.push_back("c");
    wan.pushKV("pinned_ids", pinned);
    UniValue signers(UniValue::VARR);
    signers.push_back("a");
    signers.push_back("b");
    wan.pushKV("signer_ids", signers);
    const UniValue quorum = DispatchOk("lab035.wan.quorum", wan);
    BOOST_CHECK(quorum["quorum"].isTrue());
    BOOST_CHECK_EQUAL(quorum["threshold"].getInt<int>(), 2);

    UniValue one_signer(UniValue::VARR);
    one_signer.push_back("b");
    wan.pushKV("signer_ids", one_signer);
    const UniValue short_quorum = DispatchOk("lab035.wan.quorum", wan);
    BOOST_CHECK(short_quorum["quorum"].isFalse());
    BOOST_CHECK(!short_quorum.empty());

    const char* argv[] = {"lab035", "lab035.git.digest", "{\"kind\":\"blob\",\"content\":\"a\"}"};
    std::string out;
    BOOST_REQUIRE(modelnet::Lab035Cli(3, argv, out, err));
    UniValue cli;
    BOOST_REQUIRE(cli.read(out));
    BOOST_CHECK_EQUAL(cli["digest"].get_str(), digested["digest"].get_str());
}

BOOST_AUTO_TEST_SUITE_END()
