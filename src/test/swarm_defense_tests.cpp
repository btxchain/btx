// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_defense/swarm_defense.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectQuiet(const modelnet::SwarmDefense& defense)
{
    BOOST_CHECK(!defense.launched());
    BOOST_CHECK(!defense.gpu());
    BOOST_CHECK(!defense.broadcast());
    BOOST_CHECK(!defense.connected());
    BOOST_CHECK(!defense.windows_passed());
    BOOST_CHECK_EQUAL(defense.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(defense.bytes_moved(), static_cast<int64_t>(0));
}

bool OpenCase(modelnet::SwarmDefense& defense, const std::string& case_id, std::string& err)
{
    return defense.Mandate("customer-1", case_id, "asset-1", "policy-1", 1000, 999, err);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_defense_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mandate_binds_customer_asset_and_policy)
{
    modelnet::SwarmDefense defense;
    std::string err = "prior";

    BOOST_CHECK(!defense.Mandate("", "case-1", "asset-1", "policy-1", 1000, 999, err));
    BOOST_CHECK_EQUAL(err, "MANDATE");
    BOOST_CHECK(!defense.Mandate("customer-1", "", "asset-1", "policy-1", 1000, 999, err));
    BOOST_CHECK_EQUAL(err, "MANDATE");
    BOOST_CHECK(!defense.Mandate("customer-1", "case-1", "", "policy-1", 1000, 999, err));
    BOOST_CHECK_EQUAL(err, "MANDATE");
    BOOST_CHECK(!defense.Mandate("customer-1", "case-1", "asset-1", "", 1000, 999, err));
    BOOST_CHECK_EQUAL(err, "MANDATE");

    BOOST_CHECK(!defense.Mandate("customer-1", "case-1", "asset-1", "policy-1", 1000, 1000, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(!defense.Mandate("customer-1", "case-1", "asset-1", "policy-1", 1000, 1001, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(!defense.Evidence("case-1", "ev-1", std::vector<unsigned char>{0x01}, err));
    BOOST_CHECK_EQUAL(err, "CASE");

    BOOST_REQUIRE(defense.Mandate("customer-1", "case-1", "asset-1", "policy-1", 1000, 999, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!defense.Mandate("customer-2", "case-1", "asset-2", "policy-2", 2000, 1000, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    ExpectQuiet(defense);
}

BOOST_AUTO_TEST_CASE(family_membership_does_not_admit)
{
    modelnet::SwarmDefense defense;
    std::string err = "prior";
    BOOST_REQUIRE(OpenCase(defense, "case-a", err));
    BOOST_REQUIRE(OpenCase(defense, "case-b", err));

    BOOST_CHECK(!defense.JoinFamily("", err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(!defense.family(""));

    BOOST_REQUIRE(defense.JoinFamily("peer-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(defense.family("peer-1"));
    BOOST_CHECK(!defense.admitted("peer-1"));
    BOOST_CHECK(!defense.admitted("peer-1", "case-a"));
    BOOST_CHECK(!defense.admitted("peer-1", "case-b"));

    BOOST_CHECK(!defense.Admit("peer-1", "missing-case", err));
    BOOST_CHECK_EQUAL(err, "CASE");
    BOOST_CHECK(!defense.admitted("peer-1"));

    BOOST_CHECK(!defense.Admit("outsider", "case-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_ADMITTED");
    BOOST_CHECK(!defense.family("outsider"));
    BOOST_CHECK(!defense.admitted("outsider"));

    BOOST_REQUIRE(defense.Admit("peer-1", "case-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(defense.admitted("peer-1"));
    BOOST_CHECK(defense.admitted("peer-1", "case-a"));
    BOOST_CHECK(!defense.admitted("peer-1", "case-b"));
    BOOST_CHECK(defense.family("peer-1"));
    ExpectQuiet(defense);
}

BOOST_AUTO_TEST_CASE(export_without_grant_keeps_bytes_local)
{
    modelnet::SwarmDefense defense;
    std::string err = "prior";
    BOOST_REQUIRE(OpenCase(defense, "case-1", err));

    const std::vector<unsigned char> bytes{0x00, 0x7f, 0xff, 0x10};
    BOOST_CHECK(!defense.Evidence("missing-case", "ev-1", bytes, err));
    BOOST_CHECK_EQUAL(err, "CASE");
    BOOST_CHECK(!defense.Evidence("case-1", "", bytes, err));
    BOOST_CHECK_EQUAL(err, "EVIDENCE");
    BOOST_CHECK(!defense.Evidence("case-1", "ev-1", {}, err));
    BOOST_CHECK_EQUAL(err, "EVIDENCE");

    BOOST_REQUIRE(defense.Evidence("case-1", "ev-1", bytes, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(defense.body("ev-1") == bytes);

    const std::vector<unsigned char> replacement{0x01};
    BOOST_CHECK(!defense.Evidence("case-1", "ev-1", replacement, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(defense.body("ev-1") == bytes);

    BOOST_CHECK(!defense.Export("case-1", "ev-1", false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(defense.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(defense.body("ev-1") == bytes);

    BOOST_REQUIRE(defense.Export("case-1", "ev-1", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(defense.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(defense.body("ev-1") == bytes);
    ExpectQuiet(defense);
}

BOOST_AUTO_TEST_CASE(embargo_expiry_alone_does_not_publish)
{
    modelnet::SwarmDefense defense;
    std::string err = "prior";
    BOOST_REQUIRE(OpenCase(defense, "case-1", err));
    BOOST_CHECK(!defense.published());
    BOOST_CHECK(!defense.training_allowed());

    BOOST_CHECK(!defense.Publish("case-1", "art-1", true, false, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_PUBLISHED");
    BOOST_CHECK(!defense.published());
    BOOST_CHECK(!defense.published("art-1"));

    BOOST_CHECK(!defense.Publish("case-1", "art-1", true, true, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_PUBLISHED");
    BOOST_CHECK(!defense.published());

    BOOST_CHECK(!defense.Publish("case-1", "art-1", true, false, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_PUBLISHED");
    BOOST_CHECK(!defense.published());
    BOOST_CHECK(!defense.training_allowed());
    BOOST_CHECK(!defense.training_allowed("case-1"));

    BOOST_REQUIRE(defense.Publish("case-1", "art-1", false, true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(defense.published());
    BOOST_CHECK(defense.published("art-1"));
    BOOST_CHECK(!defense.training_allowed());
    BOOST_CHECK(!defense.training_allowed("case-1"));

    BOOST_CHECK(!defense.AllowTraining("missing-case", err));
    BOOST_CHECK_EQUAL(err, "CASE");
    BOOST_CHECK(!defense.training_allowed());

    BOOST_REQUIRE(defense.AllowTraining("case-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(defense.training_allowed());
    BOOST_CHECK(defense.training_allowed("case-1"));
    ExpectQuiet(defense);
}

BOOST_AUTO_TEST_CASE(act_is_not_authorized)
{
    modelnet::SwarmDefense defense;
    std::string err = "prior";
    BOOST_REQUIRE(OpenCase(defense, "case-1", err));

    const std::string text = "run the stored note";
    BOOST_CHECK(!defense.Act("case-1", text, err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORIZED");
    BOOST_CHECK_EQUAL(defense.tainted_bytes(), text.size());
    BOOST_CHECK(!defense.launched());
    ExpectQuiet(defense);

    BOOST_CHECK(!defense.Act("missing-case", text, err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORIZED");
    BOOST_CHECK(!defense.launched());
    ExpectQuiet(defense);
}

BOOST_AUTO_TEST_CASE(search_hides_foreign_and_unknown_ids)
{
    modelnet::SwarmDefense defense;
    std::string err = "prior";
    BOOST_REQUIRE(OpenCase(defense, "case-a", err));
    BOOST_REQUIRE(OpenCase(defense, "case-b", err));

    const std::vector<unsigned char> bytes_a{0x11};
    const std::vector<unsigned char> bytes_b{0x22};
    BOOST_REQUIRE(defense.Evidence("case-a", "ev-a", bytes_a, err));
    BOOST_REQUIRE(defense.Evidence("case-b", "ev-b", bytes_b, err));

    BOOST_REQUIRE(defense.Search("case-a", "ev-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(defense.body("ev-a") == bytes_a);

    std::string foreign_err = "prior";
    BOOST_CHECK(!defense.Search("case-a", "ev-b", foreign_err));
    BOOST_CHECK_EQUAL(foreign_err, "NOT_VISIBLE");

    std::string unknown_err = "prior";
    BOOST_CHECK(!defense.Search("case-a", "ev-missing", unknown_err));
    BOOST_CHECK_EQUAL(unknown_err, "NOT_VISIBLE");
    BOOST_CHECK_EQUAL(foreign_err, unknown_err);

    BOOST_CHECK(defense.body("ev-b") == bytes_b);
    ExpectQuiet(defense);
}

BOOST_AUTO_TEST_SUITE_END()
