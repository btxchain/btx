// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_ancestry.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_ancestry_tests, BasicTestingSetup)

namespace {

std::string HexId(char nibble)
{
    return std::string(96, nibble);
}

modelnet::ContributionLink Link(std::string id, std::string kind, std::vector<std::string> physical, std::vector<std::string> informed, bool announcement = false)
{
    modelnet::ContributionLink link;
    link.record_id = std::move(id);
    link.kind = std::move(kind);
    link.physical_parent_ids = std::move(physical);
    link.informed_by = std::move(informed);
    link.announcement = announcement;
    return link;
}

bool Contains(const std::vector<std::string>& ids, const std::string& id)
{
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}

} // namespace

BOOST_AUTO_TEST_CASE(negative_result_via_informed_by_keeps_separate_physical_parent)
{
    const std::string hypothesis = HexId('1');
    const std::string parent = HexId('2');
    const std::string negative = HexId('3');
    BOOST_REQUIRE(parent != negative);

    std::map<std::string, modelnet::ContributionLink> links;
    links.emplace(hypothesis, Link(hypothesis, "HYPOTHESIS", {parent}, {negative}));
    links.emplace(parent, Link(parent, "EXPERIMENT", {}, {}));
    links.emplace(negative, Link(negative, "NEGATIVE_RESULT", {}, {}));

    modelnet::AncestryReport report;
    std::string err;
    BOOST_REQUIRE(modelnet::WalkAncestry(hypothesis, links, report, err));
    BOOST_CHECK(err.empty());
    const std::vector<std::string> expected{hypothesis, parent, negative};
    BOOST_CHECK(report.record_ids == expected);
    BOOST_CHECK(report.includes_negative);
    BOOST_CHECK(report.informed_edges >= 1);
    BOOST_CHECK(report.physical_edges >= 1);
    BOOST_CHECK(Contains(report.record_ids, parent));
    BOOST_CHECK(Contains(report.record_ids, negative));
    BOOST_CHECK(report.missing_ids.empty());
}

BOOST_AUTO_TEST_CASE(cycle_returns_schema)
{
    const std::string left = HexId('a');
    const std::string right = HexId('b');
    std::map<std::string, modelnet::ContributionLink> links;
    links.emplace(left, Link(left, "HYPOTHESIS", {right}, {}));
    links.emplace(right, Link(right, "EXPERIMENT", {left}, {}));

    modelnet::AncestryReport report;
    report.record_ids.push_back(HexId('c'));
    report.physical_edges = 4;
    std::string err = "stale";
    BOOST_CHECK(!modelnet::WalkAncestry(left, links, report, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(report.record_ids.empty());
    BOOST_CHECK_EQUAL(report.physical_edges, 0U);
    BOOST_CHECK_EQUAL(report.informed_edges, 0U);
    BOOST_CHECK(report.missing_ids.empty());
    BOOST_CHECK(!report.includes_negative);
}

BOOST_AUTO_TEST_CASE(announcement_cited_via_informed_by_is_absent_from_record_ids)
{
    const std::string start = HexId('c');
    const std::string announcement = HexId('d');
    std::map<std::string, modelnet::ContributionLink> links;
    links.emplace(start, Link(start, "HYPOTHESIS", {}, {announcement}));
    links.emplace(announcement, Link(announcement, "", {}, {}, true));

    modelnet::AncestryReport report;
    std::string err;
    BOOST_REQUIRE(modelnet::WalkAncestry(start, links, report, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!Contains(report.record_ids, announcement));
    BOOST_CHECK(report.record_ids == std::vector<std::string>{start});
    BOOST_CHECK_EQUAL(report.informed_edges, 0U);
    BOOST_CHECK_EQUAL(report.physical_edges, 0U);
    BOOST_CHECK(!Contains(report.missing_ids, announcement));
}

BOOST_AUTO_TEST_CASE(missing_informed_by_is_listed_and_walk_succeeds)
{
    const std::string start = HexId('e');
    const std::string missing = HexId('f');
    std::map<std::string, modelnet::ContributionLink> links;
    links.emplace(start, Link(start, "SYNTHESIS", {}, {missing}));

    modelnet::AncestryReport report;
    std::string err;
    BOOST_REQUIRE(modelnet::WalkAncestry(start, links, report, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(Contains(report.missing_ids, missing));
    BOOST_CHECK(!Contains(report.record_ids, missing));
    BOOST_CHECK(report.record_ids == std::vector<std::string>{start});
    BOOST_CHECK_EQUAL(report.informed_edges, 0U);
    BOOST_CHECK(!report.includes_negative);
}

BOOST_AUTO_TEST_SUITE_END()
