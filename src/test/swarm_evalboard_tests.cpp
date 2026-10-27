// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalboard/board.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_evalboard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_stores_nothing)
{
    modelnet::SwarmEvalProbeBoard board;
    std::string err = "prior";

    BOOST_CHECK(!board.Submit("", "ann", "vision", 10, true, true, err));
    BOOST_CHECK_EQUAL(err, "REPORT");
    BOOST_CHECK(!board.Submit("model", "", "vision", 10, true, true, err));
    BOOST_CHECK_EQUAL(err, "REPORT");
    BOOST_CHECK(!board.Submit("model", "ann", "", 10, true, true, err));
    BOOST_CHECK_EQUAL(err, "REPORT");

    BOOST_REQUIRE(board.scores("model").empty());
    BOOST_REQUIRE(board.scores("").empty());
    BOOST_REQUIRE(!board.accepted("model"));
    BOOST_REQUIRE(!board.attached("model"));
}

BOOST_AUTO_TEST_CASE(self_score_is_not_stored)
{
    modelnet::SwarmEvalProbeBoard board;
    std::string err = "prior";

    BOOST_CHECK(!board.Submit("model", "model", "vision", 10, true, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
    BOOST_REQUIRE(board.scores("model").empty());
    BOOST_REQUIRE(!board.accepted("model"));

    // A held self-score is still NOT_SCORED. The author slot stays open.
    BOOST_CHECK(!board.Submit("model", "model", "vision", 10, false, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
    BOOST_REQUIRE(board.Submit("model", "ann", "vision", 10, true, true, err));
    BOOST_REQUIRE_EQUAL(board.scores("model").size(), 1U);
    BOOST_REQUIRE_EQUAL(board.scores("model")[0].author, "ann");
    BOOST_REQUIRE_EQUAL(board.scores("model")[0].score, 10);
    BOOST_REQUIRE(!board.accepted("model"));
}

BOOST_AUTO_TEST_CASE(held_and_not_rotating_store_nothing)
{
    modelnet::SwarmEvalProbeBoard board;
    std::string err = "prior";

    BOOST_CHECK(!board.Submit("model", "ann", "vision", 10, false, true, err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!board.Submit("model", "ann", "vision", 10, false, false, err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!board.Submit("model", "ben", "language", 20, true, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_ROTATING");
    BOOST_REQUIRE(board.scores("model").empty());
    BOOST_REQUIRE(!board.accepted("model"));

    BOOST_REQUIRE(board.Submit("model", "ann", "vision", 10, true, true, err));
    BOOST_REQUIRE(board.Submit("model", "ben", "language", 20, true, true, err));
    BOOST_REQUIRE_EQUAL(board.scores("model").size(), 2U);
}

BOOST_AUTO_TEST_CASE(score_outside_range_stores_nothing)
{
    modelnet::SwarmEvalProbeBoard board;
    std::string err = "prior";

    BOOST_CHECK(!board.Submit("model", "ann", "vision", -1, true, true, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK(!board.Submit("model", "ann", "vision", 1000001, true, true, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_REQUIRE(board.scores("model").empty());

    BOOST_REQUIRE(board.Submit("model", "ann", "vision", 0, true, true, err));
    BOOST_REQUIRE(board.Submit("model", "ben", "language", 1000000, true, true, err));
    const std::vector<modelnet::SwarmEvalReport> rows = board.scores("model");
    BOOST_REQUIRE_EQUAL(rows.size(), 2U);
    BOOST_REQUIRE_EQUAL(rows[0].score, 0);
    BOOST_REQUIRE_EQUAL(rows[1].score, 1000000);
    // Legal endpoints are stored. Their spread is wider than 10000.
    BOOST_REQUIRE(!board.accepted("model"));

    BOOST_CHECK(!board.Submit("model", "ann", "audio", -1, true, true, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_REQUIRE_EQUAL(board.scores("model").size(), 2U);
    BOOST_REQUIRE_EQUAL(board.scores("model")[0].score, 0);
    BOOST_REQUIRE_EQUAL(board.scores("model")[0].domain, "vision");
}

BOOST_AUTO_TEST_CASE(same_domain_is_not_accepted)
{
    modelnet::SwarmEvalProbeBoard board;
    std::string err = "prior";

    BOOST_REQUIRE(board.Submit("model", "ann", "vision", 40, true, true, err));
    BOOST_REQUIRE(!board.accepted("model"));
    BOOST_CHECK(!board.Attach("model", err));
    BOOST_CHECK_EQUAL(err, "ATTACH");
    BOOST_REQUIRE(!board.attached("model"));

    BOOST_REQUIRE(board.Submit("model", "ben", "vision", 40, true, true, err));
    BOOST_REQUIRE(!board.accepted("model"));
    const std::vector<modelnet::SwarmEvalReport> rows = board.scores("model");
    BOOST_REQUIRE_EQUAL(rows.size(), 2U);
    BOOST_REQUIRE_EQUAL(rows[0].author, "ann");
    BOOST_REQUIRE_EQUAL(rows[0].domain, "vision");
    BOOST_REQUIRE_EQUAL(rows[0].score, 40);
    BOOST_REQUIRE_EQUAL(rows[1].author, "ben");
    BOOST_REQUIRE_EQUAL(rows[1].domain, "vision");
    BOOST_REQUIRE_EQUAL(rows[1].score, 40);

    BOOST_CHECK(!board.Attach("model", err));
    BOOST_CHECK_EQUAL(err, "ATTACH");
    BOOST_REQUIRE(!board.attached("model"));
    BOOST_REQUIRE(board.bytes_moved() == 0);
    BOOST_REQUIRE(!board.gpu());
}

BOOST_AUTO_TEST_CASE(two_domains_within_spread_are_accepted)
{
    modelnet::SwarmEvalProbeBoard board;
    std::string err = "prior";

    BOOST_REQUIRE(board.Submit("model", "ann", "vision", 0, true, true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!board.accepted("model"));
    BOOST_CHECK(!board.Attach("model", err));
    BOOST_CHECK_EQUAL(err, "ATTACH");
    BOOST_REQUIRE(!board.attached("model"));

    BOOST_REQUIRE(board.Submit("model", "ben", "language", 10000, true, true, err));
    BOOST_REQUIRE(board.accepted("model"));
    BOOST_REQUIRE(board.Attach("model", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(board.attached("model"));

    const std::vector<modelnet::SwarmEvalReport> rows = board.scores("model");
    BOOST_REQUIRE_EQUAL(rows.size(), 2U);
    BOOST_REQUIRE_EQUAL(rows[0].author, "ann");
    BOOST_REQUIRE_EQUAL(rows[0].domain, "vision");
    BOOST_REQUIRE_EQUAL(rows[0].score, 0);
    BOOST_REQUIRE(rows[0].independent);
    BOOST_REQUIRE(rows[0].rotating);
    BOOST_REQUIRE_EQUAL(rows[1].author, "ben");
    BOOST_REQUIRE_EQUAL(rows[1].domain, "language");
    BOOST_REQUIRE_EQUAL(rows[1].score, 10000);

    // A third row inside the same spread is stored beside the first two.
    BOOST_REQUIRE(board.Submit("model", "cy", "audio", 5000, true, true, err));
    BOOST_REQUIRE(board.accepted("model"));
    const std::vector<modelnet::SwarmEvalReport> kept = board.scores("model");
    BOOST_REQUIRE_EQUAL(kept.size(), 3U);
    BOOST_REQUIRE_EQUAL(kept[0].score, 0);
    BOOST_REQUIRE_EQUAL(kept[1].score, 10000);
    BOOST_REQUIRE_EQUAL(kept[2].score, 5000);
    BOOST_REQUIRE(board.bytes_moved() == 0);
    BOOST_REQUIRE(!board.gpu());
}

BOOST_AUTO_TEST_CASE(spread_above_10000_is_not_accepted)
{
    modelnet::SwarmEvalProbeBoard board;
    std::string err = "prior";

    BOOST_REQUIRE(board.Submit("wide", "ann", "vision", 0, true, true, err));
    BOOST_REQUIRE(board.Submit("wide", "ben", "language", 10001, true, true, err));
    BOOST_REQUIRE(!board.accepted("wide"));

    const std::vector<modelnet::SwarmEvalReport> rows = board.scores("wide");
    BOOST_REQUIRE_EQUAL(rows.size(), 2U);
    BOOST_REQUIRE_EQUAL(rows[0].score, 0);
    BOOST_REQUIRE_EQUAL(rows[1].score, 10001);
    BOOST_REQUIRE(rows[0].domain != rows[1].domain);

    BOOST_CHECK(!board.Attach("wide", err));
    BOOST_CHECK_EQUAL(err, "ATTACH");
    BOOST_REQUIRE(!board.attached("wide"));
    BOOST_REQUIRE(board.bytes_moved() == 0);
    BOOST_REQUIRE(!board.gpu());
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_score)
{
    modelnet::SwarmEvalProbeBoard board;
    std::string err = "prior";

    BOOST_REQUIRE(board.Submit("model", "ann", "vision", 10, true, true, err));
    BOOST_CHECK(!board.Submit("model", "ann", "language", 99, true, true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    const std::vector<modelnet::SwarmEvalReport> rows = board.scores("model");
    BOOST_REQUIRE_EQUAL(rows.size(), 1U);
    BOOST_REQUIRE_EQUAL(rows[0].author, "ann");
    BOOST_REQUIRE_EQUAL(rows[0].domain, "vision");
    BOOST_REQUIRE_EQUAL(rows[0].score, 10);

    // The same author may score a different subject.
    BOOST_REQUIRE(board.Submit("other", "ann", "audio", 12, true, true, err));
    BOOST_REQUIRE_EQUAL(board.scores("other").size(), 1U);
    BOOST_REQUIRE_EQUAL(board.scores("other")[0].score, 12);
    BOOST_REQUIRE_EQUAL(board.scores("model")[0].score, 10);
}

BOOST_AUTO_TEST_CASE(regression_blocks_attach)
{
    modelnet::SwarmEvalProbeBoard board;
    std::string err = "prior";

    BOOST_REQUIRE(board.Submit("model", "ann", "vision", 100, true, true, err));
    BOOST_REQUIRE(board.Submit("model", "ben", "language", 200, true, true, err));
    BOOST_REQUIRE(board.accepted("model"));
    BOOST_REQUIRE(board.Attach("model", err));
    BOOST_REQUIRE(board.attached("model"));

    BOOST_CHECK(!board.Regress("model", err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_REQUIRE(board.regressed("model"));
    BOOST_REQUIRE(board.accepted("model"));

    const std::vector<modelnet::SwarmEvalReport> rows = board.scores("model");
    BOOST_REQUIRE_EQUAL(rows.size(), 2U);
    BOOST_REQUIRE_EQUAL(rows[0].score, 100);
    BOOST_REQUIRE_EQUAL(rows[1].score, 200);

    BOOST_CHECK(!board.Attach("model", err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_REQUIRE(board.attached("model"));

    // Regression before any attach leaves that subject unattached.
    BOOST_REQUIRE(board.Submit("other", "ann", "vision", 1, true, true, err));
    BOOST_REQUIRE(board.Submit("other", "ben", "audio", 2, true, true, err));
    BOOST_REQUIRE(board.accepted("other"));
    BOOST_CHECK(!board.Regress("other", err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!board.Attach("other", err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_REQUIRE(!board.attached("other"));
    BOOST_REQUIRE_EQUAL(board.scores("other").size(), 2U);
    BOOST_REQUIRE_EQUAL(board.scores("other")[0].score, 1);
    BOOST_REQUIRE_EQUAL(board.scores("other")[1].score, 2);

    BOOST_CHECK(!board.Regress("ghost", err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_REQUIRE(board.scores("ghost").empty());
    BOOST_CHECK(!board.Attach("ghost", err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_REQUIRE(!board.attached("ghost"));
    BOOST_REQUIRE(board.bytes_moved() == 0);
    BOOST_REQUIRE(!board.gpu());
}

BOOST_AUTO_TEST_CASE(graduate_is_refused)
{
    modelnet::SwarmEvalProbeBoard board;
    std::string err = "prior";

    BOOST_REQUIRE(!board.graduated());
    BOOST_REQUIRE_EQUAL(std::string(board.active_id()), "base");
    BOOST_REQUIRE(!board.mines());
    BOOST_REQUIRE(!board.broadcasts());

    BOOST_CHECK(!board.Graduate("model", err));
    BOOST_CHECK_EQUAL(err, "REALM");
    BOOST_REQUIRE(!board.graduated());
    BOOST_REQUIRE_EQUAL(std::string(board.active_id()), "base");

    BOOST_REQUIRE(board.Submit("model", "ann", "vision", 5, true, true, err));
    BOOST_REQUIRE(board.Submit("model", "ben", "language", 9, true, true, err));
    BOOST_REQUIRE(board.accepted("model"));
    BOOST_REQUIRE(board.Attach("model", err));

    BOOST_CHECK(!board.Graduate("model", err));
    BOOST_CHECK_EQUAL(err, "REALM");
    BOOST_REQUIRE(!board.graduated());
    BOOST_REQUIRE_EQUAL(std::string(board.active_id()), "base");
    BOOST_REQUIRE(board.accepted("model"));
    BOOST_REQUIRE(board.attached("model"));
    BOOST_REQUIRE_EQUAL(board.scores("model").size(), 2U);
    BOOST_REQUIRE_EQUAL(board.scores("model")[0].score, 5);
    BOOST_REQUIRE_EQUAL(board.scores("model")[1].score, 9);
    BOOST_REQUIRE(!board.mines());
    BOOST_REQUIRE(!board.broadcasts());
    BOOST_REQUIRE(board.bytes_moved() == 0);
    BOOST_REQUIRE(!board.gpu());
}

BOOST_AUTO_TEST_CASE(bytes_moved_stay_zero)
{
    modelnet::SwarmEvalProbeBoard board;
    std::string err = "prior";

    BOOST_REQUIRE(board.bytes_moved() == 0);
    BOOST_REQUIRE(!board.gpu());
    BOOST_REQUIRE(!board.graduated());
    BOOST_REQUIRE_EQUAL(std::string(board.active_id()), "base");

    BOOST_REQUIRE(board.Submit("model", "ann", "vision", 0, true, true, err));
    BOOST_REQUIRE(board.Submit("model", "ben", "language", 10000, true, true, err));
    BOOST_REQUIRE(board.accepted("model"));
    BOOST_REQUIRE(board.Attach("model", err));
    BOOST_CHECK(!board.Regress("model", err));
    BOOST_CHECK(!board.Graduate("model", err));

    BOOST_REQUIRE(board.bytes_moved() == 0);
    BOOST_REQUIRE(!board.gpu());
    BOOST_REQUIRE(!board.mines());
    BOOST_REQUIRE(!board.broadcasts());
    BOOST_REQUIRE(!board.graduated());
    BOOST_REQUIRE_EQUAL(std::string(board.active_id()), "base");
    BOOST_REQUIRE_EQUAL(board.scores("model").size(), 2U);
    BOOST_REQUIRE_EQUAL(board.scores("model")[0].score, 0);
    BOOST_REQUIRE_EQUAL(board.scores("model")[1].score, 10000);
}

BOOST_AUTO_TEST_SUITE_END()
