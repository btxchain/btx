// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_moe/dt_moe.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(dt_moe_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(configure_shape_stores_nothing)
{
    modelnet::DtMoe moe;
    std::string err = "prior";
    BOOST_CHECK(!moe.qualified_v41());
    BOOST_CHECK(!moe.gpu());
    BOOST_CHECK(!moe.launched());
    BOOST_CHECK(!moe.broadcast());
    BOOST_CHECK_EQUAL(moe.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(moe.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!moe.Configure(0, 1, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_MOE_SHAPE);
    BOOST_CHECK_EQUAL(moe.experts(), 0);
    BOOST_CHECK_EQUAL(moe.top_k(), 0);
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!moe.Configure(-1, 1, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_MOE_SHAPE);
    BOOST_CHECK(!moe.Configure(4, 0, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK(!moe.Configure(4, 5, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK_EQUAL(moe.experts(), 0);
    BOOST_CHECK_EQUAL(moe.optimizer_owners(0), 0);

    const std::vector<int64_t> scores{
        static_cast<int64_t>(1),
        static_cast<int64_t>(3),
        static_cast<int64_t>(2),
    };
    BOOST_CHECK(!moe.Route(static_cast<int64_t>(1), scores, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_MOE_SHAPE);
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(0));
    BOOST_CHECK(moe.selected().empty());

    BOOST_CHECK(!moe.GpuDispatch(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!moe.gpu());

    BOOST_REQUIRE(moe.Configure(3, 2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(moe.experts(), 3);
    BOOST_CHECK_EQUAL(moe.top_k(), 2);
    BOOST_CHECK_EQUAL(moe.optimizer_owners(0), 1);
    BOOST_CHECK_EQUAL(moe.optimizer_owners(1), 1);
    BOOST_CHECK_EQUAL(moe.optimizer_owners(2), 1);
    BOOST_CHECK_EQUAL(moe.weight(0), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(moe.weight(1), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(moe.weight(2), static_cast<int64_t>(0));

    BOOST_CHECK(!moe.Configure(1, 2, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK_EQUAL(moe.experts(), 3);
    BOOST_CHECK_EQUAL(moe.top_k(), 2);
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!moe.qualified_v41());
}

BOOST_AUTO_TEST_CASE(top2_selects_experts_1_and_2)
{
    modelnet::DtMoe moe;
    std::string err = "prior";
    BOOST_REQUIRE(moe.Configure(3, 2, err));
    BOOST_CHECK(moe.Rematerialize(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(0));

    const std::vector<int64_t> tied{
        static_cast<int64_t>(4),
        static_cast<int64_t>(4),
        static_cast<int64_t>(1),
    };
    BOOST_CHECK(!moe.Route(static_cast<int64_t>(9), tied, err));
    BOOST_CHECK_EQUAL(err, "DUPLICATE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_MOE_DUPLICATE);
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(0));
    BOOST_CHECK(moe.selected().empty());
    BOOST_CHECK_EQUAL(moe.last_token(), static_cast<int64_t>(0));

    const std::vector<int64_t> scores{
        static_cast<int64_t>(1),
        static_cast<int64_t>(3),
        static_cast<int64_t>(2),
    };
    BOOST_CHECK(moe.Route(static_cast<int64_t>(7), scores, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE_EQUAL(moe.selected().size(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(moe.selected()[0], 1);
    BOOST_CHECK_EQUAL(moe.selected()[1], 2);
    BOOST_CHECK(moe.selected()[0] != moe.selected()[1]);
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(moe.last_token(), static_cast<int64_t>(7));

    const std::vector<int64_t> short_scores{static_cast<int64_t>(1), static_cast<int64_t>(2)};
    BOOST_CHECK(!moe.Route(static_cast<int64_t>(8), short_scores, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_MOE_SHAPE);
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(moe.selected()[0], 1);
    BOOST_CHECK_EQUAL(moe.selected()[1], 2);
    BOOST_CHECK_EQUAL(moe.last_token(), static_cast<int64_t>(7));

    BOOST_CHECK(!moe.Route(static_cast<int64_t>(9), tied, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_MOE_DUPLICATE);
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(moe.selected()[0], 1);
    BOOST_CHECK_EQUAL(moe.selected()[1], 2);
    BOOST_CHECK_EQUAL(moe.last_token(), static_cast<int64_t>(7));

    BOOST_CHECK(moe.Rematerialize(err));
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(moe.weight(1), static_cast<int64_t>(0));
    BOOST_CHECK(!moe.gpu());
    BOOST_CHECK(!moe.qualified_v41());
}

BOOST_AUTO_TEST_CASE(duplicate_contribution_single_owner_and_apply_once)
{
    modelnet::DtMoe moe;
    std::string err = "prior";
    BOOST_REQUIRE(moe.Configure(3, 2, err));
    const std::vector<int64_t> scores{
        static_cast<int64_t>(1),
        static_cast<int64_t>(3),
        static_cast<int64_t>(2),
    };
    BOOST_REQUIRE(moe.Route(static_cast<int64_t>(7), scores, err));
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));

    BOOST_CHECK(!moe.Apply(err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK_EQUAL(err, modelnet::DT_MOE_MISSING);
    BOOST_CHECK_EQUAL(moe.weight(0), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(moe.weight(1), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(moe.weight(2), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));

    BOOST_CHECK(moe.Contribute(1, 10, static_cast<int64_t>(4), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(moe.contributed(1));
    BOOST_CHECK_EQUAL(moe.contribution(1), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(moe.optimizer_owners(1), 1);
    BOOST_REQUIRE_EQUAL(moe.replicas(1).size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(moe.replicas(1)[0], 10);

    BOOST_CHECK(!moe.Contribute(1, 11, static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, "DUPLICATE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_MOE_DUPLICATE);
    BOOST_CHECK_EQUAL(moe.contribution(1), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(moe.optimizer_owners(1), 1);
    BOOST_REQUIRE_EQUAL(moe.replicas(1).size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(moe.replicas(1)[0], 10);
    BOOST_CHECK_EQUAL(moe.weight(1), static_cast<int64_t>(0));

    BOOST_CHECK(!moe.Contribute(0, 1, static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_MOE_SHAPE);
    BOOST_CHECK(!moe.contributed(0));
    BOOST_CHECK_EQUAL(moe.contribution(1), static_cast<int64_t>(4));

    BOOST_CHECK(!moe.Apply(err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_MOE_MISSING);
    BOOST_CHECK_EQUAL(moe.weight(0), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(moe.weight(1), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(moe.weight(2), static_cast<int64_t>(0));

    BOOST_CHECK(moe.Contribute(2, 20, static_cast<int64_t>(6), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(moe.optimizer_owners(2), 1);
    BOOST_REQUIRE_EQUAL(moe.replicas(2).size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(moe.replicas(2)[0], 20);
    BOOST_CHECK_EQUAL(moe.contribution(2), static_cast<int64_t>(6));

    BOOST_CHECK(moe.Apply(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(moe.weight(1), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(moe.weight(2), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(moe.weight(0), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));

    BOOST_CHECK(!moe.Apply(err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK_EQUAL(moe.weight(1), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(moe.weight(2), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(moe.optimizer_owners(1), 1);
    BOOST_CHECK_EQUAL(moe.optimizer_owners(2), 1);

    const int64_t tokens = moe.token_count();
    const int64_t weight1 = moe.weight(1);
    const int64_t weight2 = moe.weight(2);
    BOOST_CHECK(moe.Rematerialize(err));
    BOOST_CHECK_EQUAL(moe.token_count(), tokens);
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(moe.weight(1), weight1);
    BOOST_CHECK_EQUAL(moe.weight(2), weight2);

    BOOST_CHECK(!moe.GpuDispatch(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(moe.weight(1), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(moe.weight(2), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(moe.weight(0), static_cast<int64_t>(0));
    BOOST_CHECK(!moe.gpu());
    BOOST_CHECK(!moe.launched());
    BOOST_CHECK(!moe.broadcast());
    BOOST_CHECK(!moe.qualified_v41());
    BOOST_CHECK_EQUAL(moe.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(moe.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(top1_tie_picks_lowest_index)
{
    modelnet::DtMoe moe;
    std::string err = "prior";
    BOOST_REQUIRE(moe.Configure(3, 1, err));
    const std::vector<int64_t> tied{
        static_cast<int64_t>(4),
        static_cast<int64_t>(4),
        static_cast<int64_t>(1),
    };
    BOOST_CHECK(moe.Route(static_cast<int64_t>(3), tied, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE_EQUAL(moe.selected().size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(moe.selected()[0], 0);
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(moe.optimizer_owners(0), 1);

    BOOST_CHECK(moe.Contribute(0, 2, static_cast<int64_t>(8), err));
    BOOST_CHECK(!moe.Contribute(0, 3, static_cast<int64_t>(8), err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_MOE_DUPLICATE);
    BOOST_CHECK_EQUAL(moe.optimizer_owners(0), 1);
    BOOST_CHECK(moe.Apply(err));
    BOOST_CHECK_EQUAL(moe.weight(0), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(moe.weight(1), static_cast<int64_t>(0));
    BOOST_CHECK(moe.Rematerialize(err));
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!moe.GpuDispatch(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(moe.token_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(moe.weight(0), static_cast<int64_t>(8));
    BOOST_CHECK(!moe.launched());
    BOOST_CHECK(!moe.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
