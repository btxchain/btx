// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_data/dt_data.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_data_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(public_training_admit_advances_cursor)
{
    modelnet::DtData data;
    std::string err = "stale";
    BOOST_CHECK(data.Admit("pub", "mit", "training", "public_trajectory", "training", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(data.admitted("pub"));
    BOOST_CHECK_EQUAL(data.license("pub"), "mit");
    BOOST_CHECK_EQUAL(data.purpose("pub"), "training");
    BOOST_CHECK_EQUAL(data.Cursor("pub", err), static_cast<int64_t>(0));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(data.Train("pub", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(data.Cursor("pub", err), static_cast<int64_t>(1));
    BOOST_CHECK(data.Train("pub", err));
    BOOST_CHECK_EQUAL(data.Cursor("pub", err), static_cast<int64_t>(2));

    BOOST_CHECK(data.Admit("syn", "apache", "training", "synthetic_trajectory", "shard-0", err));
    BOOST_CHECK_EQUAL(data.Cursor("syn", err), static_cast<int64_t>(0));
    BOOST_CHECK(data.Train("syn", err));
    BOOST_CHECK_EQUAL(data.Cursor("syn", err), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(data.Cursor("pub", err), static_cast<int64_t>(2));

    BOOST_CHECK(!data.Train("absent", err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK_EQUAL(data.Cursor("absent", err), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(err, "DATASET");

    BOOST_CHECK(!data.launched());
    BOOST_CHECK(!data.gpu());
    BOOST_CHECK(!data.broadcast());
    BOOST_CHECK_EQUAL(data.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(data.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(incident_kind_stores_nothing)
{
    modelnet::DtData data;
    std::string err = "stale";
    BOOST_CHECK(!data.Admit("inc", "secret-license", "training", "incident", "training", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!data.admitted("inc"));
    BOOST_CHECK(data.license("inc").empty());
    BOOST_CHECK(data.purpose("inc").empty());
    BOOST_CHECK_EQUAL(data.Cursor("inc", err), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK(!data.Train("inc", err));
    BOOST_CHECK_EQUAL(err, "DATASET");

    BOOST_CHECK(data.Admit("inc", "public-license", "training", "public_trajectory", "training", err));
    BOOST_CHECK_EQUAL(data.license("inc"), "public-license");
    BOOST_CHECK_EQUAL(data.Cursor("inc", err), static_cast<int64_t>(0));

    BOOST_CHECK(!data.Admit("priv", "secret-license", "training", "private", "training", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!data.admitted("priv"));
    BOOST_CHECK_EQUAL(data.Cursor("priv", err), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(err, "DATASET");

    BOOST_CHECK(!data.Admit("misc", "lic", "training", "internal", "training", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!data.admitted("misc"));

    BOOST_CHECK(!data.Admit("", "lic", "training", "public_trajectory", "training", err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK(!data.admitted(""));

    BOOST_CHECK(!data.Admit("blank-lic", "", "training", "public_trajectory", "training", err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK(!data.admitted("blank-lic"));
    BOOST_CHECK_EQUAL(data.Cursor("blank-lic", err), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(evaluation_data_is_not_trained)
{
    modelnet::DtData data;
    std::string err = "stale";
    BOOST_CHECK(data.Admit("train", "mit", "training", "public_trajectory", "training", err));
    BOOST_CHECK(data.Admit("hold", "eval-license", "evaluation", "public_trajectory", "evaluation", err));
    BOOST_CHECK(data.admitted("hold"));
    BOOST_CHECK_EQUAL(data.purpose("hold"), "evaluation");
    BOOST_CHECK_EQUAL(data.Cursor("hold", err), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK(!data.Train("hold", err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK(!data.Train("hold", err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK_EQUAL(data.Cursor("train", err), static_cast<int64_t>(0));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(data.Train("train", err));
    BOOST_CHECK_EQUAL(data.Cursor("train", err), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(data.Cursor("hold", err), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");

    BOOST_CHECK(data.Admit("hold-syn", "lic", "evaluation", "synthetic_trajectory", "shard-eval", err));
    BOOST_CHECK(!data.Train("hold-syn", err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK_EQUAL(data.Cursor("train", err), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(duplicate_admit_keeps_first_license)
{
    modelnet::DtData data;
    std::string err = "stale";
    BOOST_CHECK(data.Admit("pub", "first-license", "training", "public_trajectory", "part-a", err));
    BOOST_CHECK(data.Train("pub", err));
    BOOST_CHECK_EQUAL(data.Cursor("pub", err), static_cast<int64_t>(1));

    BOOST_CHECK(!data.Admit("pub", "second-license", "evaluation", "synthetic_trajectory", "part-b", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(data.license("pub"), "first-license");
    BOOST_CHECK_EQUAL(data.purpose("pub"), "training");
    BOOST_CHECK_EQUAL(data.kind("pub"), "public_trajectory");
    BOOST_CHECK_EQUAL(data.partition("pub"), "part-a");
    BOOST_CHECK(data.Train("pub", err));
    BOOST_CHECK_EQUAL(data.Cursor("pub", err), static_cast<int64_t>(2));

    BOOST_CHECK(!data.Admit("pub", "", "training", "public_trajectory", "part-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(data.license("pub"), "first-license");
}

BOOST_AUTO_TEST_CASE(defensive_purpose_is_refused)
{
    modelnet::DtData data;
    std::string err = "stale";
    BOOST_CHECK(!data.Admit("sec", "nope", "defensive", "public_trajectory", "training", err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORIZED");
    BOOST_CHECK(!data.admitted("sec"));
    BOOST_CHECK(data.license("sec").empty());
    BOOST_CHECK(data.purpose("sec").empty());
    BOOST_CHECK_EQUAL(data.Cursor("sec", err), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK(!data.Train("sec", err));
    BOOST_CHECK_EQUAL(err, "DATASET");

    BOOST_CHECK(data.Admit("sec", "yes", "training", "public_trajectory", "training", err));
    BOOST_CHECK_EQUAL(data.license("sec"), "yes");
    BOOST_CHECK_EQUAL(data.purpose("sec"), "training");
    BOOST_CHECK_EQUAL(data.Cursor("sec", err), static_cast<int64_t>(0));

    BOOST_CHECK(!data.Admit("blank-purpose", "mit", "", "synthetic_trajectory", "training", err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORIZED");
    BOOST_CHECK(!data.admitted("blank-purpose"));

    BOOST_CHECK(!data.launched());
    BOOST_CHECK(!data.gpu());
    BOOST_CHECK(!data.broadcast());
    BOOST_CHECK_EQUAL(data.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
