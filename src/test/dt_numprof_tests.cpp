// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_numprof/dt_numprof.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_numprof_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(four_profiles_store_a_complete_shape)
{
    modelnet::DtNumProf prof;
    std::string err = "prior";

    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.qualified());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK(!prof.launched());
    BOOST_CHECK(!prof.gpu());
    BOOST_CHECK(!prof.broadcast());
    BOOST_CHECK_EQUAL(prof.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(prof.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(prof.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!prof.defined(modelnet::DT_NUMPROF_CED));
    BOOST_CHECK(!prof.defined(modelnet::DT_NUMPROF_CSA2));
    BOOST_CHECK(!prof.defined(modelnet::DT_NUMPROF_ENGRAM));
    BOOST_CHECK(!prof.defined(modelnet::DT_NUMPROF_MHC));

    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_CED, static_cast<int64_t>(64), static_cast<int64_t>(4), static_cast<int64_t>(8), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(prof.defined(modelnet::DT_NUMPROF_CED));
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(64));
    BOOST_CHECK_EQUAL(prof.layers(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(prof.heads(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(8));

    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_CSA2, static_cast<int64_t>(32), static_cast<int64_t>(2), static_cast<int64_t>(4), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(prof.defined(modelnet::DT_NUMPROF_CSA2));
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_CSA2), static_cast<int64_t>(32));
    BOOST_CHECK_EQUAL(prof.layers(modelnet::DT_NUMPROF_CSA2), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(prof.heads(modelnet::DT_NUMPROF_CSA2), static_cast<int64_t>(4));

    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_ENGRAM, static_cast<int64_t>(16), static_cast<int64_t>(3), static_cast<int64_t>(2), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(prof.defined(modelnet::DT_NUMPROF_ENGRAM));
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_ENGRAM), static_cast<int64_t>(16));
    BOOST_CHECK_EQUAL(prof.layers(modelnet::DT_NUMPROF_ENGRAM), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(prof.heads(modelnet::DT_NUMPROF_ENGRAM), static_cast<int64_t>(2));

    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_MHC, static_cast<int64_t>(128), static_cast<int64_t>(6), static_cast<int64_t>(16), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(prof.defined(modelnet::DT_NUMPROF_MHC));
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_MHC), static_cast<int64_t>(128));
    BOOST_CHECK_EQUAL(prof.layers(modelnet::DT_NUMPROF_MHC), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(prof.heads(modelnet::DT_NUMPROF_MHC), static_cast<int64_t>(16));

    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.qualified());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK(!prof.launched());
    BOOST_CHECK(!prof.gpu());
    BOOST_CHECK(!prof.broadcast());
    BOOST_CHECK_EQUAL(prof.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(prof.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(unknown_name_stores_nothing)
{
    modelnet::DtNumProf prof;
    std::string err = "prior";

    BOOST_CHECK(!prof.Define("other", static_cast<int64_t>(8), static_cast<int64_t>(2), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_NAME);
    BOOST_CHECK(!prof.defined("other"));
    BOOST_CHECK_EQUAL(prof.hidden("other"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.layers("other"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.heads("other"), static_cast<int64_t>(0));

    BOOST_CHECK(!prof.Define("", static_cast<int64_t>(8), static_cast<int64_t>(2), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_NAME);
    BOOST_CHECK(!prof.defined(""));

    BOOST_CHECK(!prof.Define("CED", static_cast<int64_t>(8), static_cast<int64_t>(2), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_NAME);
    BOOST_CHECK(!prof.defined(modelnet::DT_NUMPROF_CED));
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(0));

    BOOST_CHECK(!prof.Advertise("other", err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_NAME);
    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.qualified());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK_EQUAL(prof.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(prof.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(zero_hidden_stores_nothing)
{
    modelnet::DtNumProf prof;
    std::string err = "prior";

    BOOST_CHECK(!prof.Define(modelnet::DT_NUMPROF_CED, static_cast<int64_t>(0), static_cast<int64_t>(4), static_cast<int64_t>(8), err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_SHAPE);
    BOOST_CHECK(!prof.defined(modelnet::DT_NUMPROF_CED));
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.layers(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.heads(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(0));

    BOOST_CHECK(!prof.Define(modelnet::DT_NUMPROF_CSA2, static_cast<int64_t>(-1), static_cast<int64_t>(2), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_SHAPE);
    BOOST_CHECK(!prof.defined(modelnet::DT_NUMPROF_CSA2));

    BOOST_CHECK(!prof.Define(modelnet::DT_NUMPROF_ENGRAM, static_cast<int64_t>(16), static_cast<int64_t>(0), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_SHAPE);
    BOOST_CHECK(!prof.defined(modelnet::DT_NUMPROF_ENGRAM));
    BOOST_CHECK_EQUAL(prof.layers(modelnet::DT_NUMPROF_ENGRAM), static_cast<int64_t>(0));

    BOOST_CHECK(!prof.Define(modelnet::DT_NUMPROF_MHC, static_cast<int64_t>(16), static_cast<int64_t>(2), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_SHAPE);
    BOOST_CHECK(!prof.defined(modelnet::DT_NUMPROF_MHC));
    BOOST_CHECK_EQUAL(prof.heads(modelnet::DT_NUMPROF_MHC), static_cast<int64_t>(0));

    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK_EQUAL(prof.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_hidden_size)
{
    modelnet::DtNumProf prof;
    std::string err = "prior";

    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_CED, static_cast<int64_t>(64), static_cast<int64_t>(4), static_cast<int64_t>(8), err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!prof.Define(modelnet::DT_NUMPROF_CED, static_cast<int64_t>(128), static_cast<int64_t>(9), static_cast<int64_t>(16), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(prof.defined(modelnet::DT_NUMPROF_CED));
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(64));
    BOOST_CHECK_EQUAL(prof.layers(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(prof.heads(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(8));

    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_CSA2, static_cast<int64_t>(32), static_cast<int64_t>(2), static_cast<int64_t>(4), err));
    BOOST_CHECK(!prof.Define(modelnet::DT_NUMPROF_CSA2, static_cast<int64_t>(7), static_cast<int64_t>(2), static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_CSA2), static_cast<int64_t>(32));

    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_ENGRAM, static_cast<int64_t>(16), static_cast<int64_t>(3), static_cast<int64_t>(2), err));
    BOOST_CHECK(!prof.Define(modelnet::DT_NUMPROF_ENGRAM, static_cast<int64_t>(16), static_cast<int64_t>(1), static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_ENGRAM), static_cast<int64_t>(16));
    BOOST_CHECK_EQUAL(prof.layers(modelnet::DT_NUMPROF_ENGRAM), static_cast<int64_t>(3));

    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_MHC, static_cast<int64_t>(128), static_cast<int64_t>(6), static_cast<int64_t>(16), err));
    BOOST_CHECK(!prof.Define(modelnet::DT_NUMPROF_MHC, static_cast<int64_t>(1), static_cast<int64_t>(1), static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_MHC), static_cast<int64_t>(128));
    BOOST_CHECK_EQUAL(prof.heads(modelnet::DT_NUMPROF_MHC), static_cast<int64_t>(16));

    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.qualified());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK_EQUAL(prof.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(advertise_before_define_is_incomplete)
{
    modelnet::DtNumProf prof;
    std::string err = "prior";

    BOOST_CHECK(!prof.Advertise(modelnet::DT_NUMPROF_CED, err));
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_INCOMPLETE);
    BOOST_CHECK(!prof.defined(modelnet::DT_NUMPROF_CED));
    BOOST_CHECK(!prof.advertised());

    BOOST_CHECK(!prof.Advertise(modelnet::DT_NUMPROF_CSA2, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_INCOMPLETE);
    BOOST_CHECK(!prof.defined(modelnet::DT_NUMPROF_CSA2));
    BOOST_CHECK(!prof.advertised());

    BOOST_CHECK(!prof.Advertise(modelnet::DT_NUMPROF_ENGRAM, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_INCOMPLETE);
    BOOST_CHECK(!prof.advertised());

    BOOST_CHECK(!prof.Advertise(modelnet::DT_NUMPROF_MHC, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_NUMPROF_INCOMPLETE);
    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.qualified());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK(!prof.launched());
    BOOST_CHECK(!prof.gpu());
    BOOST_CHECK(!prof.broadcast());
    BOOST_CHECK_EQUAL(prof.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(prof.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(advertise_after_define_is_unqualified)
{
    modelnet::DtNumProf prof;
    std::string err = "prior";

    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_CED, static_cast<int64_t>(64), static_cast<int64_t>(4), static_cast<int64_t>(8), err));
    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_CSA2, static_cast<int64_t>(32), static_cast<int64_t>(2), static_cast<int64_t>(4), err));
    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_ENGRAM, static_cast<int64_t>(16), static_cast<int64_t>(3), static_cast<int64_t>(2), err));
    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_MHC, static_cast<int64_t>(128), static_cast<int64_t>(6), static_cast<int64_t>(16), err));

    BOOST_CHECK(!prof.Advertise(modelnet::DT_NUMPROF_CED, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.qualified());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(64));

    BOOST_CHECK(!prof.Advertise(modelnet::DT_NUMPROF_CSA2, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!prof.advertised());

    BOOST_CHECK(!prof.Advertise(modelnet::DT_NUMPROF_ENGRAM, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!prof.advertised());

    BOOST_CHECK(!prof.Advertise(modelnet::DT_NUMPROF_MHC, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.qualified());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK(!prof.launched());
    BOOST_CHECK(!prof.gpu());
    BOOST_CHECK(!prof.broadcast());
    BOOST_CHECK_EQUAL(prof.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(prof.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(gpu_is_engine_absent)
{
    modelnet::DtNumProf prof;
    std::string err = "prior";

    BOOST_CHECK(prof.Define(modelnet::DT_NUMPROF_CED, static_cast<int64_t>(64), static_cast<int64_t>(4), static_cast<int64_t>(8), err));

    BOOST_CHECK(!prof.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!prof.advertised());
    BOOST_CHECK(!prof.qualified());
    BOOST_CHECK(!prof.hardware_qualified());
    BOOST_CHECK(!prof.gpu());
    BOOST_CHECK(!prof.launched());
    BOOST_CHECK(!prof.broadcast());
    BOOST_CHECK(prof.defined(modelnet::DT_NUMPROF_CED));
    BOOST_CHECK_EQUAL(prof.hidden(modelnet::DT_NUMPROF_CED), static_cast<int64_t>(64));
    BOOST_CHECK_EQUAL(prof.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(prof.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(prof.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
