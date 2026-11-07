// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/git_origin/git_origin.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::GitOrigin& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(git_origin_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_digest_sha1_replay_hosts_and_spend)
{
    modelnet::GitOrigin eng;
    std::string err = "stale";
    const std::string name = "origin-a";
    const std::string digest(64, 'a');

    BOOST_CHECK(!eng.Record(name, "sha1", err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK(!eng.stored(name));
    BOOST_CHECK(eng.digest(name).empty());

    BOOST_CHECK(eng.Record(name, digest, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored(name));
    BOOST_CHECK_EQUAL(eng.digest(name), digest);

    BOOST_CHECK(!eng.Record(name, digest, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.digest(name), digest);

    const std::string other(64, 'b');
    BOOST_CHECK(!eng.Record(name, other, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.digest(name), digest);

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.digest(name), digest);

    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
