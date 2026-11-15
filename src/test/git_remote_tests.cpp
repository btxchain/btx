// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/git_remote/git_remote.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::GitRemote& remote)
{
    std::string err;
    BOOST_CHECK(!remote.launched());
    BOOST_CHECK(!remote.gpu());
    BOOST_CHECK(!remote.broadcast());
    BOOST_CHECK(!remote.qualified());
    BOOST_CHECK(!remote.release_qualified());
    BOOST_CHECK(!remote.hardware_qualified());
    BOOST_CHECK(!remote.passed());
    BOOST_CHECK_EQUAL(remote.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(remote.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(remote.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(remote.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!remote.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(remote.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(remote.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(remote.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!remote.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!remote.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!remote.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!remote.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!remote.passed());
    BOOST_CHECK_EQUAL(remote.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(git_remote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_https_shell_and_spend)
{
    modelnet::GitRemote remote;
    std::string err = "stale";

    BOOST_CHECK(!remote.Add("origin-a", "shell", err));
    BOOST_CHECK_EQUAL(err, "HELPER");
    BOOST_CHECK(!remote.stored());
    BOOST_CHECK(remote.url().empty());

    BOOST_CHECK(remote.Add("origin-a", "https://example.invalid/repo", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(remote.stored());
    BOOST_CHECK_EQUAL(remote.name(), "origin-a");
    BOOST_CHECK_EQUAL(remote.url(), "https://example.invalid/repo");

    BOOST_CHECK(!remote.Add("origin-b", "https://example.invalid/repo", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(remote.name(), "origin-a");
    BOOST_CHECK_EQUAL(remote.url(), "https://example.invalid/repo");

    BOOST_CHECK(!remote.Add("origin-a", "https://example.invalid/other", err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(remote.url(), "https://example.invalid/repo");

    BOOST_CHECK(!remote.Add("origin-a", "shell", err));
    BOOST_CHECK_EQUAL(err, "HELPER");
    BOOST_CHECK_EQUAL(remote.url(), "https://example.invalid/repo");
    BOOST_CHECK_EQUAL(remote.name(), "origin-a");

    BOOST_CHECK(!remote.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(remote.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(remote.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(remote.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!remote.passed());
    Idle(remote);
}

BOOST_AUTO_TEST_SUITE_END()
