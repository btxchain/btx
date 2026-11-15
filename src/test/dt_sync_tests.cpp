// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_sync/dt_sync.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_sync_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_fragments_commit_head_twenty)
{
    modelnet::DtSync sync;
    std::string err;
    BOOST_CHECK_EQUAL(sync.head(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sync.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(sync.quorum_available());
    BOOST_CHECK(!sync.permanent_leader());
    BOOST_CHECK(!sync.diloco_complete());
    BOOST_CHECK(!sync.launched());
    BOOST_CHECK(!sync.gpu());
    BOOST_CHECK(!sync.broadcast());
    BOOST_CHECK_EQUAL(sync.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(sync.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(sync.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);

    BOOST_CHECK(!sync.Admit("", "m1", static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, "FRAGMENT");
    BOOST_CHECK(!sync.admitted(""));

    BOOST_CHECK(!sync.Admit("a", "", static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_CHECK(!sync.admitted("a"));

    BOOST_CHECK(sync.Admit("a", "first", static_cast<int64_t>(10), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!sync.Admit("a", "second", static_cast<int64_t>(99), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(sync.member("a"), "first");
    BOOST_CHECK_EQUAL(sync.version("a"), static_cast<int64_t>(10));

    BOOST_CHECK(!sync.Commit(err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
    BOOST_CHECK_EQUAL(sync.head(), static_cast<int64_t>(0));

    BOOST_CHECK(sync.Admit("b", "second", static_cast<int64_t>(30), err));
    BOOST_CHECK(sync.Commit(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(sync.head(), static_cast<int64_t>(20));
    BOOST_CHECK_EQUAL(sync.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(third_fragment_lag_three_blocks_commit)
{
    modelnet::DtSync sync;
    std::string err;
    BOOST_CHECK(sync.Admit("a", "m1", static_cast<int64_t>(10), err));
    BOOST_CHECK(sync.Admit("b", "m2", static_cast<int64_t>(30), err));
    BOOST_CHECK(sync.NoteStale("a", static_cast<int64_t>(2), err));
    BOOST_CHECK(sync.usable("a"));
    BOOST_CHECK(sync.Commit(err));
    BOOST_CHECK_EQUAL(sync.head(), static_cast<int64_t>(20));

    BOOST_CHECK(sync.Admit("c", "m3", static_cast<int64_t>(100), err));
    BOOST_CHECK(!sync.NoteStale("c", static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK(sync.admitted("c"));
    BOOST_CHECK(!sync.usable("c"));
    BOOST_CHECK_EQUAL(sync.member("c"), "m3");
    BOOST_CHECK_EQUAL(sync.version("c"), static_cast<int64_t>(100));
    BOOST_CHECK(!sync.Commit(err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(sync.head(), static_cast<int64_t>(20));

    BOOST_CHECK(!sync.NoteStale("", static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, "FRAGMENT");
    BOOST_CHECK(!sync.NoteStale("missing", static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, "FRAGMENT");
    BOOST_CHECK(!sync.admitted("missing"));
    BOOST_CHECK_EQUAL(sync.version("missing"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sync.head(), static_cast<int64_t>(20));
}

BOOST_AUTO_TEST_CASE(replace_synchronizer_leaves_permanent_leader_false)
{
    modelnet::DtSync sync;
    std::string err;
    BOOST_CHECK(!sync.permanent_leader());
    BOOST_CHECK(sync.synchronizer().empty());
    BOOST_CHECK(!sync.Replace("previous", "", err));
    BOOST_CHECK_EQUAL(err, "SYNC");
    BOOST_CHECK(sync.synchronizer().empty());
    BOOST_CHECK(!sync.permanent_leader());

    BOOST_CHECK(sync.Replace("previous", "local", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(sync.synchronizer(), "local");
    BOOST_CHECK(!sync.permanent_leader());
    BOOST_CHECK(!sync.diloco_complete());

    BOOST_CHECK(!sync.Replace("other", "next", err));
    BOOST_CHECK_EQUAL(err, "SYNC");
    BOOST_CHECK_EQUAL(sync.synchronizer(), "local");
    BOOST_CHECK(!sync.permanent_leader());

    BOOST_CHECK(sync.Replace("local", "next", err));
    BOOST_CHECK_EQUAL(sync.synchronizer(), "next");
    BOOST_CHECK(!sync.permanent_leader());
    BOOST_CHECK(!sync.launched());
    BOOST_CHECK(!sync.gpu());
    BOOST_CHECK(!sync.broadcast());
    BOOST_CHECK_EQUAL(sync.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(sync.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(partition_blocks_later_commit)
{
    modelnet::DtSync sync;
    std::string err;
    BOOST_CHECK(sync.quorum_available());
    BOOST_CHECK(sync.Admit("a", "m1", static_cast<int64_t>(10), err));
    BOOST_CHECK(sync.Admit("b", "m2", static_cast<int64_t>(30), err));
    BOOST_CHECK(sync.Commit(err));
    BOOST_CHECK_EQUAL(sync.head(), static_cast<int64_t>(20));

    sync.Partition();
    BOOST_CHECK(!sync.quorum_available());
    BOOST_CHECK(sync.Admit("c", "m3", static_cast<int64_t>(5), err));
    BOOST_CHECK(!sync.NoteStale("c", static_cast<int64_t>(4), err));
    BOOST_CHECK(!sync.Commit(err));
    BOOST_CHECK_EQUAL(err, "PARTITION");
    BOOST_CHECK_EQUAL(sync.head(), static_cast<int64_t>(20));
    BOOST_CHECK_EQUAL(sync.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(wan_is_no_route_and_bytes_stay_zero)
{
    modelnet::DtSync sync;
    std::string err;
    BOOST_CHECK_EQUAL(sync.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sync.head(), static_cast<int64_t>(0));
    BOOST_CHECK(!sync.Wan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(sync.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!sync.Scan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NOT_SCAN);
    BOOST_CHECK_EQUAL(sync.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sync.head(), static_cast<int64_t>(0));
    BOOST_CHECK(!sync.launched());
    BOOST_CHECK(!sync.gpu());
    BOOST_CHECK(!sync.broadcast());
    BOOST_CHECK(!sync.permanent_leader());
    BOOST_CHECK(!sync.diloco_complete());
    BOOST_CHECK_EQUAL(sync.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(sync.physical_hosts(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
