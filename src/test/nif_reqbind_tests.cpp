// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_reqbind/nif_reqbind.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

modelnet::NifRequestRecord Complete()
{
    modelnet::NifRequestRecord record;
    record.principal = "principal-a";
    record.receiver = "receiver-a";
    record.realm = "realm-a";
    record.generation = "gen-a";
    record.runtime_image = "image-a";
    record.commitment = "commit-a";
    record.attempt = "attempt-a";
    record.epoch = static_cast<std::uint64_t>(1);
    record.ceiling_bytes = static_cast<std::uint64_t>(64);
    record.lease_until_ms = static_cast<std::uint64_t>(1000);
    return record;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(nif_reqbind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bind_keeps_the_first_attempt)
{
    modelnet::NifReqBind bind;
    std::string err = "stale";
    modelnet::NifRequestRecord found;
    found.principal = "sentinel";

    BOOST_CHECK_EQUAL(bind.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(bind.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!bind.launched());
    BOOST_CHECK(!bind.gpu());
    BOOST_CHECK(!bind.broadcast());
    BOOST_CHECK(!bind.qualified());
    BOOST_CHECK_EQUAL(bind.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(bind.automatic_spend(), "0");
    BOOST_CHECK(!bind.Find("attempt-a", found));
    BOOST_CHECK_EQUAL(found.principal, "sentinel");

    modelnet::NifRequestRecord empty_principal = Complete();
    empty_principal.principal.clear();
    BOOST_CHECK(!bind.Bind(empty_principal, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_REQBIND_FIELD);
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!bind.Find("attempt-a", found));
    BOOST_CHECK_EQUAL(found.principal, "sentinel");

    modelnet::NifRequestRecord epoch_zero = Complete();
    epoch_zero.epoch = static_cast<std::uint64_t>(0);
    BOOST_CHECK(!bind.Bind(epoch_zero, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_REQBIND_BOUND);
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!bind.Find("attempt-a", found));
    BOOST_CHECK_EQUAL(found.principal, "sentinel");

    const modelnet::NifRequestRecord first = Complete();
    BOOST_CHECK(bind.Bind(first, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(bind.Find("attempt-a", found));
    BOOST_CHECK_EQUAL(found.principal, "principal-a");
    BOOST_CHECK_EQUAL(found.attempt, "attempt-a");
    BOOST_CHECK_EQUAL(found.epoch, static_cast<std::uint64_t>(1));
    BOOST_CHECK_EQUAL(found.ceiling_bytes, static_cast<std::uint64_t>(64));
    BOOST_CHECK_EQUAL(found.lease_until_ms, static_cast<std::uint64_t>(1000));

    modelnet::NifRequestRecord replay = Complete();
    replay.principal = "principal-b";
    replay.epoch = static_cast<std::uint64_t>(2);
    replay.ceiling_bytes = static_cast<std::uint64_t>(128);
    BOOST_CHECK(!bind.Bind(replay, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(bind.Find("attempt-a", found));
    BOOST_CHECK_EQUAL(found.principal, "principal-a");
    BOOST_CHECK_EQUAL(found.epoch, static_cast<std::uint64_t>(1));
    BOOST_CHECK_EQUAL(found.ceiling_bytes, static_cast<std::uint64_t>(64));

    BOOST_CHECK(!bind.Find("attempt-b", found));
    BOOST_CHECK_EQUAL(found.principal, "principal-a");

    BOOST_CHECK(!bind.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(bind.Find("attempt-a", found));
    BOOST_CHECK_EQUAL(found.principal, "principal-a");
    BOOST_CHECK_EQUAL(found.receiver, "receiver-a");
    BOOST_CHECK_EQUAL(found.epoch, static_cast<std::uint64_t>(1));
    BOOST_CHECK_EQUAL(bind.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(bind.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!bind.launched());
    BOOST_CHECK(!bind.gpu());
    BOOST_CHECK(!bind.broadcast());
    BOOST_CHECK(!bind.qualified());
    BOOST_CHECK_EQUAL(bind.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_SUITE_END()
