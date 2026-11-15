// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_guard/nif_guard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(nif_guard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stale_leader_is_not_stored)
{
    modelnet::NifGuard guard;
    std::string err;

    BOOST_CHECK_EQUAL(guard.leader_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.Leader("L", static_cast<int64_t>(4), static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(guard.leader_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.leader_stored("L"));
    BOOST_CHECK_EQUAL(guard.leader_epoch("L"), static_cast<int64_t>(0));

    BOOST_CHECK(guard.Leader("L", static_cast<int64_t>(5), static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(guard.leader_count(), static_cast<int64_t>(1));
    BOOST_CHECK(guard.leader_stored("L"));
    BOOST_CHECK_EQUAL(guard.leader_epoch("L"), static_cast<int64_t>(5));

    BOOST_CHECK(!guard.Leader("L", static_cast<int64_t>(5), static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(guard.leader_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(guard.leader_epoch("L"), static_cast<int64_t>(5));

    BOOST_CHECK(!guard.Leader("L", static_cast<int64_t>(4), static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(guard.leader_count(), static_cast<int64_t>(1));
    BOOST_CHECK(guard.leader_stored("L"));
    BOOST_CHECK_EQUAL(guard.leader_epoch("L"), static_cast<int64_t>(5));

    BOOST_CHECK(!guard.Leader("old", static_cast<int64_t>(1), static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(guard.leader_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!guard.leader_stored("old"));
    BOOST_CHECK_EQUAL(guard.leader_epoch("old"), static_cast<int64_t>(0));

    modelnet::NifGuard zero;
    BOOST_CHECK(zero.Leader("z", static_cast<int64_t>(0), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(zero.leader_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(zero.leader_epoch("z"), static_cast<int64_t>(0));
    BOOST_CHECK(!zero.Leader("neg", static_cast<int64_t>(-1), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(zero.leader_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!zero.leader_stored("neg"));
    BOOST_CHECK_EQUAL(zero.leader_epoch("neg"), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(expired_cohort_is_not_stored)
{
    modelnet::NifGuard guard;
    std::string err;

    BOOST_CHECK_EQUAL(guard.cohort_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.Cohort("c", static_cast<int64_t>(10), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(guard.cohort_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.cohort_stored("c"));

    BOOST_CHECK(!guard.Cohort("c", static_cast<int64_t>(11), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(guard.cohort_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.cohort_stored("c"));

    BOOST_CHECK(guard.Cohort("c", static_cast<int64_t>(9), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(guard.cohort_count(), static_cast<int64_t>(1));
    BOOST_CHECK(guard.cohort_stored("c"));

    BOOST_CHECK(!guard.Cohort("c", static_cast<int64_t>(9), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(guard.cohort_count(), static_cast<int64_t>(1));

    BOOST_CHECK(!guard.Cohort("late", static_cast<int64_t>(10), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(guard.cohort_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!guard.cohort_stored("late"));
    BOOST_CHECK(guard.cohort_stored("c"));
}

BOOST_AUTO_TEST_CASE(revoked_data_is_not_stored)
{
    modelnet::NifGuard guard;
    std::string err;

    BOOST_CHECK_EQUAL(guard.data_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.Data("d", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
    BOOST_CHECK_EQUAL(guard.data_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.data_stored("d"));

    BOOST_CHECK(guard.Data("d", false, err));
    BOOST_CHECK_EQUAL(guard.data_count(), static_cast<int64_t>(1));
    BOOST_CHECK(guard.data_stored("d"));

    BOOST_CHECK(!guard.Data("d", false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(guard.data_count(), static_cast<int64_t>(1));

    BOOST_CHECK(!guard.Data("gone", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
    BOOST_CHECK_EQUAL(guard.data_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!guard.data_stored("gone"));
    BOOST_CHECK(guard.data_stored("d"));
}

BOOST_AUTO_TEST_CASE(foreign_tenant_cache_is_not_stored)
{
    modelnet::NifGuard guard;
    std::string err;

    BOOST_CHECK_EQUAL(guard.cache_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.Cache("ten", "key-a", "other", err));
    BOOST_CHECK_EQUAL(err, "TENANT");
    BOOST_CHECK_EQUAL(guard.cache_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.cache_stored("ten"));
    BOOST_CHECK(!guard.cache_stored("other"));
    BOOST_CHECK(guard.cache_key("ten").empty());

    BOOST_CHECK(guard.Cache("ten", "key-a", "ten", err));
    BOOST_CHECK_EQUAL(guard.cache_count(), static_cast<int64_t>(1));
    BOOST_CHECK(guard.cache_stored("ten"));
    BOOST_CHECK_EQUAL(guard.cache_key("ten"), "key-a");

    BOOST_CHECK(!guard.Cache("ten", "key-b", "ten", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(guard.cache_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(guard.cache_key("ten"), "key-a");

    BOOST_CHECK(!guard.Cache("ten", "key-a", "other", err));
    BOOST_CHECK_EQUAL(err, "TENANT");
    BOOST_CHECK_EQUAL(guard.cache_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(guard.cache_key("ten"), "key-a");
    BOOST_CHECK(!guard.cache_stored("other"));
}

BOOST_AUTO_TEST_CASE(receipt_replay_does_not_add)
{
    modelnet::NifGuard guard;
    std::string err;

    BOOST_CHECK_EQUAL(guard.receipt_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.receipt_stored("r"));
    BOOST_CHECK(guard.Receipt("r", err));
    BOOST_CHECK_EQUAL(guard.receipt_count(), static_cast<int64_t>(1));
    BOOST_CHECK(guard.receipt_stored("r"));

    BOOST_CHECK(!guard.Receipt("r", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(guard.receipt_count(), static_cast<int64_t>(1));
    BOOST_CHECK(guard.receipt_stored("r"));
}

BOOST_AUTO_TEST_CASE(checkpoint_code_is_not_stored)
{
    modelnet::NifGuard guard;
    std::string err;

    BOOST_CHECK_EQUAL(guard.checkpoint_count(), static_cast<int64_t>(0));
    BOOST_CHECK(guard.checkpoint().empty());
    BOOST_CHECK(!guard.executable());

    const std::vector<unsigned char> elf{0x7f, 'E', 'L', 'F', 'x'};
    BOOST_CHECK(!guard.Checkpoint(elf, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(guard.checkpoint_count(), static_cast<int64_t>(0));
    BOOST_CHECK(guard.checkpoint().empty());
    BOOST_CHECK(!guard.executable());

    const std::vector<unsigned char> elf_only{0x7f, 'E', 'L', 'F'};
    BOOST_CHECK(!guard.Checkpoint(elf_only, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(guard.checkpoint_count(), static_cast<int64_t>(0));
    BOOST_CHECK(guard.checkpoint().empty());

    std::vector<unsigned char> pickle{'a'};
    const char marker[] = "PYTHON_PICKLE";
    pickle.insert(pickle.end(), marker, marker + sizeof(marker) - 1);
    BOOST_CHECK(!guard.Checkpoint(pickle, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(guard.checkpoint_count(), static_cast<int64_t>(0));
    BOOST_CHECK(guard.checkpoint().empty());
    BOOST_CHECK(!guard.executable());

    const std::vector<unsigned char> pickle_only(marker, marker + sizeof(marker) - 1);
    BOOST_CHECK(!guard.Checkpoint(pickle_only, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(guard.checkpoint_count(), static_cast<int64_t>(0));

    const std::vector<unsigned char> plain{'p', 'l', 'a', 'i', 'n'};
    BOOST_CHECK(guard.Checkpoint(plain, err));
    BOOST_CHECK(guard.checkpoint() == plain);
    BOOST_CHECK_EQUAL(guard.checkpoint_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!guard.executable());

    BOOST_CHECK(!guard.Checkpoint(elf, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(guard.checkpoint() == plain);
    BOOST_CHECK_EQUAL(guard.checkpoint_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!guard.executable());

    BOOST_CHECK(!guard.Checkpoint(pickle, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(guard.checkpoint() == plain);
    BOOST_CHECK_EQUAL(guard.checkpoint_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!guard.executable());
}

BOOST_AUTO_TEST_CASE(negative_rank_is_not_stored)
{
    modelnet::NifGuard guard;
    std::string err;

    BOOST_CHECK_EQUAL(guard.tensor_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.Tensor(static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "METADATA");
    BOOST_CHECK_EQUAL(guard.tensor_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.tensor_stored(static_cast<int64_t>(-1)));

    BOOST_CHECK(guard.Tensor(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(guard.tensor_count(), static_cast<int64_t>(1));
    BOOST_CHECK(guard.tensor_stored(static_cast<int64_t>(0)));

    BOOST_CHECK(!guard.Tensor(static_cast<int64_t>(-2), err));
    BOOST_CHECK_EQUAL(err, "METADATA");
    BOOST_CHECK_EQUAL(guard.tensor_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!guard.tensor_stored(static_cast<int64_t>(-2)));
    BOOST_CHECK(guard.tensor_stored(static_cast<int64_t>(0)));
}

BOOST_AUTO_TEST_CASE(spend_key_is_not_stored)
{
    modelnet::NifGuard guard;
    std::string err;

    BOOST_CHECK(!guard.launched());
    BOOST_CHECK(!guard.gpu());
    BOOST_CHECK(!guard.broadcast());
    BOOST_CHECK(!guard.executable());
    BOOST_CHECK(!guard.spend_key_held());
    BOOST_CHECK_EQUAL(guard.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(guard.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(guard.wallet_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!guard.Wallet(true, err));
    BOOST_CHECK_EQUAL(err, "WALLET");
    BOOST_CHECK_EQUAL(guard.wallet_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!guard.spend_key_held());
    BOOST_CHECK_EQUAL(guard.automatic_spend(), "0");

    BOOST_CHECK(guard.Wallet(false, err));
    BOOST_CHECK_EQUAL(guard.wallet_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!guard.spend_key_held());
    BOOST_CHECK_EQUAL(guard.automatic_spend(), "0");

    BOOST_CHECK(!guard.Wallet(true, err));
    BOOST_CHECK_EQUAL(err, "WALLET");
    BOOST_CHECK_EQUAL(guard.wallet_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!guard.spend_key_held());
    BOOST_CHECK_EQUAL(guard.automatic_spend(), "0");
    BOOST_CHECK(!guard.launched());
    BOOST_CHECK(!guard.gpu());
    BOOST_CHECK(!guard.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
