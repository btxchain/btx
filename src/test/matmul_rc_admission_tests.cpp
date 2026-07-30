// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <boost/test/unit_test.hpp>

#include <arith_uint256.h>
#include <node/matmul_rc_admission.h>

#include <chrono>
#include <limits>

BOOST_AUTO_TEST_SUITE(matmul_rc_admission_tests)

namespace {
CBlockHeader Header()
{
    CBlockHeader h;
    h.nVersion = 4;
    h.nTime = 1'900'000'000;
    h.nBits = 0x207fffff; // regtest-easy target
    h.nNonce64 = 7;
    h.hashPrevBlock = uint256{1};
    h.hashMerkleRoot = uint256{2};
    h.matmul_digest = uint256{3};
    h.seed_a = uint256{4};
    h.seed_b = uint256{5};
    h.matmul_dim = 32;
    return h;
}

uint256 RegtestPowLimit()
{
    arith_uint256 limit;
    limit.SetCompact(0x207fffff);
    return ArithToUint256(limit);
}

arith_uint256 WorkTarget(uint32_t bits)
{
    arith_uint256 target{1};
    target <<= 256 - bits;
    target -= 1;
    return target;
}
} // namespace

BOOST_AUTO_TEST_CASE(target_scaling_is_frozen_and_bounded)
{
    const uint256 pow_limit{RegtestPowLimit()};
    const auto easiest{
        node::DeriveRCAdmissionTarget(0x207fffff, pow_limit)};
    BOOST_REQUIRE(easiest);
    BOOST_CHECK(*easiest == WorkTarget(12));

    arith_uint256 middle_block_target{1};
    middle_block_target <<= 191;
    const auto middle{node::DeriveRCAdmissionTarget(
        middle_block_target.GetCompact(), pow_limit)};
    BOOST_REQUIRE(middle);
    BOOST_CHECK(*middle == (middle_block_target << 48));

    arith_uint256 hard_block_target{1};
    hard_block_target <<= 127;
    const auto hardest{node::DeriveRCAdmissionTarget(
        hard_block_target.GetCompact(), pow_limit)};
    BOOST_REQUIRE(hardest);
    BOOST_CHECK(*hardest == WorkTarget(20));
}

BOOST_AUTO_TEST_CASE(ticket_is_sidecar_bound_and_grindable)
{
    const CBlockHeader header{Header()};
    const uint256 pow_limit{RegtestPowLimit()};
    node::RCAdmissionTicket ticket;
    uint64_t tries{2'000'000};
    BOOST_REQUIRE(node::GrindRCAdmissionTicket(
        header, pow_limit, ticket, tries));
    BOOST_CHECK(ticket.block_hash == header.GetHash());
    BOOST_CHECK(node::CheckRCAdmissionTicket(
        ticket, header, pow_limit));

    CBlockHeader other{header};
    ++other.nTime;
    BOOST_CHECK(!node::CheckRCAdmissionTicket(
        ticket, other, pow_limit));
    BOOST_CHECK_EQUAL(::GetSerializeSize(header), 182U);
    BOOST_CHECK_EQUAL(::GetSerializeSize(ticket), 40U);
}

BOOST_AUTO_TEST_CASE(store_enforces_netgroup_quota_ttl_and_single_use)
{
    node::RCAdmissionStore store{{
        .max_entries = 3,
        .max_entries_per_netgroup = 1,
        .ttl = std::chrono::seconds{2},
    }};
    const auto now{std::chrono::steady_clock::now()};
    CBlockHeader a{Header()};
    CBlockHeader b{a};
    ++b.nTime;
    node::RCAdmissionTicket ta{a.GetHash(), 0};
    node::RCAdmissionTicket tb{b.GetHash(), 0};

    BOOST_CHECK(store.Remember(ta, 11, now) ==
                node::RCAdmissionStore::RememberResult::Stored);
    BOOST_CHECK(store.Remember(ta, 11, now) ==
                node::RCAdmissionStore::RememberResult::Duplicate);
    BOOST_CHECK(store.Remember(tb, 11, now) ==
                node::RCAdmissionStore::RememberResult::NetgroupQuota);
    BOOST_CHECK_EQUAL(store.Size(), 1U);

    // Easy regtest target: find a valid nonce deterministically.
    const uint256 pow_limit{RegtestPowLimit()};
    uint64_t tries{2'000'000};
    BOOST_REQUIRE(node::GrindRCAdmissionTicket(
        a, pow_limit, ta, tries));
    store.Erase(a.GetHash());
    BOOST_REQUIRE(store.Remember(ta, 11, now) ==
                  node::RCAdmissionStore::RememberResult::Stored);
    BOOST_CHECK(store.Consume(
        a, 11, pow_limit, now));
    BOOST_CHECK(!store.Consume(
        a, 11, pow_limit, now));

    BOOST_REQUIRE(store.Remember(tb, 12, now) ==
                  node::RCAdmissionStore::RememberResult::Stored);
    store.Prune(now + std::chrono::seconds{3});
    BOOST_CHECK_EQUAL(store.Size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
