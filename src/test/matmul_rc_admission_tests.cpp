// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <boost/test/unit_test.hpp>

#include <arith_uint256.h>
#include <node/matmul_rc_admission.h>

#include <chrono>
#include <limits>
#include <vector>

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

node::RCAdmissionTicket ValidTicket(const CBlockHeader& header,
                                    const uint256& pow_limit)
{
    node::RCAdmissionTicket ticket{header.GetHash(), 0};
    uint64_t tries{2'000'000};
    BOOST_REQUIRE(node::GrindRCAdmissionTicket(
        header, pow_limit, ticket, tries));
    return ticket;
}

node::RCAdmissionTicket InvalidTicket(const CBlockHeader& header,
                                      const uint256& pow_limit,
                                      uint64_t start_nonce = 0)
{
    node::RCAdmissionTicket ticket{header.GetHash(), start_nonce};
    while (node::CheckRCAdmissionTicket(ticket, header, pow_limit)) {
        ++ticket.nonce;
    }
    return ticket;
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
        .max_unknown_entries_per_netgroup = 1,
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
    BOOST_CHECK_EQUAL(store.UnknownSize(), 1U);
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 0U);

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

BOOST_AUTO_TEST_CASE(unknown_quarantine_cannot_fill_validated_capacity)
{
    node::RCAdmissionStore store{{
        .max_entries = 2,
        .max_entries_per_netgroup = 2,
        .max_unknown_entries = 3,
        .max_unknown_entries_per_netgroup = 1,
        .max_unknown_candidates_per_hash = 2,
        .max_unknown_submissions_per_netgroup = 8,
    }};
    const auto now{std::chrono::steady_clock::now()};
    const uint256 pow_limit{RegtestPowLimit()};

    // Fill the entire unverified quarantine using independent netgroups.
    std::vector<CBlockHeader> unknown_headers;
    for (uint64_t group = 1; group <= 3; ++group) {
        CBlockHeader header{Header()};
        header.nTime += group;
        unknown_headers.push_back(header);
        BOOST_REQUIRE(
            store.Remember(
                node::RCAdmissionTicket{header.GetHash(), group},
                group, now) ==
            node::RCAdmissionStore::RememberResult::Stored);
    }
    CBlockHeader overflow{Header()};
    overflow.nTime += 100;
    BOOST_CHECK(
        store.Remember(
            node::RCAdmissionTicket{overflow.GetHash(), 0}, 4, now) ==
        node::RCAdmissionStore::RememberResult::GlobalQuota);
    BOOST_CHECK_EQUAL(store.UnknownSize(), 3U);
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 0U);

    // A cryptographically valid sidecar for a known honest header uses the
    // separate validated capacity and remains consumable.
    CBlockHeader honest{Header()};
    honest.nTime += 200;
    const auto valid{ValidTicket(honest, pow_limit)};
    BOOST_REQUIRE(
        store.RememberKnown(valid, honest, 99, pow_limit, now) ==
        node::RCAdmissionStore::RememberResult::Stored);
    BOOST_CHECK_EQUAL(store.UnknownSize(), 3U);
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 1U);
    BOOST_CHECK(store.Consume(honest, 99, pow_limit, now));
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 0U);
    BOOST_CHECK_EQUAL(store.UnknownSize(), 3U);
}

BOOST_AUTO_TEST_CASE(hash_poison_does_not_censor_other_netgroup)
{
    node::RCAdmissionStore store{{
        .max_entries = 4,
        .max_entries_per_netgroup = 2,
        .max_unknown_entries = 8,
        .max_unknown_entries_per_netgroup = 4,
        .max_unknown_candidates_per_hash = 2,
    }};
    const auto now{std::chrono::steady_clock::now()};
    const uint256 pow_limit{RegtestPowLimit()};
    const CBlockHeader header{Header()};
    const auto poison{InvalidTicket(header, pow_limit)};
    const auto valid{ValidTicket(header, pow_limit)};

    BOOST_REQUIRE(
        store.Remember(poison, 11, now) ==
        node::RCAdmissionStore::RememberResult::Stored);
    BOOST_REQUIRE(
        store.Remember(valid, 22, now) ==
        node::RCAdmissionStore::RememberResult::Stored);
    BOOST_CHECK_EQUAL(store.UnknownCandidatesForHash(header.GetHash()), 2U);
    BOOST_CHECK(
        store.Remember(valid, 33, now) ==
        node::RCAdmissionStore::RememberResult::HashQuota);

    // A cross-netgroup consume does not spend either candidate.
    BOOST_CHECK(!store.Consume(header, 33, pow_limit, now));
    BOOST_CHECK_EQUAL(store.UnknownCandidatesForHash(header.GetHash()), 2U);

    // Consuming the poison erases only group A. Group B's valid ticket remains.
    BOOST_CHECK(!store.Consume(header, 11, pow_limit, now));
    BOOST_CHECK_EQUAL(store.UnknownCandidatesForHash(header.GetHash()), 1U);
    node::RCAdmissionTicket accepted;
    BOOST_CHECK(store.Consume(header, 22, pow_limit, now, &accepted));
    BOOST_CHECK(accepted.nonce == valid.nonce);
    BOOST_CHECK_EQUAL(store.UnknownCandidatesForHash(header.GetHash()), 0U);
}

BOOST_AUTO_TEST_CASE(known_valid_replaces_same_source_poison_and_cannot_be_evicted)
{
    node::RCAdmissionStore store;
    const auto now{std::chrono::steady_clock::now()};
    const uint256 pow_limit{RegtestPowLimit()};
    const CBlockHeader header{Header()};
    const auto poison{InvalidTicket(header, pow_limit)};
    const auto valid{ValidTicket(header, pow_limit)};

    BOOST_REQUIRE(
        store.Remember(poison, 42, now) ==
        node::RCAdmissionStore::RememberResult::Stored);
    BOOST_CHECK(
        store.RememberKnown(poison, header, 42, pow_limit, now) ==
        node::RCAdmissionStore::RememberResult::Invalid);
    BOOST_CHECK_EQUAL(store.UnknownSize(), 1U);

    BOOST_REQUIRE(
        store.RememberKnown(valid, header, 42, pow_limit, now) ==
        node::RCAdmissionStore::RememberResult::Stored);
    BOOST_CHECK_EQUAL(store.UnknownSize(), 0U);
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 1U);

    // A later invalid same-hash message cannot displace validated state.
    BOOST_CHECK(
        store.RememberKnown(poison, header, 42, pow_limit, now) ==
        node::RCAdmissionStore::RememberResult::Invalid);
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 1U);
    node::RCAdmissionTicket accepted;
    BOOST_CHECK(store.Consume(header, 42, pow_limit, now, &accepted));
    BOOST_CHECK(accepted.nonce == valid.nonce);
}

BOOST_AUTO_TEST_CASE(quarantine_rate_limits_and_counters_are_exact)
{
    node::RCAdmissionStore store{{
        .max_entries = 4,
        .max_entries_per_netgroup = 2,
        .max_unknown_entries = 8,
        .max_unknown_entries_per_netgroup = 3,
        .max_unknown_candidates_per_hash = 2,
        .max_unknown_submissions_per_netgroup = 2,
        .unknown_submission_window = std::chrono::seconds{5},
        .ttl = std::chrono::seconds{10},
    }};
    const auto now{std::chrono::steady_clock::now()};
    CBlockHeader a{Header()};
    CBlockHeader b{a};
    CBlockHeader c{a};
    b.nTime += 2;
    c.nTime += 3;

    BOOST_REQUIRE(
        store.Remember({a.GetHash(), 1}, 7, now) ==
        node::RCAdmissionStore::RememberResult::Stored);
    BOOST_REQUIRE(
        store.Remember({b.GetHash(), 2}, 7, now) ==
        node::RCAdmissionStore::RememberResult::Stored);
    BOOST_CHECK(
        store.Remember({c.GetHash(), 3}, 7, now) ==
        node::RCAdmissionStore::RememberResult::RateLimited);
    BOOST_CHECK_EQUAL(store.UnknownNetgroupSize(7), 2U);

    // Erasing storage does not refund the reconnect-resistant submission rate.
    store.Erase(a.GetHash());
    BOOST_CHECK_EQUAL(store.UnknownNetgroupSize(7), 1U);
    BOOST_CHECK(
        store.Remember({c.GetHash(), 3}, 7, now) ==
        node::RCAdmissionStore::RememberResult::RateLimited);

    // Once the rate window expires the same netgroup can submit again.
    const auto later{now + std::chrono::seconds{6}};
    BOOST_REQUIRE(
        store.Remember({c.GetHash(), 3}, 7, later) ==
        node::RCAdmissionStore::RememberResult::Stored);
    BOOST_CHECK_EQUAL(store.UnknownNetgroupSize(7), 2U);

    // TTL pruning updates every aggregate exactly once.
    store.Prune(now + std::chrono::seconds{17});
    BOOST_CHECK_EQUAL(store.Size(), 0U);
    BOOST_CHECK_EQUAL(store.UnknownNetgroupSize(7), 0U);
    BOOST_CHECK_EQUAL(store.UnknownCandidatesForHash(b.GetHash()), 0U);
    BOOST_CHECK_EQUAL(store.UnknownCandidatesForHash(c.GetHash()), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
