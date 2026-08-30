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

BOOST_AUTO_TEST_CASE(deferred_body_cooldown_is_non_refreshing_and_expires)
{
    node::RCDeferredBodyCooldowns cooldowns{{
        .max_entries = 4,
        .cooldown = std::chrono::seconds{60},
    }};
    const auto start{std::chrono::steady_clock::time_point{
        std::chrono::seconds{1'000}}};
    const uint256 hash{1};

    BOOST_CHECK(cooldowns.Mark(hash, /*keyed_netgroup=*/1, start));
    BOOST_CHECK(cooldowns.Contains(hash, /*keyed_netgroup=*/1, start + std::chrono::seconds{59}));

    // A malicious duplicate immediately before expiry cannot extend the
    // process-wide suppression window for an honest source.
    BOOST_CHECK(!cooldowns.Mark(hash, /*keyed_netgroup=*/1, start + std::chrono::seconds{59}));
    BOOST_CHECK(!cooldowns.Contains(hash, /*keyed_netgroup=*/1, start + std::chrono::seconds{60}));
    BOOST_CHECK_EQUAL(cooldowns.Size(start + std::chrono::seconds{60}), 0U);

    // Once expired, the same hash may acquire one fresh bounded cooldown.
    BOOST_CHECK(cooldowns.Mark(hash, /*keyed_netgroup=*/1, start + std::chrono::seconds{60}));
}

BOOST_AUTO_TEST_CASE(deferred_body_cooldown_is_bounded_and_explicitly_clearable)
{
    node::RCDeferredBodyCooldowns cooldowns{{
        .max_entries = 2,
        .cooldown = std::chrono::seconds{60},
    }};
    const auto start{std::chrono::steady_clock::time_point{
        std::chrono::seconds{2'000}}};
    const uint256 first{1};
    const uint256 second{2};
    const uint256 third{3};

    BOOST_REQUIRE(cooldowns.Mark(first, /*keyed_netgroup=*/1, start));
    BOOST_REQUIRE(cooldowns.Mark(second, /*keyed_netgroup=*/1, start + std::chrono::seconds{1}));
    BOOST_CHECK_EQUAL(cooldowns.Size(start + std::chrono::seconds{1}), 2U);

    // Capacity evicts the oldest deadline rather than growing on arbitrary
    // hashes. The newer entry and newly installed entry remain active.
    BOOST_REQUIRE(cooldowns.Mark(third, /*keyed_netgroup=*/1, start + std::chrono::seconds{2}));
    BOOST_CHECK(!cooldowns.Contains(first, /*keyed_netgroup=*/1, start + std::chrono::seconds{2}));
    BOOST_CHECK(cooldowns.Contains(second, /*keyed_netgroup=*/1, start + std::chrono::seconds{2}));
    BOOST_CHECK(cooldowns.Contains(third, /*keyed_netgroup=*/1, start + std::chrono::seconds{2}));

    // Valid ticket/body admission and terminal verdicts use this erase path.
    cooldowns.Erase(second);
    BOOST_CHECK(!cooldowns.Contains(second, /*keyed_netgroup=*/1, start + std::chrono::seconds{2}));
    BOOST_CHECK_EQUAL(cooldowns.Size(start + std::chrono::seconds{2}), 1U);
    cooldowns.Clear();
    BOOST_CHECK_EQUAL(cooldowns.Size(start + std::chrono::seconds{2}), 0U);
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

BOOST_AUTO_TEST_CASE(consumed_known_ticket_can_be_restored_before_work_starts)
{
    const CBlockHeader header{Header()};
    CBlockHeader competing_header{header};
    ++competing_header.nTime;
    const uint256 pow_limit{RegtestPowLimit()};
    const node::RCAdmissionTicket ticket{ValidTicket(header, pow_limit)};
    const node::RCAdmissionTicket competing_ticket{
        ValidTicket(competing_header, pow_limit)};

    node::RCAdmissionStore store{{
        .max_entries = 1,
        .max_entries_per_netgroup = 1,
        .max_validated_candidates_per_hash = 1,
    }};
    const auto now{std::chrono::steady_clock::now()};
    constexpr uint64_t netgroup{17};
    constexpr uint64_t competing_netgroup{29};
    BOOST_REQUIRE(store.RememberKnown(
        ticket, header, netgroup, pow_limit, now) ==
        node::RCAdmissionStore::RememberResult::Stored);

    node::RCAdmissionTicket accepted;
    BOOST_REQUIRE(store.Consume(
        header, netgroup, pow_limit, now, &accepted));
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 0U);

    // Model the race in which another valid candidate occupies the exact
    // global slot released by Consume() before pending/rate/worker admission
    // fails. Ordinary RememberKnown() would now reject the paid ticket.
    BOOST_REQUIRE(store.RememberKnown(
        competing_ticket, competing_header, competing_netgroup, pow_limit,
        now + std::chrono::seconds{1}) ==
        node::RCAdmissionStore::RememberResult::Stored);
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 1U);

    // Rollback is guaranteed and cap-preserving: it deterministically reclaims
    // a conflicting slot, restores the source-bound attempt, and leaves all
    // counters exact.
    BOOST_REQUIRE(store.RestoreConsumed(
        accepted, header, netgroup, pow_limit,
        now + std::chrono::seconds{2}));
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 1U);
    BOOST_CHECK_EQUAL(store.NetgroupSize(netgroup), 1U);
    BOOST_CHECK_EQUAL(store.NetgroupSize(competing_netgroup), 0U);
    BOOST_CHECK_EQUAL(store.ValidatedCandidatesForHash(header.GetHash()), 1U);
    BOOST_CHECK_EQUAL(
        store.ValidatedCandidatesForHash(competing_header.GetHash()), 0U);
    BOOST_CHECK(store.Consume(
        header, netgroup, pow_limit,
        now + std::chrono::seconds{2}));
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 0U);
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

BOOST_AUTO_TEST_CASE(validated_same_hash_replay_cannot_fill_global_capacity)
{
    node::RCAdmissionStore store{{
        .max_entries = 4,
        .max_entries_per_netgroup = 4,
        .max_validated_candidates_per_hash = 2,
        .ttl = std::chrono::seconds{10},
    }};
    const auto now{std::chrono::steady_clock::now()};
    const uint256 pow_limit{RegtestPowLimit()};
    const CBlockHeader replayed_header{Header()};
    const auto replayed_ticket{ValidTicket(replayed_header, pow_limit)};

    // The ticket is valid and source-bound once stored, but replaying the same
    // bytes through 64 keyed netgroups must consume at most the per-hash fan-in
    // rather than the entire validated global quota.
    for (uint64_t group = 1; group <= 64; ++group) {
        const auto result{store.RememberKnown(
            replayed_ticket, replayed_header, group, pow_limit, now)};
        if (group <= 2) {
            BOOST_CHECK(
                result == node::RCAdmissionStore::RememberResult::Stored);
        } else {
            BOOST_CHECK(
                result == node::RCAdmissionStore::RememberResult::HashQuota);
        }
    }
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 2U);
    BOOST_CHECK_EQUAL(
        store.ValidatedCandidatesForHash(replayed_header.GetHash()), 2U);

    // The replay cannot censor a different honest hash even though enough
    // Sybil groups attempted to exceed the process-wide capacity.
    CBlockHeader honest_header{Header()};
    ++honest_header.nTime;
    const auto honest_ticket{ValidTicket(honest_header, pow_limit)};
    BOOST_REQUIRE(
        store.RememberKnown(
            honest_ticket, honest_header, 100, pow_limit, now) ==
        node::RCAdmissionStore::RememberResult::Stored);
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 3U);
    BOOST_CHECK_EQUAL(
        store.ValidatedCandidatesForHash(honest_header.GetHash()), 1U);

    // Consumption and hash-wide erasure update both aggregate dimensions
    // exactly once.
    BOOST_CHECK(store.Consume(
        replayed_header, 1, pow_limit, now));
    BOOST_CHECK_EQUAL(
        store.ValidatedCandidatesForHash(replayed_header.GetHash()), 1U);
    store.Erase(replayed_header.GetHash());
    BOOST_CHECK_EQUAL(
        store.ValidatedCandidatesForHash(replayed_header.GetHash()), 0U);
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 1U);

    // Short bursts for distinct known hashes remain admissible.
    CBlockHeader burst_header{honest_header};
    ++burst_header.nTime;
    const auto burst_ticket{ValidTicket(burst_header, pow_limit)};
    BOOST_REQUIRE(
        store.RememberKnown(
            burst_ticket, burst_header, 100, pow_limit, now) ==
        node::RCAdmissionStore::RememberResult::Stored);
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 2U);

    // TTL pruning clears the per-hash counters as well as global/group state.
    store.Prune(now + std::chrono::seconds{11});
    BOOST_CHECK_EQUAL(store.ValidatedSize(), 0U);
    BOOST_CHECK_EQUAL(store.NetgroupSize(100), 0U);
    BOOST_CHECK_EQUAL(
        store.ValidatedCandidatesForHash(honest_header.GetHash()), 0U);
    BOOST_CHECK_EQUAL(
        store.ValidatedCandidatesForHash(burst_header.GetHash()), 0U);
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


BOOST_AUTO_TEST_CASE(deferred_cooldown_is_scoped_to_reconnect_resistant_netgroup)
{
    // An unsolicited ticketless body reaches the deferral path with
    // force_processing=false. Keyed by hash alone, that one delivery would gate
    // FindNextBlocksToDownload for EVERY peer, turning "here is the block" into
    // "you may not download this block" -- renewable once per cooldown. Scoping
    // to the delivering keyed netgroup keeps the anti-busy-loop property
    // without letting one source censor a hash node-wide or bypass the hold by
    // disconnecting and acquiring a fresh ephemeral NodeId.
    node::RCDeferredBodyCooldowns cooldowns;
    const uint256 hash{uint256::ONE};
    const auto start{std::chrono::steady_clock::now()};

    constexpr uint64_t source_netgroup{11};
    constexpr uint64_t independent_netgroup{22};
    BOOST_CHECK(cooldowns.Mark(hash, source_netgroup, start));
    BOOST_CHECK(cooldowns.Contains(hash, source_netgroup, start));
    // Reconnection changes NodeId but retains the keyed netgroup: still held.
    BOOST_CHECK(!cooldowns.Mark(hash, source_netgroup, start));
    BOOST_CHECK(cooldowns.Contains(hash, source_netgroup, start));
    // An independent source stays immediately eligible for the same block.
    BOOST_CHECK(!cooldowns.Contains(hash, independent_netgroup, start));
    BOOST_CHECK(cooldowns.Mark(hash, independent_netgroup, start));

    // A terminal verdict clears the hash for all peers, not just one.
    cooldowns.Erase(hash);
    BOOST_CHECK(!cooldowns.Contains(hash, source_netgroup, start));
    BOOST_CHECK(!cooldowns.Contains(hash, independent_netgroup, start));
}

BOOST_AUTO_TEST_CASE(ticketless_followed_chain_persists_or_retains_competing_stays_header_only)
{
    // Closed livelock: a delivered followed historical hole always persists
    // (HAVE_DATA). persist_without_gpu=true covers pin-covered mirror hashes
    // and the unique followed consensus tip-child (catch-up without rcadmit).
    // Competing siblings keep persist=false so they HEADER_ONLY / retain.
    BOOST_CHECK(
        node::ClassifyTicketlessRCBody(
            /*followed_historical_hole=*/true,
            /*tip_child=*/false,
            /*persist_without_exactreplay_gpu=*/false) ==
        node::TicketlessRCBodyAction::PersistWithoutGpu);
    BOOST_CHECK(
        node::ClassifyTicketlessRCBody(
            /*followed_historical_hole=*/true,
            /*tip_child=*/false,
            /*persist_without_exactreplay_gpu=*/true) ==
        node::TicketlessRCBodyAction::PersistWithoutGpu);
    BOOST_CHECK(
        node::ClassifyTicketlessRCBody(
            /*followed_historical_hole=*/false,
            /*tip_child=*/true,
            /*persist_without_exactreplay_gpu=*/true) ==
        node::TicketlessRCBodyAction::PersistWithoutGpu);
    BOOST_CHECK(
        node::ClassifyTicketlessRCBody(
            /*followed_historical_hole=*/false,
            /*tip_child=*/true,
            /*persist_without_exactreplay_gpu=*/false) ==
        node::TicketlessRCBodyAction::RetainUntilTicketOrRetry);
    BOOST_CHECK(
        node::ClassifyTicketlessRCBody(
            /*followed_historical_hole=*/false,
            /*tip_child=*/false,
            /*persist_without_exactreplay_gpu=*/true) ==
        node::TicketlessRCBodyAction::HeaderOnlyPerPeerCooldown);
    BOOST_CHECK(
        node::ClassifyTicketlessRCBody(
            /*followed_historical_hole=*/false,
            /*tip_child=*/false,
            /*persist_without_exactreplay_gpu=*/false) ==
        node::TicketlessRCBodyAction::HeaderOnlyPerPeerCooldown);

    node::RCDeferredBodyCooldowns cooldowns;
    const uint256 competing{uint256::ONE};
    const auto start{std::chrono::steady_clock::now()};
    constexpr uint64_t source_netgroup{11};
    constexpr uint64_t independent_netgroup{22};
    BOOST_REQUIRE(cooldowns.Mark(competing, source_netgroup, start));
    BOOST_CHECK(cooldowns.Contains(competing, source_netgroup, start));
    BOOST_CHECK(!cooldowns.Contains(competing, independent_netgroup, start));
}


// A bounded store declining to allocate is NOT peer misbehaviour.
//
// Two limiters on the RCADMIT path used to punish the sender: the per-peer recv
// bucket (charged whenever the sidecar's header has not reached our index yet,
// which is the ORDINARY relay ordering) and RememberResult::RateLimited. Both
// disconnected honest miners and relayers producing blocks faster than the
// allowance. This pins the store's half of that contract: RateLimited is a
// refusal to store, reached by ordinary volume, and it is distinct from the
// Invalid verdict that genuinely indicates abuse.
BOOST_AUTO_TEST_CASE(rate_limited_is_a_refusal_to_store_not_an_invalid_ticket)
{
    node::RCAdmissionStore::Config cfg;
    node::RCAdmissionStore store{cfg};
    const auto now{std::chrono::steady_clock::now()};
    const uint64_t netgroup{7};

    // Push well past the per-netgroup unknown allowance with well-formed
    // tickets for distinct hashes -- exactly what a burst of ordinary relay
    // from one source looks like.
    size_t rate_limited{0};
    size_t invalid{0};
    for (size_t i = 0; i < cfg.max_unknown_submissions_per_netgroup + 8; ++i) {
        node::RCAdmissionTicket ticket{};
        // Not uint256{i + 1}: base_blob's only integral constructor takes
        // uint8_t, so a non-constant wider operand is a narrowing conversion in
        // a braced-init-list. GCC accepts it with a pedwarn, Clang rejects it
        // outright, so the case built here and failed on Apple Clang. Going
        // through arith_uint256 also keeps the hashes distinct past 255.
        ticket.block_hash = ArithToUint256(arith_uint256{i + 1});
        const auto result{store.Remember(ticket, netgroup, now)};
        if (result == node::RCAdmissionStore::RememberResult::RateLimited) ++rate_limited;
        if (result == node::RCAdmissionStore::RememberResult::Invalid) ++invalid;
    }

    // The allowance is reached...
    BOOST_CHECK_GT(rate_limited, 0U);
    // ...and reaching it never masquerades as an invalid ticket, which is the
    // verdict callers are still entitled to treat as misbehaviour.
    BOOST_CHECK_EQUAL(invalid, 0U);
    // Memory stays bounded by the store itself, which is why the caller can
    // safely drop instead of disconnecting.
    BOOST_CHECK_LE(store.UnknownSize(), cfg.max_unknown_entries);
}

BOOST_AUTO_TEST_SUITE_END()
