// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <arith_uint256.h>
#include <chainparams.h>
#include <node/matmul_rc_admission.h>
#include <primitives/block.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/check.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <set>
#include <vector>

namespace {

struct TicketedHeader {
    CBlockHeader header;
    std::vector<node::RCAdmissionTicket> valid_tickets;
};

constexpr size_t HEADER_POOL{6};
constexpr uint64_t NETGROUPS{6};
std::vector<TicketedHeader> g_headers;
uint256 g_pow_limit;

void initialize_matmul_rc_admission()
{
    SelectParams(ChainType::MAIN);
    g_pow_limit = Params().GetConsensus().powLimit;
    // nBits at the pow limit gives the easiest admission target (12 work
    // bits), so a few valid tickets per header grind quickly.
    const uint32_t easy_bits{UintToArith256(g_pow_limit).GetCompact()};
    g_headers.clear();
    for (size_t i = 0; i < HEADER_POOL; ++i) {
        TicketedHeader th;
        th.header.nVersion = 4;
        th.header.nTime = 1'700'000'000 + static_cast<uint32_t>(i);
        th.header.nBits = easy_bits;
        th.header.nNonce = static_cast<uint32_t>(i);
        node::RCAdmissionTicket ticket;
        for (int n = 0; n < 2; ++n) {
            uint64_t tries{1U << 20};
            Assert(node::GrindRCAdmissionTicket(th.header, g_pow_limit, ticket, tries));
            th.valid_tickets.push_back(ticket);
            ++ticket.nonce;
        }
        g_headers.push_back(th);
    }
}

} // namespace

// The rcadmit sidecar store behind PeerManager (net_processing.cpp RCADMIT):
// any peer can submit tickets for unknown hashes, and tickets for known
// headers are authenticated before they take validated capacity. Every
// entry bound must hold under any order of calls, and the per-netgroup
// and per-hash counters must stay in step with the entries.
FUZZ_TARGET(matmul_rc_admission_store, .init = initialize_matmul_rc_admission)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    node::RCAdmissionStore::Config config;
    config.max_entries = fdp.ConsumeIntegralInRange<size_t>(0, 8);
    config.max_entries_per_netgroup = fdp.ConsumeIntegralInRange<size_t>(0, 4);
    config.max_validated_candidates_per_hash = fdp.ConsumeIntegralInRange<size_t>(0, 4);
    config.max_unknown_entries = fdp.ConsumeIntegralInRange<size_t>(0, 8);
    config.max_unknown_entries_per_netgroup = fdp.ConsumeIntegralInRange<size_t>(0, 4);
    config.max_unknown_candidates_per_hash = fdp.ConsumeIntegralInRange<size_t>(0, 4);
    config.max_unknown_submissions_per_netgroup = fdp.ConsumeIntegralInRange<size_t>(0, 8);
    config.max_unknown_submission_netgroups = fdp.ConsumeIntegralInRange<size_t>(0, 8);
    config.unknown_submission_window = std::chrono::seconds{fdp.ConsumeIntegralInRange<int64_t>(0, 120)};
    config.ttl = std::chrono::seconds{fdp.ConsumeIntegralInRange<int64_t>(0, 300)};
    node::RCAdmissionStore store{config};
    // The constructor raises every cap to at least one.
    const size_t max_entries{std::max<size_t>(1, config.max_entries)};
    const size_t max_per_netgroup{std::max<size_t>(1, config.max_entries_per_netgroup)};
    const size_t max_per_hash{std::max<size_t>(1, config.max_validated_candidates_per_hash)};
    const size_t max_unknown{std::max<size_t>(1, config.max_unknown_entries)};
    const size_t max_unknown_per_netgroup{std::max<size_t>(1, config.max_unknown_entries_per_netgroup)};
    const size_t max_unknown_per_hash{std::max<size_t>(1, config.max_unknown_candidates_per_hash)};

    auto now{std::chrono::steady_clock::time_point{} + std::chrono::hours{1}};
    // PeerManager only takes the unknown path for a hash that is not in the
    // block index, and an indexed header stays indexed, so once a hash has
    // been offered as known it is never offered as unknown again.
    std::set<uint256> known_hashes;

    LIMITED_WHILE(fdp.ConsumeBool(), 2000)
    {
        now += std::chrono::seconds{fdp.ConsumeIntegralInRange<int64_t>(0, 90)};
        const uint64_t netgroup{fdp.ConsumeIntegralInRange<uint64_t>(0, NETGROUPS - 1)};
        const TicketedHeader& th{PickValue(fdp, g_headers)};
        const uint256 hash{th.header.GetHash()};
        node::RCAdmissionTicket ticket;
        if (fdp.ConsumeBool()) {
            ticket = PickValue(fdp, th.valid_tickets);
        } else {
            ticket.block_hash = fdp.ConsumeBool() ? hash : PickValue(fdp, g_headers).header.GetHash();
            ticket.nonce = fdp.ConsumeIntegral<uint64_t>();
        }
        CallOneOf(
            fdp,
            [&] {
                if (known_hashes.contains(ticket.block_hash)) return;
                (void)store.Remember(ticket, netgroup, now);
            },
            [&] {
                known_hashes.insert(hash);
                const auto result{store.RememberKnown(ticket, th.header, netgroup, g_pow_limit, now)};
                if (result == node::RCAdmissionStore::RememberResult::Stored) {
                    Assert(node::CheckRCAdmissionTicket(ticket, th.header, g_pow_limit));
                }
            },
            [&] {
                known_hashes.insert(hash);
                const size_t before{store.Size()};
                node::RCAdmissionTicket accepted;
                if (store.Consume(th.header, netgroup, g_pow_limit, now, &accepted)) {
                    Assert(accepted.block_hash == hash);
                    Assert(node::CheckRCAdmissionTicket(accepted, th.header, g_pow_limit));
                    Assert(store.Size() < before);
                }
            },
            [&] {
                known_hashes.insert(hash);
                if (store.RestoreConsumed(ticket, th.header, netgroup, g_pow_limit, now)) {
                    Assert(node::CheckRCAdmissionTicket(ticket, th.header, g_pow_limit));
                }
            },
            [&] {
                store.Erase(hash);
                Assert(store.ValidatedCandidatesForHash(hash) == 0);
                Assert(store.UnknownCandidatesForHash(hash) == 0);
            },
            [&] { store.Prune(now); },
            [&] {
                store.Clear();
                Assert(store.Size() == 0);
            });

        Assert(store.ValidatedSize() <= max_entries);
        Assert(store.UnknownSize() <= max_unknown);
        Assert(store.Size() == store.ValidatedSize() + store.UnknownSize());
        size_t validated_by_group{0}, unknown_by_group{0};
        for (uint64_t g{0}; g < NETGROUPS; ++g) {
            Assert(store.NetgroupSize(g) <= max_per_netgroup);
            Assert(store.UnknownNetgroupSize(g) <= max_unknown_per_netgroup);
            validated_by_group += store.NetgroupSize(g);
            unknown_by_group += store.UnknownNetgroupSize(g);
        }
        Assert(validated_by_group == store.ValidatedSize());
        Assert(unknown_by_group == store.UnknownSize());
        size_t validated_by_hash{0}, unknown_by_hash{0};
        for (const auto& h : g_headers) {
            const uint256 header_hash{h.header.GetHash()};
            Assert(store.ValidatedCandidatesForHash(header_hash) <= max_per_hash);
            Assert(store.UnknownCandidatesForHash(header_hash) <= max_unknown_per_hash);
            validated_by_hash += store.ValidatedCandidatesForHash(header_hash);
            unknown_by_hash += store.UnknownCandidatesForHash(header_hash);
        }
        Assert(validated_by_hash == store.ValidatedSize());
        Assert(unknown_by_hash == store.UnknownSize());
    }
}
