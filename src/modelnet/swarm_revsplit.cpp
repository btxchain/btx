// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_revsplit.h>

#include <cstdint>

namespace modelnet {
namespace {

constexpr int64_t kIllustrationGross = 10000;
constexpr int64_t kIllustrationSponsorPpm = 700000;
constexpr int64_t kIllustrationWorkerPpm = 200000;
constexpr int64_t kIllustrationReservePpm = 100000;
constexpr int64_t kPpmTotal = 1000000;

bool KnownIllustration(const SwarmRevenueSplitRequest& split)
{
    return split.gross == kIllustrationGross &&
           split.sponsor_ppm == kIllustrationSponsorPpm &&
           split.worker_ppm == kIllustrationWorkerPpm &&
           split.reserve_ppm == kIllustrationReservePpm;
}

SwarmRevenueSplitResult Refuse(const std::string& code, std::string& err)
{
    SwarmRevenueSplitResult result;
    result.sponsor_atoms = 0;
    result.worker_atoms = 0;
    result.reserve_atoms = 0;
    result.paid = false;
    result.code = code;
    err = code;
    return result;
}

SwarmRevenueSplitResult Record(const std::string& code, std::string& err)
{
    SwarmRevenueSplitResult result;
    result.sponsor_atoms = 7000;
    result.worker_atoms = 2000;
    result.reserve_atoms = 1000;
    result.paid = false;
    result.code = code;
    err.clear();
    return result;
}

} // namespace

SwarmRevenueSplitResult SwarmNoteRevenueSplit(const SwarmRevenueSplitRequest& split, std::string& err)
{
    if (split.pool_id.empty() || split.gross < 0 || split.sponsor_ppm < 0 || split.worker_ppm < 0 ||
        split.reserve_ppm < 0) {
        return Refuse("SPLIT", err);
    }
    // The three parts are non-negative. Stop before the running sum
    // would pass INT64_MAX. An overflowing add is SPLIT.
    const int64_t parts[3] = {split.sponsor_ppm, split.worker_ppm, split.reserve_ppm};
    int64_t sum = 0;
    for (const int64_t part : parts) {
        if (part > INT64_MAX - sum) {
            return Refuse("SPLIT", err);
        }
        sum += part;
    }
    // A sum other than 1000000 is SUM even when want_pay is true.
    if (sum != kPpmTotal) {
        return Refuse("SUM", err);
    }
    // ILLUSTRATION wins even when want_pay is true. This note does
    // not invent a general split.
    if (!KnownIllustration(split)) {
        return Refuse("ILLUSTRATION", err);
    }
    // Nothing is signed and nothing is broadcast.
    if (split.want_pay) {
        return Record("HELD", err);
    }
    return Record("NOTED", err);
}

} // namespace modelnet
