// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/proc04/proc04.h>

#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace modelnet {
namespace {

// alpha, beta, gamma. Empty is impossible: each literal has characters.
const char* const kCorpus[] = {"alpha", "beta", "gamma"};
constexpr int kCorpusCount = 3;

int DistinctCharacters(const std::string& sentence)
{
    bool seen[256]{};
    int count = 0;
    for (unsigned char ch : sentence) {
        if (seen[ch]) continue;
        seen[ch] = true;
        ++count;
    }
    return count;
}

int SingleAgentScore()
{
    int sum = 0;
    for (int i = 0; i < kCorpusCount; ++i) {
        sum += static_cast<int>(std::string(kCorpus[i]).size());
    }
    return sum;
}

int CentralScore()
{
    int sum = 0;
    for (int i = 0; i < kCorpusCount; ++i) {
        sum += DistinctCharacters(std::string(kCorpus[i]));
    }
    return sum;
}

} // namespace

bool Proc04::Compare(std::string& err)
{
    if (m_compared) {
        err.clear();
        return true;
    }
    if (passed() || release_qualified() || gpu_passed() || windows_passed() || hardware_qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    const int single = SingleAgentScore();
    const int central = CentralScore();
    m_single = single;
    m_central = central;
    m_count = kCorpusCount;
    m_compared = true;
    err.clear();
    return true;
}

bool Proc04::RefuseEmpty(const std::string& extra, std::string& err)
{
    if (extra.empty()) {
        err = "FIELD";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
