// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <script/descriptor.h>
#include <util/strencodings.h>
#include <wallet/balance_watch.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

namespace wallet {
namespace {

std::string PkhDescriptor(const CPubKey& pubkey)
{
    return "pkh(" + HexStr(pubkey) + ")";
}

std::string FreshPkhDescriptor()
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    return PkhDescriptor(key.GetPubKey());
}

bool FetchListContains(const std::vector<BalanceWatchMiss>& fetched, const std::string& descriptor)
{
    return std::any_of(fetched.begin(), fetched.end(), [&](const BalanceWatchMiss& miss) {
        return miss.descriptor == descriptor;
    });
}

void AddOwnedPkh(CWallet& wallet, const CPubKey& pubkey)
{
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse(PkhDescriptor(pubkey), provider, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(descs.size() == 1, error);
    WalletDescriptor w_desc(std::move(descs.at(0)), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/1, /*next_index=*/1);
    BOOST_REQUIRE(wallet.AddWalletDescriptor(w_desc, provider, "", /*internal=*/false));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(balance_watch_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(balance_watch_not_ready_withholds_amount)
{
    // WalletTestingSetup leaves the wallet at height -1. TestingSetup's chain
    // is genesis, so the watch has not caught the tip.
    const std::optional<int> tip = m_wallet.chain().getHeight();
    BOOST_REQUIRE(tip.has_value());
    BOOST_CHECK_EQUAL(*tip, 0);

    const BalanceAtHeightResult at_tip = GetBalanceAtHeight(m_wallet, *tip);
    // Proven balance requires ready. The amount field is ignored until then.
    BOOST_CHECK(!at_tip.ready);

    const BalanceWatchStatus status = GetBalanceWatchStatus(m_wallet, m_wallet.chain());
    BOOST_CHECK_EQUAL(status.chain_height, 0);
    BOOST_CHECK_EQUAL(status.wallet_height, -1);
    BOOST_CHECK(!status.ready);
    BOOST_CHECK(!status.shielded_foreign_watch);
}

BOOST_AUTO_TEST_CASE(balance_watch_fetch_ignores_owned_and_caps)
{
    CKey owned_key;
    owned_key.MakeNewKey(/*fCompressed=*/true);
    AddOwnedPkh(m_wallet, owned_key.GetPubKey());

    const BalanceWatchStatus before = GetBalanceWatchStatus(m_wallet, m_wallet.chain());
    BOOST_CHECK(!before.shielded_foreign_watch);
    BOOST_REQUIRE(!before.descriptors.empty());
    BOOST_CHECK(before.fetched.empty());
    const std::string owned = before.descriptors.front();

    const int height = m_wallet.chain().getHeight().value_or(0);
    const std::string unknown = FreshPkhDescriptor();
    BOOST_REQUIRE(unknown != owned);

    NoteBalanceWatchFetch(m_wallet, unknown, height);
    const BalanceWatchStatus one_fetch = GetBalanceWatchStatus(m_wallet, m_wallet.chain());
    BOOST_CHECK_EQUAL(one_fetch.fetched.size(), 1U);
    BOOST_CHECK(FetchListContains(one_fetch.fetched, unknown));
    BOOST_CHECK(!one_fetch.shielded_foreign_watch);

    NoteBalanceWatchFetch(m_wallet, owned, height);
    const BalanceWatchStatus after_owned = GetBalanceWatchStatus(m_wallet, m_wallet.chain());
    BOOST_CHECK_EQUAL(after_owned.fetched.size(), one_fetch.fetched.size());
    BOOST_CHECK(FetchListContains(after_owned.fetched, unknown));
    BOOST_CHECK(!FetchListContains(after_owned.fetched, owned));

    // `unknown` is already noted. 32 further distinct strings make 33.
    std::vector<std::string> extra;
    extra.reserve(32);
    while (extra.size() < 32) {
        std::string descriptor = FreshPkhDescriptor();
        if (descriptor == owned || descriptor == unknown) continue;
        if (std::find(extra.begin(), extra.end(), descriptor) != extra.end()) continue;
        extra.push_back(std::move(descriptor));
    }
    for (const std::string& descriptor : extra) {
        NoteBalanceWatchFetch(m_wallet, descriptor, height);
    }

    const BalanceWatchStatus capped = GetBalanceWatchStatus(m_wallet, m_wallet.chain());
    BOOST_CHECK_EQUAL(capped.fetched.size(), 32U);
    BOOST_CHECK(!FetchListContains(capped.fetched, owned));
    BOOST_CHECK(!capped.shielded_foreign_watch);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
