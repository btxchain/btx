// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <banman.h>
#include <chainparams.h>
#include <netbase.h>
#include <streams.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/readwritefile.h>


#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(banman_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(file)
{
    SetMockTime(777s);
    const fs::path banlist_path{m_args.GetDataDirBase() / "banlist_test"};
    {
        const std::string entries_write{
            "{ \"banned_nets\": ["
            "  { \"version\": 1, \"ban_created\": 0, \"banned_until\": 778, \"address\": \"aaaaaaaaa\" },"
            "  { \"version\": 2, \"ban_created\": 0, \"banned_until\": 778, \"address\": \"bbbbbbbbb\" },"
            "  { \"version\": 1, \"ban_created\": 0, \"banned_until\": 778, \"address\": \"1.0.0.0/8\" }"
            "] }",
        };
        BOOST_REQUIRE(WriteBinaryFile(banlist_path + ".json", entries_write));
        {
            // The invalid entries will be dropped, but the valid one remains
            ASSERT_DEBUG_LOG("Dropping entry with unparseable address or subnet (aaaaaaaaa) from ban list");
            ASSERT_DEBUG_LOG("Dropping entry with unknown version (2) from ban list");
            BanMan banman{banlist_path, /*client_interface=*/nullptr, /*default_ban_time=*/0};
            banmap_t entries_read;
            banman.GetBanned(entries_read);
            BOOST_CHECK_EQUAL(entries_read.size(), 1);
        }
    }
}

BOOST_AUTO_TEST_CASE(automatic_bans)
{
    SetMockTime(1'000'000s);
    const fs::path banlist_path{m_args.GetDataDirBase() / "banlist_automatic"};
    const fs::path banlist_json{banlist_path + ".json"};
    BanMan banman{banlist_path, /*client_interface=*/nullptr, DEFAULT_MISBEHAVING_BANTIME};
    // Unique local IPv6 addresses (RFC 4193). Addresses in 2001:db8::/32 are
    // not IsValid(), so a ban of one never matches.
    const auto automatic_addr{[](uint32_t i) {
        return LookupHost(strprintf("fd17::%x:%x", i >> 16, i & 0xffff), /*fAllowLookup=*/false).value();
    }};
    const CNetAddr manual{LookupHost("198.51.100.1", /*fAllowLookup=*/false).value()};

    banman.Ban(manual);
    const auto after_manual{ReadBinaryFile(banlist_json)};
    BOOST_REQUIRE(after_manual.first);
    BOOST_CHECK(after_manual.second.find("198.51.100.1") != std::string::npos);

    // Each automatic ban ends one second after the previous one.
    for (uint32_t i{0}; i < MAX_AUTOMATIC_BANS + 10; ++i) {
        SetMockTime(std::chrono::seconds{1'000'000 + i});
        banman.BanAutomatic(automatic_addr(i));
    }
    // Automatic bans do not write the ban list.
    BOOST_CHECK(ReadBinaryFile(banlist_json).second == after_manual.second);

    // At most MAX_AUTOMATIC_BANS automatic bans; the ones that end first are
    // dropped, and the ban from Ban() stays and does not count.
    banmap_t banned;
    banman.GetBanned(banned);
    BOOST_CHECK_EQUAL(banned.size(), MAX_AUTOMATIC_BANS + 1);
    BOOST_CHECK(banman.IsBanned(manual));
    for (uint32_t i{0}; i < 10; ++i) BOOST_CHECK(!banman.IsBanned(automatic_addr(i)));
    BOOST_CHECK(banman.IsBanned(automatic_addr(10)));
    BOOST_CHECK(banman.IsBanned(automatic_addr(MAX_AUTOMATIC_BANS + 9)));

    // Ban() on an automatic ban makes it an ordinary ban: it frees one place
    // and is not dropped. The second new automatic ban drops the next one.
    banman.Ban(automatic_addr(10), /*ban_time_offset=*/2 * DEFAULT_MISBEHAVING_BANTIME);
    banman.BanAutomatic(automatic_addr(MAX_AUTOMATIC_BANS + 10));
    BOOST_CHECK(banman.IsBanned(automatic_addr(11)));
    banman.BanAutomatic(automatic_addr(MAX_AUTOMATIC_BANS + 11));
    BOOST_CHECK(banman.IsBanned(automatic_addr(10)));
    BOOST_CHECK(!banman.IsBanned(automatic_addr(11)));

    // The next dump writes the automatic bans.
    banman.DumpBanlist();
    BanMan reloaded{banlist_path, /*client_interface=*/nullptr, DEFAULT_MISBEHAVING_BANTIME};
    banmap_t read;
    reloaded.GetBanned(read);
    BOOST_CHECK_EQUAL(read.size(), banned.size() + 1);
    BOOST_CHECK(reloaded.IsBanned(automatic_addr(MAX_AUTOMATIC_BANS + 11)));
}

BOOST_AUTO_TEST_SUITE_END()
