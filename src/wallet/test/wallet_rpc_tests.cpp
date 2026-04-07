// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/request.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <wallet/rpc/util.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>

namespace wallet {
static std::string TestWalletName(const std::string& endpoint, std::optional<std::string> parameter = std::nullopt)
{
    JSONRPCRequest req;
    req.URI = endpoint;
    return EnsureUniqueWalletName(req, parameter ? &*parameter : nullptr);
}

BOOST_FIXTURE_TEST_SUITE(wallet_rpc_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(ensure_unique_wallet_name)
{
    // EnsureUniqueWalletName should only return if exactly one unique wallet name is provided
    BOOST_CHECK_EQUAL(TestWalletName("/wallet/foo"), "foo");
    BOOST_CHECK_EQUAL(TestWalletName("/wallet/foo", "foo"), "foo");
    BOOST_CHECK_EQUAL(TestWalletName("/", "foo"), "foo");
    BOOST_CHECK_EQUAL(TestWalletName("/bar", "foo"), "foo");

    BOOST_CHECK_THROW(TestWalletName("/"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/foo"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/wallet/foo", "bar"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/wallet/foo", "foobar"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/wallet/foobar", "foo"), UniValue);
}

BOOST_AUTO_TEST_CASE(validate_wallet_bundle_archive_directory_name)
{
    BOOST_CHECK_EQUAL(ValidateWalletBundleArchiveDirectoryName("wallet.bundle"), "wallet.bundle");
    BOOST_CHECK_THROW(ValidateWalletBundleArchiveDirectoryName(""), UniValue);
    BOOST_CHECK_THROW(ValidateWalletBundleArchiveDirectoryName(".."), UniValue);
    BOOST_CHECK_THROW(ValidateWalletBundleArchiveDirectoryName("../wallet.bundle"), UniValue);
    BOOST_CHECK_THROW(ValidateWalletBundleArchiveDirectoryName("nested/wallet.bundle"), UniValue);
    BOOST_CHECK_THROW(ValidateWalletBundleArchiveDirectoryName("/tmp/wallet.bundle"), UniValue);
}

BOOST_AUTO_TEST_CASE(validate_wallet_bundle_archive_relative_path)
{
    BOOST_CHECK_EQUAL(ValidateWalletBundleArchiveRelativePath("manifest.json"), "manifest.json");
    BOOST_CHECK_EQUAL(ValidateWalletBundleArchiveRelativePath("shielded_viewing_keys/./index.tsv"),
                      "shielded_viewing_keys/index.tsv");
    BOOST_CHECK_THROW(ValidateWalletBundleArchiveRelativePath(""), UniValue);
    BOOST_CHECK_THROW(ValidateWalletBundleArchiveRelativePath("../manifest.json"), UniValue);
    BOOST_CHECK_THROW(ValidateWalletBundleArchiveRelativePath("/tmp/manifest.json"), UniValue);
}

BOOST_AUTO_TEST_CASE(validate_wallet_bundle_archive_relative_paths_are_unique)
{
    BOOST_CHECK_NO_THROW(EnsureUniqueWalletBundleArchiveRelativePaths(
        {"manifest.json", "shielded.backup.dat", "shielded_viewing_keys/index.tsv"}));
    BOOST_CHECK_THROW(EnsureUniqueWalletBundleArchiveRelativePaths(
        {"manifest.json", "manifest.json"}), UniValue);
    BOOST_CHECK_THROW(EnsureUniqueWalletBundleArchiveRelativePaths(
        {"shielded_viewing_keys/index.tsv", "shielded_viewing_keys/./index.tsv"}), UniValue);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
