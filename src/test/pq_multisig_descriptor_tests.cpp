// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <outputtype.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <script/pqm.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> MakePattern(size_t size, unsigned char seed)
{
    std::vector<unsigned char> out(size);
    for (size_t i = 0; i < out.size(); ++i) out[i] = static_cast<unsigned char>(seed + i);
    return out;
}

std::unique_ptr<Descriptor> ParseDescriptorChecked(const std::string& descriptor)
{
    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(descriptor, provider, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), error);
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
    return std::move(parsed[0]);
}

std::array<unsigned char, 32> MakePQSeed(unsigned char seed)
{
    std::array<unsigned char, 32> out{};
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<unsigned char>(seed + i);
    }
    return out;
}

std::string MakePQHDExpr(const std::array<unsigned char, 32>& seed, uint32_t account, uint32_t change)
{
    const std::string coin_type = Params().IsTestChain() ? "1h" : "0h";
    return "pqhd(" + HexStr(seed) + "/" + coin_type + "/" + strprintf("%uh", account) + "/" + strprintf("%u", change) + "/*)";
}

CScript BuildP2MROutput(const uint256& merkle_root)
{
    CScript script;
    script << OP_2 << ToByteVector(merkle_root);
    return script;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_multisig_descriptor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(parse_multi_pq_mixed_roundtrip_and_expand)
{
    const std::vector<unsigned char> ml1 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x11);
    const std::vector<unsigned char> ml2 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x22);
    const std::vector<unsigned char> slh = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x33);

    const std::string no_checksum =
        "mr(multi_pq(2," + HexStr(ml1) + "," + HexStr(ml2) + ",pk_slh(" + HexStr(slh) + ")))";
    const std::string descriptor = AddChecksum(no_checksum);
    const auto desc = ParseDescriptorChecked(descriptor);
    BOOST_CHECK_EQUAL(desc->ToString(), descriptor);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto leaf_script = BuildP2MRMultisigScript(
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, ml1},
            {PQAlgorithm::ML_DSA_44, ml2},
            {PQAlgorithm::SLH_DSA_128S, slh},
        });
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));

    const auto out_type = desc->GetOutputType();
    BOOST_REQUIRE(out_type.has_value());
    BOOST_CHECK_EQUAL(*out_type, OutputType::P2MR);
}

BOOST_AUTO_TEST_CASE(parse_sortedmulti_pq_sorts_by_pubkey_bytes)
{
    const std::vector<unsigned char> k_a = MakePattern(MLDSA44_PUBKEY_SIZE, 0x02);
    const std::vector<unsigned char> k_b = MakePattern(MLDSA44_PUBKEY_SIZE, 0x01);
    const std::vector<unsigned char> k_c = MakePattern(MLDSA44_PUBKEY_SIZE, 0x03);

    const std::string no_checksum =
        "mr(sortedmulti_pq(2," + HexStr(k_a) + "," + HexStr(k_b) + "," + HexStr(k_c) + "))";
    const auto desc = ParseDescriptorChecked(AddChecksum(no_checksum));

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> sorted{
        {PQAlgorithm::ML_DSA_44, k_a},
        {PQAlgorithm::ML_DSA_44, k_b},
        {PQAlgorithm::ML_DSA_44, k_c},
    };
    std::sort(sorted.begin(), sorted.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.second < rhs.second;
    });

    const auto leaf_script = BuildP2MRMultisigScript(/*threshold=*/2, sorted);
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));
}

BOOST_AUTO_TEST_CASE(parse_multi_pq_rejects_invalid_threshold)
{
    const std::vector<unsigned char> key = MakePattern(MLDSA44_PUBKEY_SIZE, 0x77);
    const std::string descriptor = AddChecksum("mr(multi_pq(2," + HexStr(key) + "))");

    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(descriptor, provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
    BOOST_CHECK(!error.empty());
}

BOOST_AUTO_TEST_CASE(parse_multi_pq_rejects_single_key_multisig)
{
    const std::vector<unsigned char> key = MakePattern(MLDSA44_PUBKEY_SIZE, 0x88);
    const std::string descriptor = AddChecksum("mr(multi_pq(1," + HexStr(key) + "))");

    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(descriptor, provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
    BOOST_CHECK(error.find("at least 2 keys") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(parse_multi_pq_rejects_duplicate_keys)
{
    const std::vector<unsigned char> key = MakePattern(MLDSA44_PUBKEY_SIZE, 0x99);
    const std::string descriptor = AddChecksum("mr(multi_pq(2," + HexStr(key) + "," + HexStr(key) + "))");

    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(descriptor, provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
    BOOST_CHECK(error.find("duplicate") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(multi_pq_hd_derivation_expand_and_cache_roundtrip)
{
    const auto pq_seed = MakePQSeed(0x01);
    const std::string descriptor = AddChecksum(
        "mr(multi_pq(2,"
        + MakePQHDExpr(pq_seed, /*account=*/0, /*change=*/0) + ","
        + MakePQHDExpr(pq_seed, /*account=*/1, /*change=*/0) + ","
        "pk_slh(" + MakePQHDExpr(pq_seed, /*account=*/2, /*change=*/0) + ")))");

    const auto desc = ParseDescriptorChecked(descriptor);
    DescriptorCache cache;

    std::vector<CScript> scripts_first;
    FlatSigningProvider out_first;
    DescriptorCache tmp;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts_first, out_first, &tmp));
    BOOST_REQUIRE_EQUAL(scripts_first.size(), 1U);
    cache.MergeAndDiff(tmp);
    BOOST_CHECK(out_first.pq_keys.empty());

    std::vector<CScript> scripts_cached;
    FlatSigningProvider out_cached;
    BOOST_REQUIRE(desc->ExpandFromCache(/*pos=*/0, cache, scripts_cached, out_cached));
    BOOST_REQUIRE_EQUAL(scripts_cached.size(), 1U);
    BOOST_CHECK(scripts_cached[0] == scripts_first[0]);
    BOOST_CHECK(out_cached.pq_keys.empty());
}

BOOST_AUTO_TEST_SUITE_END()
