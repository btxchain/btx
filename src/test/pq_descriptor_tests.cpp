// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <outputtype.h>
#include <key.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <script/pqm.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

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

std::unique_ptr<Descriptor> ParseSingleDescriptor(
    const std::string& descriptor,
    bool require_checksum = true,
    const DescriptorParseOptions& options = {})
{
    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(descriptor, provider, error, require_checksum, options);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), error);
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
    return std::move(parsed[0]);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_descriptor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(parse_mr_descriptor_single_key)
{
    const std::string mldsa_hex = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x11));
    const auto desc = ParseSingleDescriptor(AddChecksum("mr(" + mldsa_hex + ")"));

    const auto out_type = desc->GetOutputType();
    BOOST_REQUIRE(out_type.has_value());
    BOOST_CHECK_EQUAL(*out_type, OutputType::P2MR);
}

BOOST_AUTO_TEST_CASE(mr_descriptor_produces_correct_script)
{
    const std::vector<unsigned char> mldsa_key = MakePattern(MLDSA44_PUBKEY_SIZE, 0x21);
    const std::string desc_str = AddChecksum("mr(" + HexStr(mldsa_key) + ")");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, mldsa_key);
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 expected_root = ComputeP2MRMerkleRoot({leaf_hash});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(expected_root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_hd_derivation)
{
    const auto seed = MakePQSeed(0x31);
    const std::string desc_str = AddChecksum("mr(" + MakePQHDExpr(seed, /*account=*/0, /*change=*/0) + ")");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));

    DescriptorCache cache;
    std::array<CScript, 3> derived_scripts{};
    for (int i = 0; i < 3; ++i) {
        std::vector<CScript> expanded;
        FlatSigningProvider expanded_out;
        DescriptorCache tmp;
        BOOST_REQUIRE(desc->Expand(i, DUMMY_SIGNING_PROVIDER, expanded, expanded_out, &tmp));
        BOOST_REQUIRE_EQUAL(expanded.size(), 1U);
        BOOST_CHECK(expanded_out.pq_keys.empty());
        cache.MergeAndDiff(tmp);
        derived_scripts[i] = expanded[0];

        int witver{-1};
        std::vector<unsigned char> witprog;
        BOOST_REQUIRE(derived_scripts[i].IsWitnessProgram(witver, witprog));
        BOOST_CHECK_EQUAL(witver, 2);
        BOOST_CHECK_EQUAL(witprog.size(), WITNESS_V2_P2MR_SIZE);

        // Cache-based expansion should work without access to secrets and should not leak PQ keys.
        std::vector<CScript> from_cache;
        FlatSigningProvider cache_out;
        BOOST_REQUIRE(desc->ExpandFromCache(i, cache, from_cache, cache_out));
        BOOST_REQUIRE_EQUAL(from_cache.size(), 1U);
        BOOST_CHECK(from_cache[0] == derived_scripts[i]);
        BOOST_CHECK(cache_out.pq_keys.empty());
    }

    BOOST_CHECK(derived_scripts[0] != derived_scripts[1]);
    BOOST_CHECK(derived_scripts[1] != derived_scripts[2]);
    BOOST_CHECK(derived_scripts[0] != derived_scripts[2]);
}

BOOST_AUTO_TEST_CASE(mr_descriptor_two_leaf_tree)
{
    const std::vector<unsigned char> mldsa_key = MakePattern(MLDSA44_PUBKEY_SIZE, 0x31);
    const std::vector<unsigned char> slh_key = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x61);
    const std::string desc_str = AddChecksum("mr(" + HexStr(mldsa_key) + ",pk_slh(" + HexStr(slh_key) + "))");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto ml_leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, mldsa_key);
    const auto slh_leaf_script = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, slh_key);
    const uint256 expected_root = ComputeP2MRMerkleRoot({
        ComputeP2MRLeafHash(P2MR_LEAF_VERSION, ml_leaf_script),
        ComputeP2MRLeafHash(P2MR_LEAF_VERSION, slh_leaf_script),
    });
    BOOST_CHECK(scripts[0] == BuildP2MROutput(expected_root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_reports_max_satisfaction_for_checksig_tree)
{
    const std::vector<unsigned char> mldsa_key = MakePattern(MLDSA44_PUBKEY_SIZE, 0x41);
    const std::vector<unsigned char> slh_key = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x71);
    const auto desc = ParseSingleDescriptor(AddChecksum("mr(" + HexStr(mldsa_key) + ",pk_slh(" + HexStr(slh_key) + "))"));

    const auto max_weight = desc->MaxSatisfactionWeight(/*use_max_sig=*/false);
    const auto max_elems = desc->MaxSatisfactionElems();
    BOOST_REQUIRE(max_weight.has_value());
    BOOST_REQUIRE(max_elems.has_value());

    const auto slh_leaf_script = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, slh_key);
    BOOST_REQUIRE(!slh_leaf_script.empty());
    const int64_t control_size = P2MR_CONTROL_BASE_SIZE + P2MR_CONTROL_NODE_SIZE;
    const int64_t expected_weight =
        GetSizeOfCompactSize(SLHDSA128S_SIGNATURE_SIZE) + SLHDSA128S_SIGNATURE_SIZE +
        GetSizeOfCompactSize(slh_leaf_script.size()) + static_cast<int64_t>(slh_leaf_script.size()) +
        GetSizeOfCompactSize(control_size) + control_size;
    BOOST_CHECK_EQUAL(*max_weight, expected_weight);
    BOOST_CHECK_EQUAL(*max_elems, 3);
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_multi_pq_leaf)
{
    const std::vector<unsigned char> ml1 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x93);
    const std::vector<unsigned char> ml2 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x94);
    const std::vector<unsigned char> slh = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x95);
    const std::string no_checksum = "mr(multi_pq(2," + HexStr(ml1) + "," + HexStr(ml2) + ",pk_slh(" + HexStr(slh) + ")))";
    const auto desc = ParseSingleDescriptor(AddChecksum(no_checksum));

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
    const uint256 expected_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(expected_root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_sortedmulti_pq_leaf)
{
    const std::vector<unsigned char> k_a = MakePattern(MLDSA44_PUBKEY_SIZE, 0x11);
    const std::vector<unsigned char> k_b = MakePattern(MLDSA44_PUBKEY_SIZE, 0x55);
    const std::vector<unsigned char> k_c = MakePattern(MLDSA44_PUBKEY_SIZE, 0x33);
    const std::string no_checksum = "mr(sortedmulti_pq(2," + HexStr(k_b) + "," + HexStr(k_a) + "," + HexStr(k_c) + "))";
    const auto desc = ParseSingleDescriptor(AddChecksum(no_checksum));

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> sorted_keys{
        {PQAlgorithm::ML_DSA_44, k_b},
        {PQAlgorithm::ML_DSA_44, k_a},
        {PQAlgorithm::ML_DSA_44, k_c},
    };
    std::sort(sorted_keys.begin(), sorted_keys.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.second < rhs.second;
    });
    const auto leaf_script = BuildP2MRMultisigScript(/*threshold=*/2, sorted_keys);
    const uint256 expected_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(expected_root));
    BOOST_CHECK_EQUAL(desc->ToString(), AddChecksum(no_checksum));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_tree_syntax_single_backup_wrapper)
{
    const std::vector<unsigned char> mldsa_key = MakePattern(MLDSA44_PUBKEY_SIZE, 0x37);
    const std::vector<unsigned char> slh_key = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x67);

    const auto plain_desc = ParseSingleDescriptor(AddChecksum("mr(" + HexStr(mldsa_key) + ",pk_slh(" + HexStr(slh_key) + "))"));
    const auto tree_desc = ParseSingleDescriptor(AddChecksum("mr(" + HexStr(mldsa_key) + ",{pk_slh(" + HexStr(slh_key) + ")})"));

    std::vector<CScript> plain_scripts;
    FlatSigningProvider plain_out;
    BOOST_REQUIRE(plain_desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, plain_scripts, plain_out));
    BOOST_REQUIRE_EQUAL(plain_scripts.size(), 1U);

    std::vector<CScript> tree_scripts;
    FlatSigningProvider tree_out;
    BOOST_REQUIRE(tree_desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, tree_scripts, tree_out));
    BOOST_REQUIRE_EQUAL(tree_scripts.size(), 1U);

    BOOST_CHECK(plain_scripts[0] == tree_scripts[0]);
}

BOOST_AUTO_TEST_CASE(mr_descriptor_tree_syntax_multiple_backups)
{
    const std::vector<unsigned char> mldsa_key = MakePattern(MLDSA44_PUBKEY_SIZE, 0x39);
    const std::vector<unsigned char> slh_key_a = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x69);
    const std::vector<unsigned char> slh_key_b = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x89);
    const std::string desc_str = AddChecksum(
        "mr(" + HexStr(mldsa_key) + ",{{pk_slh(" + HexStr(slh_key_a) + ")},pk_slh(" + HexStr(slh_key_b) + ")})");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto ml_leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, mldsa_key);
    const auto slh_leaf_script_a = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, slh_key_a);
    const auto slh_leaf_script_b = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, slh_key_b);
    const uint256 expected_root = ComputeP2MRMerkleRoot({
        ComputeP2MRLeafHash(P2MR_LEAF_VERSION, ml_leaf_script),
        ComputeP2MRLeafHash(P2MR_LEAF_VERSION, slh_leaf_script_a),
        ComputeP2MRLeafHash(P2MR_LEAF_VERSION, slh_leaf_script_b),
    });

    BOOST_REQUIRE_EQUAL(out.p2mr_spends.size(), 1U);
    BOOST_CHECK_EQUAL(out.p2mr_spends.begin()->second.scripts.size(), 3U);
    BOOST_CHECK(scripts[0] == BuildP2MROutput(expected_root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_two_leaf_tree_with_hd_backup)
{
    const auto seed = MakePQSeed(0x52);
    const std::string key_expr = MakePQHDExpr(seed, /*account=*/0, /*change=*/0);
    const std::string desc_str = AddChecksum("mr(" + key_expr + ",pk_slh(" + key_expr + "))");
    const auto desc = ParseSingleDescriptor(desc_str);

    DescriptorCache cache;

    std::vector<CScript> scripts0;
    FlatSigningProvider out0;
    DescriptorCache tmp0;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts0, out0, &tmp0));
    BOOST_REQUIRE_EQUAL(scripts0.size(), 1U);
    BOOST_CHECK(out0.pq_keys.empty());
    cache.MergeAndDiff(tmp0);

    std::vector<CScript> cached0;
    FlatSigningProvider cached_out0;
    BOOST_REQUIRE(desc->ExpandFromCache(/*pos=*/0, cache, cached0, cached_out0));
    BOOST_REQUIRE_EQUAL(cached0.size(), 1U);
    BOOST_CHECK(cached0[0] == scripts0[0]);
    BOOST_CHECK(cached_out0.pq_keys.empty());
    BOOST_REQUIRE_EQUAL(cached_out0.p2mr_spends.size(), 1U);
    BOOST_CHECK_EQUAL(cached_out0.p2mr_spends.begin()->second.scripts.size(), 2U);

    // PQ secret keys should only be produced when private key material is available.
    desc->ExpandPrivate(/*pos=*/0, DUMMY_SIGNING_PROVIDER, cached_out0);
    BOOST_CHECK_EQUAL(cached_out0.pq_keys.size(), 2U);

    std::vector<CScript> scripts1;
    FlatSigningProvider out1;
    DescriptorCache tmp1;
    BOOST_REQUIRE(desc->Expand(/*pos=*/1, DUMMY_SIGNING_PROVIDER, scripts1, out1, &tmp1));
    BOOST_REQUIRE_EQUAL(scripts1.size(), 1U);
    BOOST_CHECK(out1.pq_keys.empty());
    cache.MergeAndDiff(tmp1);

    std::vector<CScript> cached1;
    FlatSigningProvider cached_out1;
    BOOST_REQUIRE(desc->ExpandFromCache(/*pos=*/1, cache, cached1, cached_out1));
    BOOST_REQUIRE_EQUAL(cached1.size(), 1U);
    BOOST_CHECK(cached1[0] == scripts1[0]);
    BOOST_CHECK(cached_out1.pq_keys.empty());
    desc->ExpandPrivate(/*pos=*/1, DUMMY_SIGNING_PROVIDER, cached_out1);
    BOOST_CHECK_EQUAL(cached_out1.pq_keys.size(), 2U);

    int witver{-1};
    std::vector<unsigned char> witprog;
    BOOST_REQUIRE(scripts0[0].IsWitnessProgram(witver, witprog));
    BOOST_CHECK_EQUAL(witver, 2);
    BOOST_CHECK_EQUAL(witprog.size(), WITNESS_V2_P2MR_SIZE);
    BOOST_CHECK(scripts0[0] != scripts1[0]);
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_pqhd_fingerprint_form)
{
    const auto seed = MakePQSeed(0x71);
    const std::string private_expr = MakePQHDExpr(seed, /*account=*/0, /*change=*/0);
    const auto private_desc = ParseSingleDescriptor(AddChecksum("mr(" + private_expr + ",pk_slh(" + private_expr + "))"));

    std::vector<CScript> scripts_private;
    FlatSigningProvider out_private;
    DescriptorCache cache;
    BOOST_REQUIRE(private_desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts_private, out_private, &cache));
    BOOST_REQUIRE_EQUAL(scripts_private.size(), 1U);

    const std::string public_desc = private_desc->ToString();
    const std::string desc_str = AddChecksum(public_desc.substr(0, public_desc.find('#')));
    const auto desc = ParseSingleDescriptor(desc_str);
    BOOST_CHECK_EQUAL(desc->ToString(), desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_CHECK(!desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    scripts.clear();
    out = FlatSigningProvider{};
    BOOST_REQUIRE(desc->ExpandFromCache(/*pos=*/0, cache, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
    BOOST_CHECK(scripts[0] == scripts_private[0]);

    std::vector<CScript> from_cache;
    FlatSigningProvider cache_out;
    BOOST_REQUIRE(desc->ExpandFromCache(/*pos=*/0, cache, from_cache, cache_out));
    BOOST_REQUIRE_EQUAL(from_cache.size(), 1U);
    BOOST_CHECK(from_cache[0] == scripts[0]);
    BOOST_CHECK(cache_out.pq_keys.empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_roundtrip_string)
{
    const std::string mldsa_hex = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x41));
    const std::string slh_hex = HexStr(MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x71));
    const std::string no_checksum = "mr(" + mldsa_hex + ",pk_slh(" + slh_hex + "))";
    const auto desc = ParseSingleDescriptor(AddChecksum(no_checksum));

    BOOST_CHECK_EQUAL(desc->ToString(), AddChecksum(no_checksum));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_ctv_leaf)
{
    const uint256 ctv_hash{MakePattern(32, 0x90)};
    const std::string desc_str = AddChecksum("mr(ctv(" + HexStr(ctv_hash) + "))");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto leaf_script = BuildP2MRCTVScript(ctv_hash);
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_ctv_checksig_leaf)
{
    const std::vector<unsigned char> signer = MakePattern(MLDSA44_PUBKEY_SIZE, 0x91);
    const uint256 ctv_hash{MakePattern(32, 0x92)};
    const std::string desc_str = AddChecksum("mr(ctv_pk(" + HexStr(ctv_hash) + "," + HexStr(signer) + "))");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto leaf_script = BuildP2MRCTVChecksigScript(ctv_hash, PQAlgorithm::ML_DSA_44, signer);
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_ctv_multisig_leaf)
{
    const uint256 ctv_hash{MakePattern(32, 0x93)};
    const std::vector<unsigned char> pk1 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x94);
    const std::vector<unsigned char> pk2 = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x95);
    const std::string desc_str = AddChecksum(
        "mr(ctv_multi_pq(" + HexStr(ctv_hash) + ",1," + HexStr(pk1) + ",pk_slh(" + HexStr(pk2) + ")))");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto leaf_script = BuildP2MRMultisigCTVScript(
        ctv_hash,
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, pk1},
            {PQAlgorithm::SLH_DSA_128S, pk2},
        });
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_csfs_leaf)
{
    const std::vector<unsigned char> oracle = MakePattern(MLDSA44_PUBKEY_SIZE, 0x93);
    const std::string desc_str = AddChecksum("mr(csfs(" + HexStr(oracle) + "))");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto leaf_script = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, oracle);
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_csfs_pk_leaf)
{
    const std::vector<unsigned char> oracle = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x12);
    const std::vector<unsigned char> spender = MakePattern(MLDSA44_PUBKEY_SIZE, 0x34);
    const std::string desc_str = AddChecksum("mr(csfs_pk(pk_slh(" + HexStr(oracle) + ")," + HexStr(spender) + "))");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto leaf_script = BuildP2MRDelegationScript(
        PQAlgorithm::SLH_DSA_128S, oracle, PQAlgorithm::ML_DSA_44, spender);
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_htlc_leaf)
{
    const std::vector<unsigned char> hash160 = MakePattern(uint160::size(), 0x44);
    const std::vector<unsigned char> oracle = MakePattern(MLDSA44_PUBKEY_SIZE, 0x45);
    const std::string desc_str = AddChecksum("mr(htlc(" + HexStr(hash160) + "," + HexStr(oracle) + "))");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto leaf_script = BuildP2MRHTLCLeaf(hash160, PQAlgorithm::ML_DSA_44, oracle);
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_refund_leaf)
{
    const std::vector<unsigned char> spender = MakePattern(MLDSA44_PUBKEY_SIZE, 0x46);
    const std::string desc_str = AddChecksum("mr(refund(700," + HexStr(spender) + "))");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto leaf_script = BuildP2MRRefundLeaf(/*timeout=*/700, PQAlgorithm::ML_DSA_44, spender);
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_cltv_multisig_leaf)
{
    const std::vector<unsigned char> pk1 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x4A);
    const std::vector<unsigned char> pk2 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x4B);
    const std::vector<unsigned char> pk3 = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x4C);
    const std::string desc_str = AddChecksum(
        "mr(cltv_sortedmulti_pq(700,2," + HexStr(pk2) + "," + HexStr(pk1) + ",pk_slh(" + HexStr(pk3) + ")))");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> keys{
        {PQAlgorithm::ML_DSA_44, pk2},
        {PQAlgorithm::ML_DSA_44, pk1},
        {PQAlgorithm::SLH_DSA_128S, pk3},
    };
    std::sort(keys.begin(), keys.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.second < rhs.second;
    });
    const auto leaf_script = BuildP2MRCLTVMultisigScript(/*locktime=*/700, /*threshold=*/2, keys);
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_csv_multisig_leaf)
{
    const std::vector<unsigned char> pk1 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x4D);
    const std::vector<unsigned char> pk2 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x4E);
    const std::vector<unsigned char> pk3 = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x4F);
    const std::string desc_str = AddChecksum(
        "mr(csv_sortedmulti_pq(144,2," + HexStr(pk2) + "," + HexStr(pk1) + ",pk_slh(" + HexStr(pk3) + ")))");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> keys{
        {PQAlgorithm::ML_DSA_44, pk2},
        {PQAlgorithm::ML_DSA_44, pk1},
        {PQAlgorithm::SLH_DSA_128S, pk3},
    };
    std::sort(keys.begin(), keys.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.second < rhs.second;
    });
    const auto leaf_script = BuildP2MRCSVMultisigScript(/*sequence=*/144, /*threshold=*/2, keys);
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_parses_two_leaf_htlc_refund_tree)
{
    const std::vector<unsigned char> hash160 = MakePattern(uint160::size(), 0x47);
    const std::vector<unsigned char> oracle = MakePattern(MLDSA44_PUBKEY_SIZE, 0x48);
    const std::vector<unsigned char> spender = MakePattern(MLDSA44_PUBKEY_SIZE, 0x49);
    const std::string desc_str = AddChecksum(
        "mr(htlc(" + HexStr(hash160) + "," + HexStr(oracle) + "),refund(1024," + HexStr(spender) + "))");
    const auto desc = ParseSingleDescriptor(desc_str);

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(desc->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const auto htlc_leaf = BuildP2MRHTLCLeaf(hash160, PQAlgorithm::ML_DSA_44, oracle);
    const auto refund_leaf = BuildP2MRRefundLeaf(/*timeout=*/1024, PQAlgorithm::ML_DSA_44, spender);
    const uint256 root = ComputeP2MRMerkleRoot({
        ComputeP2MRLeafHash(P2MR_LEAF_VERSION, htlc_leaf),
        ComputeP2MRLeafHash(P2MR_LEAF_VERSION, refund_leaf),
    });
    BOOST_CHECK(scripts[0] == BuildP2MROutput(root));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_rejects_ctv_wrong_hash_length)
{
    const std::string bad_hash = HexStr(MakePattern(31, 0x55));
    FlatSigningProvider provider;
    std::string error;
    const auto parsed = Parse(AddChecksum("mr(ctv(" + bad_hash + "))"), provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_rejects_htlc_wrong_hash_length)
{
    const std::string bad_hash = HexStr(MakePattern(uint160::size() - 1, 0x51));
    const std::string oracle = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x52));
    FlatSigningProvider provider;
    std::string error;
    const auto parsed = Parse(AddChecksum("mr(htlc(" + bad_hash + "," + oracle + "))"), provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_rejects_csfs_pk_leaf_above_policy_limit)
{
    const std::string ml_a = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x61));
    const std::string ml_b = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x62));
    FlatSigningProvider provider;
    std::string error;
    const auto parsed = Parse(AddChecksum("mr(csfs_pk(" + ml_a + "," + ml_b + "))"), provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_CASE(tr_raw_leaf_rejects_p2mr_opsuccess_without_override)
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const std::string xonly = HexStr(XOnlyPubKey(key.GetPubKey()));
    for (const char* opcode_hex : {"bd", "c0", "c1", "c2"}) {
        const std::string desc_str = AddChecksum("tr(" + xonly + ",raw(" + std::string{opcode_hex} + "))");

        FlatSigningProvider provider;
        std::string error;
        const auto parsed = Parse(desc_str, provider, error, /*require_checksum=*/true);
        BOOST_CHECK(parsed.empty());
        BOOST_CHECK(error.find("allow_op_success") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(tr_raw_leaf_allows_p2mr_opsuccess_with_override)
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const std::string xonly = HexStr(XOnlyPubKey(key.GetPubKey()));
    DescriptorParseOptions options;
    options.allow_p2tr_op_success = true;
    for (const char* opcode_hex : {"bd", "c0", "c1", "c2"}) {
        const std::string desc_str = AddChecksum("tr(" + xonly + ",raw(" + std::string{opcode_hex} + "))");
        const auto desc = ParseSingleDescriptor(desc_str, /*require_checksum=*/true, options);
        BOOST_REQUIRE(desc);
        BOOST_CHECK(desc->ToString().find("raw(" + std::string{opcode_hex} + ")") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_builder_helpers_emit_expected_bytes)
{
    const uint256 ctv_hash{MakePattern(32, 0x73)};
    const std::vector<unsigned char> oracle = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x74);
    const std::vector<unsigned char> spender = MakePattern(MLDSA44_PUBKEY_SIZE, 0x75);

    CScript ctv_expected;
    ctv_expected << ToByteVector(ctv_hash) << OP_CHECKTEMPLATEVERIFY;
    BOOST_CHECK(BuildP2MRCTVScript(ctv_hash) ==
                std::vector<unsigned char>(ctv_expected.begin(), ctv_expected.end()));

    CScript delegation_expected;
    delegation_expected << oracle << OP_CHECKSIGFROMSTACK << OP_VERIFY << spender << OP_CHECKSIG_MLDSA;
    BOOST_CHECK(BuildP2MRDelegationScript(
                    PQAlgorithm::SLH_DSA_128S, oracle,
                    PQAlgorithm::ML_DSA_44, spender) ==
                std::vector<unsigned char>(delegation_expected.begin(), delegation_expected.end()));
}

BOOST_AUTO_TEST_CASE(p2mr_multisig_builder_emits_expected_bytes)
{
    const std::vector<unsigned char> pk1 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x81);
    const std::vector<unsigned char> pk2 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x82);
    const std::vector<unsigned char> pk3 = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x83);

    const auto script = BuildP2MRMultisigScript(
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, pk1},
            {PQAlgorithm::ML_DSA_44, pk2},
            {PQAlgorithm::SLH_DSA_128S, pk3},
        });

    CScript expected;
    expected << pk1 << OP_CHECKSIG_MLDSA
             << pk2 << OP_CHECKSIGADD_MLDSA
             << pk3 << OP_CHECKSIGADD_SLHDSA
             << OP_2 << OP_NUMEQUAL;
    BOOST_CHECK(script == std::vector<unsigned char>(expected.begin(), expected.end()));
}

BOOST_AUTO_TEST_CASE(p2mr_multisig_ctv_builder_emits_expected_bytes)
{
    const uint256 ctv_hash{MakePattern(32, 0x84)};
    const std::vector<unsigned char> pk1 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x85);
    const std::vector<unsigned char> pk2 = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x86);

    const auto script = BuildP2MRMultisigCTVScript(
        ctv_hash,
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, pk1},
            {PQAlgorithm::SLH_DSA_128S, pk2},
        });

    const auto multisig_tail = BuildP2MRMultisigScript(
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, pk1},
            {PQAlgorithm::SLH_DSA_128S, pk2},
        });
    CScript expected;
    expected << ToByteVector(ctv_hash) << OP_CHECKTEMPLATEVERIFY << OP_DROP;
    std::vector<unsigned char> expected_bytes(expected.begin(), expected.end());
    expected_bytes.insert(expected_bytes.end(), multisig_tail.begin(), multisig_tail.end());
    BOOST_CHECK(script == expected_bytes);
}

BOOST_AUTO_TEST_CASE(p2mr_multisig_cltv_builder_emits_expected_bytes)
{
    const std::vector<unsigned char> pk1 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x87);
    const std::vector<unsigned char> pk2 = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x88);

    const auto script = BuildP2MRCLTVMultisigScript(
        /*locktime=*/700,
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, pk1},
            {PQAlgorithm::SLH_DSA_128S, pk2},
        });

    const auto multisig_tail = BuildP2MRMultisigScript(
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, pk1},
            {PQAlgorithm::SLH_DSA_128S, pk2},
        });
    CScript expected;
    expected << CScriptNum{700} << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    std::vector<unsigned char> expected_bytes(expected.begin(), expected.end());
    expected_bytes.insert(expected_bytes.end(), multisig_tail.begin(), multisig_tail.end());
    BOOST_CHECK(script == expected_bytes);
}

BOOST_AUTO_TEST_CASE(p2mr_multisig_csv_builder_emits_expected_bytes)
{
    const std::vector<unsigned char> pk1 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x89);
    const std::vector<unsigned char> pk2 = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x8A);

    const auto script = BuildP2MRCSVMultisigScript(
        /*sequence=*/144,
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, pk1},
            {PQAlgorithm::SLH_DSA_128S, pk2},
        });

    const auto multisig_tail = BuildP2MRMultisigScript(
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, pk1},
            {PQAlgorithm::SLH_DSA_128S, pk2},
        });
    CScript expected;
    expected << CScriptNum{144} << OP_CHECKSEQUENCEVERIFY << OP_DROP;
    std::vector<unsigned char> expected_bytes(expected.begin(), expected.end());
    expected_bytes.insert(expected_bytes.end(), multisig_tail.begin(), multisig_tail.end());
    BOOST_CHECK(script == expected_bytes);
}

BOOST_AUTO_TEST_CASE(p2mr_timelock_builders_use_minimal_small_int_encoding)
{
    const std::vector<unsigned char> pk1 = MakePattern(MLDSA44_PUBKEY_SIZE, 0x8B);
    const std::vector<unsigned char> pk2 = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x8C);

    const auto cltv_script = BuildP2MRCLTVMultisigScript(
        /*locktime=*/1,
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, pk1},
            {PQAlgorithm::SLH_DSA_128S, pk2},
        });
    BOOST_REQUIRE_GE(cltv_script.size(), 3U);
    BOOST_CHECK_EQUAL(cltv_script[0], static_cast<unsigned char>(OP_1));
    BOOST_CHECK_EQUAL(cltv_script[1], static_cast<unsigned char>(OP_CHECKLOCKTIMEVERIFY));
    BOOST_CHECK_EQUAL(cltv_script[2], static_cast<unsigned char>(OP_DROP));

    const auto csv_script = BuildP2MRCSVMultisigScript(
        /*sequence=*/1,
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, pk1},
            {PQAlgorithm::SLH_DSA_128S, pk2},
        });
    BOOST_REQUIRE_GE(csv_script.size(), 3U);
    BOOST_CHECK_EQUAL(csv_script[0], static_cast<unsigned char>(OP_1));
    BOOST_CHECK_EQUAL(csv_script[1], static_cast<unsigned char>(OP_CHECKSEQUENCEVERIFY));
    BOOST_CHECK_EQUAL(csv_script[2], static_cast<unsigned char>(OP_DROP));

    const auto refund_script = BuildP2MRRefundLeaf(/*timeout=*/1, PQAlgorithm::ML_DSA_44, pk1);
    BOOST_REQUIRE_GE(refund_script.size(), 3U);
    BOOST_CHECK_EQUAL(refund_script[0], static_cast<unsigned char>(OP_1));
    BOOST_CHECK_EQUAL(refund_script[1], static_cast<unsigned char>(OP_CHECKLOCKTIMEVERIFY));
    BOOST_CHECK_EQUAL(refund_script[2], static_cast<unsigned char>(OP_DROP));
}

BOOST_AUTO_TEST_CASE(p2mr_multisig_builder_rejects_bad_threshold)
{
    const std::vector<unsigned char> pk = MakePattern(MLDSA44_PUBKEY_SIZE, 0x90);
    BOOST_CHECK(BuildP2MRMultisigScript(
                    /*threshold=*/0,
                    {{PQAlgorithm::ML_DSA_44, pk}})
                    .empty());
    BOOST_CHECK(BuildP2MRMultisigScript(
                    /*threshold=*/2,
                    {{PQAlgorithm::ML_DSA_44, pk}})
                    .empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_roundtrip_new_leaf_expressions)
{
    const std::string ctv_hash = HexStr(MakePattern(32, 0x88));
    const std::string oracle = HexStr(MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x21));
    const std::string spender = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x22));
    const std::string no_checksum = "mr(ctv(" + ctv_hash + "),csfs_pk(pk_slh(" + oracle + ")," + spender + "))";
    const auto desc = ParseSingleDescriptor(AddChecksum(no_checksum));
    BOOST_CHECK_EQUAL(desc->ToString(), AddChecksum(no_checksum));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_roundtrip_timelocked_multisig_expressions)
{
    const std::string ctv_hash = HexStr(MakePattern(32, 0x99));
    const std::string pk1 = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x9A));
    const std::string pk2 = HexStr(MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x9B));

    const std::string ctv_expr = "mr(ctv_sortedmulti_pq(" + ctv_hash + ",1," + pk1 + ",pk_slh(" + pk2 + ")))";
    const auto ctv_desc = ParseSingleDescriptor(AddChecksum(ctv_expr));
    BOOST_CHECK_EQUAL(ctv_desc->ToString(), AddChecksum(ctv_expr));

    const std::string cltv_expr = "mr(cltv_multi_pq(2048,1," + pk1 + ",pk_slh(" + pk2 + ")))";
    const auto cltv_desc = ParseSingleDescriptor(AddChecksum(cltv_expr));
    BOOST_CHECK_EQUAL(cltv_desc->ToString(), AddChecksum(cltv_expr));

    const std::string csv_expr = "mr(csv_sortedmulti_pq(144,1," + pk1 + ",pk_slh(" + pk2 + ")))";
    const auto csv_desc = ParseSingleDescriptor(AddChecksum(csv_expr));
    BOOST_CHECK_EQUAL(csv_desc->ToString(), AddChecksum(csv_expr));
}

BOOST_AUTO_TEST_CASE(mr_descriptor_checksum_validation)
{
    const std::string mldsa_hex = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x51));
    const std::string with_checksum = AddChecksum("mr(" + mldsa_hex + ")");

    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(with_checksum, provider, error, /*require_checksum=*/true);
    BOOST_REQUIRE(!parsed.empty());

    std::string bad = with_checksum;
    bad.back() = bad.back() == 'q' ? 'p' : 'q';
    parsed = Parse(bad, provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_tree_syntax_rejects_malformed_backup_tree)
{
    const std::string mldsa_hex = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x5a));
    const std::string slh_hex = HexStr(MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x8a));
    const std::string malformed = AddChecksum("mr(" + mldsa_hex + ",{pk_slh(" + slh_hex + "),})");

    FlatSigningProvider provider;
    std::string error;
    const auto parsed = Parse(malformed, provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_rejects_missing_primary_key)
{
    FlatSigningProvider provider;
    std::string error;
    const auto parsed = Parse(AddChecksum("mr()"), provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_rejects_wrong_primary_key_size)
{
    const std::string mldsa_hex = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE - 1, 0x1a));
    FlatSigningProvider provider;
    std::string error;
    const auto parsed = Parse(AddChecksum("mr(" + mldsa_hex + ")"), provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_rejects_wrong_backup_key_size)
{
    const std::string mldsa_hex = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x2a));
    const std::string slh_hex = HexStr(MakePattern(SLHDSA128S_PUBKEY_SIZE - 1, 0x3a));

    FlatSigningProvider provider;
    std::string error;
    const auto parsed = Parse(AddChecksum("mr(" + mldsa_hex + ",pk_slh(" + slh_hex + "))"), provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_rejects_unknown_backup_wrapper)
{
    const std::string mldsa_hex = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x4a));
    const std::string slh_hex = HexStr(MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x5a));

    FlatSigningProvider provider;
    std::string error;
    const auto parsed = Parse(AddChecksum("mr(" + mldsa_hex + ",pk(" + slh_hex + "))"), provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_rejects_empty_backup_tree_expression)
{
    const std::string mldsa_hex = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x6a));
    FlatSigningProvider provider;
    std::string error;
    const auto parsed = Parse(AddChecksum("mr(" + mldsa_hex + ",{})"), provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_rejects_non_top_level_mr)
{
    const std::string mldsa_hex = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x7a));
    FlatSigningProvider provider;
    std::string error;
    const auto parsed = Parse(AddChecksum("sh(mr(" + mldsa_hex + "))"), provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_CASE(mr_descriptor_rejects_multipath_derivation_syntax)
{
    const std::string xpub =
        "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";

    // Multipath derivation is intentionally unsupported for mr().
    FlatSigningProvider provider;
    std::string error;
    const auto parsed = Parse(AddChecksum("mr(" + xpub + "/87h/<0;1>/0/*)"), provider, error, /*require_checksum=*/true);
    BOOST_CHECK(parsed.empty());
}

BOOST_AUTO_TEST_SUITE_END()
