// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <hash.h>
#include <net.h>
#include <signet.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <validation.h>

#include <algorithm>
#include <limits>
#include <string>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    const int maxHalvings{64};
    const CAmount nInitialSubsidy{consensusParams.nInitialSubsidy};

    CAmount nPreviousSubsidy = nInitialSubsidy * 2; // for height == 0
    BOOST_CHECK_EQUAL(nPreviousSubsidy, nInitialSubsidy * 2);
    for (int nHalvings = 0; nHalvings < maxHalvings; nHalvings++) {
        int nHeight = nHalvings * consensusParams.nSubsidyHalvingInterval;
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        BOOST_CHECK(nSubsidy <= nInitialSubsidy);
        BOOST_CHECK_EQUAL(nSubsidy, nPreviousSubsidy / 2);
        nPreviousSubsidy = nSubsidy;
    }
    BOOST_CHECK_EQUAL(GetBlockSubsidy(maxHalvings * consensusParams.nSubsidyHalvingInterval, consensusParams), 0);
}

static void TestBlockSubsidyHalvings(int nSubsidyHalvingInterval)
{
    Consensus::Params consensusParams;
    consensusParams.nSubsidyHalvingInterval = nSubsidyHalvingInterval;
    TestBlockSubsidyHalvings(consensusParams);
}

BOOST_AUTO_TEST_CASE(checkpoint_sanity)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& checkpoints = chainParams->Checkpoints();
    const auto& checkpoint_map = checkpoints.mapCheckpoints;
    BOOST_REQUIRE(!checkpoint_map.empty());

    for (const auto& [height, hash] : checkpoint_map) {
        BOOST_CHECK(checkpoints.CheckBlock(height, hash));

        uint256 wrong_hash{1};
        if (wrong_hash == hash) wrong_hash = uint256{2};
        BOOST_CHECK(!checkpoints.CheckBlock(height, wrong_hash));

        int non_checkpoint_height{height + 1};
        while (checkpoint_map.count(non_checkpoint_height) != 0) ++non_checkpoint_height;
        BOOST_CHECK(checkpoints.CheckBlock(non_checkpoint_height, wrong_hash));
    }
}

BOOST_AUTO_TEST_CASE(checkpoint_height_empty_defaults_to_zero)
{
    CCheckpointData checkpoints;
    BOOST_CHECK_EQUAL(checkpoints.GetHeight(), 0);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    TestBlockSubsidyHalvings(chainParams->GetConsensus()); // As in main
    TestBlockSubsidyHalvings(150); // As in regtest
    TestBlockSubsidyHalvings(1000); // Just another interval
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus{chainParams->GetConsensus()};

    // Sum block subsidies over each halving interval. Total supply is slightly less than
    // nMaxMoney due to integer rounding during halvings.
    CAmount nSum{0};
    for (int halving = 0; halving < 64; ++halving) {
        nSum += (consensus.nInitialSubsidy >> halving) * consensus.nSubsidyHalvingInterval;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK(nSum <= consensus.nMaxMoney);
    BOOST_CHECK_EQUAL(nSum, CAmount{2099999993175000});
}

BOOST_AUTO_TEST_CASE(mldsa_mempool_policy_window)
{
    Consensus::Params consensus_params;
    consensus_params.nMLDSADisableHeight = 2000;

    BOOST_CHECK(!IsMLDSADisallowedForMempool(consensus_params, 1039));
    BOOST_CHECK(IsMLDSADisallowedForMempool(consensus_params, 1040));
    BOOST_CHECK(IsMLDSADisallowedForMempool(consensus_params, 2000));
    BOOST_CHECK(IsMLDSADisallowedForMempool(consensus_params, 5000));
}

BOOST_AUTO_TEST_CASE(mldsa_mempool_policy_disabled_without_cutover_height)
{
    Consensus::Params consensus_params;
    consensus_params.nMLDSADisableHeight = std::numeric_limits<int32_t>::max();

    BOOST_CHECK(!IsMLDSADisallowedForMempool(consensus_params, 0));
    BOOST_CHECK(!IsMLDSADisallowedForMempool(consensus_params, std::numeric_limits<int>::max()));
}

BOOST_AUTO_TEST_CASE(regtest_mldsa_disable_height_override)
{
    ArgsManager args;
    args.ForceSetArg("-mldsadisableheight", "321");

    const auto params = CreateChainParams(args, ChainType::REGTEST);
    BOOST_REQUIRE(params);
    BOOST_CHECK_EQUAL(params->GetConsensus().nMLDSADisableHeight, 321);
}

BOOST_AUTO_TEST_CASE(regtest_mldsa_disable_height_rejects_negative)
{
    ArgsManager args;
    args.ForceSetArg("-mldsadisableheight", "-1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(regtest_shielded_tx_binding_activation_height_override)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedtxbindingactivationheight", "132");

    const auto params = CreateChainParams(args, ChainType::REGTEST);
    BOOST_REQUIRE(params);
    BOOST_CHECK_EQUAL(params->GetConsensus().nShieldedTxBindingActivationHeight, 132);
    BOOST_CHECK(!params->GetConsensus().IsShieldedTxBindingActive(131));
    BOOST_CHECK(params->GetConsensus().IsShieldedTxBindingActive(132));
}

BOOST_AUTO_TEST_CASE(regtest_shielded_tx_binding_activation_height_rejects_negative)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedtxbindingactivationheight", "-1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(regtest_shielded_bridge_tag_activation_height_override)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedbridgetagactivationheight", "132");

    const auto params = CreateChainParams(args, ChainType::REGTEST);
    BOOST_REQUIRE(params);
    BOOST_CHECK_EQUAL(params->GetConsensus().nShieldedBridgeTagActivationHeight, 132);
    BOOST_CHECK(!params->GetConsensus().IsShieldedBridgeTagUpgradeActive(131));
    BOOST_CHECK(params->GetConsensus().IsShieldedBridgeTagUpgradeActive(132));
}

BOOST_AUTO_TEST_CASE(regtest_shielded_bridge_tag_activation_height_rejects_negative)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedbridgetagactivationheight", "-1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(regtest_shielded_smile_rice_codec_disable_height_override)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedsmilericecodecdisableheight", "132");

    const auto params = CreateChainParams(args, ChainType::REGTEST);
    BOOST_REQUIRE(params);
    BOOST_CHECK_EQUAL(params->GetConsensus().nShieldedSmileRiceCodecDisableHeight, 132);
    BOOST_CHECK(!params->GetConsensus().IsShieldedSmileRiceCodecDisabled(131));
    BOOST_CHECK(params->GetConsensus().IsShieldedSmileRiceCodecDisabled(132));
}

BOOST_AUTO_TEST_CASE(regtest_shielded_smile_rice_codec_disable_height_rejects_negative)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedsmilericecodecdisableheight", "-1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(regtest_shielded_matrict_disable_height_override)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedmatrictdisableheight", "132");

    const auto params = CreateChainParams(args, ChainType::REGTEST);
    BOOST_REQUIRE(params);
    BOOST_CHECK_EQUAL(params->GetConsensus().nShieldedMatRiCTDisableHeight, 132);
}

BOOST_AUTO_TEST_CASE(regtest_shielded_matrict_disable_height_rejects_negative)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedmatrictdisableheight", "-1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(regtest_shielded_spend_path_recovery_activation_height_default)
{
    ArgsManager args;

    const auto params = CreateChainParams(args, ChainType::REGTEST);
    BOOST_REQUIRE(params);
    BOOST_CHECK_EQUAL(params->GetConsensus().nShieldedSpendPathRecoveryActivationHeight, 0);
    BOOST_CHECK(params->GetConsensus().IsShieldedSpendPathRecoveryActive(0));
}

BOOST_AUTO_TEST_CASE(regtest_shielded_spend_path_recovery_activation_height_override)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedspendpathrecoveryactivationheight", "245");

    const auto params = CreateChainParams(args, ChainType::REGTEST);
    BOOST_REQUIRE(params);
    BOOST_CHECK_EQUAL(params->GetConsensus().nShieldedSpendPathRecoveryActivationHeight, 245);
    BOOST_CHECK(!params->GetConsensus().IsShieldedSpendPathRecoveryActive(244));
    BOOST_CHECK(params->GetConsensus().IsShieldedSpendPathRecoveryActive(245));
}

BOOST_AUTO_TEST_CASE(regtest_shielded_spend_path_recovery_activation_height_rejects_negative)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedspendpathrecoveryactivationheight", "-1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(regtest_shielded_pq128_upgrade_height_override)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedpq128upgradeheight", "612");

    const auto params = CreateChainParams(args, ChainType::REGTEST);
    BOOST_REQUIRE(params);
    BOOST_CHECK_EQUAL(params->GetConsensus().nShieldedPQ128UpgradeHeight, 612);
    BOOST_CHECK(!params->GetConsensus().IsShieldedPQ128UpgradeActive(611));
    BOOST_CHECK(params->GetConsensus().IsShieldedPQ128UpgradeActive(612));
}

BOOST_AUTO_TEST_CASE(regtest_shielded_pq128_upgrade_height_rejects_negative)
{
    ArgsManager args;
    args.ForceSetArg("-regtestshieldedpq128upgradeheight", "-1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(signet_parse_tests)
{
    ArgsManager signet_argsman;
    signet_argsman.ForceSetArg("-signetchallenge", "51"); // set challenge to OP_TRUE
    const auto signet_params = CreateChainParams(signet_argsman, ChainType::SIGNET);
    CBlock block;
    BOOST_CHECK(signet_params->GetConsensus().signet_challenge == std::vector<uint8_t>{OP_TRUE});
    CScript challenge{OP_TRUE};

    // empty block is invalid
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no witness commitment
    CMutableTransaction cb;
    cb.vout.emplace_back(0, CScript{});
    block.vtx.push_back(MakeTransactionRef(cb));
    block.vtx.push_back(MakeTransactionRef(cb)); // Add dummy tx to exercise merkle root code
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no header is treated valid
    std::vector<uint8_t> witness_commitment_section_141{0xaa, 0x21, 0xa9, 0xed};
    for (int i = 0; i < 32; ++i) {
        witness_commitment_section_141.push_back(0xff);
    }
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no data after header, valid
    std::vector<uint8_t> witness_commitment_section_325{0xec, 0xc7, 0xda, 0xa2};
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Premature end of data, invalid
    witness_commitment_section_325.push_back(0x01);
    witness_commitment_section_325.push_back(0x51);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // has data, valid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Extraneous data, invalid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));
}

//! Test retrieval of valid regtest assumeutxo values.
BOOST_AUTO_TEST_CASE(test_regtest_assumeutxo)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const auto snapshot_heights = params->GetAvailableSnapshotHeights();
    const std::vector<int> expected_snapshot_heights{110, 299, 61'010};
    struct SnapshotExpectation {
        int height;
        const char* hash_serialized;
        int chain_tx_count;
        const char* blockhash;
    };
    const std::vector<SnapshotExpectation> expected_snapshots{
        {
            110,
            "c35580bfd4f6c2ab69a8b1ac446962e5aacb164dc13e237867bd2170b91d7c98",
            111,
            "9e3817054fd9df2c2a27f647a3b9f55f8bc91f05168753543a902074a8f21700",
        },
        {
            299,
            "0ffcf7afd7682a59057ad717784b70ca8fb86cf9209912ccca20261aafa5001a",
            300,
            "78e6ea382d4d5466b1d8421c1b8789e9c7cde9de8b6da4042be00ca2948a4860",
        },
        {
            61'010,
            "0000000000000000000000000000000000000000000000000000000000000000",
            61'011,
            "0000000000000000000000000000000000000000000000000000000000000000",
        },
    };

    // These heights don't have assumeutxo configurations associated, per the contents
    // of kernel/chainparams.cpp.
    const std::vector<int> bad_heights{0, 100, 111, 115, 209, 211};

    BOOST_REQUIRE_EQUAL(snapshot_heights.size(), expected_snapshot_heights.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(snapshot_heights.begin(),
                                  snapshot_heights.end(),
                                  expected_snapshot_heights.begin(),
                                  expected_snapshot_heights.end());

    for (const auto& expected_snapshot : expected_snapshots) {
        const auto out = params->AssumeutxoForHeight(expected_snapshot.height);
        BOOST_REQUIRE(out);
        const auto expected_hash = uint256::FromHex(expected_snapshot.hash_serialized);
        BOOST_REQUIRE(expected_hash.has_value());
        BOOST_CHECK_EQUAL(out->height, expected_snapshot.height);
        BOOST_CHECK_EQUAL(out->hash_serialized.ToString(), expected_snapshot.hash_serialized);
        BOOST_CHECK_EQUAL(out->m_chain_tx_count, expected_snapshot.chain_tx_count);
        BOOST_CHECK_EQUAL(out->blockhash.GetHex(), expected_snapshot.blockhash);
        BOOST_CHECK(params->AssumeutxoHashMatches(*out, *expected_hash));
        BOOST_CHECK_EQUAL(params->AssumeutxoHashMatches(*out, uint256{1}),
                          expected_snapshot.height == 61'010);

        const auto out_by_hash = params->AssumeutxoForBlockhash(out->blockhash);
        BOOST_REQUIRE(out_by_hash);

        BOOST_CHECK_EQUAL(out_by_hash->height, out->height);
        BOOST_CHECK_EQUAL(out_by_hash->hash_serialized.ToString(), out->hash_serialized.ToString());
        BOOST_CHECK_EQUAL(out_by_hash->m_chain_tx_count, out->m_chain_tx_count);
    }

    for (const auto empty : bad_heights) {
        if (std::find(snapshot_heights.begin(), snapshot_heights.end(), empty) != snapshot_heights.end()) continue;
        BOOST_CHECK(!params->AssumeutxoForHeight(empty));
    }
    BOOST_CHECK(!params->AssumeutxoForBlockhash(uint256{1}));
}

BOOST_AUTO_TEST_CASE(test_mainnet_assumeutxo_snapshot_metadata)
{
    // Mainnet snapshots are anchored again; verify the published heights and a
    // few positive/negative lookups.
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto snapshot_heights = params->GetAvailableSnapshotHeights();
    const std::vector<int> expected_snapshot_heights{55'000, 60'760, 64'900, 71'260, 71'435, 85'850};

    BOOST_REQUIRE_EQUAL(snapshot_heights.size(), expected_snapshot_heights.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(snapshot_heights.begin(),
                                  snapshot_heights.end(),
                                  expected_snapshot_heights.begin(),
                                  expected_snapshot_heights.end());

    BOOST_CHECK(params->AssumeutxoForHeight(55'000));
    BOOST_CHECK(params->AssumeutxoForHeight(60'760));
    BOOST_CHECK(params->AssumeutxoForHeight(64'900));
    BOOST_CHECK(params->AssumeutxoForHeight(71'260));
    BOOST_CHECK(params->AssumeutxoForHeight(71'435));
    BOOST_CHECK(params->AssumeutxoForHeight(85'850));
    BOOST_CHECK(!params->AssumeutxoForHeight(50'000));
    BOOST_CHECK(!params->AssumeutxoForHeight(0));
}

BOOST_AUTO_TEST_CASE(block_malleation)
{
    // Test utilities that calls `IsBlockMutated` and then clears the validity
    // cache flags on `CBlock`.
    auto is_mutated = [](CBlock& block, bool check_witness_root) {
        bool mutated{IsBlockMutated(block, check_witness_root)};
        block.fChecked = false;
        block.m_checked_witness_commitment = false;
        block.m_checked_merkle_root = false;
        return mutated;
    };
    auto is_not_mutated = [&is_mutated](CBlock& block, bool check_witness_root) {
        return !is_mutated(block, check_witness_root);
    };

    // Test utilities to create coinbase transactions and insert witness
    // commitments.
    //
    // Note: this will not include the witness stack by default to avoid
    // triggering the "no witnesses allowed for blocks that don't commit to
    // witnesses" rule when testing other malleation vectors.
    auto create_coinbase_tx = [](bool include_witness = false) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        if (include_witness) {
            coinbase.vin[0].scriptWitness.stack.resize(1);
            coinbase.vin[0].scriptWitness.stack[0] = std::vector<unsigned char>(32, 0x00);
        }

        coinbase.vout.resize(1);
        coinbase.vout[0].scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        coinbase.vout[0].scriptPubKey[0] = OP_RETURN;
        coinbase.vout[0].scriptPubKey[1] = 0x24;
        coinbase.vout[0].scriptPubKey[2] = 0xaa;
        coinbase.vout[0].scriptPubKey[3] = 0x21;
        coinbase.vout[0].scriptPubKey[4] = 0xa9;
        coinbase.vout[0].scriptPubKey[5] = 0xed;

        auto tx = MakeTransactionRef(coinbase);
        assert(tx->IsCoinBase());
        return tx;
    };
    auto insert_witness_commitment = [](CBlock& block, uint256 commitment) {
        assert(!block.vtx.empty() && block.vtx[0]->IsCoinBase() && !block.vtx[0]->vout.empty());

        CMutableTransaction mtx{*block.vtx[0]};
        CHash256().Write(commitment).Write(std::vector<unsigned char>(32, 0x00)).Finalize(commitment);
        memcpy(&mtx.vout[0].scriptPubKey[6], commitment.begin(), 32);
        block.vtx[0] = MakeTransactionRef(mtx);
    };

    {
        CBlock block;

        // Empty block is expected to have merkle root of 0x0.
        BOOST_CHECK(block.vtx.empty());
        block.hashMerkleRoot = uint256{1};
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = uint256{};
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with a single coinbase tx is mutated if the merkle root is not
        // equal to the coinbase tx's hash.
        block.vtx.push_back(create_coinbase_tx());
        BOOST_CHECK(block.vtx[0]->GetHash() != block.hashMerkleRoot);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = block.vtx[0]->GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if the merkle root does not
        // match the double sha256 of the concatenation of the two transaction
        // hashes.
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        HashWriter hasher;
        hasher.write(block.vtx[0]->GetHash());
        hasher.write(block.vtx[1]->GetHash());
        block.hashMerkleRoot = hasher.GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if any node is duplicate.
        {
            block.vtx[1] = block.vtx[0];
            HashWriter hasher;
            hasher.write(block.vtx[0]->GetHash());
            hasher.write(block.vtx[1]->GetHash());
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        }

        // Blocks with 64-byte coinbase transactions are not considered mutated
        block.vtx.clear();
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.resize(1);
            mtx.vout[0].scriptPubKey.resize(4);
            block.vtx.push_back(MakeTransactionRef(mtx));
            block.hashMerkleRoot = block.vtx.back()->GetHash();
            assert(block.vtx.back()->IsCoinBase());
            assert(GetSerializeSize(TX_NO_WITNESS(block.vtx.back())) == 64);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));
    }

    {
        // Test merkle root malleation

        // Pseudo code to mine transactions tx{1,2,3}:
        //
        // ```
        // loop {
        //   tx1 = random_tx()
        //   tx2 = random_tx()
        //   tx3 = deserialize_tx(txid(tx1) || txid(tx2));
        //   if serialized_size_without_witness(tx3) == 64 {
        //     print(hex(tx3))
        //     break
        //   }
        // }
        // ```
        //
        // The `random_tx` function used to mine the txs below simply created
        // empty transactions with a random version field.
        CMutableTransaction tx1;
        BOOST_CHECK(DecodeHexTx(tx1, "ff204bd0000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx2;
        BOOST_CHECK(DecodeHexTx(tx2, "8ae53c92000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx3;
        BOOST_CHECK(DecodeHexTx(tx3, "cdaf22d00002c6a7f848f8ae4d30054e61dcf3303d6fe01d282163341f06feecc10032b3160fcab87bdfe3ecfb769206ef2d991b92f8a268e423a6ef4d485f06", /*try_no_witness=*/true, /*try_witness=*/false));
        {
            // Verify that double_sha256(txid1||txid2) == txid3
            HashWriter hasher;
            hasher.write(tx1.GetHash());
            hasher.write(tx2.GetHash());
            assert(hasher.GetHash() == tx3.GetHash());
            // Verify that tx3 is 64 bytes in size (without witness).
            assert(GetSerializeSize(TX_NO_WITNESS(tx3)) == 64);
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(tx1));
        block.vtx.push_back(MakeTransactionRef(tx2));
        uint256 merkle_root = block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Mutate the block by replacing the two transactions with one 64-byte
        // transaction that serializes into the concatenation of the txids of
        // the transactions in the unmutated block.
        block.vtx.clear();
        block.vtx.push_back(MakeTransactionRef(tx3));
        BOOST_CHECK(!block.vtx.back()->IsCoinBase());
        BOOST_CHECK(BlockMerkleRoot(block) == merkle_root);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
    }

    {
        CBlock block;
        block.vtx.push_back(create_coinbase_tx(/*include_witness=*/true));
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vin[0].scriptWitness.stack.resize(1);
            mtx.vin[0].scriptWitness.stack[0] = {0};
            block.vtx.push_back(MakeTransactionRef(mtx));
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        // Block with witnesses is considered mutated if the witness commitment
        // is not validated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        // Block with invalid witness commitment is considered mutated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));

        // Block with valid commitment is not mutated
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Malleating witnesses should be caught by `IsBlockMutated`.
        {
            CMutableTransaction mtx{*block.vtx[1]};
            assert(!mtx.vin[0].scriptWitness.stack[0].empty());
            ++mtx.vin[0].scriptWitness.stack[0][0];
            block.vtx[1] = MakeTransactionRef(mtx);
        }
        // Without also updating the witness commitment, the merkle root should
        // not change when changing one of the witnesses.
        BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Test malleating the coinbase witness reserved value
        {
            CMutableTransaction mtx{*block.vtx[0]};
            mtx.vin[0].scriptWitness.stack.resize(0);
            block.vtx[0] = MakeTransactionRef(mtx);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
    }
}

BOOST_AUTO_TEST_SUITE_END()
