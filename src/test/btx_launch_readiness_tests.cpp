// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Launch readiness regression tests: validates critical security and consensus
// properties remain intact across code changes.  Each test targets a specific
// property identified in the 2026-03-06 deep audit.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <crypto/ml_kem.h>
#include <dandelion.h>
#include <random.h>
#include <shielded/bundle.h>
#include <shielded/lattice/params.h>
#include <shielded/merkle_tree.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <shielded/nullifier.h>
#include <shielded/ringct/ring_selection.h>
#include <shielded/smile2/domain_separation.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/overflow.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <set>
#include <vector>

namespace lattice = shielded::lattice;

BOOST_FIXTURE_TEST_SUITE(btx_launch_readiness_tests, BasicTestingSetup)

// =========================================================================
// LR-1: P2MR-only enforcement on production networks
// =========================================================================
BOOST_AUTO_TEST_CASE(lr1_p2mr_enforced_on_production_networks)
{
    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET}) {
        ArgsManager args;
        const auto params = CreateChainParams(args, chain);
        BOOST_CHECK_MESSAGE(params->GetConsensus().fEnforceP2MROnlyOutputs,
                            "P2MR enforcement must be enabled on production network");
    }
    // Regtest intentionally allows non-P2MR for testing flexibility
    {
        ArgsManager args;
        const auto params = CreateChainParams(args, ChainType::REGTEST);
        BOOST_CHECK(!params->GetConsensus().fEnforceP2MROnlyOutputs);
    }
}

// =========================================================================
// LR-2: Shielded pool active from genesis on all networks
// =========================================================================
BOOST_AUTO_TEST_CASE(lr2_shielded_pool_active_from_genesis)
{
    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::REGTEST}) {
        ArgsManager args;
        const auto params = CreateChainParams(args, chain);
        BOOST_CHECK_EQUAL(params->GetConsensus().nShieldedPoolActivationHeight, 0);
    }
}

// =========================================================================
// LR-3: ML-KEM-768 key sizes are NIST-correct
// =========================================================================
BOOST_AUTO_TEST_CASE(lr3_mlkem768_key_sizes)
{
    BOOST_CHECK_EQUAL(mlkem::PUBLICKEYBYTES, 1184u);
    BOOST_CHECK_EQUAL(mlkem::SECRETKEYBYTES, 2400u);
    BOOST_CHECK_EQUAL(mlkem::CIPHERTEXTBYTES, 1088u);
    BOOST_CHECK_EQUAL(mlkem::SHAREDSECRETBYTES, 32u);
}

// =========================================================================
// LR-4: Lattice parameters match NIST Level 2 (Dilithium-2)
// =========================================================================
BOOST_AUTO_TEST_CASE(lr4_lattice_params_nist_level2)
{
    BOOST_CHECK_EQUAL(lattice::POLY_N, 256);
    BOOST_CHECK_EQUAL(lattice::POLY_Q, 8380417);
    BOOST_CHECK_EQUAL(lattice::MODULE_RANK, 4);
    BOOST_CHECK_EQUAL(lattice::SECRET_SMALL_ETA, 2);
    // Q must be prime
    const int32_t q = lattice::POLY_Q;
    bool is_prime = (q > 1);
    for (int32_t i = 2; i * i <= q; ++i) {
        if (q % i == 0) { is_prime = false; break; }
    }
    BOOST_CHECK(is_prime);
    // Q ≡ 1 (mod 2*N) for NTT compatibility
    BOOST_CHECK_EQUAL(q % (2 * lattice::POLY_N), 1);
}

// =========================================================================
// LR-5: Rejection sampling gap is positive and sufficient
// =========================================================================
BOOST_AUTO_TEST_CASE(lr5_rejection_sampling_gap)
{
    const int32_t gap = lattice::GAMMA_RESPONSE -
                        lattice::BETA_CHALLENGE * lattice::SECRET_SMALL_ETA;
    BOOST_CHECK_GT(gap, 0);
    BOOST_CHECK_GT(gap, 100000);
}

// =========================================================================
// LR-6: Launch ring policy is 8 by default with a larger supported ceiling
// =========================================================================
BOOST_AUTO_TEST_CASE(lr6_ring_size_minimum)
{
    BOOST_CHECK_EQUAL(lattice::RING_SIZE, lattice::DEFAULT_RING_SIZE);
    BOOST_CHECK_EQUAL(lattice::DEFAULT_RING_SIZE, 8u);
    BOOST_CHECK_GE(lattice::MIN_RING_SIZE, 8u);
    BOOST_CHECK_GE(lattice::MAX_RING_SIZE, 32u);
}

// =========================================================================
// LR-7: EncryptedNote fields are value-initialized (no UB)
// =========================================================================
BOOST_AUTO_TEST_CASE(lr7_encrypted_note_default_initialization)
{
    shielded::EncryptedNote note;
    bool all_zero = std::all_of(note.kem_ciphertext.begin(),
                                note.kem_ciphertext.end(),
                                [](uint8_t b) { return b == 0; });
    BOOST_CHECK(all_zero);
    bool nonce_zero = std::all_of(note.aead_nonce.begin(),
                                  note.aead_nonce.end(),
                                  [](uint8_t b) { return b == 0; });
    BOOST_CHECK(nonce_zero);
}

// =========================================================================
// LR-8: Note encryption round-trip works correctly
// =========================================================================
BOOST_AUTO_TEST_CASE(lr8_note_encryption_roundtrip)
{
    auto kp = mlkem::KeyGen();
    const auto& pk = kp.pk;
    const auto& sk = kp.sk;

    ShieldedNote test_note;
    test_note.value = 50 * COIN;
    test_note.recipient_pk_hash = GetRandHash();
    test_note.rho = GetRandHash();
    test_note.rcm = GetRandHash();
    BOOST_CHECK(test_note.IsValid());

    auto encrypted = shielded::NoteEncryption::Encrypt(test_note, pk);
    auto decrypted = shielded::NoteEncryption::TryDecrypt(encrypted, pk, sk);
    BOOST_CHECK(decrypted.has_value());
    BOOST_CHECK_EQUAL(decrypted->value, test_note.value);
    BOOST_CHECK_EQUAL(decrypted->rho.ToString(), test_note.rho.ToString());
    BOOST_CHECK_EQUAL(decrypted->rcm.ToString(), test_note.rcm.ToString());
}

// =========================================================================
// LR-9: Nullifier uniqueness from random data
// =========================================================================
BOOST_AUTO_TEST_CASE(lr9_nullifier_uniqueness)
{
    std::set<std::string> nullifiers;
    for (int i = 0; i < 100; ++i) {
        Nullifier nf;
        GetRandBytes(Span<unsigned char>{nf.begin(), static_cast<size_t>(nf.size())});
        BOOST_CHECK(!nf.IsNull());
        nullifiers.insert(nf.ToString());
    }
    BOOST_CHECK_EQUAL(nullifiers.size(), 100u);
}

// =========================================================================
// LR-10: Merkle tree domain separation
// =========================================================================
BOOST_AUTO_TEST_CASE(lr10_merkle_tree_domain_separation)
{
    const uint256 empty = shielded::EmptyLeafHash();
    BOOST_CHECK(!empty.IsNull());
    BOOST_CHECK_EQUAL(shielded::EmptyRoot(0).ToString(), empty.ToString());
    const uint256 expected_depth1 = shielded::BranchHash(empty, empty);
    BOOST_CHECK_EQUAL(shielded::EmptyRoot(1).ToString(), expected_depth1.ToString());
}

// =========================================================================
// LR-11: Ring selection is deterministic from seed
// =========================================================================
BOOST_AUTO_TEST_CASE(lr11_ring_selection_deterministic_from_seed)
{
    const uint256 seed1 = GetRandHash();
    const uint256 seed2 = GetRandHash();

    auto ring1 = shielded::ringct::SelectRingPositions(5, 100, seed1, 16);
    auto ring2 = shielded::ringct::SelectRingPositions(5, 100, seed2, 16);
    auto ring1_again = shielded::ringct::SelectRingPositions(5, 100, seed1, 16);

    BOOST_CHECK(ring1.positions == ring1_again.positions);
    BOOST_CHECK_EQUAL(ring1.real_index, ring1_again.real_index);
    BOOST_CHECK(ring1.positions != ring2.positions);
}

// =========================================================================
// LR-12: CheckedAdd prevents overflow in auto-shield accumulation
// =========================================================================
BOOST_AUTO_TEST_CASE(lr12_checked_add_overflow_detection)
{
    auto result = CheckedAdd(MAX_MONEY, CAmount{1});
    BOOST_CHECK(!result.has_value() || !MoneyRange(*result));

    auto normal = CheckedAdd(CAmount{100}, CAmount{200});
    BOOST_CHECK(normal.has_value());
    BOOST_CHECK_EQUAL(*normal, 300);
}

// =========================================================================
// LR-13: MatMul PoW parameters are set on mainnet
// =========================================================================
BOOST_AUTO_TEST_CASE(lr13_matmul_pow_parameters)
{
    ArgsManager args;
    const auto params = CreateChainParams(args, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    BOOST_CHECK(consensus.fMatMulPOW);
    BOOST_CHECK_EQUAL(consensus.nMatMulDimension, 512u);
    BOOST_CHECK_GT(consensus.nMatMulTranscriptBlockSize, 0u);
}

// =========================================================================
// LR-14: Fast-mine phase is enabled through the bootstrap window; ASERT activates at boundary
// =========================================================================
BOOST_AUTO_TEST_CASE(lr14_fast_mine_window)
{
    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::REGTEST}) {
        ArgsManager args;
        const auto params = CreateChainParams(args, chain);
        const auto& consensus = params->GetConsensus();

        const int32_t expected_fast_height =
            chain == ChainType::REGTEST ? 0 :
            chain == ChainType::MAIN ? 50'000 :
            61'000;
        BOOST_CHECK_EQUAL(consensus.nFastMineHeight, expected_fast_height);
        BOOST_CHECK_EQUAL(consensus.nMatMulAsertHeight, expected_fast_height);
        BOOST_CHECK_LT(consensus.nPowTargetSpacingFastMs,
                       consensus.nPowTargetSpacing * 1000);
    }
}

// =========================================================================
// LR-15: Monetary supply cap is correct
// =========================================================================
BOOST_AUTO_TEST_CASE(lr15_monetary_supply_cap)
{
    BOOST_CHECK_EQUAL(MAX_MONEY, int64_t{21000000} * COIN);
}

// =========================================================================
// LR-16: MatRiCT disable height is consistently enforced at block 61000
// =========================================================================
BOOST_AUTO_TEST_CASE(lr16_matrict_disable_height_boundary)
{
    for (const auto chain : {ChainType::MAIN,
                             ChainType::TESTNET,
                             ChainType::TESTNET4,
                             ChainType::SIGNET,
                             ChainType::REGTEST,
                             ChainType::SHIELDEDV2DEV}) {
        ArgsManager args;
        const auto params = CreateChainParams(args, chain);
        const auto& consensus = params->GetConsensus();

        BOOST_CHECK_GE(consensus.nShieldedMatRiCTDisableHeight, 0);
        if (consensus.nShieldedMatRiCTDisableHeight > 0) {
            BOOST_CHECK(!consensus.IsShieldedMatRiCTDisabled(consensus.nShieldedMatRiCTDisableHeight - 1));
        }
        BOOST_CHECK(consensus.IsShieldedMatRiCTDisabled(consensus.nShieldedMatRiCTDisableHeight));
        BOOST_CHECK(consensus.IsShieldedMatRiCTDisabled(consensus.nShieldedMatRiCTDisableHeight + 1));
    }
}

BOOST_AUTO_TEST_CASE(lr17_smile_domain_registry_constants_are_centralized)
{
    BOOST_CHECK_EQUAL(smile2::domainsep::MEMBERSHIP_GAMMA1_ROWS, 300U);
    BOOST_CHECK_EQUAL(smile2::domainsep::MembershipRecursionGamma(2), 332U);
    BOOST_CHECK_EQUAL(smile2::domainsep::MEMBERSHIP_FINAL_GAMMA, 360U);
    BOOST_CHECK_EQUAL(smile2::domainsep::CT_OPENING_CHALLENGE_BASE, 920U);
}

BOOST_AUTO_TEST_CASE(lr18_account_registry_total_entry_cap_is_bounded_post_fork)
{
    for (const auto chain : {ChainType::MAIN,
                             ChainType::TESTNET,
                             ChainType::TESTNET4,
                             ChainType::SIGNET,
                             ChainType::REGTEST,
                             ChainType::SHIELDEDV2DEV}) {
        ArgsManager args;
        const auto params = CreateChainParams(args, chain);
        const auto& consensus = params->GetConsensus();

        BOOST_CHECK_EQUAL(consensus.nMaxShieldedAccountRegistryEntries, 65'536U);
        BOOST_CHECK(consensus.IsShieldedMatRiCTDisabled(61'000));
    }
}

BOOST_AUTO_TEST_CASE(lr19_dandelion_activation_matches_fork_boundary)
{
    Dandelion::DandelionManager manager;
    const auto& consensus = Params().GetConsensus();
    BOOST_CHECK(!manager.IsActive(consensus.nShieldedMatRiCTDisableHeight - 1));
    BOOST_CHECK(manager.IsActive(consensus.nShieldedMatRiCTDisableHeight));
}

BOOST_AUTO_TEST_CASE(lr20_settlement_anchor_maturity_activates_at_fork_boundary)
{
    for (const auto chain : {ChainType::MAIN,
                             ChainType::TESTNET,
                             ChainType::TESTNET4,
                             ChainType::SIGNET,
                             ChainType::REGTEST,
                             ChainType::SHIELDEDV2DEV}) {
        ArgsManager args;
        const auto params = CreateChainParams(args, chain);
        const auto& consensus = params->GetConsensus();

        BOOST_CHECK_EQUAL(consensus.nShieldedSettlementAnchorMaturity, 6U);
        if (consensus.nShieldedMatRiCTDisableHeight > 0) {
            BOOST_CHECK_EQUAL(
                consensus.GetShieldedSettlementAnchorMaturityDepth(consensus.nShieldedMatRiCTDisableHeight - 1),
                0U);
        }
        BOOST_CHECK_EQUAL(
            consensus.GetShieldedSettlementAnchorMaturityDepth(consensus.nShieldedMatRiCTDisableHeight),
            6U);
        BOOST_CHECK_EQUAL(
            consensus.GetShieldedSettlementAnchorMaturityDepth(consensus.nShieldedMatRiCTDisableHeight + 1),
            6U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
