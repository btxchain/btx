// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>
#include <shielded/note.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <set>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(shielded_note_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(commitment_determinism)
{
    ShieldedNote note;
    note.value = 50 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    const uint256 cm1 = note.GetCommitment();
    const uint256 cm2 = note.GetCommitment();
    BOOST_CHECK(cm1 == cm2);
    BOOST_CHECK(!cm1.IsNull());
}

BOOST_AUTO_TEST_CASE(commitment_uniqueness_different_rho)
{
    ShieldedNote note1;
    ShieldedNote note2;
    note1.value = note2.value = 100 * COIN;
    note1.recipient_pk_hash = note2.recipient_pk_hash = uint256::ONE;
    note1.rcm = note2.rcm = GetRandHash();
    note1.rho = GetRandHash();
    note2.rho = GetRandHash();

    BOOST_CHECK(note1.GetCommitment() != note2.GetCommitment());
}

BOOST_AUTO_TEST_CASE(commitment_uniqueness_different_value)
{
    ShieldedNote note1;
    ShieldedNote note2;
    note1.recipient_pk_hash = note2.recipient_pk_hash = uint256::ONE;
    note1.rho = note2.rho = GetRandHash();
    note1.rcm = note2.rcm = GetRandHash();
    note1.value = 50 * COIN;
    note2.value = 51 * COIN;

    BOOST_CHECK(note1.GetCommitment() != note2.GetCommitment());
}

BOOST_AUTO_TEST_CASE(nullifier_determinism)
{
    ShieldedNote note;
    note.value = 10 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    std::vector<unsigned char> sk(32, 0x42);
    const uint256 nf1 = note.GetNullifier(sk);
    const uint256 nf2 = note.GetNullifier(sk);
    BOOST_CHECK(nf1 == nf2);
    BOOST_CHECK(!nf1.IsNull());
}

BOOST_AUTO_TEST_CASE(nullifier_different_spending_keys)
{
    ShieldedNote note;
    note.value = 10 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    std::vector<unsigned char> sk1(32, 0x01);
    std::vector<unsigned char> sk2(32, 0x02);
    BOOST_CHECK(note.GetNullifier(sk1) != note.GetNullifier(sk2));
}

BOOST_AUTO_TEST_CASE(collision_resistance_10000_notes)
{
    std::set<uint256> commitments;
    std::set<uint256> nullifiers;
    std::vector<unsigned char> sk(32, 0xAB);

    for (int i = 0; i < 10000; ++i) {
        ShieldedNote note;
        note.value = i * COIN;
        note.recipient_pk_hash = uint256::ONE;
        note.rho = GetRandHash();
        note.rcm = GetRandHash();

        BOOST_CHECK(commitments.insert(note.GetCommitment()).second);
        BOOST_CHECK(nullifiers.insert(note.GetNullifier(sk)).second);
    }
}

BOOST_AUTO_TEST_CASE(max_money_note)
{
    ShieldedNote note;
    note.value = MAX_MONEY;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    BOOST_CHECK(note.IsValid());
    BOOST_CHECK(!note.GetCommitment().IsNull());
}

BOOST_AUTO_TEST_CASE(invalid_note_negative_value)
{
    ShieldedNote note;
    note.value = -1;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    BOOST_CHECK(!note.IsValid());
}

BOOST_AUTO_TEST_CASE(invalid_note_null_rho)
{
    ShieldedNote note;
    note.value = COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = uint256::ZERO;
    note.rcm = GetRandHash();

    BOOST_CHECK(!note.IsValid());
}

BOOST_AUTO_TEST_CASE(invalid_note_too_large_memo)
{
    ShieldedNote note;
    note.value = COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();
    note.memo.resize(MAX_SHIELDED_MEMO_SIZE + 1, 0x01);

    BOOST_CHECK(!note.IsValid());
}

BOOST_AUTO_TEST_CASE(serialization_roundtrip)
{
    ShieldedNote note;
    note.value = 42 * COIN;
    note.recipient_pk_hash = GetRandHash();
    note.rho = GetRandHash();
    note.rcm = GetRandHash();
    note.memo = {0x01, 0x02, 0x03};

    DataStream ss{};
    ss << note;

    ShieldedNote decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(note.value, decoded.value);
    BOOST_CHECK(note.recipient_pk_hash == decoded.recipient_pk_hash);
    BOOST_CHECK(note.rho == decoded.rho);
    BOOST_CHECK(note.rcm == decoded.rcm);
    BOOST_CHECK(note.memo == decoded.memo);
    BOOST_CHECK(note.GetCommitment() == decoded.GetCommitment());
}

BOOST_AUTO_TEST_CASE(serialization_rejects_oversized_memo)
{
    ShieldedNote note;
    note.value = COIN;
    note.recipient_pk_hash = GetRandHash();
    note.rho = GetRandHash();
    note.rcm = GetRandHash();
    note.memo.resize(MAX_SHIELDED_MEMO_SIZE + 1, 0x42);

    DataStream ss{};
    BOOST_CHECK_EXCEPTION(ss << note, std::ios_base::failure, HasReason("ShieldedNote::Serialize oversized memo"));
}

BOOST_AUTO_TEST_CASE(unserialization_rejects_oversized_memo)
{
    ShieldedNote note;
    note.value = COIN;
    note.recipient_pk_hash = GetRandHash();
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    DataStream ss{};
    ss << note.value << note.recipient_pk_hash << note.rho << note.rcm;
    uint64_t memo_size = MAX_SHIELDED_MEMO_SIZE + 1;
    ::Serialize(ss, COMPACTSIZE(memo_size));

    ShieldedNote decoded;
    BOOST_CHECK_EXCEPTION(ss >> decoded,
                          std::ios_base::failure,
                          HasReason("ShieldedNote::Unserialize oversized memo"));
}

BOOST_AUTO_TEST_SUITE_END()
