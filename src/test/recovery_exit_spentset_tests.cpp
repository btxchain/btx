// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>
#include <shielded/nullifier.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <filesystem>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(recovery_exit_spentset_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(insert_and_contains)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_rx_basic", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const uint256 cm = GetRandHash();

    BOOST_CHECK(!ns.ContainsRecoveryExitCommitment(cm));
    BOOST_CHECK(ns.InsertRecoveryExitCommitments({cm}));
    BOOST_CHECK(ns.ContainsRecoveryExitCommitment(cm));
}

// Connect on block N (Insert), then a fresh restart must still see the commitment
// purely from the persisted DB (on-demand ExistsInDB read), proving persistence.
BOOST_AUTO_TEST_CASE(persists_across_restart)
{
    const std::filesystem::path db_path = m_args.GetDataDirNet() / "test_rx_restart";
    const uint256 cm_a = GetRandHash();
    const uint256 cm_b = GetRandHash();

    {
        NullifierSet ns(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
        BOOST_CHECK(ns.InsertRecoveryExitCommitments({cm_a, cm_b}));
        BOOST_CHECK(ns.ContainsRecoveryExitCommitment(cm_a));
        BOOST_CHECK(ns.ContainsRecoveryExitCommitment(cm_b));
    }

    {
        // Fresh instance: empty in-memory caches, so Contains must hit ExistsInDB.
        NullifierSet restarted(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/false);
        BOOST_CHECK(restarted.ContainsRecoveryExitCommitment(cm_a));
        BOOST_CHECK(restarted.ContainsRecoveryExitCommitment(cm_b));

        std::vector<uint256> persisted;
        BOOST_CHECK(restarted.ForEachPersistedRecoveryExitCommitment([&](const uint256& cm) {
            persisted.push_back(cm);
            return true;
        }));
        BOOST_CHECK_EQUAL(persisted.size(), 2U);
        BOOST_CHECK(std::find(persisted.begin(), persisted.end(), cm_a) != persisted.end());
        BOOST_CHECK(std::find(persisted.begin(), persisted.end(), cm_b) != persisted.end());
    }
}

// DisconnectBlock undo: Remove reverses an Insert (reorg-safe), in-memory and on a
// fresh read after restart.
BOOST_AUTO_TEST_CASE(remove_reverses_insert_reorg)
{
    const std::filesystem::path db_path = m_args.GetDataDirNet() / "test_rx_reorg";
    const uint256 cm_a = GetRandHash();
    const uint256 cm_b = GetRandHash();
    const uint256 cm_c = GetRandHash();

    NullifierSet ns(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);

    // ConnectBlock
    BOOST_CHECK(ns.InsertRecoveryExitCommitments({cm_a, cm_b, cm_c}));
    BOOST_CHECK(ns.ContainsRecoveryExitCommitment(cm_a));
    BOOST_CHECK(ns.ContainsRecoveryExitCommitment(cm_b));
    BOOST_CHECK(ns.ContainsRecoveryExitCommitment(cm_c));

    // DisconnectBlock
    BOOST_CHECK(ns.RemoveRecoveryExitCommitments({cm_a, cm_b, cm_c}));
    BOOST_CHECK(!ns.ContainsRecoveryExitCommitment(cm_a));
    BOOST_CHECK(!ns.ContainsRecoveryExitCommitment(cm_b));
    BOOST_CHECK(!ns.ContainsRecoveryExitCommitment(cm_c));

    // Re-connect a different block re-spending one of them must succeed.
    BOOST_CHECK(ns.InsertRecoveryExitCommitments({cm_a}));
    BOOST_CHECK(ns.ContainsRecoveryExitCommitment(cm_a));

    // The removal must also be durable across a restart (DB-level erase, not just cache).
    BOOST_CHECK(ns.RemoveRecoveryExitCommitments({cm_a}));
}

BOOST_AUTO_TEST_CASE(removal_durable_across_restart)
{
    const std::filesystem::path db_path = m_args.GetDataDirNet() / "test_rx_remove_restart";
    const uint256 cm = GetRandHash();

    {
        NullifierSet ns(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
        BOOST_CHECK(ns.InsertRecoveryExitCommitments({cm}));
        BOOST_CHECK(ns.RemoveRecoveryExitCommitments({cm}));
    }

    {
        NullifierSet restarted(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/false);
        BOOST_CHECK(!restarted.ContainsRecoveryExitCommitment(cm));
    }
}

BOOST_AUTO_TEST_CASE(double_insert_idempotent)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_rx_dup", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const uint256 cm = GetRandHash();

    BOOST_CHECK(ns.InsertRecoveryExitCommitments({cm}));
    BOOST_CHECK(ns.InsertRecoveryExitCommitments({cm}));
    BOOST_CHECK(ns.ContainsRecoveryExitCommitment(cm));
    BOOST_CHECK(ns.RemoveRecoveryExitCommitments({cm}));
    BOOST_CHECK(!ns.ContainsRecoveryExitCommitment(cm));
}

BOOST_AUTO_TEST_CASE(empty_and_null_rejected)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_rx_bad", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);

    // Null commitment is never contained and is rejected on insert/remove.
    BOOST_CHECK(!ns.ContainsRecoveryExitCommitment(uint256::ZERO));
    BOOST_CHECK(!ns.InsertRecoveryExitCommitments({uint256::ZERO}));
    BOOST_CHECK(!ns.RemoveRecoveryExitCommitments({uint256::ZERO}));

    // Empty insert is rejected (nothing to connect). Empty remove is a no-op success.
    BOOST_CHECK(!ns.InsertRecoveryExitCommitments({}));
    BOOST_CHECK(ns.RemoveRecoveryExitCommitments({}));
}

// Critical: the recovery-exit commitment set and the nullifier set live in SEPARATE
// LevelDB keyspaces (distinct prefix bytes 'R' vs 'N'). The SAME uint256 value inserted
// into one set must NOT appear in the other, in either direction.
BOOST_AUTO_TEST_CASE(separate_keyspace_from_nullifiers)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_rx_keyspace", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const uint256 shared = GetRandHash();

    // Insert as a recovery-exit commitment only.
    BOOST_CHECK(ns.InsertRecoveryExitCommitments({shared}));
    BOOST_CHECK(ns.ContainsRecoveryExitCommitment(shared));
    // It must NOT leak into the nullifier keyspace.
    BOOST_CHECK(!ns.Contains(static_cast<Nullifier>(shared)));
    BOOST_CHECK(!ns.AnyExist({static_cast<Nullifier>(shared)}));

    // Now insert the SAME value as a nullifier.
    BOOST_CHECK(ns.Insert({static_cast<Nullifier>(shared)}));
    BOOST_CHECK(ns.Contains(static_cast<Nullifier>(shared)));
    // Both sets independently report the value present.
    BOOST_CHECK(ns.ContainsRecoveryExitCommitment(shared));

    // Removing it from the nullifier set must NOT remove it from the commitment set.
    BOOST_CHECK(ns.Remove({static_cast<Nullifier>(shared)}));
    BOOST_CHECK(!ns.Contains(static_cast<Nullifier>(shared)));
    BOOST_CHECK(ns.ContainsRecoveryExitCommitment(shared)); // commitment survives

    // And vice-versa: removing from the commitment set leaves any (re-inserted)
    // nullifier untouched.
    BOOST_CHECK(ns.Insert({static_cast<Nullifier>(shared)}));
    BOOST_CHECK(ns.RemoveRecoveryExitCommitments({shared}));
    BOOST_CHECK(!ns.ContainsRecoveryExitCommitment(shared));
    BOOST_CHECK(ns.Contains(static_cast<Nullifier>(shared))); // nullifier survives
}

BOOST_AUTO_TEST_SUITE_END()
