// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clearing.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_clearing_tests, BasicTestingSetup)

namespace {

modelnet::SwarmPoolSlice Slice(std::string pool_id, int64_t reserved)
{
    modelnet::SwarmPoolSlice slice;
    slice.pool_id = std::move(pool_id);
    slice.reserved = reserved;
    return slice;
}

modelnet::SwarmCoordinatedPayment Pay(std::string payment_id, std::string from_pool, std::string to_pool, int64_t atoms)
{
    modelnet::SwarmCoordinatedPayment payment;
    payment.payment_id = std::move(payment_id);
    payment.from_pool = std::move(from_pool);
    payment.to_pool = std::move(to_pool);
    payment.atoms = atoms;
    return payment;
}

struct TmpDir {
    fs::path path;
    explicit TmpDir(const char* name)
    {
        path = fs::temp_directory_path() / (std::string("btx-swarm-clearing-") + name + "-" + std::to_string(::getpid()));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~TmpDir() { fs::remove_all(path); }
};

} // namespace

BOOST_AUTO_TEST_CASE(one_batch_nets_three_pools_inside_one_channel)
{
    modelnet::SwarmClearingBook book;
    std::string err;
    const std::vector<modelnet::SwarmPoolSlice> slices{Slice("A", 100), Slice("B", 100), Slice("C", 100)};
    BOOST_CHECK(book.Open(300, slices, err));

    modelnet::SwarmClearingReceipt ignored;
    BOOST_CHECK(!book.Apply({}, ignored, err));
    BOOST_CHECK_EQUAL(err, "EMPTY");

    const std::vector<modelnet::SwarmCoordinatedPayment> duplicated{
        Pay("dup", "A", "B", 1),
        Pay("dup", "A", "B", 1),
    };
    BOOST_CHECK(!book.Apply(duplicated, ignored, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.Sequence(), 0);
    BOOST_CHECK_EQUAL(book.Balance("A"), 100);

    const std::vector<modelnet::SwarmCoordinatedPayment> batch{
        Pay("p1", "A", "B", 40),
        Pay("p2", "B", "A", 10),
        Pay("p3", "A", "C", 5),
    };
    modelnet::SwarmClearingReceipt receipt;
    BOOST_CHECK(book.Apply(batch, receipt, err));
    BOOST_CHECK_EQUAL(book.Balance("A"), 65);
    BOOST_CHECK_EQUAL(book.Balance("B"), 130);
    BOOST_CHECK_EQUAL(book.Balance("C"), 105);
    BOOST_CHECK_EQUAL(book.Balance("A") + book.Balance("B") + book.Balance("C"), 300);
    BOOST_CHECK_EQUAL(book.Sequence(), 1);
    BOOST_CHECK_EQUAL(receipt.sequence, 1);
    BOOST_CHECK_EQUAL(receipt.payments, 3);
    BOOST_CHECK_EQUAL(receipt.l1_transactions, 0);
    BOOST_CHECK(!receipt.broadcast);
    BOOST_CHECK_EQUAL(receipt.automatic_spend_atoms, "0");
    BOOST_CHECK_EQUAL(receipt.close_outputs, 3);

    BOOST_CHECK(!book.Apply(batch, receipt, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.Balance("A"), 65);
    BOOST_CHECK_EQUAL(book.Balance("B"), 130);
    BOOST_CHECK_EQUAL(book.Balance("C"), 105);
    BOOST_CHECK_EQUAL(book.Sequence(), 1);

    modelnet::SwarmClearingReceipt untouched;
    BOOST_CHECK(!book.Apply({Pay("p4", "A", "B", 66)}, untouched, err));
    BOOST_CHECK_EQUAL(err, "INSUFFICIENT");
    BOOST_CHECK_EQUAL(book.Sequence(), 1);
    BOOST_CHECK_EQUAL(book.Balance("A"), 65);
    BOOST_CHECK_EQUAL(book.Balance("B"), 130);
    BOOST_CHECK_EQUAL(book.Balance("C"), 105);

    BOOST_CHECK(!book.Open(300, slices, err));
    BOOST_CHECK_EQUAL(err, "REOPEN");
    BOOST_CHECK_EQUAL(book.Balance("A"), 65);
}

BOOST_AUTO_TEST_CASE(two_hundred_payments_advance_sequence_once)
{
    modelnet::SwarmClearingBook book;
    std::string err;
    BOOST_CHECK(book.Open(250, {Slice("A", 200), Slice("B", 50)}, err));
    std::vector<modelnet::SwarmCoordinatedPayment> batch;
    batch.reserve(200);
    for (int i = 0; i < 200; ++i) {
        batch.push_back(Pay("atom-" + std::to_string(i), "A", "B", 1));
    }
    const int64_t before = book.Sequence();
    modelnet::SwarmClearingReceipt receipt;
    BOOST_CHECK(book.Apply(batch, receipt, err));
    BOOST_CHECK_EQUAL(book.Sequence(), before + 1);
    BOOST_CHECK_EQUAL(receipt.sequence, before + 1);
    BOOST_CHECK_EQUAL(receipt.payments, 200);
    BOOST_CHECK_EQUAL(receipt.l1_transactions, 0);
    BOOST_CHECK(!receipt.broadcast);
    BOOST_CHECK_EQUAL(receipt.automatic_spend_atoms, "0");
    BOOST_CHECK_EQUAL(book.Balance("A"), 0);
    BOOST_CHECK_EQUAL(book.Balance("B"), 250);
}

BOOST_AUTO_TEST_CASE(equal_cycle_keeps_balances_and_advances_once)
{
    modelnet::SwarmClearingBook book;
    std::string err;
    BOOST_CHECK(book.Open(300, {Slice("A", 100), Slice("B", 100), Slice("C", 100)}, err));
    const int64_t before = book.Sequence();
    const std::vector<modelnet::SwarmCoordinatedPayment> cycle{
        Pay("c1", "A", "B", 40),
        Pay("c2", "B", "C", 40),
        Pay("c3", "C", "A", 40),
    };
    modelnet::SwarmClearingReceipt receipt;
    BOOST_CHECK(book.Apply(cycle, receipt, err));
    BOOST_CHECK_EQUAL(book.Balance("A"), 100);
    BOOST_CHECK_EQUAL(book.Balance("B"), 100);
    BOOST_CHECK_EQUAL(book.Balance("C"), 100);
    BOOST_CHECK_EQUAL(book.Sequence(), before + 1);
    BOOST_CHECK_EQUAL(receipt.sequence, before + 1);
    BOOST_CHECK_EQUAL(receipt.l1_transactions, 0);
    BOOST_CHECK(!receipt.broadcast);
    BOOST_CHECK_EQUAL(receipt.automatic_spend_atoms, "0");
}

BOOST_AUTO_TEST_CASE(persist_then_load_restores_balances)
{
    const TmpDir dir("roundtrip");
    modelnet::SwarmClearingBook book;
    std::string err;
    BOOST_CHECK(book.Open(300, {Slice("A", 100), Slice("B", 100), Slice("C", 100)}, err));
    modelnet::SwarmClearingReceipt receipt;
    BOOST_CHECK(book.Apply({Pay("p1", "A", "B", 40), Pay("p2", "B", "A", 10), Pay("p3", "A", "C", 5)}, receipt, err));
    BOOST_CHECK(book.Persist(dir.path, err));
    BOOST_CHECK(fs::exists(dir.path / "swarm" / "clearing.json"));

    modelnet::SwarmClearingBook restored;
    BOOST_CHECK(restored.Load(dir.path, err));
    BOOST_CHECK_EQUAL(restored.Balance("A"), book.Balance("A"));
    BOOST_CHECK_EQUAL(restored.Balance("B"), book.Balance("B"));
    BOOST_CHECK_EQUAL(restored.Balance("C"), book.Balance("C"));
    BOOST_CHECK_EQUAL(restored.Balance("A"), 65);
    BOOST_CHECK_EQUAL(restored.Balance("B"), 130);
    BOOST_CHECK_EQUAL(restored.Balance("C"), 105);
    BOOST_CHECK_EQUAL(restored.Sequence(), book.Sequence());

    BOOST_CHECK(!restored.Apply({Pay("p1", "A", "B", 1)}, receipt, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(restored.Balance("A"), 65);

    modelnet::SwarmClearingBook missing;
    BOOST_CHECK(!missing.Load(dir.path / "absent", err));
    BOOST_CHECK_EQUAL(err, "CLEARING_READ");
}

BOOST_AUTO_TEST_CASE(slices_above_capacity_fail_open)
{
    modelnet::SwarmClearingBook book;
    std::string err;
    BOOST_CHECK(!book.Open(150, {Slice("A", 100), Slice("B", 100)}, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(book.Sequence(), 0);
    BOOST_CHECK_EQUAL(book.Balance("A"), 0);
    BOOST_CHECK_EQUAL(book.Balance("B"), 0);
}

BOOST_AUTO_TEST_CASE(one_close_template_covers_every_pool)
{
    modelnet::SwarmClearingBook book;
    std::string err;
    BOOST_REQUIRE(book.Open(300, {Slice("A", 100), Slice("B", 100), Slice("C", 100)}, err));
    modelnet::SwarmClearingReceipt receipt;
    BOOST_REQUIRE(book.Apply({Pay("p1", "A", "B", 40), Pay("p2", "B", "A", 10), Pay("p3", "A", "C", 5)}, receipt, err));
    std::map<std::string, std::vector<unsigned char>> scripts = {
        {"A", {0x51}},
        {"B", {0x52}},
        {"C", {0x53}},
    };
    const Txid funding = Txid::FromUint256(uint256::ONE);
    modelnet::SwarmClearingClose close;
    BOOST_REQUIRE(modelnet::SwarmBuildClearingClose(book, funding, scripts, "B", 100, close, err));
    BOOST_CHECK(!close.broadcast);
    BOOST_CHECK_EQUAL(close.templates, 1);
    BOOST_CHECK_EQUAL(close.outputs, 3);
    BOOST_CHECK_EQUAL(close.tx.vin.size(), 1U);
    BOOST_CHECK(close.tx.vin[0].prevout.hash == funding);
    BOOST_CHECK_EQUAL(close.tx.vout[0].nValue + close.tx.vout[1].nValue + close.tx.vout[2].nValue, 300);
    BOOST_CHECK(!modelnet::SwarmBuildClearingClose(book, funding, scripts, "B", 200, close, err));
    BOOST_CHECK_EQUAL(err, "DECREASING_PAYMENT");
}

BOOST_AUTO_TEST_SUITE_END()
