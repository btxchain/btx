// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/threadpool.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <functional>
#include <future>
#include <vector>

BOOST_AUTO_TEST_SUITE(threadpool_tests)

template <typename F>
[[nodiscard]] auto Submit(ThreadPool& pool, F&& fn)
{
    auto result{pool.Submit(std::forward<F>(fn))};
    BOOST_REQUIRE(result.has_value());
    return std::move(*result);
}

BOOST_AUTO_TEST_CASE(submit_reports_inactive_and_interrupted)
{
    ThreadPool pool{"test"};
    auto result{pool.Submit([] {})};
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(SubmitErrorString(result.error()), "No active workers");

    pool.Start(2);
    pool.Interrupt();
    result = pool.Submit([] {});
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(SubmitErrorString(result.error()), "Interrupted");
    pool.Stop();
}

BOOST_AUTO_TEST_CASE(single_and_range_submission)
{
    ThreadPool pool{"test"};
    pool.Start(4);
    std::atomic<int> total{0};

    auto one{Submit(pool, [&] { total.fetch_add(1, std::memory_order_relaxed); })};
    std::vector<std::function<void()>> tasks(32, [&] {
        total.fetch_add(1, std::memory_order_relaxed);
    });
    auto range_result{pool.Submit(std::move(tasks))};
    BOOST_REQUIRE(range_result.has_value());

    one.get();
    for (auto& future : *range_result) future.get();
    BOOST_CHECK_EQUAL(total.load(std::memory_order_relaxed), 33);
    pool.Stop();
}

BOOST_AUTO_TEST_CASE(task_exception_propagates)
{
    ThreadPool pool{"test"};
    pool.Start(1);
    auto future{Submit(pool, []() -> void { throw std::runtime_error{"worker failure"}; })};
    BOOST_CHECK_THROW(future.get(), std::runtime_error);
    pool.Stop();
}

BOOST_AUTO_TEST_CASE(stop_drains_and_pool_can_restart)
{
    ThreadPool pool{"test"};
    std::atomic<int> total{0};
    pool.Start(2);
    std::vector<std::future<void>> futures;
    for (int i = 0; i < 64; ++i) {
        futures.emplace_back(Submit(pool, [&] { total.fetch_add(1, std::memory_order_relaxed); }));
    }
    pool.Stop();
    for (auto& future : futures) future.get();
    BOOST_CHECK_EQUAL(total.load(std::memory_order_relaxed), 64);

    pool.Start(1);
    Submit(pool, [&] { total.fetch_add(1, std::memory_order_relaxed); }).get();
    pool.Stop();
    BOOST_CHECK_EQUAL(total.load(std::memory_order_relaxed), 65);
}

BOOST_AUTO_TEST_SUITE_END()
