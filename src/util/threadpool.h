// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_THREADPOOL_H
#define BITCOIN_UTIL_THREADPOOL_H

#include <sync.h>
#include <tinyformat.h>
#include <util/check.h>
#include <util/expected.h>
#include <util/thread.h>

#include <cassert>
#include <condition_variable>
#include <functional>
#include <future>
#include <queue>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

/** Fixed-size pool for running arbitrary tasks concurrently. */
class ThreadPool
{
private:
    std::string m_name;
    Mutex m_mutex;
    std::queue<std::packaged_task<void()>> m_work_queue GUARDED_BY(m_mutex);
    std::condition_variable m_cv;
    bool m_interrupt GUARDED_BY(m_mutex){false};
    std::vector<std::thread> m_workers GUARDED_BY(m_mutex);

    void WorkerThread() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, wait_lock);
        for (;;) {
            std::packaged_task<void()> task;
            {
                if (!m_interrupt && m_work_queue.empty()) {
                    m_cv.wait(wait_lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                        return m_interrupt || !m_work_queue.empty();
                    });
                }
                if (m_interrupt && m_work_queue.empty()) return;
                task = std::move(m_work_queue.front());
                m_work_queue.pop();
            }
            {
                REVERSE_LOCK(wait_lock);
                task();
            }
        }
    }

public:
    explicit ThreadPool(const std::string& name) : m_name(name) {}
    ~ThreadPool() { Stop(); }

    /** Start worker threads. Must be called by a non-worker controller thread. */
    void Start(int num_workers) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        assert(num_workers > 0);
        LOCK(m_mutex);
        if (m_interrupt) throw std::runtime_error("Thread pool has been interrupted or is stopping");
        if (!m_workers.empty()) throw std::runtime_error("Thread pool already started");
        m_workers.reserve(num_workers);
        for (int i = 0; i < num_workers; ++i) {
            m_workers.emplace_back(&util::TraceThread, strprintf("%s.%02d", m_name, i), [this] {
                WorkerThread();
            });
        }
    }

    /** Stop accepting work, drain the queue, and join all workers. */
    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        std::vector<std::thread> threads_to_join;
        {
            LOCK(m_mutex);
            const auto id{std::this_thread::get_id()};
            for (const auto& worker : m_workers) assert(worker.get_id() != id);
            m_interrupt = true;
            threads_to_join.swap(m_workers);
        }
        m_cv.notify_all();
        while (ProcessTask()) {}
        for (auto& worker : threads_to_join) worker.join();

        LOCK(m_mutex);
        Assume(m_work_queue.empty());
        m_interrupt = false;
    }

    enum class SubmitError {
        Inactive,
        Interrupted,
    };

    template <class F>
    using Future = std::future<std::invoke_result_t<F>>;
    template <class R>
    using RangeFuture = Future<std::ranges::range_reference_t<R>>;
    template <class F>
    using PackagedTask = std::packaged_task<std::invoke_result_t<F>()>;

    /** Submit one task without throwing for lifecycle races. */
    template <class F>
    [[nodiscard]] util::Expected<Future<F>, SubmitError> Submit(F&& fn) noexcept EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        PackagedTask<F> task{std::forward<F>(fn)};
        auto future{task.get_future()};
        {
            LOCK(m_mutex);
            if (m_workers.empty()) return util::Unexpected{SubmitError::Inactive};
            if (m_interrupt) return util::Unexpected{SubmitError::Interrupted};
            m_work_queue.emplace(std::move(task));
        }
        m_cv.notify_one();
        return {std::move(future)};
    }

    /** Submit a sized rvalue range while holding the queue lock once. */
    template <std::ranges::sized_range R>
        requires(!std::is_lvalue_reference_v<R>)
    [[nodiscard]] util::Expected<std::vector<RangeFuture<R>>, SubmitError> Submit(R&& fns) noexcept EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        std::vector<RangeFuture<R>> futures;
        futures.reserve(std::ranges::size(fns));
        {
            LOCK(m_mutex);
            if (m_workers.empty()) return util::Unexpected{SubmitError::Inactive};
            if (m_interrupt) return util::Unexpected{SubmitError::Interrupted};
            for (auto&& fn : fns) {
                PackagedTask<std::ranges::range_reference_t<R>> task{std::move(fn)};
                futures.emplace_back(task.get_future());
                m_work_queue.emplace(std::move(task));
            }
        }
        m_cv.notify_all();
        return {std::move(futures)};
    }

    /** Execute one queued task synchronously. */
    bool ProcessTask() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        std::packaged_task<void()> task;
        {
            LOCK(m_mutex);
            if (m_work_queue.empty()) return false;
            task = std::move(m_work_queue.front());
            m_work_queue.pop();
        }
        task();
        return true;
    }

    /** Stop accepting new tasks without waiting for workers. */
    void Interrupt() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WITH_LOCK(m_mutex, m_interrupt = true);
        m_cv.notify_all();
    }

    size_t WorkQueueSize() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        return WITH_LOCK(m_mutex, return m_work_queue.size());
    }

    size_t WorkersCount() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        return WITH_LOCK(m_mutex, return m_workers.size());
    }
};

constexpr std::string_view SubmitErrorString(const ThreadPool::SubmitError err) noexcept
{
    switch (err) {
    case ThreadPool::SubmitError::Inactive: return "No active workers";
    case ThreadPool::SubmitError::Interrupted: return "Interrupted";
    }
    Assume(false);
    return "Unknown error";
}

#endif // BITCOIN_UTIL_THREADPOOL_H
