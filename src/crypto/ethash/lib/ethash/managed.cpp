// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "crypto/ethash/lib/ethash/ethash-internal.hpp"
#include "sync.h"

#include <atomic>
#include <memory>

#if !defined(__has_cpp_attribute)
#define __has_cpp_attribute(x) 0
#endif

#if __has_cpp_attribute(gnu::noinline)
#define ATTRIBUTE_NOINLINE [[gnu::noinline]]
#elif defined(_MSC_VER)
#define ATTRIBUTE_NOINLINE __declspec(noinline)
#else
#define ATTRIBUTE_NOINLINE
#endif

using namespace ethash;

namespace
{

Mutex shared_context_cs;
std::shared_ptr<epoch_context> shared_context;
int shared_context_epoch{-1};
std::atomic<uint64_t> shared_context_generation{1};
thread_local const epoch_context* thread_local_context{nullptr};
thread_local int thread_local_context_epoch{-1};
thread_local uint64_t thread_local_context_generation{0};

Mutex shared_context_full_cs;
std::shared_ptr<epoch_context_full> shared_context_full;
int shared_context_full_epoch{-1};
std::atomic<uint64_t> shared_context_full_generation{1};
thread_local const epoch_context_full* thread_local_context_full{nullptr};
thread_local int thread_local_context_full_epoch{-1};
thread_local uint64_t thread_local_context_full_generation{0};

/// Update thread local epoch context.
///
/// This function is on the slow path. It's separated to allow inlining the fast
/// path.
///
/// @todo: Redesign to guarantee deallocation before new allocation.
ATTRIBUTE_NOINLINE
void update_local_context(int epoch_number) LOCKS_EXCLUDED(shared_context_cs) NO_THREAD_SAFETY_ANALYSIS
{
    LOCK(shared_context_cs);

    if (!shared_context || shared_context_epoch != epoch_number)
    {
        shared_context = create_epoch_context(epoch_number);
        shared_context_epoch = shared_context ? shared_context->epoch_number : -1;
        shared_context_generation.fetch_add(1, std::memory_order_release);
    }

    thread_local_context = shared_context.get();
    thread_local_context_epoch = shared_context_epoch;
    thread_local_context_generation = shared_context_generation.load(std::memory_order_acquire);
}

ATTRIBUTE_NOINLINE
void update_local_context_full(int epoch_number) LOCKS_EXCLUDED(shared_context_full_cs) NO_THREAD_SAFETY_ANALYSIS
{
    LOCK(shared_context_full_cs);

    if (!shared_context_full || shared_context_full_epoch != epoch_number)
    {
        shared_context_full = create_epoch_context_full(epoch_number);
        shared_context_full_epoch = shared_context_full ? shared_context_full->epoch_number : -1;
        shared_context_full_generation.fetch_add(1, std::memory_order_release);
    }

    thread_local_context_full = shared_context_full.get();
    thread_local_context_full_epoch = shared_context_full_epoch;
    thread_local_context_full_generation =
        shared_context_full_generation.load(std::memory_order_acquire);
}
}  // namespace

const ethash_epoch_context* ethash_get_global_epoch_context(int epoch_number) noexcept
{
    const uint64_t shared_generation{shared_context_generation.load(std::memory_order_acquire)};
    if (!thread_local_context || thread_local_context_epoch != epoch_number ||
        thread_local_context_generation != shared_generation) {
        update_local_context(epoch_number);
    }

    return thread_local_context;
}

const ethash_epoch_context_full* ethash_get_global_epoch_context_full(int epoch_number) noexcept
{
    const uint64_t shared_generation{shared_context_full_generation.load(std::memory_order_acquire)};
    if (!thread_local_context_full || thread_local_context_full_epoch != epoch_number ||
        thread_local_context_full_generation != shared_generation) {
        update_local_context_full(epoch_number);
    }

    return thread_local_context_full;
}
