// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matrix.h>
#include <matmul/solver_runtime.h>

#include <hash.h>
#include <uint256.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace matmul {
namespace {

std::atomic<uint64_t> g_matrix_constructed{0};
std::atomic<uint64_t> g_matrix_destroyed{0};
std::atomic<uint64_t> g_matrix_live_bytes{0};
std::atomic<uint64_t> g_matrix_peak_live_bytes{0};

constexpr size_t FROM_SEED_CACHE_CAPACITY{8};

struct FromSeedCacheEntry {
    uint256 seed;
    uint32_t n{0};
    std::shared_ptr<const Matrix> matrix;
};

std::mutex g_from_seed_cache_mutex;
std::vector<FromSeedCacheEntry> g_from_seed_cache;

void AddTrackedMatrixBytes(uint64_t bytes)
{
    if (bytes == 0) return;
    const uint64_t live_now = g_matrix_live_bytes.fetch_add(bytes, std::memory_order_relaxed) + bytes;
    uint64_t observed_peak = g_matrix_peak_live_bytes.load(std::memory_order_relaxed);
    while (live_now > observed_peak &&
           !g_matrix_peak_live_bytes.compare_exchange_weak(
               observed_peak, live_now, std::memory_order_relaxed)) {
    }
}

void SubtractTrackedMatrixBytes(uint64_t bytes)
{
    if (bytes == 0) return;
    g_matrix_live_bytes.fetch_sub(bytes, std::memory_order_relaxed);
}

uint32_t ResolveBlockedMultiplyWorkerCount(uint32_t rows, uint32_t cols, uint32_t shared_dim, uint32_t tile_size)
{
    const uint32_t row_tiles = (rows + tile_size - 1) / tile_size;
    if (row_tiles <= 1) {
        return 1;
    }

    const char* env = std::getenv("BTX_MATMUL_BLOCKED_MULTIPLY_THREADS");
    if (env != nullptr && env[0] != '\0') {
        char* end = nullptr;
        const long parsed = std::strtol(env, &end, 10);
        if (end != env && *end == '\0') {
            if (parsed <= 1) {
                return 1;
            }
            return ClampSolveWorkerThreads(std::min<uint32_t>(
                row_tiles,
                static_cast<uint32_t>(std::min<long>(parsed, std::numeric_limits<uint32_t>::max()))));
        }
    }

    const uint32_t hw_threads = std::max<uint32_t>(1, std::thread::hardware_concurrency());
    if (hw_threads <= 1) {
        return 1;
    }

    // Keep small matrices on a single thread to avoid thread-management overhead.
    const uint64_t estimated_mul_ops = static_cast<uint64_t>(rows) * cols * shared_dim;
    constexpr uint64_t kParallelMinMulOps = 4'000'000;
    if (estimated_mul_ops < kParallelMinMulOps) {
        return 1;
    }

    return ClampSolveWorkerThreads(std::min<uint32_t>(row_tiles, hw_threads));
}

} // namespace

ConstMatrixView::ConstMatrixView(const field::Element* data, uint32_t rows, uint32_t cols, uint32_t stride)
    : m_data(data), m_rows(rows), m_cols(cols), m_stride(stride)
{
}

const field::Element& ConstMatrixView::at(uint32_t row, uint32_t col) const
{
    assert(row < m_rows);
    assert(col < m_cols);
    return m_data[static_cast<size_t>(row) * m_stride + col];
}

const field::Element* ConstMatrixView::row_ptr(uint32_t row) const
{
    assert(row < m_rows);
    return &m_data[static_cast<size_t>(row) * m_stride];
}

uint32_t ConstMatrixView::rows() const
{
    return m_rows;
}

uint32_t ConstMatrixView::cols() const
{
    return m_cols;
}

MatrixView::MatrixView(field::Element* data, uint32_t rows, uint32_t cols, uint32_t stride)
    : m_data(data), m_rows(rows), m_cols(cols), m_stride(stride)
{
}

field::Element& MatrixView::at(uint32_t row, uint32_t col)
{
    assert(row < m_rows);
    assert(col < m_cols);
    return m_data[static_cast<size_t>(row) * m_stride + col];
}

const field::Element& MatrixView::at(uint32_t row, uint32_t col) const
{
    assert(row < m_rows);
    assert(col < m_cols);
    return m_data[static_cast<size_t>(row) * m_stride + col];
}

field::Element* MatrixView::row_ptr(uint32_t row)
{
    assert(row < m_rows);
    return &m_data[static_cast<size_t>(row) * m_stride];
}

const field::Element* MatrixView::row_ptr(uint32_t row) const
{
    assert(row < m_rows);
    return &m_data[static_cast<size_t>(row) * m_stride];
}

uint32_t MatrixView::rows() const
{
    return m_rows;
}

uint32_t MatrixView::cols() const
{
    return m_cols;
}

Matrix::Matrix(uint32_t rows, uint32_t cols) : m_rows(rows), m_cols(cols), m_data()
{
    g_matrix_constructed.fetch_add(1, std::memory_order_relaxed);
    const uint64_t size = static_cast<uint64_t>(rows) * cols;
    if (size > std::numeric_limits<size_t>::max()) {
        throw std::runtime_error("matrix too large");
    }
    m_data.assign(static_cast<size_t>(size), 0);
    ReconcileTrackedBytes(m_data.size() * sizeof(field::Element));
}

Matrix::Matrix(const Matrix& other)
    : m_rows(other.m_rows), m_cols(other.m_cols), m_data(other.m_data), m_tracked_bytes(0)
{
    g_matrix_constructed.fetch_add(1, std::memory_order_relaxed);
    ReconcileTrackedBytes(m_data.size() * sizeof(field::Element));
}

Matrix::Matrix(Matrix&& other) noexcept
    : m_rows(other.m_rows), m_cols(other.m_cols), m_data(std::move(other.m_data)), m_tracked_bytes(other.m_tracked_bytes)
{
    g_matrix_constructed.fetch_add(1, std::memory_order_relaxed);
    other.m_rows = 0;
    other.m_cols = 0;
    other.m_tracked_bytes = 0;
}

Matrix& Matrix::operator=(const Matrix& other)
{
    if (this == &other) return *this;

    m_rows = other.m_rows;
    m_cols = other.m_cols;
    m_data = other.m_data;
    ReconcileTrackedBytes(m_data.size() * sizeof(field::Element));
    return *this;
}

Matrix& Matrix::operator=(Matrix&& other) noexcept
{
    if (this == &other) return *this;

    ReconcileTrackedBytes(0);
    m_rows = other.m_rows;
    m_cols = other.m_cols;
    m_data = std::move(other.m_data);
    m_tracked_bytes = other.m_tracked_bytes;
    other.m_rows = 0;
    other.m_cols = 0;
    other.m_tracked_bytes = 0;
    return *this;
}

Matrix::~Matrix()
{
    g_matrix_destroyed.fetch_add(1, std::memory_order_relaxed);
    ReconcileTrackedBytes(0);
}

void Matrix::ReconcileTrackedBytes(size_t new_bytes)
{
    if (new_bytes == m_tracked_bytes) return;
    if (new_bytes > m_tracked_bytes) {
        AddTrackedMatrixBytes(static_cast<uint64_t>(new_bytes - m_tracked_bytes));
    } else {
        SubtractTrackedMatrixBytes(static_cast<uint64_t>(m_tracked_bytes - new_bytes));
    }
    m_tracked_bytes = new_bytes;
}

field::Element& Matrix::at(uint32_t row, uint32_t col)
{
    assert(row < m_rows);
    assert(col < m_cols);
    return m_data[static_cast<size_t>(row) * m_cols + col];
}

const field::Element& Matrix::at(uint32_t row, uint32_t col) const
{
    assert(row < m_rows);
    assert(col < m_cols);
    return m_data[static_cast<size_t>(row) * m_cols + col];
}

uint32_t Matrix::rows() const
{
    return m_rows;
}

uint32_t Matrix::cols() const
{
    return m_cols;
}

field::Element* Matrix::data()
{
    return m_data.data();
}

const field::Element* Matrix::data() const
{
    return m_data.data();
}

Matrix Matrix::block(uint32_t bi, uint32_t bj, uint32_t b) const
{
    assert(b > 0);
    const uint32_t row0 = bi * b;
    const uint32_t col0 = bj * b;
    assert(row0 + b <= m_rows);
    assert(col0 + b <= m_cols);

    Matrix out(b, b);
    for (uint32_t r = 0; r < b; ++r) {
        for (uint32_t c = 0; c < b; ++c) {
            out.at(r, c) = at(row0 + r, col0 + c);
        }
    }
    return out;
}

ConstMatrixView Matrix::block_view(uint32_t bi, uint32_t bj, uint32_t b) const
{
    assert(b > 0);
    const uint32_t row0 = bi * b;
    const uint32_t col0 = bj * b;
    assert(row0 + b <= m_rows);
    assert(col0 + b <= m_cols);

    return ConstMatrixView{
        &m_data[static_cast<size_t>(row0) * m_cols + col0],
        b,
        b,
        m_cols,
    };
}

MatrixView Matrix::mutable_block_view(uint32_t bi, uint32_t bj, uint32_t b)
{
    assert(b > 0);
    const uint32_t row0 = bi * b;
    const uint32_t col0 = bj * b;
    assert(row0 + b <= m_rows);
    assert(col0 + b <= m_cols);

    return MatrixView{
        &m_data[static_cast<size_t>(row0) * m_cols + col0],
        b,
        b,
        m_cols,
    };
}

void Matrix::set_block(uint32_t bi, uint32_t bj, uint32_t b, const Matrix& blk)
{
    assert(blk.rows() == b);
    assert(blk.cols() == b);

    const uint32_t row0 = bi * b;
    const uint32_t col0 = bj * b;
    assert(row0 + b <= m_rows);
    assert(col0 + b <= m_cols);

    for (uint32_t r = 0; r < b; ++r) {
        for (uint32_t c = 0; c < b; ++c) {
            at(row0 + r, col0 + c) = blk.at(r, c);
        }
    }
}

Matrix Matrix::operator+(const Matrix& rhs) const
{
    assert(m_rows == rhs.m_rows);
    assert(m_cols == rhs.m_cols);

    Matrix out(m_rows, m_cols);
    for (size_t i = 0; i < m_data.size(); ++i) {
        out.m_data[i] = field::add(m_data[i], rhs.m_data[i]);
    }
    return out;
}

Matrix Matrix::operator-(const Matrix& rhs) const
{
    assert(m_rows == rhs.m_rows);
    assert(m_cols == rhs.m_cols);

    Matrix out(m_rows, m_cols);
    for (size_t i = 0; i < m_data.size(); ++i) {
        out.m_data[i] = field::sub(m_data[i], rhs.m_data[i]);
    }
    return out;
}

Matrix Matrix::operator*(const Matrix& rhs) const
{
    assert(m_cols == rhs.m_rows);

    Matrix out(m_rows, rhs.m_cols);
    std::vector<field::Element> col(rhs.m_rows);

    for (uint32_t i = 0; i < m_rows; ++i) {
        const field::Element* row_ptr = &m_data[static_cast<size_t>(i) * m_cols];
        for (uint32_t j = 0; j < rhs.m_cols; ++j) {
            for (uint32_t k = 0; k < rhs.m_rows; ++k) {
                col[k] = rhs.at(k, j);
            }
            out.at(i, j) = field::dot(row_ptr, col.data(), m_cols);
        }
    }

    return out;
}

Matrix MultiplyBlocked(const Matrix& lhs, const Matrix& rhs, uint32_t tile_size)
{
    if (tile_size == 0) {
        throw std::runtime_error("matrix multiply tile size must be non-zero");
    }
    if (lhs.cols() != rhs.rows()) {
        throw std::runtime_error("matrix multiply dimension mismatch");
    }

    Matrix out(lhs.rows(), rhs.cols());
    const field::Element* lhs_data = lhs.data();
    const field::Element* rhs_data = rhs.data();
    field::Element* out_data = out.data();

    const uint32_t lhs_rows = lhs.rows();
    const uint32_t lhs_cols = lhs.cols();
    const uint32_t rhs_cols = rhs.cols();
    const uint32_t row_tiles = (lhs_rows + tile_size - 1) / tile_size;
    const uint32_t worker_count = ResolveBlockedMultiplyWorkerCount(lhs_rows, rhs_cols, lhs_cols, tile_size);

    auto process_row_tile_span = [&](uint32_t tile_begin, uint32_t tile_end) {
        for (uint32_t tile = tile_begin; tile < tile_end; ++tile) {
            const uint32_t ii = tile * tile_size;
            const uint32_t i_end = std::min<uint32_t>(ii + tile_size, lhs_rows);
            for (uint32_t kk = 0; kk < lhs_cols; kk += tile_size) {
                const uint32_t k_end = std::min<uint32_t>(kk + tile_size, lhs_cols);
                for (uint32_t jj = 0; jj < rhs_cols; jj += tile_size) {
                    const uint32_t j_end = std::min<uint32_t>(jj + tile_size, rhs_cols);

                    for (uint32_t i = ii; i < i_end; ++i) {
                        const size_t lhs_row_base = static_cast<size_t>(i) * lhs_cols;
                        const size_t out_row_base = static_cast<size_t>(i) * rhs_cols;
                        for (uint32_t k = kk; k < k_end; ++k) {
                            const field::Element a_ik = lhs_data[lhs_row_base + k];
                            const field::Element* rhs_row = rhs_data + static_cast<size_t>(k) * rhs_cols;
                            for (uint32_t j = jj; j < j_end; ++j) {
                                const size_t out_idx = out_row_base + j;
                                out_data[out_idx] = field::add(out_data[out_idx], field::mul(a_ik, rhs_row[j]));
                            }
                        }
                    }
                }
            }
        }
    };

    if (worker_count <= 1) {
        process_row_tile_span(0, row_tiles);
        return out;
    }

    const uint32_t tiles_per_worker = (row_tiles + worker_count - 1) / worker_count;
    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (uint32_t worker = 0; worker < worker_count; ++worker) {
        const uint32_t tile_begin = worker * tiles_per_worker;
        if (tile_begin >= row_tiles) {
            break;
        }
        const uint32_t tile_end = std::min<uint32_t>(tile_begin + tiles_per_worker, row_tiles);
        workers.emplace_back(process_row_tile_span, tile_begin, tile_end);
    }
    for (auto& worker : workers) {
        worker.join();
    }

    return out;
}

uint256 Matrix::ContentHash() const
{
    HashWriter hasher{};
    for (const field::Element v : m_data) {
        hasher << v;
    }
    return hasher.GetSHA256();
}

bool Matrix::operator==(const Matrix& rhs) const
{
    return m_rows == rhs.m_rows && m_cols == rhs.m_cols && m_data == rhs.m_data;
}

MatrixMemoryStats ProbeMatrixMemoryStats()
{
    MatrixMemoryStats stats;
    stats.matrices_constructed = g_matrix_constructed.load(std::memory_order_relaxed);
    stats.matrices_destroyed = g_matrix_destroyed.load(std::memory_order_relaxed);
    stats.live_bytes = g_matrix_live_bytes.load(std::memory_order_relaxed);
    stats.peak_live_bytes = g_matrix_peak_live_bytes.load(std::memory_order_relaxed);
    return stats;
}

void ResetMatrixMemoryStats()
{
    g_matrix_constructed.store(0, std::memory_order_relaxed);
    g_matrix_destroyed.store(0, std::memory_order_relaxed);
    const uint64_t live = g_matrix_live_bytes.load(std::memory_order_relaxed);
    g_matrix_peak_live_bytes.store(live, std::memory_order_relaxed);
}

Matrix Identity(uint32_t n)
{
    Matrix out(n, n);
    for (uint32_t i = 0; i < n; ++i) {
        out.at(i, i) = 1;
    }
    return out;
}

Matrix FromSeed(const uint256& seed, uint32_t n)
{
    assert(static_cast<uint64_t>(n) * n <= std::numeric_limits<uint32_t>::max());
    Matrix out(n, n);
    for (uint32_t row = 0; row < n; ++row) {
        for (uint32_t col = 0; col < n; ++col) {
            out.at(row, col) = field::from_oracle(seed, row * n + col);
        }
    }
    return out;
}

std::shared_ptr<const Matrix> SharedFromSeed(const uint256& seed, uint32_t n)
{
    {
        std::lock_guard<std::mutex> lock(g_from_seed_cache_mutex);
        for (auto it = g_from_seed_cache.begin(); it != g_from_seed_cache.end(); ++it) {
            if (it->n != n || it->seed != seed) {
                continue;
            }
            auto cached = it->matrix;
            if (!cached) {
                break;
            }
            if (it != g_from_seed_cache.begin()) {
                auto entry = *it;
                g_from_seed_cache.erase(it);
                g_from_seed_cache.insert(g_from_seed_cache.begin(), std::move(entry));
            }
            return cached;
        }
    }

    auto matrix = std::make_shared<Matrix>(FromSeed(seed, n));
    {
        std::lock_guard<std::mutex> lock(g_from_seed_cache_mutex);
        for (auto it = g_from_seed_cache.begin(); it != g_from_seed_cache.end(); ++it) {
            if (it->n == n && it->seed == seed) {
                if (it->matrix) {
                    return it->matrix;
                }
                g_from_seed_cache.erase(it);
                break;
            }
        }
        g_from_seed_cache.insert(g_from_seed_cache.begin(), FromSeedCacheEntry{seed, n, matrix});
        if (g_from_seed_cache.size() > FROM_SEED_CACHE_CAPACITY) {
            g_from_seed_cache.resize(FROM_SEED_CACHE_CAPACITY);
        }
    }
    return matrix;
}

} // namespace matmul
