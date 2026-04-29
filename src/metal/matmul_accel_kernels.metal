#include <metal_stdlib>
using namespace metal;

constant uint MODULUS = 0x7fffffffu;
constant uint MAX_BLOCK_ELEMENTS = 256u;
constant uint FC_SPEC_N [[function_constant(0)]];
constant uint FC_SPEC_B [[function_constant(1)]];
constant uint FC_SPEC_R [[function_constant(2)]];
constant uint FC_SPEC_NBLOCKS [[function_constant(3)]];

struct KernelParams {
    uint n;
    uint b;
    uint r;
    uint N;
};

struct HashParams {
    uint compressed_words;
};

inline uint reduce64(ulong x)
{
    const ulong fold1 = (x & (ulong)MODULUS) + (x >> 31);
    const uint lo = (uint)(fold1 & (ulong)MODULUS);
    const uint hi = (uint)(fold1 >> 31);
    uint result = lo + hi;
    const uint ge_mask = result >= MODULUS ? 0xffffffffu : 0u;
    result -= MODULUS & ge_mask;
    return result;
}

inline uint add_mod(uint a, uint b)
{
    uint s = a + b;
    const uint ge_mask = s >= MODULUS ? 0xffffffffu : 0u;
    s -= MODULUS & ge_mask;
    return s;
}

inline uint mul_mod(uint a, uint b)
{
    return reduce64((ulong)a * (ulong)b);
}

inline uint dot_step(uint acc, uint a, uint b)
{
    return reduce64((ulong)acc + ((ulong)a * (ulong)b));
}

inline uint reduce_simdgroup_add_mod(uint value, uint simd_size)
{
    for (uint offset = simd_size >> 1u; offset > 0u; offset >>= 1u) {
        value = add_mod(value, simd_shuffle_xor(value, offset));
    }
    return value;
}

inline uint rotr(uint x, uint n)
{
    return (x >> n) | (x << (32u - n));
}

inline uint sha_ch(uint x, uint y, uint z)
{
    return (x & y) ^ ((~x) & z);
}

inline uint sha_maj(uint x, uint y, uint z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint sha_bsig0(uint x)
{
    return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
}

inline uint sha_bsig1(uint x)
{
    return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
}

inline uint sha_ssig0(uint x)
{
    return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
}

inline uint sha_ssig1(uint x)
{
    return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
}

constant uint SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

inline void sha256_compress(thread uint state[8], thread uint w[64])
{
    for (uint t = 16; t < 64; ++t) {
        w[t] = sha_ssig1(w[t - 2]) + w[t - 7] + sha_ssig0(w[t - 15]) + w[t - 16];
    }

    uint a = state[0];
    uint b = state[1];
    uint c = state[2];
    uint d = state[3];
    uint e = state[4];
    uint f = state[5];
    uint g = state[6];
    uint h = state[7];

    for (uint t = 0; t < 64; ++t) {
        const uint t1 = h + sha_bsig1(e) + sha_ch(e, f, g) + SHA256_K[t] + w[t];
        const uint t2 = sha_bsig0(a) + sha_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

inline uint MessageByteAt(device const uint* compressed, uint64_t msg_len_bytes, uint64_t total_bytes, uint64_t offset)
{
    if (offset < msg_len_bytes) {
        const uint64_t word_index = offset >> 2;
        const uint lane = (uint)(offset & 3u);
        const uint word = compressed[word_index];
        return (word >> (lane * 8u)) & 0xffu;
    }

    if (offset == msg_len_bytes) {
        return 0x80u;
    }

    if (offset >= (total_bytes - 8u)) {
        const uint64_t bit_len = msg_len_bytes * 8u;
        const uint shift = (uint)((total_bytes - 1u - offset) * 8u);
        return (uint)((bit_len >> shift) & 0xffu);
    }

    return 0u;
}

inline uint FinalEllMessageByteAt(device const uint* compressed, uint N, uint64_t msg_len_bytes, uint64_t total_bytes, uint64_t offset)
{
    if (offset < msg_len_bytes) {
        const uint64_t word_index = offset >> 2;
        const uint lane = (uint)(offset & 3u);
        const uint64_t physical_index = word_index * (uint64_t)N + (uint64_t)(N - 1u);
        const uint word = compressed[physical_index];
        return (word >> (lane * 8u)) & 0xffu;
    }

    if (offset == msg_len_bytes) {
        return 0x80u;
    }

    if (offset >= (total_bytes - 8u)) {
        const uint64_t bit_len = msg_len_bytes * 8u;
        const uint shift = (uint)((total_bytes - 1u - offset) * 8u);
        return (uint)((bit_len >> shift) & 0xffu);
    }

    return 0u;
}

inline void sha256_stream_words(device const uint* compressed, uint words, thread uint out_state[8])
{
    out_state[0] = 0x6a09e667u;
    out_state[1] = 0xbb67ae85u;
    out_state[2] = 0x3c6ef372u;
    out_state[3] = 0xa54ff53au;
    out_state[4] = 0x510e527fu;
    out_state[5] = 0x9b05688cu;
    out_state[6] = 0x1f83d9abu;
    out_state[7] = 0x5be0cd19u;

    const uint64_t msg_len_bytes = (uint64_t)words * 4u;
    const uint64_t total_blocks = (msg_len_bytes + 9u + 63u) / 64u;
    const uint64_t total_bytes = total_blocks * 64u;

    thread uint w[64];
    for (uint64_t block = 0; block < total_blocks; ++block) {
        const uint64_t base = block * 64u;
        for (uint i = 0; i < 16; ++i) {
            const uint64_t off = base + (uint64_t)i * 4u;
            const uint b0 = MessageByteAt(compressed, msg_len_bytes, total_bytes, off + 0u);
            const uint b1 = MessageByteAt(compressed, msg_len_bytes, total_bytes, off + 1u);
            const uint b2 = MessageByteAt(compressed, msg_len_bytes, total_bytes, off + 2u);
            const uint b3 = MessageByteAt(compressed, msg_len_bytes, total_bytes, off + 3u);
            w[i] = (b0 << 24u) | (b1 << 16u) | (b2 << 8u) | b3;
        }
        sha256_compress(out_state, w);
    }
}

inline void sha256_stream_final_ell_words(device const uint* compressed, uint N, uint words, thread uint out_state[8])
{
    out_state[0] = 0x6a09e667u;
    out_state[1] = 0xbb67ae85u;
    out_state[2] = 0x3c6ef372u;
    out_state[3] = 0xa54ff53au;
    out_state[4] = 0x510e527fu;
    out_state[5] = 0x9b05688cu;
    out_state[6] = 0x1f83d9abu;
    out_state[7] = 0x5be0cd19u;

    const uint64_t msg_len_bytes = (uint64_t)words * 4u;
    const uint64_t total_blocks = (msg_len_bytes + 9u + 63u) / 64u;
    const uint64_t total_bytes = total_blocks * 64u;

    thread uint w[64];
    for (uint64_t block = 0; block < total_blocks; ++block) {
        const uint64_t base = block * 64u;
        for (uint i = 0; i < 16; ++i) {
            const uint64_t off = base + (uint64_t)i * 4u;
            const uint b0 = FinalEllMessageByteAt(compressed, N, msg_len_bytes, total_bytes, off + 0u);
            const uint b1 = FinalEllMessageByteAt(compressed, N, msg_len_bytes, total_bytes, off + 1u);
            const uint b2 = FinalEllMessageByteAt(compressed, N, msg_len_bytes, total_bytes, off + 2u);
            const uint b3 = FinalEllMessageByteAt(compressed, N, msg_len_bytes, total_bytes, off + 3u);
            w[i] = (b0 << 24u) | (b1 << 16u) | (b2 << 8u) | b3;
        }
        sha256_compress(out_state, w);
    }
}

inline void sha256_double_digest(thread uint first_state[8], thread uint out_state[8])
{
    out_state[0] = 0x6a09e667u;
    out_state[1] = 0xbb67ae85u;
    out_state[2] = 0x3c6ef372u;
    out_state[3] = 0xa54ff53au;
    out_state[4] = 0x510e527fu;
    out_state[5] = 0x9b05688cu;
    out_state[6] = 0x1f83d9abu;
    out_state[7] = 0x5be0cd19u;

    thread uint w[64];
    for (uint i = 0; i < 8; ++i) {
        w[i] = first_state[i];
    }
    w[8] = 0x80000000u;
    for (uint i = 9; i < 15; ++i) {
        w[i] = 0u;
    }
    w[15] = 256u;
    sha256_compress(out_state, w);
}

kernel void build_perturbed(
    constant KernelParams& p [[buffer(0)]],
    device const uint* matrix_a [[buffer(1)]],
    device const uint* matrix_b [[buffer(2)]],
    device const uint* e_l [[buffer(3)]],
    device const uint* e_r [[buffer(4)]],
    device const uint* f_l [[buffer(5)]],
    device const uint* f_r [[buffer(6)]],
    device uint* a_prime [[buffer(7)]],
    device uint* b_prime [[buffer(8)]],
    uint gid [[thread_position_in_grid]])
{
    const uint nn = p.n * p.n;
    if (gid >= nn) {
        return;
    }

    const uint row = gid / p.n;
    const uint col = gid - row * p.n;

    uint e_acc = 0;
    uint f_acc = 0;
    for (uint k = 0; k < p.r; ++k) {
        const uint el = e_l[row * p.r + k];
        const uint er = e_r[k * p.n + col];
        e_acc = add_mod(e_acc, mul_mod(el, er));

        const uint fl = f_l[row * p.r + k];
        const uint fr = f_r[k * p.n + col];
        f_acc = add_mod(f_acc, mul_mod(fl, fr));
    }

    a_prime[gid] = add_mod(matrix_a[gid], e_acc);
    b_prime[gid] = add_mod(matrix_b[gid], f_acc);
}

kernel void build_prefix(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device uint* c_prefix [[buffer(3)]],
    uint gid [[thread_position_in_grid]])
{
    const uint nn = p.n * p.n;
    if (gid >= nn) {
        return;
    }

    const uint row = gid / p.n;
    const uint col = gid - row * p.n;

    uint c_acc = 0;
    for (uint ell = 0; ell < p.N; ++ell) {
        const uint k_base = ell * p.b;

        uint product = 0;
        for (uint k = 0; k < p.b; ++k) {
            const uint a = a_prime[row * p.n + (k_base + k)];
            const uint b = b_prime[(k_base + k) * p.n + col];
            product = dot_step(product, a, b);
        }

        c_acc = add_mod(c_acc, product);
        c_prefix[ell * nn + gid] = c_acc;
    }
}

kernel void fused_final_compress(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device const uint* compress_vec [[buffer(3)]],
    device uint* compressed [[buffer(4)]],
    uint tid [[thread_index_in_threadgroup]],
    uint simd_size [[threads_per_simdgroup]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    const uint block_elements = p.b * p.b;
    if (block_elements == 0 || block_elements > MAX_BLOCK_ELEMENTS || tid >= block_elements) {
        return;
    }

    const uint tile_i = tgid.y;
    const uint tile_j = tgid.x;
    if (tile_i >= p.N || tile_j >= p.N) {
        return;
    }

    const uint br = tid / p.b;
    const uint bc = tid - br * p.b;
    const uint row = tile_i * p.b + br;
    const uint col = tile_j * p.b + bc;

    threadgroup uint weighted_terms[MAX_BLOCK_ELEMENTS];
    const uint weight = compress_vec[tid];
    uint c_acc = 0;
    for (uint ell = 0; ell < p.N; ++ell) {
        const uint k_base = ell * p.b;

        uint product = 0;
        for (uint k = 0; k < p.b; ++k) {
            const uint a = a_prime[row * p.n + (k_base + k)];
            const uint b = b_prime[(k_base + k) * p.n + col];
            product = dot_step(product, a, b);
        }

        c_acc = add_mod(c_acc, product);
    }

    weighted_terms[tid] = mul_mod(c_acc, weight);
    threadgroup_barrier(mem_flags::mem_threadgroup);

    const uint simd_lane = tid % simd_size;
    const uint simd_group = tid / simd_size;
    uint reduced = reduce_simdgroup_add_mod(weighted_terms[tid], simd_size);
    if (simd_lane == 0u) {
        weighted_terms[simd_group] = reduced;
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    const uint group_count = (block_elements + simd_size - 1u) / simd_size;
    if (simd_group == 0u) {
        reduced = tid < group_count ? weighted_terms[tid] : 0u;
        reduced = reduce_simdgroup_add_mod(reduced, simd_size);
        if (tid == 0u) {
            compressed[tile_i * p.N + tile_j] = reduced;
        }
    }
}

kernel void compress_prefix(
    constant KernelParams& p [[buffer(0)]],
    device const uint* c_prefix [[buffer(1)]],
    device const uint* compress_vec [[buffer(2)]],
    device uint* compressed [[buffer(3)]],
    uint gid [[thread_position_in_grid]])
{
    const uint n3 = p.N * p.N * p.N;
    if (gid >= n3) {
        return;
    }

    const uint i = gid / (p.N * p.N);
    const uint rem = gid - i * (p.N * p.N);
    const uint j = rem / p.N;
    const uint ell = rem - j * p.N;

    const uint row_base = i * p.b;
    const uint col_base = j * p.b;
    const uint nn = p.n * p.n;

    uint acc = 0;
    uint v_idx = 0;
    for (uint br = 0; br < p.b; ++br) {
        const uint row = row_base + br;
        for (uint bc = 0; bc < p.b; ++bc) {
            const uint col = col_base + bc;
            const uint value = c_prefix[ell * nn + row * p.n + col];
            const uint weight = compress_vec[v_idx++];
            acc = dot_step(acc, value, weight);
        }
    }

    compressed[gid] = acc;
}

kernel void build_perturbed_specialized(
    constant KernelParams& p [[buffer(0)]],
    device const uint* matrix_a [[buffer(1)]],
    device const uint* matrix_b [[buffer(2)]],
    device const uint* e_l [[buffer(3)]],
    device const uint* e_r [[buffer(4)]],
    device const uint* f_l [[buffer(5)]],
    device const uint* f_r [[buffer(6)]],
    device uint* a_prime [[buffer(7)]],
    device uint* b_prime [[buffer(8)]],
    uint gid [[thread_position_in_grid]])
{
    const uint n = FC_SPEC_N;
    const uint r = FC_SPEC_R;
    if (p.n != n || p.r != r) {
        return;
    }

    const uint nn = n * n;
    if (gid >= nn) {
        return;
    }

    const uint row = gid / n;
    const uint col = gid - row * n;

    uint e_acc = 0;
    uint f_acc = 0;
    for (uint k = 0; k < FC_SPEC_R; ++k) {
        const uint el = e_l[row * r + k];
        const uint er = e_r[k * n + col];
        e_acc = add_mod(e_acc, mul_mod(el, er));

        const uint fl = f_l[row * r + k];
        const uint fr = f_r[k * n + col];
        f_acc = add_mod(f_acc, mul_mod(fl, fr));
    }

    a_prime[gid] = add_mod(matrix_a[gid], e_acc);
    b_prime[gid] = add_mod(matrix_b[gid], f_acc);
}

kernel void build_prefix_specialized(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device uint* c_prefix [[buffer(3)]],
    uint gid [[thread_position_in_grid]])
{
    const uint n = FC_SPEC_N;
    const uint b = FC_SPEC_B;
    const uint N = FC_SPEC_NBLOCKS;
    if (p.n != n || p.b != b || p.N != N) {
        return;
    }

    const uint nn = n * n;
    if (gid >= nn) {
        return;
    }

    const uint row = gid / n;
    const uint col = gid - row * n;

    uint c_acc = 0;
    for (uint ell = 0; ell < FC_SPEC_NBLOCKS; ++ell) {
        const uint k_base = ell * b;

        uint product = 0;
        for (uint k = 0; k < FC_SPEC_B; ++k) {
            const uint a = a_prime[row * n + (k_base + k)];
            const uint b_val = b_prime[(k_base + k) * n + col];
            product = dot_step(product, a, b_val);
        }

        c_acc = add_mod(c_acc, product);
        c_prefix[ell * nn + gid] = c_acc;
    }
}

kernel void fused_final_compress_specialized(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device const uint* compress_vec [[buffer(3)]],
    device uint* compressed [[buffer(4)]],
    uint tid [[thread_index_in_threadgroup]],
    uint simd_size [[threads_per_simdgroup]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    const uint n = FC_SPEC_N;
    const uint b = FC_SPEC_B;
    const uint N = FC_SPEC_NBLOCKS;
    if (p.n != n || p.b != b || p.N != N) {
        return;
    }

    const uint block_elements = FC_SPEC_B * FC_SPEC_B;
    if (block_elements == 0 || block_elements > MAX_BLOCK_ELEMENTS || tid >= block_elements) {
        return;
    }

    const uint tile_i = tgid.y;
    const uint tile_j = tgid.x;
    if (tile_i >= N || tile_j >= N) {
        return;
    }

    const uint br = tid / b;
    const uint bc = tid - br * b;
    const uint row = tile_i * b + br;
    const uint col = tile_j * b + bc;

    threadgroup uint weighted_terms[MAX_BLOCK_ELEMENTS];
    const uint weight = compress_vec[tid];
    uint c_acc = 0;
    for (uint ell = 0; ell < FC_SPEC_NBLOCKS; ++ell) {
        const uint k_base = ell * b;

        uint product = 0;
        for (uint k = 0; k < FC_SPEC_B; ++k) {
            const uint a = a_prime[row * n + (k_base + k)];
            const uint b_val = b_prime[(k_base + k) * n + col];
            product = dot_step(product, a, b_val);
        }

        c_acc = add_mod(c_acc, product);
    }

    weighted_terms[tid] = mul_mod(c_acc, weight);
    threadgroup_barrier(mem_flags::mem_threadgroup);

    const uint simd_lane = tid % simd_size;
    const uint simd_group = tid / simd_size;
    uint reduced = reduce_simdgroup_add_mod(weighted_terms[tid], simd_size);
    if (simd_lane == 0u) {
        weighted_terms[simd_group] = reduced;
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    const uint group_count = (block_elements + simd_size - 1u) / simd_size;
    if (simd_group == 0u) {
        reduced = tid < group_count ? weighted_terms[tid] : 0u;
        reduced = reduce_simdgroup_add_mod(reduced, simd_size);
        if (tid == 0u) {
            compressed[tile_i * N + tile_j] = reduced;
        }
    }
}

kernel void compress_prefix_specialized(
    constant KernelParams& p [[buffer(0)]],
    device const uint* c_prefix [[buffer(1)]],
    device const uint* compress_vec [[buffer(2)]],
    device uint* compressed [[buffer(3)]],
    uint gid [[thread_position_in_grid]])
{
    const uint n = FC_SPEC_N;
    const uint b = FC_SPEC_B;
    const uint N = FC_SPEC_NBLOCKS;
    if (p.n != n || p.b != b || p.N != N) {
        return;
    }

    const uint n3 = N * N * N;
    if (gid >= n3) {
        return;
    }

    const uint i = gid / (N * N);
    const uint rem = gid - i * (N * N);
    const uint j = rem / N;
    const uint ell = rem - j * N;

    const uint row_base = i * b;
    const uint col_base = j * b;
    const uint nn = n * n;

    uint acc = 0;
    uint v_idx = 0;
    for (uint br = 0; br < FC_SPEC_B; ++br) {
        const uint row = row_base + br;
        for (uint bc = 0; bc < FC_SPEC_B; ++bc) {
            const uint col = col_base + bc;
            const uint value = c_prefix[ell * nn + row * n + col];
            const uint weight = compress_vec[v_idx++];
            acc = dot_step(acc, value, weight);
        }
    }

    compressed[gid] = acc;
}

kernel void fused_prefix_compress_specialized(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device const uint* compress_vec [[buffer(3)]],
    device uint* compressed [[buffer(4)]],
    uint tid [[thread_index_in_threadgroup]],
    uint simd_size [[threads_per_simdgroup]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    const uint n = FC_SPEC_N;
    const uint b = FC_SPEC_B;
    const uint N = FC_SPEC_NBLOCKS;
    if (p.n != n || p.b != b || p.N != N) {
        return;
    }

    const uint block_elements = FC_SPEC_B * FC_SPEC_B;
    if (block_elements == 0 || block_elements > MAX_BLOCK_ELEMENTS || tid >= block_elements) {
        return;
    }

    const uint tile_i = tgid.y;
    const uint tile_j = tgid.x;
    if (tile_i >= N || tile_j >= N) {
        return;
    }

    const uint br = tid / b;
    const uint bc = tid - br * b;
    const uint row = tile_i * b + br;
    const uint col = tile_j * b + bc;

    threadgroup uint weighted_terms[MAX_BLOCK_ELEMENTS];
    const uint weight = compress_vec[tid];
    uint c_acc = 0;

    for (uint ell = 0; ell < FC_SPEC_NBLOCKS; ++ell) {
        const uint k_base = ell * b;

        uint product = 0;
        for (uint k = 0; k < FC_SPEC_B; ++k) {
            const uint a = a_prime[row * n + (k_base + k)];
            const uint b_val = b_prime[(k_base + k) * n + col];
            product = dot_step(product, a, b_val);
        }

        c_acc = add_mod(c_acc, product);
        weighted_terms[tid] = mul_mod(c_acc, weight);
        threadgroup_barrier(mem_flags::mem_threadgroup);

        const uint simd_lane = tid % simd_size;
        const uint simd_group = tid / simd_size;
        uint reduced = reduce_simdgroup_add_mod(weighted_terms[tid], simd_size);
        if (simd_lane == 0u) {
            weighted_terms[simd_group] = reduced;
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);

        const uint group_count = (block_elements + simd_size - 1u) / simd_size;
        if (simd_group == 0u) {
            reduced = tid < group_count ? weighted_terms[tid] : 0u;
            reduced = reduce_simdgroup_add_mod(reduced, simd_size);
            if (tid == 0u) {
                compressed[(tile_i * N + tile_j) * N + ell] = reduced;
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
}

kernel void build_prefix_tiled(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device uint* c_prefix [[buffer(3)]],
    uint2 gid [[thread_position_in_grid]],
    uint2 tid [[thread_position_in_threadgroup]])
{
    const uint row = gid.y;
    const uint col = gid.x;
    if (row >= p.n || col >= p.n) {
        return;
    }

    threadgroup uint tile_a[16][16];
    threadgroup uint tile_b[16][16];

    uint c_acc = 0;
    for (uint ell = 0; ell < p.N; ++ell) {
        const uint k_base = ell * p.b;

        uint a_value = 0;
        uint b_value = 0;
        if (tid.x < p.b && tid.y < p.b) {
            a_value = a_prime[row * p.n + (k_base + tid.x)];
            b_value = b_prime[(k_base + tid.y) * p.n + col];
        }
        tile_a[tid.y][tid.x] = a_value;
        tile_b[tid.y][tid.x] = b_value;
        threadgroup_barrier(mem_flags::mem_threadgroup);

        uint product = 0;
        for (uint k = 0; k < p.b; ++k) {
            const uint a = tile_a[tid.y][k];
            const uint b = tile_b[k][tid.x];
            product = dot_step(product, a, b);
        }

        c_acc = add_mod(c_acc, product);
        c_prefix[ell * (p.n * p.n) + row * p.n + col] = c_acc;
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
}

kernel void fused_prefix_compress(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device const uint* compress_vec [[buffer(3)]],
    device uint* compressed [[buffer(4)]],
    uint tid [[thread_index_in_threadgroup]],
    uint simd_size [[threads_per_simdgroup]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    const uint block_elements = p.b * p.b;
    if (block_elements == 0 || block_elements > MAX_BLOCK_ELEMENTS || tid >= block_elements) {
        return;
    }

    const uint tile_i = tgid.y;
    const uint tile_j = tgid.x;
    if (tile_i >= p.N || tile_j >= p.N) {
        return;
    }

    const uint br = tid / p.b;
    const uint bc = tid - br * p.b;
    const uint row = tile_i * p.b + br;
    const uint col = tile_j * p.b + bc;

    threadgroup uint weighted_terms[MAX_BLOCK_ELEMENTS];
    const uint weight = compress_vec[tid];
    uint c_acc = 0;

    for (uint ell = 0; ell < p.N; ++ell) {
        const uint k_base = ell * p.b;

        uint product = 0;
        for (uint k = 0; k < p.b; ++k) {
            const uint a = a_prime[row * p.n + (k_base + k)];
            const uint b = b_prime[(k_base + k) * p.n + col];
            product = dot_step(product, a, b);
        }

        c_acc = add_mod(c_acc, product);
        weighted_terms[tid] = mul_mod(c_acc, weight);
        threadgroup_barrier(mem_flags::mem_threadgroup);

        const uint simd_lane = tid % simd_size;
        const uint simd_group = tid / simd_size;
        uint reduced = reduce_simdgroup_add_mod(weighted_terms[tid], simd_size);
        if (simd_lane == 0u) {
            weighted_terms[simd_group] = reduced;
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);

        const uint group_count = (block_elements + simd_size - 1u) / simd_size;
        if (simd_group == 0u) {
            reduced = tid < group_count ? weighted_terms[tid] : 0u;
            reduced = reduce_simdgroup_add_mod(reduced, simd_size);
            if (tid == 0u) {
                compressed[(tile_i * p.N + tile_j) * p.N + ell] = reduced;
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
}

kernel void transcript_sha256(
    device const uint* compressed [[buffer(0)]],
    constant HashParams& hp [[buffer(1)]],
    device uchar* hash_output [[buffer(2)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid != 0) {
        return;
    }

    thread uint first_state[8];
    sha256_stream_words(compressed, hp.compressed_words, first_state);

    thread uint final_state[8];
    sha256_double_digest(first_state, final_state);

    for (uint i = 0; i < 8; ++i) {
        const uint word = final_state[i];
        hash_output[i * 4 + 0] = (uchar)((word >> 24u) & 0xffu);
        hash_output[i * 4 + 1] = (uchar)((word >> 16u) & 0xffu);
        hash_output[i * 4 + 2] = (uchar)((word >> 8u) & 0xffu);
        hash_output[i * 4 + 3] = (uchar)(word & 0xffu);
    }
}

kernel void product_compressed_sha256(
    device const uint* compressed [[buffer(0)]],
    constant KernelParams& kp [[buffer(1)]],
    device uchar* hash_output [[buffer(2)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid != 0) {
        return;
    }

    const uint final_words = kp.N * kp.N;
    thread uint first_state[8];
    sha256_stream_final_ell_words(compressed, kp.N, final_words, first_state);

    thread uint final_state[8];
    sha256_double_digest(first_state, final_state);

    for (uint i = 0; i < 8; ++i) {
        const uint word = final_state[i];
        hash_output[i * 4 + 0] = (uchar)((word >> 24u) & 0xffu);
        hash_output[i * 4 + 1] = (uchar)((word >> 16u) & 0xffu);
        hash_output[i * 4 + 2] = (uchar)((word >> 8u) & 0xffu);
        hash_output[i * 4 + 3] = (uchar)(word & 0xffu);
    }
}
