// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Exact Poseidon2-Goldilocks row-leaf sponge for the Stage-3 FRI prover.
//
// This is the Metal counterpart of cuda/matmul_v4_rc_rowleaf_gpu.cu.  The
// permutation constants arrive in a runtime buffer populated from
// GetAlgHashConstants(); no consensus constant is duplicated here.

#include <metal_stdlib>

using namespace metal;

constant ulong GL_P = 0xFFFFFFFF00000001UL;
constant ulong GL_NEGP = 0xFFFFFFFFUL; // 2^64 mod GL_P
constant uint P2_T = 12u;
constant uint P2_RATE = 8u;

struct P2Constants {
    ulong rc_ext[8 * 12];
    ulong rc_int[22];
    ulong mu[12];
};

struct AbsorbParams {
    uint n_lde;
    uint n_lanes;
    ulong base_pos;
};

struct FinalizeParams {
    uint n_lde;
    uint reserved;
    ulong total_vals;
};

// High half of the exact 64x64->128 product. MSL's integer mulhi intrinsic is
// defined for ulong and lets the Apple compiler select the best lowering for
// the active GPU family.
inline ulong mul_hi_u64(ulong a, ulong b)
{
    return mulhi(a, b);
}

inline ulong gl_mul(ulong a, ulong b)
{
    const ulong lo = a * b;
    const ulong hi = mul_hi_u64(a, b);
    const uint hh = (uint)(hi >> 32);
    const uint hl = (uint)hi;
    ulong t0 = lo - (ulong)hh;
    if (lo < (ulong)hh) t0 -= GL_NEGP;
    const ulong t1 = (ulong)hl * GL_NEGP;
    ulong r = t0 + t1;
    if (r < t1) r += GL_NEGP;
    if (r >= GL_P) r -= GL_P;
    return r;
}

inline ulong gl_add(ulong a, ulong b)
{
    ulong s = a + b;
    if (s < a) s += GL_NEGP;
    if (s >= GL_P) s -= GL_P;
    return s;
}

inline ulong gl_dbl(ulong a)
{
    return gl_add(a, a);
}

inline ulong gl_canon(ulong a)
{
    return a >= GL_P ? a - GL_P : a;
}

inline ulong gl_pow7(ulong x)
{
    const ulong x2 = gl_mul(x, x);
    const ulong x4 = gl_mul(x2, x2);
    return gl_mul(gl_mul(x4, x2), x);
}

inline void pr_m4(thread ulong& x0, thread ulong& x1,
                  thread ulong& x2, thread ulong& x3)
{
    const ulong t0 = gl_add(x0, x1);
    const ulong t1 = gl_add(x2, x3);
    const ulong t2 = gl_add(gl_dbl(x1), t1);
    const ulong t3 = gl_add(gl_dbl(x3), t0);
    const ulong t4 = gl_add(gl_dbl(gl_dbl(t1)), t3);
    const ulong t5 = gl_add(gl_dbl(gl_dbl(t0)), t2);
    x0 = gl_add(t3, t5);
    x1 = t5;
    x2 = gl_add(t2, t4);
    x3 = t4;
}

inline void pr_external(thread ulong* s)
{
    pr_m4(s[0], s[1], s[2], s[3]);
    pr_m4(s[4], s[5], s[6], s[7]);
    pr_m4(s[8], s[9], s[10], s[11]);
    for (uint i = 0; i < 4; ++i) {
        const ulong sum = gl_add(gl_add(s[i], s[4 + i]), s[8 + i]);
        s[i] = gl_add(s[i], sum);
        s[4 + i] = gl_add(s[4 + i], sum);
        s[8 + i] = gl_add(s[8 + i], sum);
    }
}

inline void pr_internal(thread ulong* s, constant P2Constants& c)
{
    ulong sum = s[0];
    for (uint i = 1; i < P2_T; ++i) sum = gl_add(sum, s[i]);
    for (uint i = 0; i < P2_T; ++i) {
        s[i] = gl_add(sum, gl_mul(s[i], c.mu[i]));
    }
}

inline void pr_permute(thread ulong* s, constant P2Constants& c)
{
    pr_external(s);
    for (uint r = 0; r < 4; ++r) {
        for (uint i = 0; i < P2_T; ++i) {
            s[i] = gl_pow7(gl_add(s[i], c.rc_ext[r * P2_T + i]));
        }
        pr_external(s);
    }
    for (uint r = 0; r < 22; ++r) {
        s[0] = gl_pow7(gl_add(s[0], c.rc_int[r]));
        pr_internal(s, c);
    }
    for (uint r = 4; r < 8; ++r) {
        for (uint i = 0; i < P2_T; ++i) {
            s[i] = gl_pow7(gl_add(s[i], c.rc_ext[r * P2_T + i]));
        }
        pr_external(s);
    }
}

kernel void btx_rc_rowleaf_absorb(
    constant AbsorbParams& p [[buffer(0)]],
    constant P2Constants& c [[buffer(1)]],
    device ulong* state [[buffer(2)]],
    device const ulong* block [[buffer(3)]],
    uint row [[thread_position_in_grid]])
{
    if (row >= p.n_lde) return;
    ulong s[P2_T];
    for (uint j = 0; j < P2_T; ++j) {
        s[j] = state[(ulong)row * P2_T + j];
    }
    for (uint k = 0; k < p.n_lanes; ++k) {
        const ulong pos = p.base_pos + k;
        const uint lane = (uint)(pos & 7UL);
        s[lane] = gl_add(s[lane],
                         gl_canon(block[(ulong)k * p.n_lde + row]));
        if (lane == P2_RATE - 1) pr_permute(s, c);
    }
    for (uint j = 0; j < P2_T; ++j) {
        state[(ulong)row * P2_T + j] = s[j];
    }
}

kernel void btx_rc_rowleaf_finalize(
    constant FinalizeParams& p [[buffer(0)]],
    constant P2Constants& c [[buffer(1)]],
    device ulong* state [[buffer(2)]],
    device ulong* digests [[buffer(3)]],
    uint row [[thread_position_in_grid]])
{
    if (row >= p.n_lde) return;
    ulong s[P2_T];
    for (uint j = 0; j < P2_T; ++j) {
        s[j] = state[(ulong)row * P2_T + j];
    }

    uint lane = (uint)(p.total_vals & 7UL);
    s[lane] = gl_add(s[lane], (ulong)row);
    if (lane == P2_RATE - 1) pr_permute(s, c);

    lane = (uint)((p.total_vals + 1) & 7UL);
    s[lane] = gl_add(s[lane], 1UL);
    if (lane == P2_RATE - 1) pr_permute(s, c);

    if (((p.total_vals + 2) & 7UL) != 0) pr_permute(s, c);
    for (uint j = 0; j < 4; ++j) {
        digests[(ulong)row * 4 + j] = gl_canon(s[j]);
    }
}
