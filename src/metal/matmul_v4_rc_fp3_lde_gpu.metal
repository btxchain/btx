// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Exact radix-2 Fp3 NTT over Goldilocks for the Stage-3 prover.  Roots are
// supplied by the CPU as base-field powers; multiplication by a root is three
// independent base-field products because roots embed as (w, 0, 0).

#include <metal_stdlib>

using namespace metal;

constant ulong GL_P = 0xFFFFFFFF00000001UL;
constant ulong GL_EPSILON = 0xFFFFFFFFUL; // 2^64 mod GL_P

struct PermuteParams {
    uint n;
    uint log_n;
};

struct StageParams {
    uint n;
    uint len;
    uint root_stride;
    uint reserved;
};

struct ScaleParams {
    uint n;
    uint reserved;
    ulong scale;
};

inline ulong gl_canon(ulong a)
{
    return a >= GL_P ? a - GL_P : a;
}

inline ulong gl_add(ulong a, ulong b)
{
    a = gl_canon(a);
    b = gl_canon(b);
    ulong s = a + b;
    if (s < a) s += GL_EPSILON;
    if (s >= GL_P) s -= GL_P;
    return s;
}

inline ulong gl_sub(ulong a, ulong b)
{
    a = gl_canon(a);
    b = gl_canon(b);
    return a >= b ? a - b : GL_P - (b - a);
}

// Division-free reduction of the exact 64x64->128 product.  This is the same
// identity as gkr_field::Reduce128 and the audited row-leaf Metal provider.
inline ulong gl_mul(ulong a, ulong b)
{
    a = gl_canon(a);
    b = gl_canon(b);
    const ulong lo = a * b;
    const ulong hi = mulhi(a, b);
    const uint hh = (uint)(hi >> 32);
    const uint hl = (uint)hi;
    ulong t0 = lo - (ulong)hh;
    if (lo < (ulong)hh) t0 -= GL_EPSILON;
    const ulong t1 = (ulong)hl * GL_EPSILON;
    ulong r = t0 + t1;
    if (r < t1) r += GL_EPSILON;
    if (r >= GL_P) r -= GL_P;
    return r;
}

inline uint reverse_low_bits(uint value, uint count)
{
    uint reversed = 0;
    for (uint i = 0; i < count; ++i) {
        reversed = (reversed << 1) | ((value >> i) & 1u);
    }
    return reversed;
}

// One thread owns one disjoint bit-reversal pair.  Fixed points are
// canonicalized in place.  For i != reverse(i), only the smaller index runs,
// so no two threads ever write the same limb.
kernel void btx_rc_fp3_ntt_bit_reverse(
    constant PermuteParams& p [[buffer(0)]],
    device ulong* values [[buffer(1)]],
    uint i [[thread_position_in_grid]])
{
    if (i >= p.n) return;
    const uint j = reverse_low_bits(i, p.log_n);
    if (i > j) return;
    const ulong i3 = (ulong)i * 3UL;
    const ulong j3 = (ulong)j * 3UL;
    if (i == j) {
        values[i3] = gl_canon(values[i3]);
        values[i3 + 1] = gl_canon(values[i3 + 1]);
        values[i3 + 2] = gl_canon(values[i3 + 2]);
        return;
    }
    for (uint limb = 0; limb < 3; ++limb) {
        const ulong a = gl_canon(values[i3 + limb]);
        const ulong b = gl_canon(values[j3 + limb]);
        values[i3 + limb] = b;
        values[j3 + limb] = a;
    }
}

// One thread owns one butterfly.  The root-power table is natural order for
// the full domain, so stage twiddle w^j is roots[j * (n / len)].
kernel void btx_rc_fp3_ntt_stage(
    constant StageParams& p [[buffer(0)]],
    device ulong* values [[buffer(1)]],
    device const ulong* roots [[buffer(2)]],
    uint butterfly [[thread_position_in_grid]])
{
    // `half` is an MSL scalar type name, so use an unambiguous identifier.
    const uint half_len = p.len >> 1;
    const uint butterfly_count = p.n >> 1;
    if (butterfly >= butterfly_count) return;
    const uint group = butterfly / half_len;
    const uint j = butterfly - group * half_len;
    const uint lo_index = group * p.len + j;
    const uint hi_index = lo_index + half_len;
    const ulong lo3 = (ulong)lo_index * 3UL;
    const ulong hi3 = (ulong)hi_index * 3UL;
    const ulong w = gl_canon(roots[(ulong)j * p.root_stride]);
    for (uint limb = 0; limb < 3; ++limb) {
        const ulong u = values[lo3 + limb];
        const ulong v = gl_mul(values[hi3 + limb], w);
        values[lo3 + limb] = gl_add(u, v);
        values[hi3 + limb] = gl_sub(u, v);
    }
}

kernel void btx_rc_fp3_ntt_scale(
    constant ScaleParams& p [[buffer(0)]],
    device ulong* values [[buffer(1)]],
    uint i [[thread_position_in_grid]])
{
    if (i >= p.n) return;
    const ulong i3 = (ulong)i * 3UL;
    for (uint limb = 0; limb < 3; ++limb) {
        values[i3 + limb] = gl_mul(values[i3 + limb], p.scale);
    }
}
