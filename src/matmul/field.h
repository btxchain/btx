// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_FIELD_H
#define BTX_MATMUL_FIELD_H

#include <cstdint>
#include <string>

class uint256;

namespace matmul::field {

using Element = uint32_t;
constexpr Element MODULUS = 0x7FFFFFFFU;

struct DotKernelInfo {
    bool neon_compiled{false};
    std::string reason;
};

Element add(Element a, Element b);
Element sub(Element a, Element b);
Element mul(Element a, Element b);
Element inv(Element a);
Element neg(Element a);
Element from_uint32(uint32_t x);
Element from_oracle(const uint256& seed, uint32_t index);
Element dot(const Element* a, const Element* b, uint32_t len);
DotKernelInfo ProbeDotKernel();

} // namespace matmul::field

#endif // BTX_MATMUL_FIELD_H
