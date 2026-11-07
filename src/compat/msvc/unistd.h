// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_COMPAT_MSVC_UNISTD_H
#define BITCOIN_COMPAT_MSVC_UNISTD_H

// This directory is selected only for MSVC/clang-cl Modelnet compilation.
// Keep MinGW and Unix on their system unistd.h. Do not add new emulation here.
#include <compat/mingw/posix_extra.h>

#endif // BITCOIN_COMPAT_MSVC_UNISTD_H
