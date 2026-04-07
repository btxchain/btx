// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <util/translation.h>

// Standalone test/report generators do not pull in the daemon/CLI entrypoints
// that normally define this symbol, so provide the same null translator that
// the test harness uses.
const TranslateFn G_TRANSLATION_FUN{nullptr};
