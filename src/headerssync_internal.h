// Copyright (c) 2026 The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HEADERSSYNC_INTERNAL_H
#define BITCOIN_HEADERSSYNC_INTERNAL_H

#include <primitives/block.h>

#include <cstdint>
#include <utility>

namespace headerssync_internal {

template <typename PowCheck>
bool CheckExpectedTargetAndWork(const CBlockHeader& header, uint32_t expected_nbits, PowCheck&& pow_check)
{
    return header.nBits == expected_nbits && std::forward<PowCheck>(pow_check)(header);
}

} // namespace headerssync_internal

#endif // BITCOIN_HEADERSSYNC_INTERNAL_H
