// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_INTERNAL_H
#define BITCOIN_POW_INTERNAL_H

#include <arith_uint256.h>
#include <pow.h>
#include <primitives/block.h>

#include <utility>

namespace pow_internal {

// Internal callback seam lets unit tests count PoW calls and inject failures.
template <typename DigestFunction>
bool CheckProofOfWorkYespowerWithDigest(
    const CBlockHeader& header,
    const Consensus::Params& params,
    DigestFunction&& digest_function)
{
    const auto target{DeriveTarget(header.nBits, params.powLimit)};
    if (!target) return false;

    const uint256 digest{std::forward<DigestFunction>(digest_function)(header)};
    return UintToArith256(digest) <= *target;
}

template <typename YespowerCheck>
bool CheckProofOfWorkHeaderWithYespower(
    const CBlockHeader& header,
    const Consensus::Params& params,
    YespowerCheck&& yespower_check)
{
    if (params.fPowUseYespower) {
        return std::forward<YespowerCheck>(yespower_check)(header, params);
    }
    return ::CheckProofOfWork(header.GetHash(), header.nBits, params);
}

} // namespace pow_internal

#endif // BITCOIN_POW_INTERNAL_H
