// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ASERT_H
#define BITCOIN_ASERT_H

#include <arith_uint256.h>

#include <cstdint>

/**
 * Calculate the ASERT target using the absolute aserti3-2d formulation.
 *
 * time_diff is the elapsed time from the parent of the reference block to the
 * previous block; height_diff is the previous block's height minus the
 * reference block's height. target_spacing and half_life are measured in
 * seconds. This helper does not select or activate a difficulty algorithm.
 *
 * Inputs must satisfy the preconditions checked in the implementation:
 * ref_target is in [1, pow_limit], pow_limit is less than 2^224,
 * target_spacing and half_life are positive, height_diff is nonnegative, and
 * the time delta is within the ASERT fixed-point range.
 */
arith_uint256 CalculateASERT(const arith_uint256& ref_target,
                             int64_t target_spacing,
                             int64_t time_diff,
                             int64_t height_diff,
                             const arith_uint256& pow_limit,
                             int64_t half_life) noexcept;

#endif // BITCOIN_ASERT_H
