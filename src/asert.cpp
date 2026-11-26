// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <asert.h>

#include <cassert>
#include <cstdint>
#include <limits>

arith_uint256 CalculateASERT(const arith_uint256& ref_target,
                             int64_t target_spacing,
                             int64_t time_diff,
                             int64_t height_diff,
                             const arith_uint256& pow_limit,
                             int64_t half_life) noexcept
{
    // Adapted from the aserti3-2d reference algorithm in the ASERT
    // specification (version 0.6.3) by freetrader, Jonathan Toomim,
    // Calin Culianu, Mark Lundeberg, and Tobias Ruck. The polynomial
    // coefficients approximate 2^x in fixed point; no floating-point
    // operations are used.
    assert(pow_limit > 0);
    assert(ref_target > 0 && ref_target <= pow_limit);
    assert((pow_limit >> 224) == 0);
    assert(target_spacing > 0);
    assert(height_diff >= 0 && height_diff < std::numeric_limits<int64_t>::max());
    assert(half_life > 0);

    const int64_t height_delta{height_diff + 1};
    assert(target_spacing <= std::numeric_limits<int64_t>::max() / height_delta);
    const int64_t ideal_time_diff{target_spacing * height_delta};
    assert(time_diff >= std::numeric_limits<int64_t>::min() + ideal_time_diff);
    const int64_t delta{time_diff - ideal_time_diff};

    // The bound guarantees that scaling delta by 2^16 fits in int64_t.
    constexpr int64_t MAX_DELTA{int64_t{1} << 47};
    assert(delta > -MAX_DELTA && delta < MAX_DELTA);
    const int64_t exponent{(delta * 65536) / half_life};

    // The signed right shift is required to round negative exponents down.
    static_assert(int64_t{-1} >> 1 == int64_t{-1});
    int64_t shifts{exponent >> 16};
    const uint16_t frac{static_cast<uint16_t>(exponent)};
    assert(exponent == shifts * 65536 + frac);

    const uint64_t frac64{frac};
    const uint32_t factor{static_cast<uint32_t>(
        65536 + ((195766423245049ull * frac64 +
                  971821376ull * frac64 * frac64 +
                  5127ull * frac64 * frac64 * frac64 +
                  (1ull << 47)) >>
                 48))};

    // ref_target < 2^224, so multiplying by factor (< 2^18) fits in 256 bits.
    arith_uint256 next_target{ref_target * factor};
    shifts -= 16;
    if (shifts <= 0) {
        const int64_t right_shift{-shifts};
        if (right_shift >= 256) {
            next_target = 0;
        } else {
            next_target >>= static_cast<unsigned int>(right_shift);
        }
    } else if (shifts >= 256) {
        next_target = pow_limit;
    } else {
        const int left_shift{static_cast<int>(shifts)};
        const arith_uint256 shifted_target{next_target << left_shift};
        if ((shifted_target >> left_shift) != next_target) {
            next_target = pow_limit;
        } else {
            next_target = shifted_target;
        }
    }

    if (next_target == 0) {
        next_target = 1;
    } else if (next_target > pow_limit) {
        next_target = pow_limit;
    }
    return next_target;
}
