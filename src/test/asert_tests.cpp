// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <asert.h>

#include <arith_uint256.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

BOOST_AUTO_TEST_SUITE(asert_tests)

namespace {
const arith_uint256 POW_LIMIT{
    UintToArith256(uint256{"00000000ffff0000000000000000000000000000000000000000000000000000"})};
const arith_uint256 BCHN_POW_LIMIT{
    UintToArith256(uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})};
const arith_uint256 REF_TARGET{POW_LIMIT >> 4};
constexpr int64_t TARGET_SPACING{600};
constexpr int64_t HALF_LIFE{172800};
const arith_uint256 SINGLE_300_TARGET{
    UintToArith256(uint256{"00000000ffb1ffffffffffffffffffffffffffffffffffffffffffffffffffff"})};
const arith_uint256 FUNNY_REF_TARGET{
    UintToArith256(uint256{"000000008000000000000000000fffffffffffffffffffffffffffffffffffff"})};
} // namespace

BOOST_AUTO_TEST_CASE(steady_schedule)
{
    // At the ideal timestamp for the next block, the anchor target is unchanged.
    BOOST_CHECK(CalculateASERT(REF_TARGET, TARGET_SPACING, TARGET_SPACING, 0, POW_LIMIT, HALF_LIFE) == REF_TARGET);
}

BOOST_AUTO_TEST_CASE(faster_and_slower_schedule_vectors)
{
    // Reference aserti3-2d fixed-point outputs at +/-300 seconds from schedule.
    const arith_uint256 faster_target{
        UintToArith256(uint256{"000000001004dffb100000000000000000000000000000000000000000000000"})};
    const arith_uint256 slower_target{
        UintToArith256(uint256{"000000000ffb1004e00000000000000000000000000000000000000000000000"})};

    BOOST_CHECK(
        CalculateASERT(REF_TARGET, TARGET_SPACING, TARGET_SPACING + 300, 0, POW_LIMIT, HALF_LIFE) == faster_target);
    BOOST_CHECK(
        CalculateASERT(REF_TARGET, TARGET_SPACING, TARGET_SPACING - 300, 0, POW_LIMIT, HALF_LIFE) == slower_target);
}

BOOST_AUTO_TEST_CASE(half_life_response)
{
    BOOST_CHECK(
        CalculateASERT(REF_TARGET, TARGET_SPACING, TARGET_SPACING + HALF_LIFE, 0, POW_LIMIT, HALF_LIFE) ==
        REF_TARGET * 2);
    BOOST_CHECK(
        CalculateASERT(REF_TARGET, TARGET_SPACING, TARGET_SPACING - HALF_LIFE, 0, POW_LIMIT, HALF_LIFE) ==
        REF_TARGET / 2);
}

BOOST_AUTO_TEST_CASE(pow_limit_clamp)
{
    BOOST_CHECK(
        CalculateASERT(POW_LIMIT, TARGET_SPACING, TARGET_SPACING + HALF_LIFE, 0, POW_LIMIT, HALF_LIFE) ==
        POW_LIMIT);
}

BOOST_AUTO_TEST_CASE(hardest_target_boundary)
{
    BOOST_CHECK(
        CalculateASERT(POW_LIMIT, TARGET_SPACING, TARGET_SPACING - 1000, 0, POW_LIMIT, 1) == arith_uint256{1});
}

BOOST_AUTO_TEST_CASE(published_aserti3_2d_reference_vectors)
{
    // Vectors from Bitcoin Cash Node's aserti3-2d reference test:
    // https://github.com/Bitcoin-ABC/bitcoin-abc/blob/0f42e464600064d5d0c2dbb1c204c0bc8e63bcd2/src/pow/test/aserti32d_tests.cpp
    // The listed time offsets are passed with parent_time_diff=600, as in that test.
    // Boundary cases are also represented in BCHN's published vector corpus:
    // https://download.bitcoincashnode.org/misc/data/asert/test_vectors/run04
    // https://download.bitcoincashnode.org/misc/data/asert/test_vectors/run05
    struct ReferenceVector {
        arith_uint256 ref_target;
        int64_t time_diff_offset;
        int64_t height_diff;
        arith_uint256 expected_target;
        uint32_t expected_compact;
    };

    const std::vector<ReferenceVector> vectors{
        {BCHN_POW_LIMIT, 0, 2 * 144, BCHN_POW_LIMIT >> 1, 0x1c7fffff},
        {BCHN_POW_LIMIT, 0, 4 * 144, BCHN_POW_LIMIT >> 2, 0x1c3fffff},
        {BCHN_POW_LIMIT >> 1, 0, 2 * 144, BCHN_POW_LIMIT >> 2, 0x1c3fffff},
        {BCHN_POW_LIMIT >> 2, 0, 2 * 144, BCHN_POW_LIMIT >> 3, 0x1c1fffff},
        {BCHN_POW_LIMIT >> 3, 0, 2 * 144, BCHN_POW_LIMIT >> 4, 0x1c0fffff},
        {BCHN_POW_LIMIT, 0, 2 * (256 - 34) * 144, arith_uint256{3}, 0x01030000},
        {BCHN_POW_LIMIT, 0, 2 * (256 - 34) * 144 + 119, arith_uint256{3}, 0x01030000},
        {BCHN_POW_LIMIT, 0, 2 * (256 - 34) * 144 + 120, arith_uint256{2}, 0x01020000},
        {BCHN_POW_LIMIT, 0, 2 * (256 - 33) * 144 - 1, arith_uint256{2}, 0x01020000},
        {BCHN_POW_LIMIT, 0, 2 * (256 - 33) * 144, arith_uint256{1}, 0x01010000},
        {BCHN_POW_LIMIT, 0, 2 * (256 - 32) * 144, arith_uint256{1}, 0x01010000},
        {arith_uint256{1}, 0, 2 * (256 - 32) * 144, arith_uint256{1}, 0x01010000},
        {BCHN_POW_LIMIT, 2 * (512 - 32) * 144, 0, BCHN_POW_LIMIT, BCHN_POW_LIMIT.GetCompact()},
        {arith_uint256{1}, (512 - 64) * 144 * 600, 0, BCHN_POW_LIMIT, BCHN_POW_LIMIT.GetCompact()},
        {BCHN_POW_LIMIT, 300, 1, SINGLE_300_TARGET, 0x1d00ffb1},
        {FUNNY_REF_TARGET, 600 * 2 * 33 * 144, 0, BCHN_POW_LIMIT, BCHN_POW_LIMIT.GetCompact()},
        {arith_uint256{1}, 600 * 2 * 256 * 144, 0, BCHN_POW_LIMIT, BCHN_POW_LIMIT.GetCompact()},
        {arith_uint256{1}, 600 * 2 * 224 * 144 - 1, 0,
         arith_uint256{arith_uint256{0xffff8} << 204}, BCHN_POW_LIMIT.GetCompact()},
    };

    for (const auto& vector : vectors) {
        const arith_uint256 actual{CalculateASERT(
            vector.ref_target, TARGET_SPACING, TARGET_SPACING + vector.time_diff_offset,
            vector.height_diff, BCHN_POW_LIMIT, HALF_LIFE)};
        BOOST_CHECK(actual == vector.expected_target);
        BOOST_CHECK_EQUAL(actual.GetCompact(), vector.expected_compact);
    }
}

BOOST_AUTO_TEST_SUITE_END()
