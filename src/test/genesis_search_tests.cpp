// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <arith_uint256.h>
#include <chainparams.h>
#include <hash.h>
#include <kernel/genesis.h>
#include <kernel/genesis_search.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iterator>
#include <limits>
#include <mutex>
#include <span>
#include <stdexcept>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(genesis_search_tests, BasicTestingSetup)

namespace {

Consensus::Params MainConsensus(ArgsManager& args)
{
    const auto params{CreateChainParams(args, ChainType::MAIN)};
    return params->GetConsensus();
}

uint256 DigestForInteger(const arith_uint256& value)
{
    return ArithToUint256(value);
}

kernel::GenesisSearchResult SaveFoundCheckpoint(
    const kernel::GenesisSearchOptions& options,
    const Consensus::Params& consensus,
    const arith_uint256& target,
    uint32_t winning_nonce)
{
    return kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader& header) {
            if (header.nNonce == winning_nonce) return DigestForInteger(target);
            return DigestForInteger(target + arith_uint256{1});
        });
}

} // namespace

BOOST_AUTO_TEST_CASE(genesis_search_uses_production_yespower_and_deterministic_header)
{
    const kernel::GenesisSearchOptions options{1'760'000'000, 17, 17};
    const auto consensus{MainConsensus(*m_node.args)};
    const auto result{kernel::SearchVaqyronGenesis(options, consensus)};
    const uint256 expected_digest{GetPoWDigest(result.last_block)};

    BOOST_CHECK_EQUAL(
        consensus.powLimit,
        uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"});
    BOOST_CHECK(consensus.fPowUseYespower);
    BOOST_CHECK(!result.found);
    BOOST_CHECK_EQUAL(result.candidates_checked, 1U);
    BOOST_CHECK_EQUAL(result.nonce, 17U);
    BOOST_CHECK_EQUAL(result.last_block.nTime, options.time);
    BOOST_CHECK_EQUAL(result.last_block.nNonce, options.start_nonce);
    BOOST_CHECK_EQUAL(result.last_block.nBits, kernel::VAQYRON_GENESIS_NBITS);
    BOOST_CHECK_EQUAL(result.last_block.nVersion, kernel::VAQYRON_GENESIS_VERSION);
    BOOST_CHECK_EQUAL(result.last_pow_digest, expected_digest);
    BOOST_CHECK_EQUAL(UintToArith256(result.last_pow_digest), UintToArith256(expected_digest));
    BOOST_CHECK_EQUAL(
        result.found,
        CheckProofOfWorkYespower(result.last_block, consensus));
}

BOOST_AUTO_TEST_CASE(genesis_search_accepts_target_equality_and_checks_inclusive_bounds)
{
    const kernel::GenesisSearchOptions options{1'760'000'001, 10, 11};
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);

    std::vector<uint32_t> nonces;
    const auto result{kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader& header) {
            nonces.emplace_back(header.nNonce);
            BOOST_CHECK_EQUAL(header.nTime, options.time);
            const arith_uint256 digest_value{
                *target + (header.nNonce == options.start_nonce ? arith_uint256{1} : arith_uint256{0})};
            return DigestForInteger(digest_value);
        })};

    BOOST_CHECK(result.found);
    BOOST_CHECK_EQUAL(result.nonce, options.end_nonce);
    BOOST_CHECK_EQUAL(result.candidates_checked, 2U);
    BOOST_CHECK_EQUAL(result.last_block.nTime, options.time);
    BOOST_REQUIRE_EQUAL(nonces.size(), 2U);
    BOOST_CHECK_EQUAL(nonces[0], options.start_nonce);
    BOOST_CHECK_EQUAL(nonces[1], options.end_nonce);
}

BOOST_AUTO_TEST_CASE(genesis_search_respects_bounded_range_and_does_not_wrap_nonce)
{
    const kernel::GenesisSearchOptions options{
        1'760'000'002,
        std::numeric_limits<uint32_t>::max(),
        std::numeric_limits<uint32_t>::max()};
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);

    std::vector<uint32_t> nonces;
    const auto result{kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader& header) {
            nonces.emplace_back(header.nNonce);
            return DigestForInteger(*target + arith_uint256{1});
        })};

    BOOST_CHECK(!result.found);
    BOOST_CHECK_EQUAL(result.candidates_checked, 1U);
    BOOST_CHECK_EQUAL(result.nonce, std::numeric_limits<uint32_t>::max());
    BOOST_REQUIRE_EQUAL(nonces.size(), 1U);
    BOOST_CHECK_EQUAL(nonces.front(), std::numeric_limits<uint32_t>::max());
    BOOST_CHECK_EQUAL(result.last_block.nTime, options.time);
}

BOOST_AUTO_TEST_CASE(genesis_search_not_found_is_bounded_and_reports_progress)
{
    const kernel::GenesisSearchOptions options{1'760'000'003, 0, 2047};
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    unsigned int progress_calls{0};

    const auto result{kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader&) { return DigestForInteger(*target + arith_uint256{1}); },
        [&](const kernel::GenesisSearchProgress& progress) {
            ++progress_calls;
            BOOST_CHECK_EQUAL(progress.candidates_checked % 1024, 0U);
            BOOST_CHECK(progress.candidates_per_second >= 0);
            BOOST_CHECK(progress.elapsed_seconds >= 0);
        })};

    BOOST_CHECK(!result.found);
    BOOST_CHECK_EQUAL(result.candidates_checked, 2048U);
    BOOST_CHECK_EQUAL(result.nonce, options.end_nonce);
    BOOST_CHECK_EQUAL(result.last_block.nTime, options.time);
    BOOST_CHECK_EQUAL(progress_calls, 2U);
}

BOOST_AUTO_TEST_CASE(genesis_search_rejects_invalid_target_before_digest_and_propagates_failures)
{
    Consensus::Params invalid_consensus{};
    const kernel::GenesisSearchOptions one_nonce{1'760'000'004, 4, 4};
    unsigned int digest_calls{0};
    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            one_nonce,
            invalid_consensus,
            [&](const CBlockHeader&) {
                ++digest_calls;
                return uint256{};
            }),
        std::invalid_argument);
    BOOST_CHECK_EQUAL(digest_calls, 0U);

    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            one_nonce,
            MainConsensus(*m_node.args),
            [](const CBlockHeader&) -> uint256 { throw std::runtime_error{"injected yespower failure"}; }),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(genesis_search_candidate_a_uses_raw_digest_little_endian)
{
    const kernel::GenesisSearchOptions options{1'760'000'005, 8, 8};
    std::array<unsigned char, 32> raw_digest{};
    raw_digest.front() = 0x2a;
    raw_digest.back() = 0x01;
    const uint256 digest{std::span<const unsigned char>{raw_digest}};
    arith_uint256 expected{1};
    expected <<= 248;
    expected += 0x2a;
    const auto consensus{MainConsensus(*m_node.args)};
    const auto result{kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader&) { return digest; })};

    BOOST_CHECK_EQUAL(UintToArith256(result.last_pow_digest), expected);
    BOOST_CHECK(!result.found);
}

BOOST_AUTO_TEST_CASE(genesis_search_rejects_reversed_range)
{
    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            kernel::GenesisSearchOptions{1'760'000'006, 2, 1},
            MainConsensus(*m_node.args),
            [](const CBlockHeader&) { return uint256{}; }),
        std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(genesis_search_one_worker_matches_serial_production_result)
{
    const kernel::GenesisSearchOptions options{1791363600, 17, 20, 1};
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);

    bool expected_found{false};
    uint64_t expected_checked{0};
    CBlock expected_block;
    uint256 expected_digest;
    for (uint64_t nonce{options.start_nonce}; nonce <= options.end_nonce; ++nonce) {
        expected_block = kernel::CreateVaqyronGenesisBlock(
            options.time, static_cast<uint32_t>(nonce), kernel::VAQYRON_GENESIS_NBITS,
            kernel::VAQYRON_GENESIS_VERSION);
        expected_digest = GetPoWDigest(expected_block);
        ++expected_checked;
        expected_found = UintToArith256(expected_digest) <= *target;
        if (expected_found) break;
    }

    const auto result{kernel::SearchVaqyronGenesis(options, consensus)};
    BOOST_CHECK_EQUAL(result.found, expected_found);
    BOOST_CHECK_EQUAL(result.candidates_checked, expected_checked);
    BOOST_CHECK_EQUAL(result.nonce, expected_block.nNonce);
    BOOST_CHECK_EQUAL(result.last_block.nVersion, expected_block.nVersion);
    BOOST_CHECK_EQUAL(result.last_block.nTime, expected_block.nTime);
    BOOST_CHECK_EQUAL(result.last_block.nBits, expected_block.nBits);
    BOOST_CHECK_EQUAL(result.last_block.nNonce, expected_block.nNonce);
    BOOST_CHECK_EQUAL(result.last_block.hashPrevBlock, expected_block.hashPrevBlock);
    BOOST_CHECK_EQUAL(result.last_block.hashMerkleRoot, expected_block.hashMerkleRoot);
    BOOST_CHECK_EQUAL(result.last_pow_digest, expected_digest);
    BOOST_CHECK_EQUAL(result.target, *target);
    BOOST_CHECK(result.last_pow_digest != result.last_block.GetHash());
}

BOOST_AUTO_TEST_CASE(genesis_search_partitions_two_worker_range_with_exact_coverage)
{
    const auto ranges{kernel::PartitionGenesisSearchRange(20, 27, 2)};
    BOOST_REQUIRE_EQUAL(ranges.size(), 2U);
    BOOST_CHECK_EQUAL(ranges[0].worker_index, 0U);
    BOOST_CHECK_EQUAL(ranges[0].start_nonce, 20U);
    BOOST_CHECK_EQUAL(ranges[0].end_nonce, 23U);
    BOOST_CHECK_EQUAL(ranges[1].worker_index, 1U);
    BOOST_CHECK_EQUAL(ranges[1].start_nonce, 24U);
    BOOST_CHECK_EQUAL(ranges[1].end_nonce, 27U);

    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    std::mutex seen_mutex;
    std::vector<uint32_t> seen;
    std::atomic<bool> timestamp_matches{true};
    const auto result{kernel::SearchVaqyronGenesis(
        kernel::GenesisSearchOptions{1791363600, 20, 27, 2},
        consensus,
        [&](const CBlockHeader& header) {
            if (header.nTime != 1791363600) timestamp_matches.store(false);
            std::lock_guard lock{seen_mutex};
            seen.push_back(header.nNonce);
            return DigestForInteger(*target + arith_uint256{1});
        })};

    std::sort(seen.begin(), seen.end());
    BOOST_CHECK(!result.found);
    BOOST_CHECK_EQUAL(result.candidates_checked, 8U);
    BOOST_CHECK(timestamp_matches.load());
    BOOST_REQUIRE_EQUAL(seen.size(), 8U);
    for (uint32_t i{0}; i < 8; ++i) BOOST_CHECK_EQUAL(seen[i], 20U + i);
}

BOOST_AUTO_TEST_CASE(genesis_search_partitions_uneven_ranges_without_gaps)
{
    const auto ranges{kernel::PartitionGenesisSearchRange(30, 39, 3)};
    BOOST_REQUIRE_EQUAL(ranges.size(), 3U);
    BOOST_CHECK_EQUAL(ranges[0].start_nonce, 30U);
    BOOST_CHECK_EQUAL(ranges[0].end_nonce, 33U);
    BOOST_CHECK_EQUAL(ranges[1].start_nonce, 34U);
    BOOST_CHECK_EQUAL(ranges[1].end_nonce, 36U);
    BOOST_CHECK_EQUAL(ranges[2].start_nonce, 37U);
    BOOST_CHECK_EQUAL(ranges[2].end_nonce, 39U);

    uint64_t expected_start{30};
    for (const auto& range : ranges) {
        BOOST_CHECK_EQUAL(range.start_nonce, expected_start);
        expected_start = static_cast<uint64_t>(range.end_nonce) + 1;
    }
    BOOST_CHECK_EQUAL(expected_start, 40U);
}

BOOST_AUTO_TEST_CASE(genesis_search_parallel_inclusive_uint32_boundary_does_not_wrap)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    std::mutex seen_mutex;
    std::vector<uint32_t> seen;
    const auto max_nonce{std::numeric_limits<uint32_t>::max()};
    const auto result{kernel::SearchVaqyronGenesis(
        kernel::GenesisSearchOptions{1791363600, max_nonce - 3, max_nonce, 3},
        consensus,
        [&](const CBlockHeader& header) {
            std::lock_guard lock{seen_mutex};
            seen.push_back(header.nNonce);
            return DigestForInteger(*target + arith_uint256{1});
        })};

    std::sort(seen.begin(), seen.end());
    BOOST_CHECK(!result.found);
    BOOST_CHECK_EQUAL(result.candidates_checked, 4U);
    BOOST_REQUIRE_EQUAL(seen.size(), 4U);
    for (uint32_t i{0}; i < 4; ++i) BOOST_CHECK_EQUAL(seen[i], max_nonce - 3 + i);
}

BOOST_AUTO_TEST_CASE(genesis_search_parallel_worker_finds_injected_solution)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    std::mutex seen_mutex;
    std::vector<uint32_t> seen;
    const auto result{kernel::SearchVaqyronGenesis(
        kernel::GenesisSearchOptions{1791363600, 100, 105, 2},
        consensus,
        [&](const CBlockHeader& header) {
            std::lock_guard lock{seen_mutex};
            seen.push_back(header.nNonce);
            return header.nNonce == 104
                ? DigestForInteger(*target)
                : DigestForInteger(*target + arith_uint256{1});
        })};

    BOOST_CHECK(result.found);
    BOOST_CHECK_EQUAL(result.nonce, 104U);
    BOOST_CHECK_EQUAL(result.last_block.nNonce, 104U);
    BOOST_CHECK_EQUAL(result.last_pow_digest, DigestForInteger(*target));
    BOOST_CHECK(result.candidates_checked >= 1U);
    BOOST_CHECK(result.candidates_checked <= 6U);
    BOOST_CHECK(std::find(seen.begin(), seen.end(), 104U) != seen.end());
}

BOOST_AUTO_TEST_CASE(genesis_search_stops_other_workers_after_first_solution)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    std::atomic<bool> lower_worker_started{false};
    std::atomic<bool> higher_worker_started{false};
    std::mutex seen_mutex;
    std::vector<uint32_t> seen;
    const auto result{kernel::SearchVaqyronGenesis(
        kernel::GenesisSearchOptions{1791363600, 0, 3, 2},
        consensus,
        [&](const CBlockHeader& header) {
            {
                std::lock_guard lock{seen_mutex};
                seen.push_back(header.nNonce);
            }
            if (header.nNonce == 0) {
                lower_worker_started.store(true);
                const auto deadline{std::chrono::steady_clock::now() + std::chrono::seconds{5}};
                while (!higher_worker_started.load() &&
                       std::chrono::steady_clock::now() < deadline) {
                    std::this_thread::yield();
                }
                if (!higher_worker_started.load()) {
                    throw std::runtime_error{"higher worker did not start"};
                }
                return DigestForInteger(*target + arith_uint256{1});
            }
            if (header.nNonce == 2) {
                const auto deadline{std::chrono::steady_clock::now() + std::chrono::seconds{5}};
                while (!lower_worker_started.load() &&
                       std::chrono::steady_clock::now() < deadline) {
                    std::this_thread::yield();
                }
                if (!lower_worker_started.load()) {
                    throw std::runtime_error{"lower worker did not start"};
                }
                higher_worker_started.store(true);
                return DigestForInteger(*target);
            }
            return DigestForInteger(*target + arith_uint256{1});
        })};

    std::sort(seen.begin(), seen.end());
    BOOST_CHECK(result.found);
    BOOST_CHECK_EQUAL(result.nonce, 2U);
    BOOST_CHECK(std::find(seen.begin(), seen.end(), 0U) != seen.end());
    BOOST_CHECK(std::find(seen.begin(), seen.end(), 2U) != seen.end());
    BOOST_CHECK(std::find(seen.begin(), seen.end(), 3U) == seen.end());
    BOOST_CHECK(seen.size() <= 3U);
    BOOST_CHECK_EQUAL(result.candidates_checked, seen.size());
}

BOOST_AUTO_TEST_CASE(genesis_search_reports_lowest_discovered_candidate_deterministically)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    std::mutex barrier_mutex;
    std::condition_variable barrier;
    unsigned int workers_at_barrier{0};
    const auto result{kernel::SearchVaqyronGenesis(
        kernel::GenesisSearchOptions{1791363600, 0, 3, 2},
        consensus,
        [&](const CBlockHeader& header) {
            std::unique_lock lock{barrier_mutex};
            ++workers_at_barrier;
            barrier.notify_all();
            if (!barrier.wait_for(lock, std::chrono::seconds{5}, [&] {
                    return workers_at_barrier == 2;
                })) {
                throw std::runtime_error{"parallel candidate barrier timed out"};
            }
            return DigestForInteger(*target);
        })};

    BOOST_CHECK(result.found);
    BOOST_CHECK_EQUAL(result.nonce, 0U);
    BOOST_CHECK_EQUAL(result.last_block.nNonce, 0U);
    BOOST_CHECK_EQUAL(result.candidates_checked, 2U);
}

BOOST_AUTO_TEST_CASE(genesis_search_resume_start_never_skips_an_uncertain_checkpoint)
{
    const auto unknown{kernel::GenesisSearchResumeStart(std::nullopt)};
    const auto known{kernel::GenesisSearchResumeStart(541695U)};
    const auto exhausted{kernel::GenesisSearchResumeStart(
        std::numeric_limits<uint32_t>::max())};

    BOOST_REQUIRE(unknown);
    BOOST_CHECK_EQUAL(*unknown, 0U);
    BOOST_REQUIRE(known);
    BOOST_CHECK_EQUAL(*known, 541696U);
    BOOST_CHECK(!exhausted);
}

BOOST_AUTO_TEST_CASE(genesis_search_checkpoint_rejects_concurrent_owner_and_releases_after_exit)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    kernel::GenesisSearchOptions options{1791363600, 490, 490, 1};
    options.checkpoint_path = fs::PathToString(m_path_root / "ownership-checkpoint");

    std::mutex mutex;
    std::condition_variable condition;
    bool digest_started{false};
    bool release_digest{false};
    std::exception_ptr owner_error;
    std::thread owner{[&] {
        try {
            kernel::SearchVaqyronGenesis(options, consensus, [&](const CBlockHeader&) {
                std::unique_lock lock{mutex};
                digest_started = true;
                condition.notify_all();
                condition.wait(lock, [&] { return release_digest; });
                return DigestForInteger(*target + arith_uint256{1});
            });
        } catch (...) {
            owner_error = std::current_exception();
        }
    }};

    bool entered_digest{false};
    {
        std::unique_lock lock{mutex};
        entered_digest = condition.wait_for(
            lock, std::chrono::seconds{5}, [&] { return digest_started; });
    }
    if (!entered_digest) {
        {
            std::lock_guard lock{mutex};
            release_digest = true;
        }
        condition.notify_all();
        owner.join();
        BOOST_FAIL("checkpoint owner did not enter the digest function");
    }

    unsigned int competing_digest_calls{0};
    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            options,
            consensus,
            [&](const CBlockHeader&) {
                ++competing_digest_calls;
                return DigestForInteger(*target + arith_uint256{1});
            }),
        std::runtime_error);
    BOOST_CHECK_EQUAL(competing_digest_calls, 0U);

    {
        std::lock_guard lock{mutex};
        release_digest = true;
    }
    condition.notify_all();
    owner.join();
    BOOST_CHECK(!owner_error);

    unsigned int resumed_digest_calls{0};
    const auto result{kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader&) {
            ++resumed_digest_calls;
            return DigestForInteger(*target + arith_uint256{1});
        })};
    BOOST_CHECK(!result.found);
    BOOST_CHECK_EQUAL(resumed_digest_calls, 0U);
}

BOOST_AUTO_TEST_CASE(genesis_search_checkpoint_resumes_completed_search_without_rechecking)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    kernel::GenesisSearchOptions options{1791363600, 500, 503, 1};
    options.checkpoint_path = fs::PathToString(m_path_root / "resume-checkpoint");

    const auto first_result{kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader&) { return DigestForInteger(*target + arith_uint256{1}); })};
    BOOST_CHECK(!first_result.found);
    BOOST_CHECK_EQUAL(first_result.candidates_checked, 4U);

    unsigned int digest_calls{0};
    const auto resumed_result{kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader&) {
            ++digest_calls;
            return DigestForInteger(*target + arith_uint256{1});
        })};
    BOOST_CHECK(!resumed_result.found);
    BOOST_CHECK_EQUAL(resumed_result.candidates_checked, 0U);
    BOOST_CHECK_EQUAL(digest_calls, 0U);
    BOOST_CHECK_EQUAL(resumed_result.last_block.nNonce, options.end_nonce);
    BOOST_CHECK_EQUAL(
        resumed_result.last_pow_digest,
        DigestForInteger(*target + arith_uint256{1}));
}

BOOST_AUTO_TEST_CASE(genesis_search_checkpoint_persists_and_reverifies_found_candidate_on_restart)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    kernel::GenesisSearchOptions options{1791363600, 600, 603, 2};
    options.checkpoint_path = fs::PathToString(m_path_root / "found-checkpoint");
    constexpr uint32_t winning_nonce{602};

    const auto initial_result{SaveFoundCheckpoint(options, consensus, *target, winning_nonce)};
    BOOST_REQUIRE(initial_result.found);
    BOOST_CHECK_EQUAL(initial_result.nonce, winning_nonce);
    BOOST_CHECK_EQUAL(initial_result.last_pow_digest, DigestForInteger(*target));

    unsigned int invalid_verification_calls{0};
    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            options,
            consensus,
            [&](const CBlockHeader& header) {
                ++invalid_verification_calls;
                BOOST_CHECK_EQUAL(header.nNonce, winning_nonce);
                return DigestForInteger(*target + arith_uint256{1});
            }),
        std::runtime_error);
    BOOST_CHECK_EQUAL(invalid_verification_calls, 1U);

    unsigned int verification_calls{0};
    const auto resumed_result{kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader& header) {
            ++verification_calls;
            BOOST_CHECK_EQUAL(header.nNonce, winning_nonce);
            return DigestForInteger(*target);
        })};
    BOOST_CHECK(resumed_result.found);
    BOOST_CHECK_EQUAL(resumed_result.nonce, winning_nonce);
    BOOST_CHECK_EQUAL(resumed_result.last_block.GetHash(), initial_result.last_block.GetHash());
    BOOST_CHECK_EQUAL(resumed_result.last_pow_digest, initial_result.last_pow_digest);
    BOOST_CHECK_EQUAL(verification_calls, 1U);
    BOOST_CHECK_EQUAL(resumed_result.candidates_checked, 0U);
}

BOOST_AUTO_TEST_CASE(genesis_search_rejects_corrupt_found_checkpoint)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    kernel::GenesisSearchOptions options{1791363600, 610, 610, 1};
    const fs::path checkpoint_path{m_path_root / "corrupt-found-checkpoint"};
    options.checkpoint_path = fs::PathToString(checkpoint_path);

    const auto initial_result{SaveFoundCheckpoint(options, consensus, *target, options.start_nonce)};
    BOOST_REQUIRE(initial_result.found);

    std::fstream checkpoint_file{checkpoint_path, std::ios::in | std::ios::out | std::ios::binary};
    BOOST_REQUIRE(checkpoint_file.good());
    const char corrupted_byte{'\0'};
    checkpoint_file.seekp(0);
    checkpoint_file.write(&corrupted_byte, 1);
    checkpoint_file.close();

    unsigned int verification_calls{0};
    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            options,
            consensus,
            [&](const CBlockHeader&) {
                ++verification_calls;
                return DigestForInteger(*target);
            }),
        std::runtime_error);
    BOOST_CHECK_EQUAL(verification_calls, 0U);
}

BOOST_AUTO_TEST_CASE(genesis_search_rejects_incompatible_found_checkpoint_version)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    kernel::GenesisSearchOptions options{1791363600, 620, 620, 1};
    const fs::path checkpoint_path{m_path_root / "incompatible-found-checkpoint"};
    options.checkpoint_path = fs::PathToString(checkpoint_path);

    const auto initial_result{SaveFoundCheckpoint(options, consensus, *target, options.start_nonce)};
    BOOST_REQUIRE(initial_result.found);

    std::ifstream input{checkpoint_path, std::ios::binary};
    BOOST_REQUIRE(input.good());
    std::string contents{
        std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    input.close();
    constexpr size_t CHECKSUM_SIZE{uint256::size()};
    BOOST_REQUIRE(contents.size() > CHECKSUM_SIZE + 8);
    contents[4] = 0x7f;
    contents[5] = 0;
    contents[6] = 0;
    contents[7] = 0;

    const size_t payload_size{contents.size() - CHECKSUM_SIZE};
    HashWriter checksum_writer;
    checksum_writer.write(std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(contents.data()), payload_size});
    const uint256 checksum{checksum_writer.GetHash()};
    std::copy(
        checksum.begin(), checksum.end(),
        reinterpret_cast<unsigned char*>(contents.data() + payload_size));
    std::ofstream output{checkpoint_path, std::ios::binary | std::ios::trunc};
    BOOST_REQUIRE(output.good());
    output.write(contents.data(), contents.size());
    output.close();
    BOOST_REQUIRE(output.good());

    unsigned int verification_calls{0};
    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            options,
            consensus,
            [&](const CBlockHeader&) {
                ++verification_calls;
                return DigestForInteger(*target);
            }),
        std::runtime_error);
    BOOST_CHECK_EQUAL(verification_calls, 0U);
}

BOOST_AUTO_TEST_CASE(genesis_search_rejects_mismatched_found_checkpoint_configuration)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    kernel::GenesisSearchOptions options{1791363600, 630, 631, 1};
    options.checkpoint_path = fs::PathToString(m_path_root / "mismatched-found-checkpoint");
    const auto initial_result{SaveFoundCheckpoint(options, consensus, *target, options.start_nonce)};
    BOOST_REQUIRE(initial_result.found);

    ++options.end_nonce;
    unsigned int verification_calls{0};
    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            options,
            consensus,
            [&](const CBlockHeader&) {
                ++verification_calls;
                return DigestForInteger(*target);
            }),
        std::runtime_error);
    BOOST_CHECK_EQUAL(verification_calls, 0U);
}

BOOST_AUTO_TEST_CASE(genesis_search_checkpoint_recovers_interrupted_worker_without_skipping_nonce)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    kernel::GenesisSearchOptions options{1791363600, 50, 53, 1};
    options.checkpoint_path = fs::PathToString(m_path_root / "interrupted-checkpoint");

    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            options,
            consensus,
            [&](const CBlockHeader& header) {
                if (header.nNonce == 52) throw std::runtime_error{"simulated interruption"};
                return DigestForInteger(*target + arith_uint256{1});
            }),
        std::runtime_error);

    std::vector<uint32_t> resumed_nonces;
    const auto result{kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader& header) {
            resumed_nonces.push_back(header.nNonce);
            return DigestForInteger(*target + arith_uint256{1});
        })};
    BOOST_CHECK(!result.found);
    BOOST_REQUIRE_EQUAL(resumed_nonces.size(), 2U);
    BOOST_CHECK_EQUAL(resumed_nonces[0], 52U);
    BOOST_CHECK_EQUAL(resumed_nonces[1], 53U);
}

BOOST_AUTO_TEST_CASE(genesis_search_rejects_corrupt_checkpoint_before_starting_workers)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    kernel::GenesisSearchOptions options{1791363600, 70, 71, 1};
    const fs::path checkpoint_path{m_path_root / "corrupt-checkpoint"};
    options.checkpoint_path = fs::PathToString(checkpoint_path);
    kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader&) { return DigestForInteger(*target + arith_uint256{1}); });

    std::fstream checkpoint_file{checkpoint_path, std::ios::in | std::ios::out | std::ios::binary};
    BOOST_REQUIRE(checkpoint_file.good());
    const char corrupted_byte{'\0'};
    checkpoint_file.seekp(0);
    checkpoint_file.write(&corrupted_byte, 1);
    checkpoint_file.close();

    unsigned int digest_calls{0};
    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            options,
            consensus,
            [&](const CBlockHeader&) {
                ++digest_calls;
                return DigestForInteger(*target + arith_uint256{1});
            }),
        std::runtime_error);
    BOOST_CHECK_EQUAL(digest_calls, 0U);
}

BOOST_AUTO_TEST_CASE(genesis_search_rejects_mismatched_checkpoint_configuration)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    kernel::GenesisSearchOptions options{1791363600, 80, 83, 2};
    options.checkpoint_path = fs::PathToString(m_path_root / "mismatch-checkpoint");
    kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader&) { return DigestForInteger(*target + arith_uint256{1}); });

    ++options.time;
    unsigned int digest_calls{0};
    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            options,
            consensus,
            [&](const CBlockHeader&) {
                ++digest_calls;
                return DigestForInteger(*target + arith_uint256{1});
            }),
        std::runtime_error);
    BOOST_CHECK_EQUAL(digest_calls, 0U);
}

BOOST_AUTO_TEST_CASE(genesis_search_checkpoint_resume_handles_uint32_max_boundary)
{
    const auto consensus{MainConsensus(*m_node.args)};
    const auto target{DeriveTarget(kernel::VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(target);
    const uint32_t max_nonce{std::numeric_limits<uint32_t>::max()};
    kernel::GenesisSearchOptions options{1791363600, max_nonce - 1, max_nonce, 1};
    options.checkpoint_path = fs::PathToString(m_path_root / "boundary-checkpoint");

    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            options,
            consensus,
            [&](const CBlockHeader& header) {
                if (header.nNonce == max_nonce) throw std::runtime_error{"simulated interruption"};
                return DigestForInteger(*target + arith_uint256{1});
            }),
        std::runtime_error);

    std::vector<uint32_t> resumed_nonces;
    const auto result{kernel::SearchVaqyronGenesis(
        options,
        consensus,
        [&](const CBlockHeader& header) {
            resumed_nonces.push_back(header.nNonce);
            return DigestForInteger(*target + arith_uint256{1});
        })};
    BOOST_CHECK(!result.found);
    BOOST_REQUIRE_EQUAL(resumed_nonces.size(), 1U);
    BOOST_CHECK_EQUAL(resumed_nonces.front(), max_nonce);
    BOOST_CHECK_EQUAL(result.last_block.nNonce, max_nonce);
}

BOOST_AUTO_TEST_CASE(genesis_search_rejects_invalid_target_before_starting_workers)
{
    Consensus::Params invalid_consensus{};
    std::atomic<unsigned int> digest_calls{0};
    BOOST_CHECK_THROW(
        kernel::SearchVaqyronGenesis(
            kernel::GenesisSearchOptions{1791363600, 0, 3, 4},
            invalid_consensus,
            [&](const CBlockHeader&) {
                ++digest_calls;
                return uint256{};
            }),
        std::invalid_argument);
    BOOST_CHECK_EQUAL(digest_calls.load(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
