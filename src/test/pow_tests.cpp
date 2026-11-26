// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <asert.h>
#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <pow_internal.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <exception>
#include <span>
#include <stdexcept>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(frozen_vaqyron_yespower_digest_kats)
{
    struct TestVector {
        const char* header_hex;
        const char* block_id;
        const char* pow_digest;
    };
    static constexpr TestVector vectors[]{
        {
            "040000001f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01f15365ffff7f1c2a000000",
            "56389990d677bf2487915edefb7eb64e8093f54bed2fe57aeda6f9b7bea2788d",
            "a2358778eec38c3cea83dab72d3bc6187c07451d56971c33d8ef833b2c6e3c5a",
        },
        {
            "050000003f3e3d3c3b3a393837363534333231302f2e2d2c2b2a2928272625242322212055555555555555555555555555555555555555555555555555555555555555557bf15365ffff7f1c63000000",
            "ad1deacfc5f90f0e37dd94b6ad9c691b8598ca594bd64395e33b5116cf3acb1c",
            "30736e42eac69d2a67a54d20ec62f933a60b4a10acb518439a04bd2e66b1d6a6",
        },
    };

    for (const auto& test : vectors) {
        const auto header_bytes{ParseHex(test.header_hex)};
        BOOST_REQUIRE_EQUAL(header_bytes.size(), 80);

        CBlockHeader header;
        SpanReader{header_bytes} >> header;

        std::vector<unsigned char> serialized_header;
        VectorWriter{serialized_header, 0, header};
        BOOST_REQUIRE_EQUAL(serialized_header.size(), 80);
        BOOST_CHECK_EQUAL(HexStr(serialized_header), test.header_hex);
        BOOST_CHECK_EQUAL(header.GetHash().GetHex(), test.block_id);

        const uint256 pow_digest{GetPoWDigest(header)};
        const std::vector<unsigned char> pow_digest_bytes{pow_digest.begin(), pow_digest.end()};
        BOOST_CHECK_EQUAL(HexStr(pow_digest_bytes), test.pow_digest);
        BOOST_CHECK(pow_digest != header.GetHash());
    }
}

BOOST_AUTO_TEST_CASE(yespower_repeated_hashing_preserves_digest)
{
    const auto header_bytes{ParseHex("040000001f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01f15365ffff7f1c2a000000")};
    CBlockHeader header;
    SpanReader{header_bytes} >> header;

    const uint256 first_digest{GetPoWDigest(header)};
    const uint256 second_digest{GetPoWDigest(header)};
    const std::vector<unsigned char> first_digest_bytes{first_digest.begin(), first_digest.end()};

    BOOST_CHECK_EQUAL(HexStr(first_digest_bytes), "a2358778eec38c3cea83dab72d3bc6187c07451d56971c33d8ef833b2c6e3c5a");
    BOOST_CHECK_EQUAL(second_digest, first_digest);
}

BOOST_AUTO_TEST_CASE(yespower_short_lived_thread_digest_matches)
{
    const auto header_bytes{ParseHex("040000001f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01f15365ffff7f1c2a000000")};
    CBlockHeader header;
    SpanReader{header_bytes} >> header;
    uint256 worker_digest;
    std::exception_ptr worker_exception;

    std::thread worker{[&] {
        try {
            worker_digest = GetPoWDigest(header);
        } catch (...) {
            worker_exception = std::current_exception();
        }
    }};
    worker.join();

    BOOST_REQUIRE(!worker_exception);
    const std::vector<unsigned char> worker_digest_bytes{worker_digest.begin(), worker_digest.end()};
    BOOST_CHECK_EQUAL(HexStr(worker_digest_bytes), "a2358778eec38c3cea83dab72d3bc6187c07451d56971c33d8ef833b2c6e3c5a");
}

BOOST_AUTO_TEST_CASE(yespower_target_first_validation)
{
    const auto chain_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& consensus{chain_params->GetConsensus()};
    CBlockHeader header;
    unsigned int pow_calls{0};
    const auto counted_digest = [&pow_calls](const CBlockHeader&) {
        ++pow_calls;
        return uint256{42};
    };

    const auto expect_no_pow = [&](uint32_t nbits) {
        header.nBits = nbits;
        pow_calls = 0;
        BOOST_CHECK(!pow_internal::CheckProofOfWorkYespowerWithDigest(header, consensus, counted_digest));
        BOOST_CHECK_EQUAL(pow_calls, 0);
    };

    expect_no_pow(arith_uint256{42}.GetCompact(true));
    expect_no_pow(0);
    expect_no_pow(~0x00800000U);

    arith_uint256 above_pow_limit{UintToArith256(consensus.powLimit)};
    above_pow_limit *= 2;
    expect_no_pow(above_pow_limit.GetCompact());

    header.nBits = arith_uint256{43}.GetCompact();
    pow_calls = 0;
    BOOST_CHECK(pow_internal::CheckProofOfWorkYespowerWithDigest(header, consensus, counted_digest));
    BOOST_CHECK_EQUAL(pow_calls, 1);

    header.nBits = arith_uint256{42}.GetCompact();
    pow_calls = 0;
    BOOST_CHECK(pow_internal::CheckProofOfWorkYespowerWithDigest(header, consensus, counted_digest));
    BOOST_CHECK_EQUAL(pow_calls, 1);

    header.nBits = arith_uint256{41}.GetCompact();
    pow_calls = 0;
    BOOST_CHECK(!pow_internal::CheckProofOfWorkYespowerWithDigest(header, consensus, counted_digest));
    BOOST_CHECK_EQUAL(pow_calls, 1);

    std::array<unsigned char, 32> raw_digest{};
    raw_digest[0] = 0x2a;
    raw_digest[31] = 0x01;
    const uint256 candidate_a_digest{std::span<const unsigned char>{raw_digest}};
    arith_uint256 expected_candidate_a{1};
    expected_candidate_a <<= 248;
    expected_candidate_a += 42;
    BOOST_CHECK_EQUAL(UintToArith256(candidate_a_digest), expected_candidate_a);

    header.nBits = arith_uint256{43}.GetCompact();
    pow_calls = 0;
    const auto failing_digest = [&pow_calls](const CBlockHeader&) -> uint256 {
        ++pow_calls;
        throw std::runtime_error{"test PoW failure"};
    };
    BOOST_CHECK_THROW(
        pow_internal::CheckProofOfWorkYespowerWithDigest(header, consensus, failing_digest),
        std::runtime_error);
    BOOST_CHECK_EQUAL(pow_calls, 1);
}

BOOST_AUTO_TEST_CASE(main_header_pow_dispatch_preserves_legacy_networks)
{
    const auto main_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto regtest_params{CreateChainParams(*m_node.args, ChainType::REGTEST)};
    BOOST_REQUIRE(main_params->GetConsensus().fPowUseYespower);
    BOOST_CHECK(!regtest_params->GetConsensus().fPowUseYespower);

    const auto header_bytes{ParseHex("040000001f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01f15365ffff7f1c2a000000")};
    CBlockHeader header;
    SpanReader{header_bytes} >> header;

    BOOST_CHECK(!CheckProofOfWork(header, main_params->GetConsensus()));
    BOOST_CHECK(!CheckProofOfWork(header.GetHash(), header.nBits, main_params->GetConsensus()));

    unsigned int yespower_calls{0};
    const auto controlled_yespower = [&yespower_calls](const CBlockHeader& candidate, const Consensus::Params& consensus) {
        return pow_internal::CheckProofOfWorkYespowerWithDigest(candidate, consensus, [&yespower_calls](const CBlockHeader&) {
            ++yespower_calls;
            return uint256{};
        });
    };
    // Force the PoW result valid to isolate whether MAIN dispatches to yespower.
    BOOST_CHECK(pow_internal::CheckProofOfWorkHeaderWithYespower(header, main_params->GetConsensus(), controlled_yespower));
    BOOST_CHECK_EQUAL(yespower_calls, 1);

    const auto failed_yespower = [&yespower_calls](const CBlockHeader&, const Consensus::Params&) -> bool {
        ++yespower_calls;
        throw std::runtime_error{"test yespower runtime failure"};
    };
    BOOST_CHECK_THROW(
        pow_internal::CheckProofOfWorkHeaderWithYespower(header, main_params->GetConsensus(), failed_yespower),
        std::runtime_error);
    BOOST_CHECK_EQUAL(yespower_calls, 2);

    header.nBits = regtest_params->GenesisBlock().nBits;
    const bool legacy_result{CheckProofOfWork(header.GetHash(), header.nBits, regtest_params->GetConsensus())};
    BOOST_CHECK_EQUAL(pow_internal::CheckProofOfWorkHeaderWithYespower(header, regtest_params->GetConsensus(), controlled_yespower), legacy_result);
    BOOST_CHECK_EQUAL(yespower_calls, 2);
}

BOOST_AUTO_TEST_CASE(main_mining_candidate_uses_one_target_first_yespower_check)
{
    const auto main_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& consensus{main_params->GetConsensus()};
    CBlockHeader header;
    unsigned int yespower_calls{0};
    arith_uint256 above_pow_limit{UintToArith256(consensus.powLimit)};
    above_pow_limit *= 2;

    const auto candidate_check = [&](const CBlockHeader& candidate, const Consensus::Params& params) {
        return pow_internal::CheckProofOfWorkYespowerWithDigest(candidate, params, [&](const CBlockHeader&) {
            ++yespower_calls;
            return uint256{42};
        });
    };

    for (const uint32_t invalid_nbits : {
             0U,
             UintToArith256(consensus.powLimit).GetCompact(true),
             ~0x00800000U,
             above_pow_limit.GetCompact(),
         }) {
        header.nBits = invalid_nbits;
        BOOST_CHECK(!pow_internal::CheckProofOfWorkHeaderWithYespower(
            header, consensus, candidate_check));
        BOOST_CHECK_EQUAL(yespower_calls, 0);
    }

    header.nBits = arith_uint256{42}.GetCompact();
    BOOST_CHECK(pow_internal::CheckProofOfWorkHeaderWithYespower(header, consensus, candidate_check));
    BOOST_CHECK_EQUAL(yespower_calls, 1);

    header.nBits = arith_uint256{41}.GetCompact();
    BOOST_CHECK(!pow_internal::CheckProofOfWorkHeaderWithYespower(header, consensus, candidate_check));
    BOOST_CHECK_EQUAL(yespower_calls, 2);

    header.nBits = 0;
    BOOST_CHECK(!pow_internal::CheckProofOfWorkHeaderWithYespower(header, consensus, candidate_check));
    BOOST_CHECK_EQUAL(yespower_calls, 2);
}

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::TESTNET);
    const auto signetParams = CreateChainParams(*m_node.args, ChainType::SIGNET);
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1d00ffff;

    // Here (and below): expected_nbits is calculated in
    // CalculateNextWorkRequired(); redoing the calculation here would be just
    // reimplementing the same code that is written in pow.cpp. Rather than
    // copy that code, we just hardcode the expected result.
    unsigned int expected_nbits = 0x1d00d86aU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(signetParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::TESTNET);
    const auto signetParams = CreateChainParams(*m_node.args, ChainType::SIGNET);
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = 0x1d00ffff;
    unsigned int expected_nbits = 0x1d00ffffU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(signetParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::TESTNET);
    const auto signetParams = CreateChainParams(*m_node.args, ChainType::SIGNET);
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68543;
    pindexLast.nTime = 1279297671;  // Block #68543
    pindexLast.nBits = 0x1c05a3f4;
    unsigned int expected_nbits = 0x1c0168fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(signetParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that reducing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits-1;
    BOOST_CHECK(!PermittedDifficultyTransition(signetParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::TESTNET);
    const auto signetParams = CreateChainParams(*m_node.args, ChainType::SIGNET);
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46367;
    pindexLast.nTime = 1269211443;  // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    unsigned int expected_nbits = 0x1d00e1fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(signetParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that increasing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits+1;
    BOOST_CHECK(!PermittedDifficultyTransition(signetParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

BOOST_AUTO_TEST_CASE(main_asert_genesis_reference)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();
    const auto& genesis = chainParams->GenesisBlock();

    CBlockIndex block0;
    block0.nHeight = 0;
    block0.nTime = genesis.GetBlockTime();
    block0.nBits = genesis.nBits;

    arith_uint256 reference_target;
    reference_target.SetCompact(genesis.nBits);
    const arith_uint256 pow_limit{UintToArith256(consensus.powLimit)};
    const int64_t virtual_parent_time{genesis.GetBlockTime() - consensus.nPowTargetSpacing};

    CBlockHeader candidate;
    candidate.nTime = genesis.GetBlockTime() + consensus.nPowTargetSpacing;

    const arith_uint256 block1_target{CalculateASERT(
        reference_target, consensus.nPowTargetSpacing,
        block0.GetBlockTime() - virtual_parent_time, block0.nHeight,
        pow_limit, consensus.nASERTHalfLife)};
    BOOST_CHECK_EQUAL(block1_target.GetCompact(), genesis.nBits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&block0, &candidate, consensus), block1_target.GetCompact());

    CBlockIndex block1;
    block1.pprev = &block0;
    block1.nHeight = 1;
    block1.nTime = genesis.GetBlockTime() + consensus.nPowTargetSpacing;
    block1.nBits = GetNextWorkRequired(&block0, &candidate, consensus);
    candidate.nTime = block1.nTime + consensus.nPowTargetSpacing;

    const arith_uint256 block2_target{CalculateASERT(
        reference_target, consensus.nPowTargetSpacing,
        block1.GetBlockTime() - virtual_parent_time, block1.nHeight,
        pow_limit, consensus.nASERTHalfLife)};
    BOOST_CHECK_EQUAL(block2_target.GetCompact(), genesis.nBits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&block1, &candidate, consensus), block2_target.GetCompact());

    CBlockIndex block2;
    block2.pprev = &block1;
    block2.nHeight = 2;
    block2.nTime = block1.nTime + consensus.nPowTargetSpacing;
    block2.nBits = block2_target.GetCompact();
    candidate.nTime = block2.nTime + consensus.nPowTargetSpacing;

    const arith_uint256 block3_target{CalculateASERT(
        reference_target, consensus.nPowTargetSpacing,
        block2.GetBlockTime() - virtual_parent_time, block2.nHeight,
        pow_limit, consensus.nASERTHalfLife)};
    BOOST_CHECK_EQUAL(block3_target.GetCompact(), genesis.nBits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&block2, &candidate, consensus), block3_target.GetCompact());
}

BOOST_AUTO_TEST_CASE(main_asert_delayed_block1)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();
    const auto& genesis = chainParams->GenesisBlock();

    CBlockIndex block0;
    block0.nHeight = 0;
    block0.nTime = genesis.GetBlockTime();
    block0.nBits = genesis.nBits;

    CBlockIndex block1;
    block1.pprev = &block0;
    block1.nHeight = 1;
    block1.nTime = genesis.GetBlockTime() + 10 * 60;
    block1.nBits = genesis.nBits;

    arith_uint256 reference_target;
    reference_target.SetCompact(genesis.nBits);
    const arith_uint256 pow_limit{UintToArith256(consensus.powLimit)};
    const int64_t virtual_parent_time{genesis.GetBlockTime() - consensus.nPowTargetSpacing};
    const arith_uint256 expected_block2_target{CalculateASERT(
        reference_target, consensus.nPowTargetSpacing,
        block1.GetBlockTime() - virtual_parent_time, block1.nHeight,
        pow_limit, consensus.nASERTHalfLife)};
    BOOST_CHECK_EQUAL(expected_block2_target, pow_limit);

    CBlockHeader candidate;
    candidate.nTime = block1.nTime + consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&block1, &candidate, consensus), expected_block2_target.GetCompact());
    BOOST_CHECK_EQUAL(expected_block2_target.GetCompact(), UintToArith256(consensus.powLimit).GetCompact());

    CBlockIndex block2;
    block2.pprev = &block1;
    block2.nHeight = 2;
    block2.nTime = block1.nTime + consensus.nPowTargetSpacing;
    block2.nBits = expected_block2_target.GetCompact();

    const arith_uint256 expected_block3_target{CalculateASERT(
        reference_target, consensus.nPowTargetSpacing,
        block2.GetBlockTime() - virtual_parent_time, block2.nHeight,
        pow_limit, consensus.nASERTHalfLife)};
    BOOST_CHECK_EQUAL(expected_block3_target, pow_limit);
    candidate.nTime = block2.nTime + consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&block2, &candidate, consensus), expected_block3_target.GetCompact());
}

BOOST_AUTO_TEST_CASE(main_asert_selection_and_legacy_network_isolation)
{
    const auto mainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& mainConsensus = mainParams->GetConsensus();
    BOOST_CHECK(mainConsensus.fPowUseASERT);
    BOOST_CHECK_EQUAL(mainConsensus.nASERTHalfLife, 43200);
    BOOST_CHECK_EQUAL(mainConsensus.nPowTargetSpacing, 150);
    BOOST_CHECK(PermittedDifficultyTransition(mainConsensus, 1, 0x1d00ffff, 0x1c00ffff));
    BOOST_CHECK(PermittedDifficultyTransition(mainConsensus, mainConsensus.DifficultyAdjustmentInterval(),
                                               0x1d00ffff, 0x1c00ffff));

    for (const ChainType chain : {ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        const auto chainParams = CreateChainParams(*m_node.args, chain);
        const auto& consensus = chainParams->GetConsensus();
        BOOST_CHECK(!consensus.fPowUseASERT);
        BOOST_CHECK_EQUAL(consensus.nASERTHalfLife, 0);
        BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 10 * 60);

        CBlockIndex previous;
        previous.nHeight = 1;
        previous.nTime = 1'000'000;
        previous.nBits = 0x1d00ffff;
        CBlockHeader candidate;
        candidate.nTime = previous.nTime + consensus.nPowTargetSpacing;
        BOOST_CHECK_EQUAL(GetNextWorkRequired(&previous, &candidate, consensus), previous.nBits);

        if (!consensus.fPowAllowMinDifficultyBlocks) {
            BOOST_CHECK(!PermittedDifficultyTransition(consensus, 1, previous.nBits, 0x1c00ffff));
        }
    }
}

BOOST_AUTO_TEST_CASE(vaqyron_testnet_selects_yespower_and_legacy_difficulty)
{
    const auto testnet{CreateChainParams(*m_node.args, ChainType::VAQYRON_TESTNET)};
    const auto& consensus{testnet->GetConsensus()};
    BOOST_CHECK(consensus.fPowUseYespower);
    BOOST_CHECK(!consensus.fPowUseASERT);
    BOOST_CHECK_EQUAL(consensus.nASERTHalfLife, 0);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 150);
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan, 86400);
    BOOST_CHECK_EQUAL(consensus.DifficultyAdjustmentInterval(), 576);
    BOOST_CHECK(consensus.fPowAllowMinDifficultyBlocks);
    BOOST_CHECK(consensus.enforce_BIP94);
    BOOST_CHECK(!consensus.fPowNoRetargeting);
    BOOST_CHECK_EQUAL(consensus.nSubsidyHalvingInterval, 1000000);
    BOOST_CHECK_EQUAL(
        consensus.powLimit,
        uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"});

    const auto genesis_target{DeriveTarget(VAQYRON_TESTNET_PROPOSED_GENESIS_NBITS, consensus.powLimit)};
    BOOST_REQUIRE(genesis_target);
    BOOST_CHECK_EQUAL(genesis_target->GetCompact(), VAQYRON_TESTNET_PROPOSED_GENESIS_NBITS);

    CBlockIndex genesis;
    genesis.nHeight = 0;
    genesis.nTime = 1'800'000'000;
    genesis.nBits = VAQYRON_TESTNET_PROPOSED_GENESIS_NBITS;

    CBlockHeader candidate;
    candidate.nTime = genesis.nTime + consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &candidate, consensus), genesis.nBits);

    candidate.nTime = genesis.nTime + 2 * consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &candidate, consensus), genesis.nBits);

    candidate.nTime = genesis.nTime + 2 * consensus.nPowTargetSpacing + 1;
    BOOST_CHECK_EQUAL(
        GetNextWorkRequired(&genesis, &candidate, consensus),
        UintToArith256(consensus.powLimit).GetCompact());

    CBlockIndex min_difficulty_boundary;
    min_difficulty_boundary.nHeight = 1;
    min_difficulty_boundary.nTime = 1'800'000'000;
    min_difficulty_boundary.nBits = 0x207ffffe;
    candidate.nTime = min_difficulty_boundary.nTime + 2 * consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(
        GetNextWorkRequired(&min_difficulty_boundary, &candidate, consensus),
        min_difficulty_boundary.nBits);
    candidate.nTime += 1;
    BOOST_CHECK_EQUAL(
        GetNextWorkRequired(&min_difficulty_boundary, &candidate, consensus),
        UintToArith256(consensus.powLimit).GetCompact());

    CBlockIndex normal_difficulty;
    normal_difficulty.nHeight = 0;
    normal_difficulty.nTime = 1'800'000'000;
    normal_difficulty.nBits = 0x207ffffe;

    CBlockIndex minimum_difficulty;
    minimum_difficulty.pprev = &normal_difficulty;
    minimum_difficulty.nHeight = 1;
    minimum_difficulty.nTime = normal_difficulty.nTime + consensus.nPowTargetSpacing;
    minimum_difficulty.nBits = UintToArith256(consensus.powLimit).GetCompact();

    candidate.nTime = minimum_difficulty.nTime + 2 * consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(
        GetNextWorkRequired(&minimum_difficulty, &candidate, consensus),
        normal_difficulty.nBits);

    std::array<CBlockIndex, 576> retarget_chain;
    const uint32_t period_start_bits{0x20700000};
    for (size_t height{0}; height < retarget_chain.size(); ++height) {
        CBlockIndex& block{retarget_chain[height]};
        block.nHeight = static_cast<int>(height);
        block.nTime = static_cast<uint32_t>(height * (consensus.nPowTargetSpacing / 2));
        block.nBits = height == 0 ? period_start_bits : VAQYRON_TESTNET_PROPOSED_GENESIS_NBITS;
        if (height > 0) block.pprev = &retarget_chain[height - 1];
    }
    retarget_chain.back().nTime = consensus.nPowTargetTimespan / 2;
    candidate.nTime = retarget_chain[retarget_chain.size() - 2].nTime + consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(
        GetNextWorkRequired(&retarget_chain[retarget_chain.size() - 2], &candidate, consensus),
        period_start_bits);

    candidate.nTime = retarget_chain.back().nTime + consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(
        GetNextWorkRequired(&retarget_chain.back(), &candidate, consensus),
        0x20380000U);
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()
    if (!consensus.fPowNoRetargeting) {
        arith_uint256 targ_max{UintToArith256(uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})};
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET4);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

BOOST_AUTO_TEST_SUITE_END()
