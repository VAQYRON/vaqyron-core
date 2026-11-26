// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <headerssync.h>
#include <headerssync_internal.h>
#include <logging.h>
#include <pow.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/logging.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>
#include <vector>

#include <boost/test/unit_test.hpp>

struct HeadersGeneratorSetup : public RegTestingSetup {
    /** Search for a nonce to meet (regtest) proof of work */
    void FindProofOfWork(CBlockHeader& starting_header);
    /**
     * Generate headers in a chain that build off a given starting hash, using
     * the given nVersion, advancing time by 1 second from the starting
     * prev_time, and with a fixed merkle root hash.
     */
    void GenerateHeaders(std::vector<CBlockHeader>& headers, size_t count,
            const uint256& starting_hash, const int nVersion, int prev_time,
            const uint256& merkle_root, const uint32_t nBits);
};

namespace {
class ScopedNetDebugLogging
{
public:
    ScopedNetDebugLogging() :
        m_categories{LogInstance().GetCategoryMask()},
        m_category_levels_before{LogInstance().CategoryLevels()}
    {
        auto category_levels{m_category_levels_before};
        LogInstance().EnableCategory(BCLog::NET);
        category_levels[BCLog::NET] = BCLog::Level::Debug;
        LogInstance().SetCategoryLogLevel(category_levels);
    }

    ~ScopedNetDebugLogging()
    {
        LogInstance().SetCategoryLogLevel(m_category_levels_before);
        LogInstance().DisableCategory(BCLog::LogFlags::ALL);
        LogInstance().EnableCategory(BCLog::LogFlags{m_categories});
    }

private:
    const BCLog::CategoryMask m_categories;
    const std::unordered_map<BCLog::LogFlags, BCLog::Level> m_category_levels_before;
};

class MockTimeReset
{
public:
    ~MockTimeReset() { SetMockTime(0s); }
};

CBlockHeader MainASERTBlock1()
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = uint256{"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"};
    header.hashMerkleRoot = uint256{"0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"};
    header.nTime = 1231469665;
    header.nBits = 0x1d00ffff;
    header.nNonce = 2573394689;
    return header;
}

CBlockHeader MainASERTBlock2()
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = uint256{"00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"};
    header.hashMerkleRoot = uint256{"9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5"};
    header.nTime = 1231469744;
    header.nBits = 0x1d00ffff;
    header.nNonce = 1639830024;
    return header;
}

CBlockHeader MainASERTBlock3()
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = uint256{"000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd"};
    header.hashMerkleRoot = uint256{"999e1c837c76a1b7fbb7e57baf87b309960f5ffefbf2a9b95dd890602272f644"};
    header.nTime = 1231470173;
    header.nBits = 0x1d00ffff;
    header.nNonce = 1844305925;
    return header;
}

void SetBlockIndex(CBlockIndex& index, uint256& hash, CBlockIndex& previous, const CBlockHeader& header)
{
    hash = header.GetHash();
    index.phashBlock = &hash;
    index.pprev = &previous;
    index.nHeight = previous.nHeight + 1;
    index.nVersion = header.nVersion;
    index.hashMerkleRoot = header.hashMerkleRoot;
    index.nTime = header.nTime;
    index.nBits = header.nBits;
    index.nNonce = header.nNonce;
    index.nChainWork = previous.nChainWork + GetBlockProof(CBlockIndex(header));
}

struct MainASERTChain
{
    explicit MainASERTChain(ArgsManager& args) :
        params{CreateChainParams(args, ChainType::MAIN)},
        consensus{params->GetConsensus()}
    {
        // These historical ASERT fixtures contain SHA256d-valid headers.
        consensus.fPowUseYespower = false;
        CBlockHeader genesis_block;
        genesis_block.nVersion = 1;
        genesis_block.hashMerkleRoot = uint256{"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"};
        genesis_block.nTime = 1231006505;
        genesis_block.nBits = 0x1d00ffff;
        genesis_block.nNonce = 2083236893;
        consensus.hashGenesisBlock = genesis_block.GetHash();
        genesis_hash = genesis_block.GetHash();
        genesis.phashBlock = &genesis_hash;
        genesis.nHeight = 0;
        genesis.nVersion = genesis_block.nVersion;
        genesis.hashMerkleRoot = genesis_block.hashMerkleRoot;
        genesis.nTime = genesis_block.nTime;
        genesis.nBits = genesis_block.nBits;
        genesis.nNonce = genesis_block.nNonce;
    }

    std::unique_ptr<const CChainParams> params;
    Consensus::Params consensus;
    uint256 genesis_hash;
    CBlockIndex genesis;
};
} // namespace

void HeadersGeneratorSetup::FindProofOfWork(CBlockHeader& starting_header)
{
    while (!CheckProofOfWork(starting_header, Params().GetConsensus())) {
        ++(starting_header.nNonce);
    }
}

void HeadersGeneratorSetup::GenerateHeaders(std::vector<CBlockHeader>& headers,
        size_t count, const uint256& starting_hash, const int nVersion, int prev_time,
        const uint256& merkle_root, const uint32_t nBits)
{
    uint256 prev_hash = starting_hash;

    while (headers.size() < count) {
        headers.emplace_back();
        CBlockHeader& next_header = headers.back();;
        next_header.nVersion = nVersion;
        next_header.hashPrevBlock = prev_hash;
        next_header.hashMerkleRoot = merkle_root;
        next_header.nTime = prev_time+1;
        next_header.nBits = nBits;

        FindProofOfWork(next_header);
        prev_hash = next_header.GetHash();
        prev_time = next_header.nTime;
    }
    return;
}

BOOST_FIXTURE_TEST_SUITE(headers_sync_chainwork_tests, HeadersGeneratorSetup)

// In this test, we construct two sets of headers from genesis, one with
// sufficient proof of work and one without.
// 1. We deliver the first set of headers and verify that the headers sync state
//    updates to the REDOWNLOAD phase successfully.
// 2. Then we deliver the second set of headers and verify that they fail
//    processing (presumably due to commitments not matching).
// 3. Finally, we verify that repeating with the first set of headers in both
//    phases is successful.
BOOST_AUTO_TEST_CASE(headers_sync_state)
{
    BOOST_CHECK(!Params().GetConsensus().fPowUseASERT);
    std::vector<CBlockHeader> first_chain;
    std::vector<CBlockHeader> second_chain;

    std::unique_ptr<HeadersSyncState> hss;

    const int target_blocks = 15000;
    arith_uint256 chain_work = target_blocks*2;

    // Generate headers for two different chains (using differing merkle roots
    // to ensure the headers are different).
    GenerateHeaders(first_chain, target_blocks-1, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(0), Params().GenesisBlock().nBits);

    GenerateHeaders(second_chain, target_blocks-2, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(1), Params().GenesisBlock().nBits);

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    std::vector<CBlockHeader> headers_batch;

    // Feed the first chain to HeadersSyncState, by delivering 1 header
    // initially and then the rest.
    headers_batch.insert(headers_batch.end(), std::next(first_chain.begin()), first_chain.end());

    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders({first_chain.front()}, true);
    // Pretend the first header is still "full", so we don't abort.
    auto result = hss->ProcessNextHeaders(headers_batch, true);

    // This chain should look valid, and we should have met the proof-of-work
    // requirement.
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Try to sneakily feed back the second chain.
    result = hss->ProcessNextHeaders(second_chain, true);
    BOOST_CHECK(!result.success); // foiled!
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Now try again, this time feeding the first chain twice.
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    // All headers should be ready for acceptance:
    BOOST_CHECK(result.pow_validated_headers.size() == first_chain.size());
    // Nothing left for the sync logic to do:
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Finally, verify that just trying to process the second chain would not
    // succeed (too little work)
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);
     // Pretend just the first message is "full", so we don't abort.
    (void)hss->ProcessNextHeaders({second_chain.front()}, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);

    headers_batch.clear();
    headers_batch.insert(headers_batch.end(), std::next(second_chain.begin(), 1), second_chain.end());
    // Tell the sync logic that the headers message was not full, implying no
    // more headers can be requested. For a low-work-chain, this should causes
    // the sync to end with no headers for acceptance.
    result = hss->ProcessNextHeaders(headers_batch, false);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(!result.request_more);
    // Nevertheless, no validation errors should have been detected with the
    // chain:
    BOOST_CHECK(result.success);
}

BOOST_AUTO_TEST_CASE(main_asert_presync_valid_sequence)
{
    MainASERTChain main_chain{*m_node.args};
    const auto& consensus{main_chain.consensus};

    CBlockHeader header1{MainASERTBlock1()};
    BOOST_CHECK_EQUAL(header1.GetHash().GetHex(), "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048");
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&main_chain.genesis, &header1, consensus), header1.nBits);
    CBlockIndex block1;
    uint256 block1_hash;
    SetBlockIndex(block1, block1_hash, main_chain.genesis, header1);

    CBlockHeader header2{MainASERTBlock2()};
    BOOST_CHECK_EQUAL(header2.GetHash().GetHex(), "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd");
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&block1, &header2, consensus), header2.nBits);
    CBlockIndex block2;
    uint256 block2_hash;
    SetBlockIndex(block2, block2_hash, block1, header2);

    CBlockHeader header3{MainASERTBlock3()};
    BOOST_CHECK_EQUAL(header3.GetHash().GetHex(), "0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449");
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&block2, &header3, consensus), header3.nBits);
    const arith_uint256 initial_work{main_chain.genesis.nChainWork};
    HeadersSyncState sync{0, consensus, &main_chain.genesis, arith_uint256{1} << 255};
    const auto result{sync.ProcessNextHeaders({header1, header2, header3}, true)};

    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(sync.GetState() == HeadersSyncState::State::PRESYNC);
    BOOST_CHECK_EQUAL(sync.GetPresyncHeight(), 3);
    BOOST_CHECK(sync.GetPresyncWork() > initial_work);
}

BOOST_AUTO_TEST_CASE(main_asert_presync_uses_yespower_after_expected_target)
{
    MockTimeReset mock_time_reset;
    const auto chain_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    Consensus::Params consensus{chain_params->GetConsensus()};
    BOOST_REQUIRE(consensus.fPowUseYespower);
    BOOST_CHECK(consensus.fPowUseASERT);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 150);
    BOOST_CHECK_EQUAL(consensus.nASERTHalfLife, 43200);

    const auto header_bytes{ParseHex("040000001f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01f15365ffff7f1c2a000000")};
    CBlockHeader header;
    SpanReader{header_bytes} >> header;

    BOOST_CHECK_EQUAL(header.GetHash().GetHex(), "56389990d677bf2487915edefb7eb64e8093f54bed2fe57aeda6f9b7bea2788d");
    BOOST_CHECK(!CheckProofOfWork(header.GetHash(), header.nBits, consensus));

    unsigned int pow_calls{0};
    BOOST_CHECK(!headerssync_internal::CheckExpectedTargetAndWork(header, header.nBits - 1, [&](const CBlockHeader&) {
        ++pow_calls;
        return true;
    }));
    BOOST_CHECK_EQUAL(pow_calls, 0);
    BOOST_CHECK(headerssync_internal::CheckExpectedTargetAndWork(header, header.nBits, [&](const CBlockHeader&) {
        ++pow_calls;
        return true;
    }));
    BOOST_CHECK_EQUAL(pow_calls, 1);

    consensus.hashGenesisBlock = header.hashPrevBlock;
    CBlockIndex genesis;
    genesis.phashBlock = &consensus.hashGenesisBlock;
    genesis.nHeight = 0;
    genesis.nTime = header.nTime - consensus.nPowTargetSpacing;
    genesis.nBits = header.nBits;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &header, consensus), header.nBits);
    SetMockTime(header.nTime + 60 * 60);

    HeadersSyncState sync{0, consensus, &genesis, arith_uint256{1} << 255};
    const auto result{sync.ProcessNextHeaders({header}, true)};
    BOOST_CHECK(!result.success);
    BOOST_CHECK(!result.local_error);
    BOOST_CHECK_EQUAL(sync.GetPresyncHeight(), 0);
}

BOOST_AUTO_TEST_CASE(main_asert_presync_uses_zero_configured_minimum_chainwork)
{
    MockTimeReset mock_time_reset;
    MainASERTChain main_chain{*m_node.args};
    BOOST_REQUIRE(main_chain.params->GetConsensus().fPowUseYespower);
    BOOST_REQUIRE(main_chain.params->GetConsensus().nMinimumChainWork.IsNull());
    Consensus::Params main_consensus{main_chain.consensus};
    main_consensus.fPowUseYespower = true;
    BOOST_REQUIRE(main_consensus.nMinimumChainWork.IsNull());
    BOOST_REQUIRE(main_consensus.fPowUseYespower);

    const arith_uint256 minimum_required_work{UintToArith256(main_consensus.nMinimumChainWork)};
    CBlockHeader yespower_invalid_header{MainASERTBlock1()};
    SetMockTime(yespower_invalid_header.nTime + 60 * 60);
    BOOST_REQUIRE(yespower_invalid_header.hashPrevBlock == main_chain.genesis.GetBlockHash());
    BOOST_REQUIRE_EQUAL(GetNextWorkRequired(&main_chain.genesis, &yespower_invalid_header, main_consensus), yespower_invalid_header.nBits);
    BOOST_REQUIRE(!CheckProofOfWork(yespower_invalid_header, main_consensus));

    HeadersSyncState invalid_sync{0, main_consensus, &main_chain.genesis, minimum_required_work};
    const auto invalid_result{invalid_sync.ProcessNextHeaders({yespower_invalid_header}, true)};
    BOOST_CHECK(!invalid_result.success);
    BOOST_CHECK(invalid_sync.GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK_EQUAL(invalid_sync.GetPresyncWork(), main_chain.genesis.nChainWork);

    const Consensus::Params& controlled_consensus{main_chain.consensus};
    BOOST_REQUIRE(!controlled_consensus.fPowUseYespower);
    const CBlockHeader valid_header{MainASERTBlock1()};
    BOOST_REQUIRE(CheckProofOfWork(valid_header, controlled_consensus));

    HeadersSyncState valid_sync{0, controlled_consensus, &main_chain.genesis, minimum_required_work};
    const auto valid_result{valid_sync.ProcessNextHeaders({valid_header}, true)};
    BOOST_CHECK(valid_result.success);
    BOOST_CHECK(valid_result.request_more);
    BOOST_CHECK(valid_sync.GetState() == HeadersSyncState::State::REDOWNLOAD);
    BOOST_CHECK(valid_sync.GetPresyncWork() > main_chain.genesis.nChainWork);
}

BOOST_AUTO_TEST_CASE(main_asert_presync_rejects_wrong_nbits_and_insufficient_pow)
{
    MainASERTChain main_chain{*m_node.args};
    const auto& consensus{main_chain.consensus};
    const arith_uint256 initial_work{main_chain.genesis.nChainWork};

    CBlockHeader wrong_nbits{MainASERTBlock1()};
    BOOST_REQUIRE(CheckProofOfWorkImpl(wrong_nbits.GetHash(), wrong_nbits.nBits, consensus));
    wrong_nbits.nBits = 0x1c7fffff;
    HeadersSyncState wrong_bits_sync{0, consensus, &main_chain.genesis, arith_uint256{1} << 255};
    {
        ScopedNetDebugLogging log_settings;
        ASSERT_DEBUG_LOG("incorrect ASERT difficulty at height=1");
        const auto wrong_bits_result{wrong_bits_sync.ProcessNextHeaders({wrong_nbits}, true)};
        BOOST_CHECK(!wrong_bits_result.success);
    }
    BOOST_CHECK_EQUAL(wrong_bits_sync.GetPresyncWork(), initial_work);

    CBlockHeader insufficient_pow{MainASERTBlock1()};
    ++insufficient_pow.nNonce;
    BOOST_CHECK(!CheckProofOfWorkImpl(insufficient_pow.GetHash(), insufficient_pow.nBits, consensus));
    HeadersSyncState insufficient_pow_sync{0, consensus, &main_chain.genesis, arith_uint256{1} << 255};
    const auto insufficient_pow_result{insufficient_pow_sync.ProcessNextHeaders({insufficient_pow}, true)};
    BOOST_CHECK(!insufficient_pow_result.success);
    BOOST_CHECK_EQUAL(insufficient_pow_sync.GetPresyncWork(), initial_work);
}

BOOST_AUTO_TEST_CASE(main_asert_presync_rejects_mtp_violation)
{
    MainASERTChain main_chain{*m_node.args};
    const auto& consensus{main_chain.consensus};
    CBlockHeader invalid_timestamp{MainASERTBlock1()};
    invalid_timestamp.nTime = main_chain.genesis.nTime;
    HeadersSyncState sync{0, consensus, &main_chain.genesis, arith_uint256{1} << 255};

    {
        ScopedNetDebugLogging log_settings;
        ASSERT_DEBUG_LOG("timestamp does not exceed median time past at height=1");
        const auto result{sync.ProcessNextHeaders({invalid_timestamp}, true)};
        BOOST_CHECK(!result.success);
    }
    BOOST_CHECK_EQUAL(sync.GetPresyncWork(), main_chain.genesis.nChainWork);
}

BOOST_AUTO_TEST_CASE(main_asert_presync_defers_future_header_work)
{
    MockTimeReset mock_time_reset;
    MainASERTChain main_chain{*m_node.args};
    const auto& consensus{main_chain.consensus};
    CBlockHeader future_header{MainASERTBlock1()};

    SetMockTime(future_header.nTime - 3 * 60 * 60);
    HeadersSyncState early_sync{0, consensus, &main_chain.genesis, arith_uint256{1} << 255};
    const auto early_result{early_sync.ProcessNextHeaders({future_header}, true)};
    BOOST_CHECK(!early_result.success);
    BOOST_CHECK_EQUAL(early_sync.GetPresyncWork(), main_chain.genesis.nChainWork);

    SetMockTime(future_header.nTime - 60 * 60);
    HeadersSyncState caught_up_sync{0, consensus, &main_chain.genesis, arith_uint256{1} << 255};
    const auto caught_up_result{caught_up_sync.ProcessNextHeaders({future_header}, true)};
    BOOST_CHECK(caught_up_result.success);
    BOOST_CHECK_EQUAL(caught_up_sync.GetPresyncHeight(), 1);
    BOOST_CHECK(caught_up_sync.GetPresyncWork() > main_chain.genesis.nChainWork);
}

BOOST_AUTO_TEST_CASE(main_asert_presync_resolves_genesis_from_fork_point)
{
    MainASERTChain main_chain{*m_node.args};
    const auto& consensus{main_chain.consensus};

    CBlockHeader branch_header1{MainASERTBlock1()};
    CBlockIndex branch1;
    uint256 branch1_hash;
    SetBlockIndex(branch1, branch1_hash, main_chain.genesis, branch_header1);
    CBlockHeader branch_header2{MainASERTBlock2()};

    HeadersSyncState sync{0, consensus, &branch1, arith_uint256{1} << 255};
    const auto result{sync.ProcessNextHeaders({branch_header2}, true)};
    BOOST_CHECK(result.success);
    BOOST_CHECK_EQUAL(sync.GetPresyncHeight(), 2);
    BOOST_CHECK(sync.GetPresyncWork() > branch1.nChainWork);

    uint256 unrelated_genesis_hash{uint256{10}};
    CBlockIndex unrelated_genesis;
    unrelated_genesis.phashBlock = &unrelated_genesis_hash;
    unrelated_genesis.nHeight = 0;
    unrelated_genesis.nTime = main_chain.genesis.nTime;
    unrelated_genesis.nBits = main_chain.genesis.nBits;
    CBlockHeader unrelated_header{MainASERTBlock1()};
    unrelated_header.hashPrevBlock = unrelated_genesis_hash;
    HeadersSyncState unrelated_sync{0, consensus, &unrelated_genesis, arith_uint256{1} << 255};
    const auto unrelated_result{unrelated_sync.ProcessNextHeaders({unrelated_header}, true)};
    BOOST_CHECK(!unrelated_result.success);
    BOOST_CHECK_EQUAL(unrelated_sync.GetPresyncWork(), unrelated_genesis.nChainWork);
}

BOOST_AUTO_TEST_CASE(headers_sync_legacy_network_isolation)
{
    for (const ChainType chain : {ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        const auto chain_params{CreateChainParams(*m_node.args, chain)};
        const auto& consensus{chain_params->GetConsensus()};
        const CBlock& genesis_block{chain_params->GenesisBlock()};
        const uint256 genesis_hash{genesis_block.GetHash()};

        CBlockIndex genesis;
        genesis.phashBlock = &genesis_hash;
        genesis.nHeight = 0;
        genesis.nVersion = genesis_block.nVersion;
        genesis.hashMerkleRoot = genesis_block.hashMerkleRoot;
        genesis.nTime = genesis_block.nTime;
        genesis.nBits = genesis_block.nBits;
        genesis.nNonce = genesis_block.nNonce;
        BOOST_CHECK(!consensus.fPowUseASERT);
        BOOST_CHECK(!consensus.fPowUseYespower);

        CBlockHeader header;
        header.nVersion = 4;
        header.hashPrevBlock = genesis_hash;
        header.nTime = genesis.nTime + 1;
        header.nBits = genesis.nBits == 0x1d00ffff ? 0x1c7fffff : 0x1d00ffff;

        HeadersSyncState sync{0, consensus, &genesis, arith_uint256{1} << 255};
        const auto result{sync.ProcessNextHeaders({header}, true)};
        if (consensus.fPowAllowMinDifficultyBlocks) {
            BOOST_CHECK(result.success);
            BOOST_CHECK_EQUAL(sync.GetPresyncHeight(), 1);
        } else {
            BOOST_CHECK(!result.success);
            BOOST_CHECK_EQUAL(sync.GetPresyncWork(), genesis.nChainWork);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
