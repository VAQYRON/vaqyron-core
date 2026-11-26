// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <node/miner.h>
#include <pow.h>
#include <random.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>
#include <validation_internal.h>
#include <validationinterface.h>

#include <array>
#include <chrono>
#include <stdexcept>
#include <thread>

using node::BlockAssembler;

namespace validation_block_tests {
struct MinerTestingSetup : public RegTestingSetup {
    std::shared_ptr<CBlock> Block(const uint256& prev_hash);
    std::shared_ptr<const CBlock> GoodBlock(const uint256& prev_hash);
    std::shared_ptr<const CBlock> BadBlock(const uint256& prev_hash);
    std::shared_ptr<CBlock> FinalizeBlock(std::shared_ptr<CBlock> pblock);
    void BuildChain(const uint256& root, int height, const unsigned int invalid_rate, const unsigned int branch_rate, const unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks);
};

struct VaqyronTestnetHeaderTestingSetup : public ChainTestingSetup {
    VaqyronTestnetHeaderTestingSetup()
        : ChainTestingSetup{
              ChainType::VAQYRON_TESTNET,
              TestOpts{
                  .setup_net = false,
                  .setup_validation_interface = true,
              }}
    {
    }
};

struct MockTimeRestorer {
    const std::chrono::seconds previous{GetMockTime()};
    ~MockTimeRestorer() { SetMockTime(previous); }
};
} // namespace validation_block_tests

using validation_block_tests::MockTimeRestorer;
using validation_block_tests::VaqyronTestnetHeaderTestingSetup;

BOOST_FIXTURE_TEST_SUITE(vaqyron_testnet_header_tests, VaqyronTestnetHeaderTestingSetup)

BOOST_AUTO_TEST_CASE(first_child_contextual_timestamp_boundaries)
{
    MockTimeRestorer mock_time_restorer;
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{WITH_LOCK(cs_main, return chainman.InitializeChainstate(m_node.mempool.get()))};
    BOOST_REQUIRE(&chainman.ActiveChainstate() == &chainstate);

    const CChainParams& params{Params()};
    const CBlock& genesis{params.GenesisBlock()};
    const Consensus::Params& consensus{params.GetConsensus()};
    BOOST_REQUIRE(chainstate.LoadGenesisBlock());
    chainstate.InitCoinsDB(/*cache_size_bytes=*/1 << 20, /*in_memory=*/true, /*should_wipe=*/false);

    const uint256 genesis_hash{genesis.GetHash()};
    {
        LOCK(cs_main);
        chainstate.InitCoinsCache(1 << 20);
        CBlockIndex* genesis_index{chainman.m_blockman.LookupBlockIndex(genesis_hash)};
        BOOST_REQUIRE(genesis_index);
        chainstate.CoinsTip().SetBestBlock(genesis_hash);
        chainstate.setBlockIndexCandidates.insert(genesis_index);
        BOOST_REQUIRE(chainstate.LoadChainTip());
    }

    const std::array<CBlockHeader, 1> genesis_header{genesis.GetBlockHeader()};
    const CBlockIndex* genesis_index{nullptr};
    BlockValidationState genesis_state;
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders(
        genesis_header, /*min_pow_checked=*/true, genesis_state, &genesis_index));
    BOOST_REQUIRE(genesis_index);
    BOOST_CHECK_EQUAL(genesis_index->GetBlockHash(), consensus.hashGenesisBlock);
    BOOST_CHECK_EQUAL(genesis_index->nHeight, 0);
    BOOST_CHECK_EQUAL(chainman.ActiveChain().Genesis(), genesis_index);

    const auto make_child = [&](uint32_t timestamp) {
        CBlockHeader child;
        child.nVersion = 4;
        child.hashPrevBlock = genesis_index->GetBlockHash();
        child.hashMerkleRoot = genesis.hashMerkleRoot;
        child.nTime = timestamp;
        child.nBits = GetNextWorkRequired(genesis_index, &child, consensus);
        return child;
    };

    CBlockHeader mtp_header{make_child(genesis_index->GetMedianTimePast())};
    SetMockTime(std::chrono::seconds{genesis.nTime});
    BlockValidationState mtp_state;
    BOOST_CHECK(!chainman.ProcessNewBlockHeaders(
        std::array<CBlockHeader, 1>{mtp_header}, /*min_pow_checked=*/true, mtp_state));
    BOOST_CHECK_EQUAL(mtp_state.GetRejectReason(), "time-too-old");
    BOOST_CHECK_EQUAL(mtp_header.hashPrevBlock, genesis_index->GetBlockHash());
    BOOST_CHECK_EQUAL(mtp_header.nBits, GetNextWorkRequired(genesis_index, &mtp_header, consensus));

    constexpr uint32_t POW_NONCE_ATTEMPTS{1024};
    const uint32_t accepted_time{static_cast<uint32_t>(genesis_index->GetMedianTimePast() + 1)};
    CBlockHeader accepted_header{make_child(accepted_time)};
    SetMockTime(std::chrono::seconds{
        static_cast<int64_t>(accepted_time) - MAX_FUTURE_BLOCK_TIME});
    BOOST_CHECK_EQUAL(
        accepted_header.nTime,
        TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()) + MAX_FUTURE_BLOCK_TIME);

    bool found_valid_pow{false};
    for (uint32_t nonce{0}; nonce < POW_NONCE_ATTEMPTS; ++nonce) {
        accepted_header.nNonce = nonce;
        if (CheckProofOfWork(accepted_header, consensus)) {
            found_valid_pow = true;
            break;
        }
    }
    BOOST_REQUIRE_MESSAGE(found_valid_pow, "bounded production Yespower nonce search exhausted");
    BOOST_CHECK_EQUAL(accepted_header.hashPrevBlock, genesis_index->GetBlockHash());
    BOOST_CHECK_EQUAL(
        accepted_header.nBits,
        GetNextWorkRequired(genesis_index, &accepted_header, consensus));

    const CBlockIndex* accepted_index{nullptr};
    BlockValidationState accepted_state;
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders(
        std::array<CBlockHeader, 1>{accepted_header},
        /*min_pow_checked=*/true, accepted_state, &accepted_index));
    BOOST_REQUIRE(accepted_index);
    BOOST_CHECK_EQUAL(accepted_index->nHeight, 1);
    BOOST_CHECK_EQUAL(accepted_index->pprev, genesis_index);
    BOOST_CHECK_EQUAL(accepted_index->GetBlockHash(), accepted_header.GetHash());

    CBlockHeader future_header{accepted_header};
    future_header.nNonce = accepted_header.nNonce + 1;
    SetMockTime(std::chrono::seconds{
        static_cast<int64_t>(accepted_time) - MAX_FUTURE_BLOCK_TIME - 1});
    BlockValidationState future_state;
    BOOST_CHECK(!chainman.ProcessNewBlockHeaders(
        std::array<CBlockHeader, 1>{future_header}, /*min_pow_checked=*/true, future_state));
    BOOST_CHECK_EQUAL(future_state.GetRejectReason(), "time-too-new");
}

BOOST_AUTO_TEST_CASE(valid_first_child_block_is_accepted)
{
    MockTimeRestorer mock_time_restorer;
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{WITH_LOCK(cs_main, return chainman.InitializeChainstate(m_node.mempool.get()))};
    BOOST_REQUIRE(&chainman.ActiveChainstate() == &chainstate);

    const CChainParams& params{Params()};
    const CBlock& genesis{params.GenesisBlock()};
    const Consensus::Params& consensus{params.GetConsensus()};
    BOOST_REQUIRE(chainstate.LoadGenesisBlock());
    chainstate.InitCoinsDB(/*cache_size_bytes=*/1 << 20, /*in_memory=*/true, /*should_wipe=*/false);

    const uint256 genesis_hash{genesis.GetHash()};
    {
        LOCK(cs_main);
        chainstate.InitCoinsCache(1 << 20);
        CBlockIndex* genesis_index{chainman.m_blockman.LookupBlockIndex(genesis_hash)};
        BOOST_REQUIRE(genesis_index);
        chainstate.CoinsTip().SetBestBlock(genesis_hash);
        chainstate.setBlockIndexCandidates.insert(genesis_index);
        BOOST_REQUIRE(chainstate.LoadChainTip());
    }

    const CBlockIndex* genesis_index{chainman.ActiveChain().Genesis()};
    BOOST_REQUIRE(genesis_index);
    BOOST_CHECK_EQUAL(genesis_index->GetBlockHash(), consensus.hashGenesisBlock);

    CMutableTransaction coinbase;
    coinbase.version = 1;
    coinbase.vin.emplace_back(COutPoint{}, CScript{} << 1 << OP_0);
    coinbase.vout.emplace_back(GetBlockSubsidy(/*height=*/1, consensus), CScript{} << OP_TRUE);

    CBlock block;
    block.nVersion = 4;
    block.hashPrevBlock = genesis_index->GetBlockHash();
    block.nTime = static_cast<uint32_t>(genesis_index->GetMedianTimePast() + 1);
    block.nBits = GetNextWorkRequired(genesis_index, &block, consensus);
    block.vtx.push_back(MakeTransactionRef(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);

    SetMockTime(std::chrono::seconds{
        static_cast<int64_t>(block.nTime) - MAX_FUTURE_BLOCK_TIME});

    constexpr uint32_t POW_NONCE_ATTEMPTS{1024};
    bool found_valid_pow{false};
    for (uint32_t nonce{0}; nonce < POW_NONCE_ATTEMPTS; ++nonce) {
        block.nNonce = nonce;
        if (CheckProofOfWork(block, consensus)) {
            found_valid_pow = true;
            break;
        }
    }
    BOOST_REQUIRE_MESSAGE(found_valid_pow, "bounded production Yespower nonce search exhausted");

    const uint256 block_hash{block.GetHash()};
    bool new_block{false};
    BOOST_REQUIRE(chainman.ProcessNewBlock(
        std::make_shared<const CBlock>(block),
        /*force_processing=*/true,
        /*min_pow_checked=*/true,
        &new_block));
    BOOST_CHECK(new_block);

    const CBlockIndex* active_tip{nullptr};
    {
        LOCK(cs_main);
        active_tip = chainman.ActiveChain().Tip();
    }
    BOOST_REQUIRE(active_tip);
    BOOST_CHECK_EQUAL(active_tip->nHeight, 1);
    BOOST_CHECK_EQUAL(active_tip->GetBlockHash(), block_hash);
}

BOOST_AUTO_TEST_CASE(invalid_yespower_first_child_block_is_rejected)
{
    MockTimeRestorer mock_time_restorer;
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{WITH_LOCK(cs_main, return chainman.InitializeChainstate(m_node.mempool.get()))};
    BOOST_REQUIRE(&chainman.ActiveChainstate() == &chainstate);

    const CChainParams& params{Params()};
    const CBlock& genesis{params.GenesisBlock()};
    const Consensus::Params& consensus{params.GetConsensus()};
    BOOST_REQUIRE(chainstate.LoadGenesisBlock());
    chainstate.InitCoinsDB(/*cache_size_bytes=*/1 << 20, /*in_memory=*/true, /*should_wipe=*/false);

    const uint256 genesis_hash{genesis.GetHash()};
    {
        LOCK(cs_main);
        chainstate.InitCoinsCache(1 << 20);
        CBlockIndex* genesis_index{chainman.m_blockman.LookupBlockIndex(genesis_hash)};
        BOOST_REQUIRE(genesis_index);
        chainstate.CoinsTip().SetBestBlock(genesis_hash);
        chainstate.setBlockIndexCandidates.insert(genesis_index);
        BOOST_REQUIRE(chainstate.LoadChainTip());
    }

    const CBlockIndex* genesis_index{chainman.ActiveChain().Genesis()};
    BOOST_REQUIRE(genesis_index);
    BOOST_CHECK_EQUAL(genesis_index->GetBlockHash(), consensus.hashGenesisBlock);

    CMutableTransaction coinbase;
    coinbase.version = 1;
    coinbase.vin.emplace_back(COutPoint{}, CScript{} << 1 << OP_0);
    coinbase.vout.emplace_back(GetBlockSubsidy(/*height=*/1, consensus), CScript{} << OP_TRUE);

    CBlock block;
    block.nVersion = 4;
    block.hashPrevBlock = genesis_index->GetBlockHash();
    block.nTime = static_cast<uint32_t>(genesis_index->GetMedianTimePast() + 1);
    block.nBits = GetNextWorkRequired(genesis_index, &block, consensus);
    block.vtx.push_back(MakeTransactionRef(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);

    SetMockTime(std::chrono::seconds{
        static_cast<int64_t>(block.nTime) - MAX_FUTURE_BLOCK_TIME});

    constexpr uint32_t POW_NONCE_ATTEMPTS{1024};
    bool found_invalid_pow{false};
    for (uint32_t nonce{0}; nonce < POW_NONCE_ATTEMPTS; ++nonce) {
        block.nNonce = nonce;
        if (!CheckProofOfWork(block, consensus)) {
            found_invalid_pow = true;
            break;
        }
    }
    BOOST_REQUIRE_MESSAGE(found_invalid_pow, "bounded production Yespower invalid-nonce search exhausted");

    struct BlockCheckedCatcher final : CValidationInterface {
        const uint256 expected_hash;
        bool captured{false};
        BlockValidationState state;

        explicit BlockCheckedCatcher(const uint256& hash) : expected_hash{hash} {}

        void BlockChecked(
            const std::shared_ptr<const CBlock>& checked_block,
            const BlockValidationState& validation_state) override
        {
            if (checked_block->GetHash() != expected_hash) return;
            state = validation_state;
            captured = true;
        }
    };
    struct ScopedValidationRegistration {
        ValidationSignals& signals;
        std::shared_ptr<CValidationInterface> callbacks;

        ScopedValidationRegistration(
            ValidationSignals& validation_signals,
            std::shared_ptr<CValidationInterface> validation_callbacks)
            : signals{validation_signals}, callbacks{std::move(validation_callbacks)}
        {
            signals.RegisterSharedValidationInterface(callbacks);
        }

        ~ScopedValidationRegistration()
        {
            signals.UnregisterSharedValidationInterface(callbacks);
        }
    };

    auto catcher{std::make_shared<BlockCheckedCatcher>(block.GetHash())};
    ScopedValidationRegistration registration{*Assert(m_node.validation_signals), catcher};

    bool new_block{false};
    BOOST_CHECK(!chainman.ProcessNewBlock(
        std::make_shared<const CBlock>(block),
        /*force_processing=*/true,
        /*min_pow_checked=*/true,
        &new_block));
    BOOST_CHECK(!new_block);
    BOOST_REQUIRE(catcher->captured);
    BOOST_CHECK(catcher->state.IsInvalid());
    BOOST_CHECK_EQUAL(catcher->state.GetRejectReason(), "high-hash");

    const CBlockIndex* active_tip{nullptr};
    {
        LOCK(cs_main);
        active_tip = chainman.ActiveChain().Tip();
    }
    BOOST_REQUIRE(active_tip);
    BOOST_CHECK_EQUAL(active_tip->nHeight, 0);
    BOOST_CHECK_EQUAL(active_tip->GetBlockHash(), genesis_hash);
}

BOOST_AUTO_TEST_CASE(overpaid_first_child_block_is_rejected)
{
    MockTimeRestorer mock_time_restorer;
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{WITH_LOCK(cs_main, return chainman.InitializeChainstate(m_node.mempool.get()))};
    BOOST_REQUIRE(&chainman.ActiveChainstate() == &chainstate);

    const CChainParams& params{Params()};
    const CBlock& genesis{params.GenesisBlock()};
    const Consensus::Params& consensus{params.GetConsensus()};
    BOOST_REQUIRE(chainstate.LoadGenesisBlock());
    chainstate.InitCoinsDB(/*cache_size_bytes=*/1 << 20, /*in_memory=*/true, /*should_wipe=*/false);

    const uint256 genesis_hash{genesis.GetHash()};
    {
        LOCK(cs_main);
        chainstate.InitCoinsCache(1 << 20);
        CBlockIndex* genesis_index{chainman.m_blockman.LookupBlockIndex(genesis_hash)};
        BOOST_REQUIRE(genesis_index);
        chainstate.CoinsTip().SetBestBlock(genesis_hash);
        chainstate.setBlockIndexCandidates.insert(genesis_index);
        BOOST_REQUIRE(chainstate.LoadChainTip());
    }

    const CBlockIndex* genesis_index{chainman.ActiveChain().Genesis()};
    BOOST_REQUIRE(genesis_index);
    BOOST_CHECK_EQUAL(genesis_index->GetBlockHash(), consensus.hashGenesisBlock);

    CMutableTransaction coinbase;
    coinbase.version = 1;
    coinbase.vin.emplace_back(COutPoint{}, CScript{} << 1 << OP_0);
    coinbase.vout.emplace_back(
        GetBlockSubsidy(/*height=*/1, consensus) + 1, CScript{} << OP_TRUE);

    CBlock block;
    block.nVersion = 4;
    block.hashPrevBlock = genesis_index->GetBlockHash();
    block.nTime = static_cast<uint32_t>(genesis_index->GetMedianTimePast() + 1);
    block.nBits = GetNextWorkRequired(genesis_index, &block, consensus);
    block.vtx.push_back(MakeTransactionRef(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);

    SetMockTime(std::chrono::seconds{
        static_cast<int64_t>(block.nTime) - MAX_FUTURE_BLOCK_TIME});

    constexpr uint32_t POW_NONCE_ATTEMPTS{1024};
    bool found_valid_pow{false};
    for (uint32_t nonce{0}; nonce < POW_NONCE_ATTEMPTS; ++nonce) {
        block.nNonce = nonce;
        if (CheckProofOfWork(block, consensus)) {
            found_valid_pow = true;
            break;
        }
    }
    BOOST_REQUIRE_MESSAGE(found_valid_pow, "bounded production Yespower nonce search exhausted");

    struct BlockCheckedCatcher final : CValidationInterface {
        const uint256 expected_hash;
        bool captured{false};
        BlockValidationState state;

        explicit BlockCheckedCatcher(const uint256& hash) : expected_hash{hash} {}

        void BlockChecked(
            const std::shared_ptr<const CBlock>& checked_block,
            const BlockValidationState& validation_state) override
        {
            if (checked_block->GetHash() != expected_hash) return;
            state = validation_state;
            captured = true;
        }
    };
    struct ScopedValidationRegistration {
        ValidationSignals& signals;
        std::shared_ptr<CValidationInterface> callbacks;

        ScopedValidationRegistration(
            ValidationSignals& validation_signals,
            std::shared_ptr<CValidationInterface> validation_callbacks)
            : signals{validation_signals}, callbacks{std::move(validation_callbacks)}
        {
            signals.RegisterSharedValidationInterface(callbacks);
        }

        ~ScopedValidationRegistration()
        {
            signals.UnregisterSharedValidationInterface(callbacks);
        }
    };

    auto catcher{std::make_shared<BlockCheckedCatcher>(block.GetHash())};
    ScopedValidationRegistration registration{*Assert(m_node.validation_signals), catcher};

    bool new_block{false};
    BOOST_CHECK(chainman.ProcessNewBlock(
        std::make_shared<const CBlock>(block),
        /*force_processing=*/true,
        /*min_pow_checked=*/true,
        &new_block));
    BOOST_CHECK(new_block);
    BOOST_REQUIRE(catcher->captured);
    BOOST_CHECK(catcher->state.IsInvalid());
    BOOST_CHECK_EQUAL(catcher->state.GetRejectReason(), "bad-cb-amount");

    const CBlockIndex* active_tip{nullptr};
    {
        LOCK(cs_main);
        active_tip = chainman.ActiveChain().Tip();
    }
    BOOST_REQUIRE(active_tip);
    BOOST_CHECK_EQUAL(active_tip->nHeight, 0);
    BOOST_CHECK_EQUAL(active_tip->GetBlockHash(), genesis_hash);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(validation_block_tests, MinerTestingSetup)

BOOST_AUTO_TEST_CASE(pow_check_deferred_stages_call_once_and_runtime_failure_is_error)
{
    CBlockHeader header;
    BlockValidationState state;
    unsigned int pow_calls{0};
    const auto counted_check = [&pow_calls](const CBlockHeader&) {
        ++pow_calls;
        return true;
    };

    // ProcessNewBlock and block checks defer PoW until contextual header checks.
    for (const bool requested : {false, false, true, false, false}) {
        BOOST_CHECK(validation_internal::CheckProofOfWorkIfRequested(header, state, requested, counted_check));
    }
    BOOST_CHECK_EQUAL(pow_calls, 1);

    BlockValidationState runtime_failure;
    pow_calls = 0;
    const auto failing_check = [&pow_calls](const CBlockHeader&) -> bool {
        ++pow_calls;
        throw std::runtime_error{"test PoW runtime failure"};
    };
    BOOST_CHECK(!validation_internal::CheckProofOfWorkIfRequested(header, runtime_failure, true, failing_check));
    BOOST_CHECK(runtime_failure.IsError());
    BOOST_CHECK(!runtime_failure.IsInvalid());
    BOOST_CHECK_EQUAL(pow_calls, 1);
}

struct TestSubscriber final : public CValidationInterface {
    uint256 m_expected_tip;

    explicit TestSubscriber(uint256 tip) : m_expected_tip(tip) {}

    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, pindexNew->GetBlockHash());
    }

    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->hashPrevBlock);
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->pprev->GetBlockHash());

        m_expected_tip = block->GetHash();
    }

    void BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->GetHash());
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->GetBlockHash());

        m_expected_tip = block->hashPrevBlock;
    }
};

std::shared_ptr<CBlock> MinerTestingSetup::Block(const uint256& prev_hash)
{
    static int i = 0;
    static uint64_t time = Params().GenesisBlock().nTime;

    BlockAssembler::Options options;
    options.coinbase_output_script = CScript{} << i++ << OP_TRUE;
    auto ptemplate = BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
    auto pblock = std::make_shared<CBlock>(ptemplate->block);
    pblock->hashPrevBlock = prev_hash;
    pblock->nTime = ++time;

    // Make the coinbase transaction with two outputs:
    // One zero-value one that has a unique pubkey to make sure that blocks at the same height can have a different hash
    // Another one that has the coinbase reward in a P2WSH with OP_TRUE as witness program to make it easy to spend
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vout.resize(2);
    txCoinbase.vout[1].scriptPubKey = P2WSH_OP_TRUE;
    txCoinbase.vout[1].nValue = txCoinbase.vout[0].nValue;
    txCoinbase.vout[0].nValue = 0;
    txCoinbase.vin[0].scriptWitness.SetNull();
    // Always pad with OP_0 at the end to avoid bad-cb-length error
    const int prev_height{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(prev_hash)->nHeight)};
    txCoinbase.vin[0].scriptSig = CScript{} << prev_height + 1 << OP_0;
    txCoinbase.nLockTime = static_cast<uint32_t>(prev_height);
    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    return pblock;
}

std::shared_ptr<CBlock> MinerTestingSetup::FinalizeBlock(std::shared_ptr<CBlock> pblock)
{
    const CBlockIndex* prev_block{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(pblock->hashPrevBlock))};
    m_node.chainman->GenerateCoinbaseCommitment(*pblock, prev_block);

    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    while (!CheckProofOfWork(*pblock, Params().GetConsensus())) {
        ++(pblock->nNonce);
    }

    // submit block header, so that miner can get the block height from the
    // global state and the node has the topology of the chain
    BlockValidationState ignored;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders({{pblock->GetBlockHeader()}}, true, ignored));

    return pblock;
}

// construct a valid block
std::shared_ptr<const CBlock> MinerTestingSetup::GoodBlock(const uint256& prev_hash)
{
    return FinalizeBlock(Block(prev_hash));
}

// construct an invalid block (but with a valid header)
std::shared_ptr<const CBlock> MinerTestingSetup::BadBlock(const uint256& prev_hash)
{
    auto pblock = Block(prev_hash);

    CMutableTransaction coinbase_spend;
    coinbase_spend.vin.emplace_back(COutPoint(pblock->vtx[0]->GetHash(), 0), CScript(), 0);
    coinbase_spend.vout.push_back(pblock->vtx[0]->vout[0]);

    CTransactionRef tx = MakeTransactionRef(coinbase_spend);
    pblock->vtx.push_back(tx);

    auto ret = FinalizeBlock(pblock);
    return ret;
}

// NOLINTNEXTLINE(misc-no-recursion)
void MinerTestingSetup::BuildChain(const uint256& root, int height, const unsigned int invalid_rate, const unsigned int branch_rate, const unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks)
{
    if (height <= 0 || blocks.size() >= max_size) return;

    bool gen_invalid = m_rng.randrange(100U) < invalid_rate;
    bool gen_fork = m_rng.randrange(100U) < branch_rate;

    const std::shared_ptr<const CBlock> pblock = gen_invalid ? BadBlock(root) : GoodBlock(root);
    blocks.push_back(pblock);
    if (!gen_invalid) {
        BuildChain(pblock->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }

    if (gen_fork) {
        blocks.push_back(GoodBlock(root));
        BuildChain(blocks.back()->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }
}

BOOST_AUTO_TEST_CASE(processnewblock_signals_ordering)
{
    // build a large-ish chain that's likely to have some forks
    std::vector<std::shared_ptr<const CBlock>> blocks;
    while (blocks.size() < 50) {
        blocks.clear();
        BuildChain(Params().GenesisBlock().GetHash(), 100, 15, 10, 500, blocks);
    }

    bool ignored;
    // Connect the genesis block and drain any outstanding events
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<CBlock>(Params().GenesisBlock()), true, true, &ignored));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // subscribe to events (this subscriber will validate event ordering)
    const CBlockIndex* initial_tip = nullptr;
    {
        LOCK(cs_main);
        initial_tip = m_node.chainman->ActiveChain().Tip();
    }
    auto sub = std::make_shared<TestSubscriber>(initial_tip->GetBlockHash());
    m_node.validation_signals->RegisterSharedValidationInterface(sub);

    // create a bunch of threads that repeatedly process a block generated above at random
    // this will create parallelism and randomness inside validation - the ValidationInterface
    // will subscribe to events generated during block validation and assert on ordering invariance
    std::vector<std::thread> threads;
    threads.reserve(10);
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&]() {
            bool ignored;
            FastRandomContext insecure;
            for (int i = 0; i < 1000; i++) {
                const auto& block = blocks[insecure.randrange(blocks.size() - 1)];
                Assert(m_node.chainman)->ProcessNewBlock(block, true, true, &ignored);
            }

            // to make sure that eventually we process the full chain - do it here
            for (const auto& block : blocks) {
                if (block->vtx.size() == 1) {
                    bool processed = Assert(m_node.chainman)->ProcessNewBlock(block, true, true, &ignored);
                    assert(processed);
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    m_node.validation_signals->UnregisterSharedValidationInterface(sub);

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(sub->m_expected_tip, m_node.chainman->ActiveChain().Tip()->GetBlockHash());
}

/**
 * Test that mempool updates happen atomically with reorgs.
 *
 * This prevents RPC clients, among others, from retrieving immediately-out-of-date mempool data
 * during large reorgs.
 *
 * The test verifies this by creating a chain of `num_txs` blocks, matures their coinbases, and then
 * submits txns spending from their coinbase to the mempool. A fork chain is then processed,
 * invalidating the txns and evicting them from the mempool.
 *
 * We verify that the mempool updates atomically by polling it continuously
 * from another thread during the reorg and checking that its size only changes
 * once. The size changing exactly once indicates that the polling thread's
 * view of the mempool is either consistent with the chain state before reorg,
 * or consistent with the chain state after the reorg, and not just consistent
 * with some intermediate state during the reorg.
 */
BOOST_AUTO_TEST_CASE(mempool_locks_reorg)
{
    bool ignored;
    auto ProcessBlock = [&](std::shared_ptr<const CBlock> block) -> bool {
        return Assert(m_node.chainman)->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&ignored);
    };

    // Process all mined blocks
    BOOST_REQUIRE(ProcessBlock(std::make_shared<CBlock>(Params().GenesisBlock())));
    auto last_mined = GoodBlock(Params().GenesisBlock().GetHash());
    BOOST_REQUIRE(ProcessBlock(last_mined));

    // Run the test multiple times
    for (int test_runs = 3; test_runs > 0; --test_runs) {
        BOOST_CHECK_EQUAL(last_mined->GetHash(), WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));

        // Later on split from here
        const uint256 split_hash{last_mined->hashPrevBlock};

        // Create a bunch of transactions to spend the miner rewards of the
        // most recent blocks
        std::vector<CTransactionRef> txs;
        for (int num_txs = 22; num_txs > 0; --num_txs) {
            CMutableTransaction mtx;
            mtx.vin.emplace_back(COutPoint{last_mined->vtx[0]->GetHash(), 1}, CScript{});
            mtx.vin[0].scriptWitness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);
            mtx.vout.push_back(last_mined->vtx[0]->vout[1]);
            mtx.vout[0].nValue -= 1000;
            txs.push_back(MakeTransactionRef(mtx));

            last_mined = GoodBlock(last_mined->GetHash());
            BOOST_REQUIRE(ProcessBlock(last_mined));
        }

        // Mature the inputs of the txs
        for (int j = COINBASE_MATURITY; j > 0; --j) {
            last_mined = GoodBlock(last_mined->GetHash());
            BOOST_REQUIRE(ProcessBlock(last_mined));
        }

        // Mine a reorg (and hold it back) before adding the txs to the mempool
        const uint256 tip_init{last_mined->GetHash()};

        std::vector<std::shared_ptr<const CBlock>> reorg;
        last_mined = GoodBlock(split_hash);
        reorg.push_back(last_mined);
        for (size_t j = COINBASE_MATURITY + txs.size() + 1; j > 0; --j) {
            last_mined = GoodBlock(last_mined->GetHash());
            reorg.push_back(last_mined);
        }

        // Add the txs to the tx pool
        {
            LOCK(cs_main);
            for (const auto& tx : txs) {
                const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(tx);
                BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
            }
        }

        // Check that all txs are in the pool
        {
            BOOST_CHECK_EQUAL(m_node.mempool->size(), txs.size());
        }

        // Run a thread that simulates an RPC caller that is polling while
        // validation is doing a reorg
        std::thread rpc_thread{[&]() {
            // This thread is checking that the mempool either contains all of
            // the transactions invalidated by the reorg, or none of them, and
            // not some intermediate amount.
            while (true) {
                LOCK(m_node.mempool->cs);
                if (m_node.mempool->size() == 0) {
                    // We are done with the reorg
                    break;
                }
                // Internally, we might be in the middle of the reorg, but
                // externally the reorg to the most-proof-of-work chain should
                // be atomic. So the caller assumes that the returned mempool
                // is consistent. That is, it has all txs that were there
                // before the reorg.
                assert(m_node.mempool->size() == txs.size());
                continue;
            }
            LOCK(cs_main);
            // We are done with the reorg, so the tip must have changed
            assert(tip_init != m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }};

        // Submit the reorg in this thread to invalidate and remove the txs from the tx pool
        for (const auto& b : reorg) {
            ProcessBlock(b);
        }
        // Check that the reorg was eventually successful
        BOOST_CHECK_EQUAL(last_mined->GetHash(), WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));

        // We can join the other thread, which returns when the reorg was successful
        rpc_thread.join();
    }
}

BOOST_AUTO_TEST_CASE(witness_commitment_index)
{
    LOCK(Assert(m_node.chainman)->GetMutex());
    CScript pubKey;
    pubKey << 1 << OP_TRUE;
    BlockAssembler::Options options;
    options.coinbase_output_script = pubKey;
    auto ptemplate = BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
    CBlock pblock = ptemplate->block;

    CTxOut witness;
    witness.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
    witness.scriptPubKey[0] = OP_RETURN;
    witness.scriptPubKey[1] = 0x24;
    witness.scriptPubKey[2] = 0xaa;
    witness.scriptPubKey[3] = 0x21;
    witness.scriptPubKey[4] = 0xa9;
    witness.scriptPubKey[5] = 0xed;

    // A witness larger than the minimum size is still valid
    CTxOut min_plus_one = witness;
    min_plus_one.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT + 1);

    CTxOut invalid = witness;
    invalid.scriptPubKey[0] = OP_VERIFY;

    CMutableTransaction txCoinbase(*pblock.vtx[0]);
    txCoinbase.vout.resize(4);
    txCoinbase.vout[0] = witness;
    txCoinbase.vout[1] = witness;
    txCoinbase.vout[2] = min_plus_one;
    txCoinbase.vout[3] = invalid;
    pblock.vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    BOOST_CHECK_EQUAL(GetWitnessCommitmentIndex(pblock), 2);
}
BOOST_AUTO_TEST_SUITE_END()
