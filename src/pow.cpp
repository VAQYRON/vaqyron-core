// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <asert.h>
#include <chain.h>
#include <primitives/block.h>
#include <pow_internal.h>
#include <streams.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>
#include <stdexcept>
#include <vector>

#include <crypto/yespower/yespower.h>

namespace {

class YespowerWorkspace
{
public:
    YespowerWorkspace() noexcept : m_initialized{yespower_init_local(&m_local) == 0} {}

    ~YespowerWorkspace() noexcept
    {
        if (m_initialized) {
            (void)yespower_free_local(&m_local);
        }
    }

    YespowerWorkspace(const YespowerWorkspace&) = delete;
    YespowerWorkspace& operator=(const YespowerWorkspace&) = delete;

    int Hash(const uint8_t* data, size_t size, const yespower_params_t* params, yespower_binary_t* digest) noexcept
    {
        if (!m_initialized) return -1;
        return yespower(&m_local, data, size, params, digest);
    }

private:
    yespower_local_t m_local{};
    bool m_initialized;
};

} // namespace

uint256 GetPoWDigest(const CBlockHeader& header)
{
    static constexpr uint8_t PERSONALIZATION[] = "VAQYRON:pow:yespower:v1";
    static_assert(sizeof(PERSONALIZATION) - 1 == 23);

    std::vector<unsigned char> serialized_header;
    VectorWriter{serialized_header, 0, header};
    if (serialized_header.size() != 80) {
        throw std::runtime_error{"serialized block header is not 80 bytes"};
    }

    const yespower_params_t params{
        YESPOWER_1_0,
        2048,
        16,
        PERSONALIZATION,
        sizeof(PERSONALIZATION) - 1,
    };
    yespower_binary_t digest{};
    static thread_local YespowerWorkspace workspace;
    if (workspace.Hash(serialized_header.data(), serialized_header.size(), &params, &digest) != 0) {
        throw std::runtime_error{"yespower computation failed"};
    }

    uint256 result;
    std::copy(std::begin(digest.uc), std::end(digest.uc), result.begin());
    return result;
}

bool CheckProofOfWorkYespower(const CBlockHeader& header, const Consensus::Params& params)
{
    return pow_internal::CheckProofOfWorkYespowerWithDigest(
        header, params, [](const CBlockHeader& candidate) { return GetPoWDigest(candidate); });
}

bool CheckProofOfWork(const CBlockHeader& header, const Consensus::Params& params)
{
    return pow_internal::CheckProofOfWorkHeaderWithYespower(
        header, params, [](const CBlockHeader& candidate, const Consensus::Params& consensus) {
            return CheckProofOfWorkYespower(candidate, consensus);
        });
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    if (params.fPowUseASERT) {
        const CBlockIndex* pindexReference = pindexLast->GetAncestor(0);
        assert(pindexReference != nullptr);

        arith_uint256 referenceTarget;
        referenceTarget.SetCompact(pindexReference->nBits);
        const int64_t referenceParentTime{pindexReference->GetBlockTime() - params.nPowTargetSpacing};
        const int64_t timeDiff{pindexLast->GetBlockTime() - referenceParentTime};
        return CalculateASERT(referenceTarget, params.nPowTargetSpacing, timeDiff,
                              pindexLast->nHeight, UintToArith256(params.powLimit),
                              params.nASERTHalfLife).GetCompact();
    }

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then it MUST be a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    const arith_uint256 target_timespan{static_cast<uint64_t>(params.nPowTargetTimespan)};
    const arith_uint256 actual_timespan{static_cast<uint64_t>(nActualTimespan)};
    const arith_uint256 quotient{bnNew / target_timespan};
    const arith_uint256 remainder{bnNew - quotient * target_timespan};

    // Scale in quotient/remainder form to avoid overflowing for testnet's large powLimit.
    if (quotient > bnPowLimit / actual_timespan) {
        bnNew = bnPowLimit;
    } else {
        bnNew = quotient * actual_timespan + (remainder * actual_timespan) / target_timespan;
        if (bnNew > bnPowLimit) bnNew = bnPowLimit;
    }

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowUseASERT) return true;
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
