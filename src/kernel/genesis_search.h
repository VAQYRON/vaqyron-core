// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_KERNEL_GENESIS_SEARCH_H
#define BITCOIN_KERNEL_GENESIS_SEARCH_H

#include <arith_uint256.h>
#include <consensus/params.h>
#include <primitives/block.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace kernel {

inline constexpr uint32_t VAQYRON_GENESIS_NBITS{0x1d00ffff};
inline constexpr int32_t VAQYRON_GENESIS_VERSION{1};

struct GenesisSearchOptions {
    uint32_t time;
    uint32_t start_nonce;
    uint32_t end_nonce;
    uint32_t worker_count{1};
    std::string checkpoint_path;
};

struct GenesisSearchRange {
    uint32_t worker_index;
    uint32_t start_nonce;
    uint32_t end_nonce;
};

struct GenesisSearchProgress {
    uint32_t current_nonce;
    uint64_t candidates_checked;
    double elapsed_seconds;
    double candidates_per_second;
    uint32_t worker_index;
    uint32_t worker_start_nonce;
    uint32_t worker_end_nonce;
};

struct GenesisSearchResult {
    bool found{false};
    uint32_t nonce{0};
    uint64_t candidates_checked{0};
    CBlock last_block;
    uint256 last_pow_digest;
    arith_uint256 target;
    uint32_t worker_count{0};
    double elapsed_seconds{0};
    double candidates_per_second{0};
};

using GenesisDigestFunction = std::function<uint256(const CBlockHeader&)>;
using GenesisProgressFunction = std::function<void(const GenesisSearchProgress&)>;

/** Divide an inclusive nonce range into contiguous, non-overlapping ranges. */
std::vector<GenesisSearchRange> PartitionGenesisSearchRange(
    uint32_t start_nonce, uint32_t end_nonce, uint32_t worker_count);

/** Return the first nonce not confirmed complete, or nullopt when exhausted. */
std::optional<uint32_t> GenesisSearchResumeStart(
    std::optional<uint32_t> last_definitely_completed_nonce);

/** Search the inclusive nonce range using the production yespower validation contract.
 *
 * The digest function is an internal testing seam. An empty function uses the
 * production GetPoWDigest implementation. Each worker uses the production
 * thread-local yespower scratch state.
 */
GenesisSearchResult SearchVaqyronGenesis(
    const GenesisSearchOptions& options,
    const Consensus::Params& consensus,
    GenesisDigestFunction digest_function = {},
    GenesisProgressFunction progress_function = {});

} // namespace kernel

#endif // BITCOIN_KERNEL_GENESIS_SEARCH_H
