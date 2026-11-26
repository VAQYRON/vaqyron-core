// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <kernel/genesis_search.h>

#include <arith_uint256.h>
#include <hash.h>
#include <kernel/genesis.h>
#include <pow.h>
#include <pow_internal.h>
#include <streams.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/readwritefile.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace kernel {

namespace {

constexpr uint32_t CHECKPOINT_MAGIC{0x56514743};
constexpr uint32_t CHECKPOINT_VERSION{2};
constexpr uint32_t CHECKPOINT_ALGORITHM_YESPOWER_1_0{1};
constexpr size_t MAX_CHECKPOINT_SIZE{1024 * 1024};
constexpr auto CHECKPOINT_INTERVAL{std::chrono::seconds{5}};

std::mutex& CheckpointOwnershipMutex()
{
    static std::mutex mutex;
    return mutex;
}

std::set<std::string>& ProcessCheckpointOwners()
{
    static std::set<std::string> owners;
    return owners;
}

class CheckpointOwnership
{
public:
    explicit CheckpointOwnership(const fs::path& checkpoint_path)
    {
        fs::path lock_path{checkpoint_path};
        lock_path += ".lock";
        std::error_code error;
        const fs::path identity_path{fs::weakly_canonical(lock_path, error)};
        if (error) {
            throw std::runtime_error{
                "cannot resolve genesis search checkpoint ownership path: " + error.message()};
        }
        m_identity = fs::PathToString(identity_path);
        {
            std::lock_guard lock{CheckpointOwnershipMutex()};
            if (!ProcessCheckpointOwners().insert(m_identity).second) {
                throw std::runtime_error{"another search in this process owns the genesis search checkpoint"};
            }
        }

        try {
            FILE* lock_file{fsbridge::fopen(lock_path, "ab")};
            if (lock_file == nullptr) {
                throw std::runtime_error{"cannot create genesis search checkpoint ownership file"};
            }
            if (std::fclose(lock_file) != 0) {
                throw std::runtime_error{"cannot close genesis search checkpoint ownership file"};
            }

            auto file_lock{std::make_unique<fsbridge::FileLock>(lock_path)};
            if (!file_lock->TryLock()) {
                throw std::runtime_error{
                    "cannot acquire genesis search checkpoint ownership: " + file_lock->GetReason()};
            }
            m_file_lock = std::move(file_lock);
        } catch (...) {
            ReleaseProcessOwnership();
            throw;
        }
    }

    CheckpointOwnership(const CheckpointOwnership&) = delete;
    CheckpointOwnership& operator=(const CheckpointOwnership&) = delete;

    ~CheckpointOwnership()
    {
        m_file_lock.reset();
        ReleaseProcessOwnership();
    }

private:
    void ReleaseProcessOwnership()
    {
        std::lock_guard lock{CheckpointOwnershipMutex()};
        ProcessCheckpointOwners().erase(m_identity);
    }

    std::string m_identity;
    std::unique_ptr<fsbridge::FileLock> m_file_lock;
};

struct WorkerCheckpoint {
    uint32_t worker_index{0};
    uint32_t start_nonce{0};
    uint32_t end_nonce{0};
    uint8_t has_last_completed_nonce{0};
    uint32_t last_completed_nonce{0};
    uint256 last_pow_digest;

    SERIALIZE_METHODS(WorkerCheckpoint, obj)
    {
        READWRITE(obj.worker_index, obj.start_nonce, obj.end_nonce,
                  obj.has_last_completed_nonce, obj.last_completed_nonce,
                  obj.last_pow_digest);
    }
};

struct SearchCheckpoint {
    uint32_t magic{CHECKPOINT_MAGIC};
    uint32_t version{CHECKPOINT_VERSION};
    uint32_t algorithm{CHECKPOINT_ALGORITHM_YESPOWER_1_0};
    uint32_t time{0};
    uint32_t start_nonce{0};
    uint32_t end_nonce{0};
    uint32_t requested_worker_count{0};
    uint32_t nbits{VAQYRON_GENESIS_NBITS};
    int32_t block_version{VAQYRON_GENESIS_VERSION};
    uint256 pow_limit;
    uint8_t found{0};
    uint32_t found_nonce{0};
    uint256 found_header_hash;
    uint256 found_pow_digest;
    std::vector<WorkerCheckpoint> workers;

    SERIALIZE_METHODS(SearchCheckpoint, obj)
    {
        READWRITE(obj.magic, obj.version, obj.algorithm, obj.time,
                  obj.start_nonce, obj.end_nonce, obj.requested_worker_count,
                  obj.nbits, obj.block_version, obj.pow_limit, obj.found,
                  obj.found_nonce, obj.found_header_hash, obj.found_pow_digest,
                  obj.workers);
    }
};

SearchCheckpoint MakeCheckpoint(
    const GenesisSearchOptions& options,
    const Consensus::Params& consensus,
    const std::vector<GenesisSearchRange>& ranges)
{
    SearchCheckpoint checkpoint;
    checkpoint.time = options.time;
    checkpoint.start_nonce = options.start_nonce;
    checkpoint.end_nonce = options.end_nonce;
    checkpoint.requested_worker_count = options.worker_count;
    checkpoint.pow_limit = consensus.powLimit;
    checkpoint.workers.reserve(ranges.size());
    for (const auto& range : ranges) {
        checkpoint.workers.push_back(WorkerCheckpoint{
            .worker_index = range.worker_index,
            .start_nonce = range.start_nonce,
            .end_nonce = range.end_nonce,
        });
    }
    return checkpoint;
}

void ValidateCheckpoint(
    const SearchCheckpoint& checkpoint,
    const SearchCheckpoint& expected)
{
    if (checkpoint.magic != CHECKPOINT_MAGIC ||
        checkpoint.version != CHECKPOINT_VERSION ||
        checkpoint.algorithm != CHECKPOINT_ALGORITHM_YESPOWER_1_0) {
        throw std::runtime_error{"genesis search checkpoint format or algorithm is incompatible"};
    }
    if (checkpoint.time != expected.time ||
        checkpoint.start_nonce != expected.start_nonce ||
        checkpoint.end_nonce != expected.end_nonce ||
        checkpoint.requested_worker_count != expected.requested_worker_count ||
        checkpoint.nbits != expected.nbits ||
        checkpoint.block_version != expected.block_version ||
        checkpoint.pow_limit != expected.pow_limit ||
        checkpoint.workers.size() != expected.workers.size()) {
        throw std::runtime_error{"genesis search checkpoint does not match the requested search configuration"};
    }
    if (checkpoint.found > 1) {
        throw std::runtime_error{"genesis search checkpoint has an invalid FOUND status"};
    }
    if (checkpoint.found) {
        const auto winner_range{std::find_if(
            expected.workers.begin(), expected.workers.end(),
            [&](const WorkerCheckpoint& worker) {
                return checkpoint.found_nonce >= worker.start_nonce &&
                    checkpoint.found_nonce <= worker.end_nonce;
            })};
        if (winner_range == expected.workers.end()) {
            throw std::runtime_error{"genesis search checkpoint winner is outside the original worker ranges"};
        }
    } else if (checkpoint.found_nonce != 0 ||
               checkpoint.found_header_hash != uint256{} ||
               checkpoint.found_pow_digest != uint256{}) {
        throw std::runtime_error{"genesis search checkpoint has winner data without FOUND status"};
    }
    for (size_t index{0}; index < expected.workers.size(); ++index) {
        const auto& saved{checkpoint.workers[index]};
        const auto& range{expected.workers[index]};
        if (saved.worker_index != range.worker_index ||
            saved.start_nonce != range.start_nonce ||
            saved.end_nonce != range.end_nonce ||
            saved.has_last_completed_nonce > 1) {
            throw std::runtime_error{"genesis search checkpoint worker ranges are invalid or mismatched"};
        }
        if (saved.has_last_completed_nonce) {
            if (saved.last_completed_nonce < saved.start_nonce ||
                saved.last_completed_nonce > saved.end_nonce) {
                throw std::runtime_error{"genesis search checkpoint nonce is outside its worker range"};
            }
        } else if (saved.last_completed_nonce != 0 || saved.last_pow_digest != uint256{}) {
            throw std::runtime_error{"genesis search checkpoint has invalid empty worker progress"};
        }
    }
}

SearchCheckpoint ReadCheckpoint(const fs::path& path)
{
    std::error_code error;
    if (!std::filesystem::exists(path, error)) {
        if (error) {
            throw std::runtime_error{"cannot inspect genesis search checkpoint: " + error.message()};
        }
        throw std::runtime_error{"genesis search checkpoint disappeared before it could be read"};
    }

    auto [read_ok, contents]{ReadBinaryFile(path, MAX_CHECKPOINT_SIZE)};
    if (!read_ok || contents.size() >= MAX_CHECKPOINT_SIZE) {
        throw std::runtime_error{"cannot read genesis search checkpoint or checkpoint is too large"};
    }

    constexpr size_t CHECKSUM_SIZE{uint256::size()};
    if (contents.size() <= CHECKSUM_SIZE) {
        throw std::runtime_error{"genesis search checkpoint is truncated"};
    }
    const auto* const bytes{reinterpret_cast<const uint8_t*>(contents.data())};
    const size_t payload_size{contents.size() - CHECKSUM_SIZE};
    DataStream checksum_stream{std::span<const uint8_t>{bytes + payload_size, CHECKSUM_SIZE}};
    uint256 saved_checksum;
    checksum_stream >> saved_checksum;
    HashWriter checksum_writer;
    checksum_writer.write(std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(bytes), payload_size});
    if (checksum_writer.GetHash() != saved_checksum) {
        throw std::runtime_error{"genesis search checkpoint integrity check failed"};
    }

    DataStream stream{std::span<const uint8_t>{bytes, payload_size}};
    SearchCheckpoint checkpoint;
    try {
        stream >> checkpoint;
    } catch (const std::exception& error) {
        throw std::runtime_error{"genesis search checkpoint is malformed: " + std::string{error.what()}};
    }
    if (!stream.empty()) {
        throw std::runtime_error{"genesis search checkpoint contains trailing payload data"};
    }
    return checkpoint;
}

void WriteCheckpoint(const fs::path& path, const SearchCheckpoint& checkpoint)
{
    DataStream stream;
    stream << checkpoint;
    HashWriter checksum_writer;
    checksum_writer.write(std::span<const std::byte>{stream.data(), stream.size()});
    stream << checksum_writer.GetHash();
    const std::string contents{stream.str()};

    fs::path temporary_path{path};
    temporary_path += ".tmp";
    FILE* file{fsbridge::fopen(temporary_path, "wb")};
    if (file == nullptr) {
        throw std::runtime_error{"cannot open temporary genesis search checkpoint file"};
    }
    if (std::fwrite(contents.data(), 1, contents.size(), file) != contents.size()) {
        std::fclose(file);
        fs::remove(temporary_path);
        throw std::runtime_error{"cannot write temporary genesis search checkpoint file"};
    }
    if (!FileCommit(file)) {
        std::fclose(file);
        fs::remove(temporary_path);
        throw std::runtime_error{"cannot flush temporary genesis search checkpoint file"};
    }
    if (std::fclose(file) != 0) {
        fs::remove(temporary_path);
        throw std::runtime_error{"cannot close temporary genesis search checkpoint file"};
    }
    if (!RenameOver(temporary_path, path)) {
        fs::remove(temporary_path);
        throw std::runtime_error{"cannot atomically replace genesis search checkpoint file"};
    }
    const fs::path parent{path.parent_path().empty() ? fs::current_path() : path.parent_path()};
    DirectoryCommit(parent);
}

} // namespace

std::vector<GenesisSearchRange> PartitionGenesisSearchRange(
    uint32_t start_nonce, uint32_t end_nonce, uint32_t worker_count)
{
    if (start_nonce > end_nonce) {
        throw std::invalid_argument{"starting nonce must not exceed ending nonce"};
    }
    if (worker_count == 0) {
        throw std::invalid_argument{"worker count must be greater than zero"};
    }

    const uint64_t nonce_count{static_cast<uint64_t>(end_nonce) - start_nonce + 1};
    const auto actual_worker_count{static_cast<uint32_t>(
        std::min<uint64_t>(nonce_count, worker_count))};
    const uint64_t base_range_size{nonce_count / actual_worker_count};
    const uint64_t extra_nonces{nonce_count % actual_worker_count};
    uint64_t next_nonce{start_nonce};

    std::vector<GenesisSearchRange> ranges;
    ranges.reserve(actual_worker_count);
    for (uint32_t worker_index{0}; worker_index < actual_worker_count; ++worker_index) {
        const uint64_t range_size{base_range_size + (worker_index < extra_nonces ? 1 : 0)};
        const uint64_t range_end{next_nonce + range_size - 1};
        ranges.push_back(GenesisSearchRange{
            .worker_index = worker_index,
            .start_nonce = static_cast<uint32_t>(next_nonce),
            .end_nonce = static_cast<uint32_t>(range_end),
        });
        next_nonce = range_end + 1;
    }
    return ranges;
}

std::optional<uint32_t> GenesisSearchResumeStart(
    std::optional<uint32_t> last_definitely_completed_nonce)
{
    if (!last_definitely_completed_nonce) return 0;
    if (*last_definitely_completed_nonce == std::numeric_limits<uint32_t>::max()) {
        return std::nullopt;
    }
    return *last_definitely_completed_nonce + 1;
}

GenesisSearchResult SearchVaqyronGenesis(
    const GenesisSearchOptions& options,
    const Consensus::Params& consensus,
    GenesisDigestFunction digest_function,
    GenesisProgressFunction progress_function)
{
    const auto target{DeriveTarget(VAQYRON_GENESIS_NBITS, consensus.powLimit)};
    if (!target) {
        throw std::invalid_argument{"frozen genesis nBits is invalid for the supplied PoW limit"};
    }
    const auto ranges{PartitionGenesisSearchRange(
        options.start_nonce, options.end_nonce, options.worker_count)};
    const bool checkpointing{!options.checkpoint_path.empty()};
    const fs::path checkpoint_path{checkpointing
        ? fs::PathFromString(options.checkpoint_path)
        : fs::path{}};
    std::unique_ptr<CheckpointOwnership> checkpoint_ownership;
    if (checkpointing) {
        checkpoint_ownership = std::make_unique<CheckpointOwnership>(checkpoint_path);
    }
    SearchCheckpoint checkpoint{MakeCheckpoint(options, consensus, ranges)};
    if (checkpointing) {
        std::error_code error;
        const bool checkpoint_exists{std::filesystem::exists(checkpoint_path, error)};
        if (error) {
            throw std::runtime_error{"cannot inspect genesis search checkpoint path: " + error.message()};
        }
        if (checkpoint_exists) {
            checkpoint = ReadCheckpoint(checkpoint_path);
            ValidateCheckpoint(checkpoint, MakeCheckpoint(options, consensus, ranges));
        }
    }

    const auto search_start{std::chrono::steady_clock::now()};
    GenesisSearchResult result;
    result.target = *target;
    result.worker_count = static_cast<uint32_t>(ranges.size());
    if (checkpoint.found) {
        CBlock found_block{CreateVaqyronGenesisBlock(
            options.time, checkpoint.found_nonce, VAQYRON_GENESIS_NBITS, VAQYRON_GENESIS_VERSION)};
        const uint256 verified_digest{digest_function
            ? digest_function(found_block)
            : GetPoWDigest(found_block)};
        const auto verified_candidate_digest = [&](const CBlockHeader&) {
            return verified_digest;
        };
        if (found_block.GetHash() != checkpoint.found_header_hash ||
            verified_digest != checkpoint.found_pow_digest ||
            !pow_internal::CheckProofOfWorkYespowerWithDigest(
                found_block, consensus, verified_candidate_digest)) {
            throw std::runtime_error{"saved genesis search candidate failed independent verification"};
        }
        result.found = true;
        result.nonce = checkpoint.found_nonce;
        result.last_block = std::move(found_block);
        result.last_pow_digest = verified_digest;
        return result;
    }

    struct WorkerResult {
        bool attempted{false};
        uint32_t last_nonce{0};
        CBlock last_block;
        uint256 last_pow_digest;
    };
    struct FoundCandidate {
        uint32_t nonce;
        CBlock block;
        uint256 pow_digest;
    };

    std::vector<WorkerResult> worker_results(ranges.size());
    for (const auto& saved : checkpoint.workers) {
        if (saved.has_last_completed_nonce) {
            auto& worker_result{worker_results[saved.worker_index]};
            worker_result.attempted = true;
            worker_result.last_nonce = saved.last_completed_nonce;
            worker_result.last_block = CreateVaqyronGenesisBlock(
                options.time, saved.last_completed_nonce, VAQYRON_GENESIS_NBITS, VAQYRON_GENESIS_VERSION);
            worker_result.last_pow_digest = saved.last_pow_digest;
        }
    }
    std::vector<FoundCandidate> found_candidates;
    std::atomic<bool> stop_workers{false};
    std::atomic<uint64_t> candidates_checked{0};
    std::mutex result_mutex;
    std::mutex progress_mutex;
    std::mutex checkpoint_mutex;
    std::exception_ptr worker_exception;
    std::exception_ptr checkpoint_exception;

    const auto persist_checkpoint = [&] {
        SearchCheckpoint snapshot;
        {
            std::lock_guard lock{checkpoint_mutex};
            snapshot = checkpoint;
        }
        WriteCheckpoint(checkpoint_path, snapshot);
    };

    if (checkpointing) persist_checkpoint();

    std::vector<std::thread> workers;
    workers.reserve(ranges.size());

    std::mutex checkpoint_wait_mutex;
    std::condition_variable checkpoint_wait_condition;
    bool checkpoint_thread_stop{false};
    std::thread checkpoint_thread;
    if (checkpointing) {
        checkpoint_thread = std::thread{[&] {
            std::unique_lock lock{checkpoint_wait_mutex};
            while (!checkpoint_wait_condition.wait_for(
                lock, CHECKPOINT_INTERVAL, [&] { return checkpoint_thread_stop; })) {
                lock.unlock();
                try {
                    persist_checkpoint();
                } catch (...) {
                    checkpoint_exception = std::current_exception();
                    stop_workers.store(true, std::memory_order_release);
                    break;
                }
                lock.lock();
            }
        }};
    }

    const auto stop_checkpoint_thread = [&] {
        if (!checkpoint_thread.joinable()) return;
        {
            std::lock_guard lock{checkpoint_wait_mutex};
            checkpoint_thread_stop = true;
        }
        checkpoint_wait_condition.notify_one();
        checkpoint_thread.join();
    };

    const auto worker = [&](const GenesisSearchRange& range) {
        auto& worker_result{worker_results[range.worker_index]};
        auto last_progress{search_start};
        uint64_t worker_candidates_checked{0};
        try {
            uint64_t first_nonce{range.start_nonce};
            const auto& saved{checkpoint.workers[range.worker_index]};
            if (saved.has_last_completed_nonce) {
                const auto next_nonce{GenesisSearchResumeStart(saved.last_completed_nonce)};
                if (!next_nonce || *next_nonce > range.end_nonce) return;
                first_nonce = *next_nonce;
            }
            for (uint64_t nonce{first_nonce}; nonce <= range.end_nonce; ++nonce) {
                if (stop_workers.load(std::memory_order_acquire)) break;

                const auto candidate_nonce{static_cast<uint32_t>(nonce)};
                CBlock candidate_block{CreateVaqyronGenesisBlock(
                    options.time, candidate_nonce, VAQYRON_GENESIS_NBITS, VAQYRON_GENESIS_VERSION)};
                const uint256 candidate_pow_digest{digest_function
                    ? digest_function(candidate_block)
                    : GetPoWDigest(candidate_block)};
                ++worker_candidates_checked;
                candidates_checked.fetch_add(1, std::memory_order_relaxed);

                const auto candidate_digest = [&](const CBlockHeader&) {
                    return candidate_pow_digest;
                };
                if (pow_internal::CheckProofOfWorkYespowerWithDigest(
                        candidate_block, consensus, candidate_digest)) {
                    std::lock_guard lock{result_mutex};
                    found_candidates.push_back(FoundCandidate{
                        .nonce = candidate_nonce,
                        .block = std::move(candidate_block),
                        .pow_digest = candidate_pow_digest,
                    });
                    stop_workers.store(true, std::memory_order_release);
                } else {
                    worker_result.attempted = true;
                    worker_result.last_nonce = candidate_nonce;
                    worker_result.last_block = std::move(candidate_block);
                    worker_result.last_pow_digest = candidate_pow_digest;
                    if (checkpointing) {
                        std::lock_guard lock{checkpoint_mutex};
                        auto& worker_checkpoint{checkpoint.workers[range.worker_index]};
                        worker_checkpoint.has_last_completed_nonce = 1;
                        worker_checkpoint.last_completed_nonce = candidate_nonce;
                        worker_checkpoint.last_pow_digest = candidate_pow_digest;
                    }
                }

                const auto now{std::chrono::steady_clock::now()};
                if (progress_function &&
                    (worker_candidates_checked % 1024 == 0 ||
                     now - last_progress >= std::chrono::seconds{30})) {
                    const std::chrono::duration<double> elapsed{now - search_start};
                    const double elapsed_seconds{elapsed.count()};
                    std::lock_guard lock{progress_mutex};
                    const uint64_t reported_checked{
                        candidates_checked.load(std::memory_order_relaxed)};
                    progress_function(GenesisSearchProgress{
                        .current_nonce = candidate_nonce,
                        .candidates_checked = reported_checked,
                        .elapsed_seconds = elapsed_seconds,
                        .candidates_per_second = elapsed_seconds > 0
                            ? reported_checked / elapsed_seconds
                            : 0,
                        .worker_index = range.worker_index,
                        .worker_start_nonce = range.start_nonce,
                        .worker_end_nonce = range.end_nonce,
                    });
                    last_progress = now;
                }
            }
        } catch (...) {
            std::lock_guard lock{result_mutex};
            if (!worker_exception) worker_exception = std::current_exception();
            stop_workers.store(true, std::memory_order_release);
        }
    };

    try {
        for (const auto& range : ranges) workers.emplace_back(worker, std::cref(range));
    } catch (...) {
        stop_workers.store(true, std::memory_order_release);
        for (auto& thread : workers) {
            if (thread.joinable()) thread.join();
        }
        stop_checkpoint_thread();
        if (checkpointing) persist_checkpoint();
        throw;
    }
    for (auto& thread : workers) thread.join();
    stop_checkpoint_thread();
    if (checkpointing) persist_checkpoint();

    if (checkpoint_exception) std::rethrow_exception(checkpoint_exception);
    if (worker_exception) std::rethrow_exception(worker_exception);

    result.candidates_checked = candidates_checked.load(std::memory_order_relaxed);
    if (!found_candidates.empty()) {
        const auto candidate{std::min_element(
            found_candidates.begin(), found_candidates.end(),
            [](const FoundCandidate& left, const FoundCandidate& right) {
                return left.nonce < right.nonce;
            })};
        if (checkpointing) {
            {
                std::lock_guard lock{checkpoint_mutex};
                checkpoint.found = 1;
                checkpoint.found_nonce = candidate->nonce;
                checkpoint.found_header_hash = candidate->block.GetHash();
                checkpoint.found_pow_digest = candidate->pow_digest;
            }
            persist_checkpoint();
        }
        result.found = true;
        result.nonce = candidate->nonce;
        result.last_block = candidate->block;
        result.last_pow_digest = candidate->pow_digest;
    } else {
        const auto last_worker{std::max_element(
            worker_results.begin(), worker_results.end(),
            [](const WorkerResult& left, const WorkerResult& right) {
                if (left.attempted != right.attempted) return !left.attempted;
                return left.last_nonce < right.last_nonce;
            })};
        if (last_worker != worker_results.end() && last_worker->attempted) {
            result.nonce = last_worker->last_nonce;
            result.last_block = last_worker->last_block;
            result.last_pow_digest = last_worker->last_pow_digest;
        }
    }

    const std::chrono::duration<double> elapsed{std::chrono::steady_clock::now() - search_start};
    result.elapsed_seconds = elapsed.count();
    result.candidates_per_second = result.elapsed_seconds > 0
        ? result.candidates_checked / result.elapsed_seconds
        : 0;

    return result;
}

} // namespace kernel
