// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_CONTEXT_H
#define BITCOIN_NODE_CONTEXT_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class ArgsManager;
class AddrMan;
class BanMan;
class BaseIndex;
class CBlockPolicyEstimator;
class CConnman;
class ValidationSignals;
class CScheduler;
class CTxMemPool;
class ChainstateManager;
class ECC_Context;
class NetGroupManager;
class PeerManager;
namespace interfaces {
class Chain;
class ChainClient;
class Mining;
class Init;
class WalletLoader;
} // namespace interfaces
namespace kernel {
struct Context;
}
namespace util {
class SignalInterrupt;
}

namespace node {
class KernelNotifications;
class Warnings;

enum class CleanupState {
    NOT_STARTED,
    INTERRUPTING,
    SHUTTING_DOWN,
    CLEANUP_COMPLETE,
    CLEANUP_INCOMPLETE,
};

enum class CleanupPhase {
    NONE,
    INTERRUPT,
    SHUTDOWN,
};

enum class CleanupResult {
    COMPLETE,
    IN_PROGRESS,
    INCOMPLETE,
};

struct CleanupSnapshot {
    CleanupState state{CleanupState::NOT_STARTED};
    CleanupPhase phase{CleanupPhase::NONE};
    CleanupPhase failing_phase{CleanupPhase::NONE};
    std::string diagnostic;
    std::string last_progress;
    std::chrono::steady_clock::time_point progress_time{};
    bool persistence_durability_confirmed{false};
    bool stall_suspected{false};
    std::uint64_t generation{0};
};

class CleanupCoordinator
{
public:
    CleanupResult RunInterrupt(const std::function<void()>& action);
    CleanupResult RunShutdown(const std::function<void()>& action);
    bool RecordProgress(std::string progress);
    CleanupSnapshot Snapshot() const;
    bool WaitForChange(std::uint64_t generation, std::chrono::milliseconds timeout);

private:
    void MarkIncomplete(CleanupPhase phase, const char* diagnostic);

    mutable std::mutex mutex_;
    std::condition_variable changed_;
    CleanupState state_{CleanupState::NOT_STARTED};
    CleanupPhase phase_{CleanupPhase::NONE};
    CleanupPhase failing_phase_{CleanupPhase::NONE};
    std::string diagnostic_;
    std::string last_progress_;
    std::chrono::steady_clock::time_point progress_time_{};
    std::uint64_t generation_{0};
    std::thread::id owner_{};
    bool interrupt_complete_{false};
};

//! NodeContext struct containing references to chain state and connection
//! state.
//!
//! This is used by init, rpc, and test code to pass object references around
//! without needing to declare the same variables and parameters repeatedly, or
//! to use globals. More variables could be added to this struct (particularly
//! references to validation objects) to eliminate use of globals
//! and make code more modular and testable. The struct isn't intended to have
//! any member functions. It should just be a collection of references that can
//! be used without pulling in unwanted dependencies or functionality.
struct NodeContext {
    //! libbitcoin_kernel context
    std::unique_ptr<kernel::Context> kernel;
    std::unique_ptr<ECC_Context> ecc_context;
    //! Init interface for initializing current process and connecting to other processes.
    interfaces::Init* init{nullptr};
    //! Function to request a shutdown.
    std::function<bool()> shutdown_request;
    //! Interrupt object used to track whether node shutdown was requested.
    util::SignalInterrupt* shutdown_signal{nullptr};
    std::unique_ptr<AddrMan> addrman;
    std::unique_ptr<CConnman> connman;
    std::unique_ptr<CTxMemPool> mempool;
    std::unique_ptr<const NetGroupManager> netgroupman;
    std::unique_ptr<CBlockPolicyEstimator> fee_estimator;
    std::unique_ptr<PeerManager> peerman;
    std::unique_ptr<ChainstateManager> chainman;
    std::unique_ptr<BanMan> banman;
    ArgsManager* args{nullptr}; // Currently a raw pointer because the memory is not managed by this struct
    std::vector<BaseIndex*> indexes; // raw pointers because memory is not managed by this struct
    std::unique_ptr<interfaces::Chain> chain;
    //! List of all chain clients (wallet processes or other client) connected to node.
    std::vector<std::unique_ptr<interfaces::ChainClient>> chain_clients;
    //! Reference to chain client that should used to load or create wallets
    //! opened by the gui.
    std::unique_ptr<interfaces::Mining> mining;
    interfaces::WalletLoader* wallet_loader{nullptr};
    std::unique_ptr<CScheduler> scheduler;
    std::function<void()> rpc_interruption_point = [] {};
    //! Issues blocking calls about sync status, errors and warnings
    std::unique_ptr<KernelNotifications> notifications;
    //! Issues calls about blocks and transactions
    std::unique_ptr<ValidationSignals> validation_signals;
    std::atomic<int> exit_status{EXIT_SUCCESS};
    //! Manages all the node warnings
    std::unique_ptr<node::Warnings> warnings;
    std::thread background_init_thread;
    CleanupCoordinator cleanup_coordinator;
    mutable std::mutex cleanup_incident_mutex;
    std::string cleanup_incident_path;
    std::atomic<bool> cleanup_incident_persisted{false};
    std::atomic<bool> cleanup_incident_final_attempted{false};

    std::string GetCleanupIncidentPath() const;
    void SetCleanupIncidentPathIfEmpty(std::string path);

    //! Declare default constructor and destructor that are not inline, so code
    //! instantiating the NodeContext struct doesn't need to #include class
    //! definitions for all the unique_ptr members.
    NodeContext();
    ~NodeContext();
};
} // namespace node

#endif // BITCOIN_NODE_CONTEXT_H
