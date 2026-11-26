// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef VAQYRON_WINSERVICE_H
#define VAQYRON_WINSERVICE_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

class ArgsManager;
namespace node {
struct NodeContext;
}

namespace vaqyron::winservice {

enum class ServiceLifecycleState {
    Uninitialized,
    Starting,
    Running,
    StopPending,
    Stopped,
    Failed,
};

struct ServiceConfig {
    bool enabled{false};
    bool pipe_enabled{false};
    bool testnet{false};
    bool identity_verified{false};
    bool shutdown_notify_configured{false};
    std::string service_name{"VAQYRONTestnetCoreDev"};
};

enum class ServiceProgressMilestone : std::uint8_t {
    StatusMonitorStarted,
    ChainstateLoaded,
    InitialTipAvailable,
    NetworkStarted,
    RpcListenersInterrupted,
    CoreWorkersInterrupted,
    RpcServersStopped,
    ClientsAndPortMappingStopPhaseCompleted,
    PeerServicesStopped,
    BackgroundWorkersStopped,
    MempoolDumpReturned,
    FeeEstimatorFlushReturned,
    InitialChainstateFlushReturned,
    ValidationCallbacksAndIndexesStopped,
    FinalChainstateResetReturned,
    PidFileRemoved,
};

class ServiceProgressTracker {
public:
    void BeginPendingStatus() noexcept;
    bool RecordCompletedMilestone(ServiceProgressMilestone milestone) noexcept;
    void RollbackMilestone(ServiceProgressMilestone milestone, std::uint32_t checkpoint) noexcept;
    std::uint32_t checkpoint() const noexcept;
    std::uint32_t HeartbeatCheckpoint() const noexcept;

private:
    std::uint64_t reported_milestones_{0};
    std::uint32_t checkpoint_{0};
};

using CoreServiceRunner = std::function<int(const std::function<bool()>&)>;

std::string DefaultServiceName();
std::string ServiceStateName(ServiceLifecycleState state);
bool IsWindowsServiceSupported();
bool IsServiceModeEnabled(const ArgsManager& args);
bool CanReportServiceRunning(const std::atomic<bool>& stop_requested);
bool RequestShutdownOnce(std::atomic<bool>& shutdown_requested, const std::function<void()>& request_shutdown);
bool ValidateServiceConfig(const ServiceConfig& config, std::string& error);
bool ValidateServiceIdentity(const std::wstring& expected_sid, const std::wstring& actual_token_sid,
    std::string& error);
bool HandleServiceStopRequest(std::atomic<bool>& stop_requested,
    const std::function<bool()>& report_stop_pending, const std::function<void()>& request_shutdown);
void ReportServiceProgress(ServiceProgressMilestone milestone);
void RequestServiceShutdown(node::NodeContext& node);
bool VerifyCurrentProcessServiceIdentity(const std::wstring& expected_account, std::string& error);
int RunWindowsService(node::NodeContext& node, const ArgsManager& args, const CoreServiceRunner& run_core);

class WinServiceController {
public:
    explicit WinServiceController(ServiceConfig config = {});

    ServiceLifecycleState state() const;
    bool IsRunning() const;
    bool IsStopping() const;
    bool IsFailed() const;

    bool Start();
    bool RequestStop();
    bool CompleteStop();
    bool Fail();
    bool Cancel();
    bool Reset();

private:
    ServiceConfig config_;
    mutable std::mutex lifecycle_mutex_;
    std::atomic<ServiceLifecycleState> state_{ServiceLifecycleState::Uninitialized};
    std::atomic<bool> stop_requested_{false};
};

} // namespace vaqyron::winservice

#endif // VAQYRON_WINSERVICE_H
