// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef VAQYRON_RPC_NAMED_PIPE_H
#define VAQYRON_RPC_NAMED_PIPE_H

#include <rpc/request.h>

#include <any>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

class ArgsManager;
namespace node {
struct NodeContext;
}

namespace vaqyron::rpc {

using PipeDeadline = std::chrono::steady_clock::time_point;
inline constexpr unsigned int DEFAULT_PIPE_REQUEST_TIMEOUT_MS = 30000;

struct NamedPipeConfig {
    bool enabled{false};
    bool service_mode{false};
    bool allow_http_fallback{false};
    std::size_t max_frame_size{1024 * 1024};
    unsigned int request_timeout_ms{DEFAULT_PIPE_REQUEST_TIMEOUT_MS};
    std::string core_account{"NT SERVICE\\VAQYRONTestnetCoreDev"};
    std::string miner_account{"NT SERVICE\\VAQYRONMinerDev"};
};

using RpcDispatchCallback = std::function<UniValue(const JSONRPCRequest&)>;
using RpcDispatchAdmission = std::function<bool()>;

bool IsPipeFeatureEnabled(const ArgsManager& args);
bool ValidatePipeMode(bool enabled, bool service_mode, bool testnet, bool http_requested,
    bool& pipe_only, std::string& error);
unsigned int RemainingPipeTimeoutMs(PipeDeadline deadline, PipeDeadline now);
bool ValidatePipeFrameSize(std::size_t frame_size, std::size_t maximum, std::string& error);
bool ValidateClientIdentity(const std::wstring& expected_sid, const std::wstring& impersonated_token_sid,
    const std::wstring& process_token_sid, std::uint32_t client_pid, std::string& error);
bool IsRpcMethodAllowed(const std::string& method);
std::vector<std::string> AllowedRpcMethods();
bool DispatchRpcMessage(const std::string& message, const std::any& context,
    const RpcDispatchCallback& dispatch, std::string& response, std::string& error,
    const RpcDispatchAdmission& admit_dispatch = {});

bool BuildProtectedPipeSecurityDescriptor(const std::wstring& core_sid, const std::wstring& miner_sid,
    void*& descriptor, std::string& error);
bool ValidateProtectedPipeSecurityDescriptor(void* descriptor, const std::wstring& core_sid,
    const std::wstring& miner_sid, std::string& error);
void FreePipeSecurityDescriptor(void* descriptor);

class RpcNamedPipeServer {
public:
    explicit RpcNamedPipeServer(NamedPipeConfig config = {});
    ~RpcNamedPipeServer();

    RpcNamedPipeServer(const RpcNamedPipeServer&) = delete;
    RpcNamedPipeServer& operator=(const RpcNamedPipeServer&) = delete;

    bool Start(node::NodeContext& node, std::string& error);
    bool Stop();
    bool IsRunning() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

bool StartRpcNamedPipe(node::NodeContext& node, const NamedPipeConfig& config, std::string& error);
void StopRpcNamedPipe();
bool IsRpcNamedPipeRunning();

namespace detail {
bool IsPipeDeadlineActive(PipeDeadline deadline, PipeDeadline now) noexcept;
bool ShouldWritePipeResponse(bool processed, bool stopping, PipeDeadline deadline, PipeDeadline now) noexcept;

enum class PipeRegistryState {
    Stopped,
    Starting,
    Running,
    Stopping,
};

class PipeRegistryStateMachine {
public:
    bool Start(const std::function<bool()>& start)
    {
        std::lock_guard lock{mutex_};
        if (state_ != PipeRegistryState::Stopped) return false;
        state_ = PipeRegistryState::Starting;
        try {
            const bool started = start();
            state_ = started ? PipeRegistryState::Running : PipeRegistryState::Stopped;
            condition_.notify_all();
            return started;
        } catch (...) {
            state_ = PipeRegistryState::Stopped;
            condition_.notify_all();
            throw;
        }
    }

    void Stop(const std::function<void()>& stop)
    {
        std::unique_lock lock{mutex_};
        if (state_ == PipeRegistryState::Stopping) {
            condition_.wait(lock, [this] { return state_ == PipeRegistryState::Stopped; });
            return;
        }
        if (state_ == PipeRegistryState::Stopped) return;
        state_ = PipeRegistryState::Stopping;
        lock.unlock();
        stop();
        lock.lock();
        state_ = PipeRegistryState::Stopped;
        lock.unlock();
        condition_.notify_all();
    }

    bool IsRunning(const std::function<bool()>& running) const
    {
        std::lock_guard lock{mutex_};
        return state_ == PipeRegistryState::Running && running();
    }

    PipeRegistryState state() const
    {
        std::lock_guard lock{mutex_};
        return state_;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    PipeRegistryState state_{PipeRegistryState::Stopped};
};

#ifdef WIN32
bool ConnectPipeWithDeadline(void* pipe, void* stop_event, PipeDeadline deadline, std::string& error);
bool TransferPipeWithDeadline(void* pipe, void* stop_event, PipeDeadline deadline, void* data,
    std::uint32_t size, bool read, std::string& error);
#endif
}

} // namespace vaqyron::rpc

#endif // VAQYRON_RPC_NAMED_PIPE_H
