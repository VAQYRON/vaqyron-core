// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/context.h>

#include <addrman.h>
#include <banman.h>
#include <interfaces/chain.h>
#include <interfaces/mining.h>
#include <kernel/context.h>
#include <key.h>
#include <net.h>
#include <net_processing.h>
#include <netgroup.h>
#include <node/kernel_notifications.h>
#include <node/warnings.h>
#include <policy/fees.h>
#include <scheduler.h>
#include <txmempool.h>
#include <validation.h>
#include <validationinterface.h>

#include <exception>
#include <utility>

namespace node {

CleanupResult CleanupCoordinator::RunInterrupt(const std::function<void()>& action)
{
    const std::thread::id caller{std::this_thread::get_id()};
    {
        std::unique_lock lock{mutex_};
        for (;;) {
            if (state_ == CleanupState::CLEANUP_INCOMPLETE) return CleanupResult::INCOMPLETE;
            if (interrupt_complete_ || state_ == CleanupState::CLEANUP_COMPLETE) return CleanupResult::COMPLETE;
            if (state_ == CleanupState::INTERRUPTING) {
                if (owner_ == caller) return CleanupResult::IN_PROGRESS;
                changed_.wait(lock, [this] {
                    return interrupt_complete_ || state_ == CleanupState::CLEANUP_INCOMPLETE;
                });
                continue;
            }
            if (state_ != CleanupState::NOT_STARTED) return CleanupResult::INCOMPLETE;
            state_ = CleanupState::INTERRUPTING;
            phase_ = CleanupPhase::INTERRUPT;
            last_progress_ = "Interrupt phase started";
            progress_time_ = std::chrono::steady_clock::now();
            ++generation_;
            owner_ = caller;
            break;
        }
    }

    try {
        action();
    } catch (const std::exception&) {
        MarkIncomplete(CleanupPhase::INTERRUPT, "Exception during interrupt phase");
        return CleanupResult::INCOMPLETE;
    } catch (...) {
        MarkIncomplete(CleanupPhase::INTERRUPT, "Unknown exception during interrupt phase");
        return CleanupResult::INCOMPLETE;
    }

    {
        std::lock_guard lock{mutex_};
        interrupt_complete_ = true;
        owner_ = {};
        last_progress_ = "Interrupt phase completed";
        progress_time_ = std::chrono::steady_clock::now();
        ++generation_;
    }
    changed_.notify_all();
    return CleanupResult::COMPLETE;
}

CleanupResult CleanupCoordinator::RunShutdown(const std::function<void()>& action)
{
    const std::thread::id caller{std::this_thread::get_id()};
    {
        std::unique_lock lock{mutex_};
        for (;;) {
            if (state_ == CleanupState::CLEANUP_INCOMPLETE) return CleanupResult::INCOMPLETE;
            if (state_ == CleanupState::CLEANUP_COMPLETE) return CleanupResult::COMPLETE;
            if (state_ == CleanupState::SHUTTING_DOWN) {
                if (owner_ == caller) return CleanupResult::IN_PROGRESS;
                changed_.wait(lock, [this] {
                    return state_ != CleanupState::SHUTTING_DOWN;
                });
                continue;
            }
            if (!interrupt_complete_) {
                if (state_ == CleanupState::INTERRUPTING && owner_ == caller) return CleanupResult::IN_PROGRESS;
                if (state_ == CleanupState::INTERRUPTING) {
                    changed_.wait(lock, [this] {
                        return interrupt_complete_ || state_ == CleanupState::CLEANUP_INCOMPLETE;
                    });
                    continue;
                }
                return CleanupResult::IN_PROGRESS;
            }
            state_ = CleanupState::SHUTTING_DOWN;
            phase_ = CleanupPhase::SHUTDOWN;
            last_progress_ = "Shutdown phase started";
            progress_time_ = std::chrono::steady_clock::now();
            ++generation_;
            owner_ = caller;
            break;
        }
    }

    try {
        action();
    } catch (const std::exception&) {
        MarkIncomplete(CleanupPhase::SHUTDOWN, "Exception during shutdown phase");
        return CleanupResult::INCOMPLETE;
    } catch (...) {
        MarkIncomplete(CleanupPhase::SHUTDOWN, "Unknown exception during shutdown phase");
        return CleanupResult::INCOMPLETE;
    }

    {
        std::lock_guard lock{mutex_};
        state_ = CleanupState::CLEANUP_COMPLETE;
        phase_ = CleanupPhase::NONE;
        owner_ = {};
        last_progress_ = "Shutdown phase completed";
        progress_time_ = std::chrono::steady_clock::now();
        ++generation_;
    }
    changed_.notify_all();
    return CleanupResult::COMPLETE;
}

bool CleanupCoordinator::RecordProgress(std::string progress)
{
    if (progress.size() > 128) progress.resize(128);
    std::lock_guard lock{mutex_};
    if (owner_ != std::this_thread::get_id() ||
        (state_ != CleanupState::INTERRUPTING && state_ != CleanupState::SHUTTING_DOWN)) {
        return false;
    }
    last_progress_ = std::move(progress);
    progress_time_ = std::chrono::steady_clock::now();
    ++generation_;
    changed_.notify_all();
    return true;
}

CleanupSnapshot CleanupCoordinator::Snapshot() const
{
    std::lock_guard lock{mutex_};
    const bool active = state_ == CleanupState::INTERRUPTING || state_ == CleanupState::SHUTTING_DOWN;
    const bool stalled = active && progress_time_ != std::chrono::steady_clock::time_point{} &&
        std::chrono::steady_clock::now() - progress_time_ >= std::chrono::seconds{30};
    return {state_, phase_, failing_phase_, diagnostic_, last_progress_, progress_time_, false, stalled, generation_};
}

bool CleanupCoordinator::WaitForChange(std::uint64_t generation, std::chrono::milliseconds timeout)
{
    std::unique_lock lock{mutex_};
    return changed_.wait_for(lock, timeout, [this, generation] {
        return generation_ != generation || state_ == CleanupState::CLEANUP_COMPLETE ||
            state_ == CleanupState::CLEANUP_INCOMPLETE;
    });
}

void CleanupCoordinator::MarkIncomplete(CleanupPhase phase, const char* diagnostic)
{
    {
        std::lock_guard lock{mutex_};
        state_ = CleanupState::CLEANUP_INCOMPLETE;
        phase_ = phase;
        failing_phase_ = phase;
        diagnostic_ = diagnostic;
        last_progress_ = diagnostic;
        progress_time_ = std::chrono::steady_clock::now();
        ++generation_;
        owner_ = {};
    }
    changed_.notify_all();
}

std::string NodeContext::GetCleanupIncidentPath() const
{
    std::lock_guard lock{cleanup_incident_mutex};
    return cleanup_incident_path;
}

void NodeContext::SetCleanupIncidentPathIfEmpty(std::string path)
{
    std::lock_guard lock{cleanup_incident_mutex};
    if (cleanup_incident_path.empty()) cleanup_incident_path = std::move(path);
}

NodeContext::NodeContext() = default;
NodeContext::~NodeContext() = default;
} // namespace node
