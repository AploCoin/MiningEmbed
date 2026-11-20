#include <AploTlsConfig.h>

#if APLO_ENABLE_HTTPS

#include "FirmwareRuntime.h"

#include <Arduino.h>
#include <Web3.h>
#include <algorithm>
#include <new>

#ifndef APLO_FIRMWARE_VERSION
#define APLO_FIRMWARE_VERSION "dev"
#endif
#ifndef APLO_BOARD_ID
#define APLO_BOARD_ID "unknown"
#endif
#ifndef APLO_FLASH_LAYOUT
#define APLO_FLASH_LAYOUT "unknown"
#endif
#ifndef APLO_FLASH_BYTES
#define APLO_FLASH_BYTES 0
#endif
#ifndef APLO_STORAGE_OFFSET
#define APLO_STORAGE_OFFSET 0
#endif
#ifndef APLO_STORAGE_SIZE
#define APLO_STORAGE_SIZE 0
#endif

namespace miningembed {
namespace provisioning {
namespace {
constexpr uint32_t sliceUs = 6000;
constexpr uint32_t maxBatch = 2000;
constexpr uint32_t pendingPollMs = 1000;

const char* miningState(miningembed::Status status, bool pending) {
    using miningembed::Status;
    switch (status) {
    case Status::JournalFailed:
        return "journal_error";
    case Status::RecoveryRequired:
        return "recovery_required";
    case Status::SignFailed:
        return "sign_failed";
    case Status::RandomUnavailable:
        return "random_unavailable";
    case Status::RpcUnavailable:
        return "rpc_unavailable";
    case Status::SessionInvalid:
        return "session_invalid";
    case Status::Expired:
        return "session_expired";
    case Status::BudgetExceeded:
        return "budget_exceeded";
    case Status::InsufficientFunds:
        return "insufficient_funds";
    case Status::NotStaked:
        return "not_staked";
    case Status::Cooldown:
        return "cooldown";
    default:
        return pending ? "pending" : "mining";
    }
}

} // namespace

FirmwareRuntime::FirmwareRuntime(
    FlashBackend& storage,
    StartNetwork startNetwork,
    PollNetwork pollNetwork,
    SerialConfig::DiagnosticsReader diagnostics
)
    : store_(storage), serial_(store_, diagnostics, &snapshot_), startNetwork_(startNetwork),
      pollNetwork_(pollNetwork) {
    snapshot_.version = APLO_FIRMWARE_VERSION;
    snapshot_.board = APLO_BOARD_ID;
    snapshot_.layout = APLO_FLASH_LAYOUT;
    snapshot_.profileFlashBytes = APLO_FLASH_BYTES;
    snapshot_.storageOffset = APLO_STORAGE_OFFSET;
    snapshot_.storageSize = APLO_STORAGE_SIZE;
}

FirmwareRuntime::~FirmwareRuntime() = default;

void FirmwareRuntime::begin() {
    lastSampleAt_ = millis();
    if (store_.begin() && store_.ready()) {
        snapshot_.batch = store_.config().hashesPerStep;
        startNetwork_(store_.config());
    }
}

bool FirmwareRuntime::poll(Stream& port) {
    port_ = &port;
    measure(millis());
    serial_.poll(port, state_);
    if (serial_.restartRequested()) {
        return true;
    }
    state_ = runDevice();
    return false;
}

void FirmwareRuntime::serveRpcIdle(void* context) {
    auto& app = *static_cast<FirmwareRuntime*>(context);
    app.measure(millis());
    if (app.port_) {
        app.serial_.poll(*app.port_, app.state_, true);
    }
}

void FirmwareRuntime::measure(uint32_t now) {
    const uint32_t elapsed = now - lastSampleAt_;
    if (elapsed >= 1000) {
        snapshot_.hashesPerSecond =
            static_cast<uint32_t>((snapshot_.hashes - lastSampleHashes_) * 1000 / elapsed);
        lastSampleHashes_ = snapshot_.hashes;
        lastSampleAt_ = now;
    }
}

void FirmwareRuntime::runStep(uint32_t now) {
    miningembed::Submission submission;
    snapshot_.busy = true;
    const auto status = miner_->step(snapshot_.batch, submission, now);
    snapshot_.busy = false;
    switch (web3_->lastRpcEndpoint()) {
    case Web3::RpcEndpointUsed::None:
        snapshot_.rpc = status == Status::RpcUnavailable ? "unavailable" : snapshot_.rpc;
        break;
    case Web3::RpcEndpointUsed::Primary:
        snapshot_.rpc = "primary";
        break;
    case Web3::RpcEndpointUsed::Fallback:
        snapshot_.rpc = "fallback";
        break;
    }
    const uint32_t hashes = miner_->hashesTested();
    const uint32_t duration = miner_->searchMicros();
    snapshot_.hashes += hashes;
    if (hashes && duration) {
        snapshot_.activeHashesPerSecond = static_cast<uint32_t>(uint64_t(hashes) * 1000000 / duration);
        if (hashes >= snapshot_.batch) {
            const uint32_t target = static_cast<uint32_t>(uint64_t(hashes) * sliceUs / duration);
            const uint32_t lower = std::max(uint32_t(1), snapshot_.batch / 2);
            const uint32_t upper = std::min(maxBatch, snapshot_.batch * 2);
            snapshot_.batch = std::min(upper, std::max(lower, target));
        }
    }
    if (submission.state == SubmissionState::Confirmed) {
        ++snapshot_.confirmed;
    } else if (submission.state == SubmissionState::Reverted) {
        ++snapshot_.reverted;
    }
    lastStepAt_ = millis();
    lastMiningState_ = miningState(status, miner_->unresolved());
    if (miner_->unresolved()) {
        nextStepDelay_ = pendingPollMs;
    } else if (status == Status::NoCandidate || status == Status::StaleChallenge || status == Status::Ok) {
        nextStepDelay_ = 0;
    } else {
        nextStepDelay_ = store_.config().intervalMs;
    }
}

void FirmwareRuntime::setTrust(const Config& config) {
    web3_->setCertificate(
        config.primaryCa.c_str(),
        config.fallbackCa.empty() ? nullptr : config.fallbackCa.c_str()
    );
}

bool FirmwareRuntime::startMiner(const Config& config) {
    if (!key_.Import(config.key)) {
        return false;
    }

    // On ESP8266 the constructor reserves the BearSSL secondary stack.
    // Wait until Wi-Fi has associated and DHCP completed.
    web3_.reset(new (std::nothrow) Web3(config.primaryUrl.c_str(), config.fallbackUrl.c_str()));
    if (!web3_) {
        return false;
    }
    web3_->setRpcIdleCallback(serveRpcIdle, this);
    rpc_.reset(new (std::nothrow) aplo::SessionKeys(*web3_));
    if (!rpc_) {
        return false;
    }
    setTrust(config);

    if (config.mode == Mode::Direct) {
        uint256_t chainId;
        if (!miningembed::parseMiningChainId(config.chainId.c_str(), chainId)) {
            return false;
        }
        miner_.reset(new (std::nothrow)
                         MiningEmbed(*rpc_, key_, chainId, DeviceConfig::writePending, &store_));
    } else {
        miningembed::MiningSession session;
        if (!miningembed::parseMiningSession(
                config.owner.c_str(),
                config.signer.c_str(),
                config.chainId.c_str(),
                config.gaploBudget.c_str(),
                config.expiry,
                session
            )) {
            return false;
        }
        miner_.reset(new (std::nothrow)
                         MiningEmbed(*rpc_, key_, session, DeviceConfig::writePending, &store_));
    }
    const auto* pending = store_.pending();
    return miner_ && (!pending || miner_->restore(*pending));
}

void FirmwareRuntime::pauseTrust(bool pause) {
    if (pause == trustPaused_) {
        return;
    }
    trustPaused_ = pause;
    if (web3_) {
        if (pause) {
            web3_->setCertificate(nullptr, nullptr);
        } else {
            setTrust(store_.config());
        }
    }
}

const char* FirmwareRuntime::runDevice() {
    if (store_.locked()) {
        return "storage_locked";
    }
    if (serial_.provisioningActive()) {
        pauseTrust(true);
        return "provisioning";
    }
    pauseTrust(false);
    if (!store_.ready()) {
        return store_.enrolled() ? "paused" : "unconfigured";
    }
    const Config& config = store_.config();

    switch (pollNetwork_()) {
    case NetworkState::Wifi:
        snapshot_.wifi = "connecting";
        snapshot_.clockReady = false;
        snapshot_.rpc = "idle";
        return "wifi";
    case NetworkState::Clock:
        snapshot_.wifi = "connected";
        snapshot_.clockReady = false;
        snapshot_.rpc = "idle";
        return "clock";
    case NetworkState::Ready:
        snapshot_.wifi = "connected";
        snapshot_.clockReady = true;
        break;
    }
    if (miningBlocked_) {
        return "journal_error";
    }
    if (!miner_ && !startMiner(config)) {
        // A mismatched or corrupt record must never fall through to new work.
        miner_.reset();
        rpc_.reset();
        web3_.reset();
        key_.Clear();
        miningBlocked_ = true;
        return "journal_error";
    }

    const uint32_t now = millis();
    if (now - lastStepAt_ >= nextStepDelay_) {
        runStep(now);
    }
    return lastMiningState_;
}

} // namespace provisioning
} // namespace miningembed

#endif
