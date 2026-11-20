#include <AploTlsConfig.h>

#if APLO_ENABLE_HTTPS

#include "FirmwareRuntime.h"

#include <Arduino.h>
#include <Web3.h>
#include <new>

namespace miningembed {
namespace provisioning {
namespace {
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
    : store_(storage), serial_(store_, diagnostics), startNetwork_(startNetwork),
      pollNetwork_(pollNetwork) {}

FirmwareRuntime::~FirmwareRuntime() = default;

void FirmwareRuntime::begin() {
    if (store_.begin() && store_.ready()) {
        startNetwork_(store_.config());
    }
}

bool FirmwareRuntime::poll(Stream& port) {
    serial_.poll(port, state_);
    if (serial_.restartRequested()) {
        return true;
    }
    state_ = runDevice();
    return false;
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
        return "wifi";
    case NetworkState::Clock:
        return "clock";
    case NetworkState::Ready:
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
    if (now - lastStepAt_ >= config.intervalMs) {
        miningembed::Submission submission;
        const auto status = miner_->step(config.hashesPerStep, submission);
        lastStepAt_ = millis();
        lastMiningState_ = miningState(status, miner_->unresolved());
    }
    return lastMiningState_;
}

} // namespace provisioning
} // namespace miningembed

#endif
