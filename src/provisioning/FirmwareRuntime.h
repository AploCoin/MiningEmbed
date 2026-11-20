#pragma once

#include <memory>

#include "SerialConfig.h"

class Web3;

namespace miningembed {
namespace provisioning {

enum class NetworkState { Wifi, Clock, Ready };

// Mining and provisioning loop with board-owned flash, network and console.
class FirmwareRuntime {
public:
    using StartNetwork = void (*)(const Config&);
    using PollNetwork = NetworkState (*)();

    FirmwareRuntime(
        FlashBackend& storage,
        StartNetwork startNetwork,
        PollNetwork pollNetwork,
        SerialConfig::DiagnosticsReader diagnostics
    );
    ~FirmwareRuntime();
    FirmwareRuntime(const FirmwareRuntime&) = delete;
    FirmwareRuntime& operator=(const FirmwareRuntime&) = delete;

    void begin();
    // Returns true when the board should flush the reply and restart.
    bool poll(Stream& port);

private:
    void setTrust(const Config& config);
    bool startMiner(const Config& config);
    void pauseTrust(bool pause);
    void measure(uint32_t now);
    void runStep(uint32_t now);
    static void serveRpcProgress(void* context);
    const char* runDevice();

    DeviceConfig store_;
    RuntimeSnapshot snapshot_;
    SerialConfig serial_;
    StartNetwork startNetwork_;
    PollNetwork pollNetwork_;
    aplo::SessionKey key_;
    std::unique_ptr<Web3> web3_;
    std::unique_ptr<aplo::SessionKeys> rpc_;
    std::unique_ptr<MiningEmbed> miner_;
    const char* state_ = "unconfigured";
    const char* lastMiningState_ = "mining";
    bool trustPaused_ = false;
    bool miningBlocked_ = false;
    Stream* port_ = nullptr;
    uint32_t lastStepAt_ = 0, nextStepDelay_ = 0, lastSampleAt_ = 0;
    uint64_t lastSampleHashes_ = 0;
};

} // namespace provisioning
} // namespace miningembed
