#pragma once
#include "DeviceConfig.h"
class Stream;

namespace miningembed {
namespace provisioning {
struct BoardDiagnostics {
    uint32_t resetReason;
    uint32_t cpuMHz;
    uint32_t flashBytes;
    uint32_t psramBytes;
    uint32_t freeHeapBytes;
    uint32_t largestHeapBlockBytes;
};

struct RuntimeSnapshot {
    const char* version = "dev";
    const char* board = "unknown";
    const char* layout = "unknown";
    uint32_t profileFlashBytes = 0, storageOffset = 0, storageSize = 0;
    const char* wifi = "inactive";
    const char* rpc = "idle";
    bool clockReady = false, busy = false;
    uint64_t hashes = 0;
    uint32_t hashesPerSecond = 0, activeHashesPerSecond = 0;
    uint32_t batch = 0, confirmed = 0, reverted = 0;
};

class SerialConfig {
public:
    using DiagnosticsReader = BoardDiagnostics (*)();
    explicit SerialConfig(
        DeviceConfig& store, DiagnosticsReader diagnostics = nullptr,
        const RuntimeSnapshot* snapshot = nullptr
    );
    ~SerialConfig();
    // Bounded nonblocking input. Never print the supplied state verbatim.
    void poll(Stream& port, const char* state, bool readOnly = false);

    bool restartRequested() const {
        return store_.restartRequested();
    }

    // Pause mining and release Web3/TLS runtime allocations during a staged edit.
    bool provisioningActive() const {
        return staged_ != nullptr;
    }

private:
    void command(Stream& port, const char* state);
    bool publicCommand(Stream& port, uint32_t id, const char* cmd, unsigned count);
    void recoveryCommand(Stream& port, uint32_t id, const char* cmd, const char* argument);
    void clearRecovery();
    void clearStage();
    void clearLine();
    DeviceConfig& store_;
    DiagnosticsReader diagnostics_;
    const RuntimeSnapshot* snapshot_;
    Stream* port_ = nullptr;
    Config* staged_ = nullptr;
    std::string upload_;
    size_t uploadLength_ = 0;
    bool uploadFallback_ = false;
    bool uploadActive_ = false;
    char line_[513] = {};
    size_t length_ = 0;
    bool discard_ = false, authenticated_ = false;
    uint32_t bootMs_, lastByteMs_ = 0, authMs_ = 0, stageMs_ = 0, retryMs_ = 0;
    bool retryWait_ = false;
    bool enrollmentClosed_ = false;
    bool frameReady_ = false, recoveryActive_ = false, recoveryIssued_ = false;
    uint32_t recoveryMs_ = 0;
    uint8_t recoveryDigest_[32] = {}, recoveryVerifier_[32] = {};
};
} // namespace provisioning
} // namespace miningembed
