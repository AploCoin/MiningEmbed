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

class SerialConfig {
public:
    using DiagnosticsReader = BoardDiagnostics (*)();
    explicit SerialConfig(DeviceConfig& store, DiagnosticsReader diagnostics = nullptr);
    ~SerialConfig();
    // Bounded nonblocking input. Never print the supplied state verbatim.
    void poll(Stream& port, const char* state);

    bool restartRequested() const {
        return store_.restartRequested();
    }

    // Pause mining and release Web3/TLS runtime allocations during a staged edit.
    bool provisioningActive() const {
        return staged_ != nullptr;
    }

private:
    void command(Stream& port, const char* state);
    void clearStage();
    void clearLine();
    DeviceConfig& store_;
    DiagnosticsReader diagnostics_;
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
};
} // namespace provisioning
} // namespace miningembed
