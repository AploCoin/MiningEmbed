#pragma once
#include <MiningEmbed.h>
#include <stdint.h>
#include <string>

namespace miningembed {
namespace provisioning {
enum class Mode : uint8_t { Session, Direct };

struct Config {
    Mode mode = Mode::Session;
    std::string ssid, password, primaryUrl, fallbackUrl, primaryCa, fallbackCa;
    std::string owner, signer, gaploBudget, chainId = "28282";
    std::string ntpPrimary = "pool.ntp.org", ntpFallback = "time.cloudflare.com";
    uint64_t expiry = 0;
    uint32_t hashesPerStep = 64, intervalMs = 1000;
    uint8_t key[32] = {};
    uint8_t operatorVerifier[32] = {};
    bool keyPresent = false, enabled = false;
};

// Slots are replaced atomically. Error/unknown/corrupt records lock the store.
// The board supplies its own flash backend.
class FlashBackend {
public:
    enum class Read { Missing, Ok, Error };
    virtual ~FlashBackend() = default;
    virtual bool begin() = 0;
    virtual Read read(unsigned slot, std::string& bytes) = 0;
    virtual bool replace(unsigned slot, const std::string& bytes) = 0;
    virtual bool verify(unsigned slot, const std::string& expected);
};

class DeviceConfig {
public:
    explicit DeviceConfig(FlashBackend& backend);
    ~DeviceConfig();
    DeviceConfig(const DeviceConfig&) = delete;
    DeviceConfig& operator=(const DeviceConfig&) = delete;
    bool begin();

    const Config& config() const {
        return config_;
    }

    bool ready() const;

    bool locked() const {
        return locked_;
    }

    bool enrolled() const;
    const miningembed::PendingTransaction* pending() const;
    static bool writePending(const miningembed::PendingTransaction* pending, void* context);

    // Config remains immutable in RAM after commit, preserving borrowed CA pointers.
    // Caller stops mining and restarts at a loop boundary when this becomes true.
    bool restartRequested() const {
        return restart_;
    }

    bool commit(const Config& next);
    bool enroll(const std::string& tokenHex);
    bool authenticate(const std::string& tokenHex) const;
    // Explicit matching public journal hash (or NONE), after external reconciliation.
    bool factoryReset(const std::string& evidence);
    static bool validate(const Config& config);
    static bool tokenVerifier(const std::string& tokenHex, uint8_t out[32]);
    static constexpr size_t MaxPem = 4096;
    static constexpr size_t MaxRecord = 16384;
    static constexpr size_t MaxRawTransaction = 514;

private:
    bool persist(
        const Config& next,
        const miningembed::PendingTransaction* pending,
        bool immutable = false
    );
    FlashBackend& backend_;
    Config config_;
    miningembed::PendingTransaction pending_;
    uint64_t generation_ = 0;
    unsigned activeSlot_ = 1;
    bool locked_ = true, restart_ = false, hasPending_ = false;
};

// Optimizer-resistant best-effort wiping of temporary secret buffers.
void wipe(void* bytes, size_t length);
void clearConfig(Config& config);
} // namespace provisioning
} // namespace miningembed
