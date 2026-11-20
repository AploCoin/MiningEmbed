#include "SerialConfig.h"
#include <Arduino.h>
#include <Web3.h>
#include <cstring>
#include <new>
#include <session/SessionEncoding.h>
extern "C" {
#include <trezor/sha2.h>
}

namespace aplo {
bool SessionPlatformRandom(uint8_t* bytes, size_t length);
}

namespace miningembed {
namespace provisioning {
namespace {
// Stream writes are captured without touching the physical UART. The source's
// input is nonblocking; only public commands are dispatched through this view.
class ProgressStream : public Stream {
public:
    ProgressStream(Stream& source, char* output, size_t capacity)
        : source_(source), output_(output), capacity_(capacity) {}
    int available() override { return source_.available(); }
    int read() override { return source_.read(); }
    int peek() { return -1; }
    void flush() {}
    size_t write(uint8_t byte) override {
        if (length < capacity_) {
            output_[length++] = static_cast<char>(byte);
        } else {
            overflow = true;
        }
        return 1;
    }
    size_t length = 0;
    bool overflow = false;
private:
    Stream& source_;
    char* output_;
    size_t capacity_;
};

void erase(std::string& s) {
    if (!s.empty()) {
        wipe(&s[0], s.size());
    }
    s.clear();
}

bool decimal(const char* s, uint64_t& value) {
    value = 0;
    if (!s || !*s || (s[0] == '0' && s[1])) {
        return false;
    }
    for (; *s; ++s) {
        if (*s < '0' || *s > '9' || value > (UINT64_MAX - (*s - '0')) / 10) {
            return false;
        }
        value = value * 10 + (*s - '0');
    }
    return true;
}

int nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bool unhex(const char* input, std::string& output, size_t max) {
    size_t n = strlen(input);
    if (strcmp(input, "-") == 0) {
        output.clear();
        return true;
    }
    if (!n || (n & 1) || n > max * 2) {
        return false;
    }
    output.resize(n / 2);
    for (size_t i = 0; i < n / 2; ++i) {
        int a = nibble(input[i * 2]), b = nibble(input[i * 2 + 1]);
        if (a < 0 || b < 0) {
            erase(output);
            return false;
        }
        output[i] = static_cast<char>(a * 16 + b);
    }
    return true;
}

void reply(Stream& port, uint32_t id, const char* result) {
    port.print("APLO1 ");
    port.print(id);
    port.print(' ');
    port.println(result);
}

void prefix(Stream& port, uint32_t id, const char* label) {
    port.print("APLO1 ");
    port.print(id);
    port.print(" OK ");
    port.print(label);
}

void number(Stream& port, uint64_t value) {
    char digits[21] = {};
    char* p = digits + 20;
    do {
        *--p = static_cast<char>('0' + value % 10);
        value /= 10;
    } while (value);
    port.print(p);
}

void bytesHex(Stream& port, const uint8_t* bytes, size_t size) {
    const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i) {
        port.print(digits[bytes[i] >> 4]);
        port.print(digits[bytes[i] & 15]);
    }
}

bool numeric(const std::string& s) {
    return !s.empty() && s.find_first_not_of("0123456789") == std::string::npos;
}

bool readFrame(const char* line) {
    const char* id = strchr(line, ' ');
    const char* cmd = id ? strchr(id + 1, ' ') : nullptr;
    if (!cmd) {
        return false;
    }
    const char* const queries[] = {"STATUS", "DIAG", "GET_INFO", "GET_CONFIG", "GET_MINING_STATS",
                                  "GET_WALLET_INFO", "GET_NETWORK_STATUS"};
    for (const char* query : queries) {
        const size_t length = strlen(query);
        if (!strncmp(cmd + 1, query, length) &&
            (cmd[1 + length] == 0 || (cmd[1 + length] == '\r' && cmd[2 + length] == 0))) {
            return true;
        }
    }
    return false;
}

const char* safeState(const char* state) {
    const char* const allowed[] = {
        "storage_locked",
        "unconfigured",
        "paused",
        "wifi",
        "clock",
        "mining",
        "pending",
        "journal_error",
        "provisioning",
        "rpc_unavailable",
        "session_invalid",
        "session_expired",
        "budget_exceeded",
        "insufficient_funds",
        "not_staked",
        "cooldown",
        "recovery_required",
        "sign_failed",
        "random_unavailable",
        "setup",
        "time",
        "ready",
        "disabled",
        "error",
        "storage",
        "connecting",
        "offline"
    };
    if (state) {
        for (const char* candidate : allowed) {
            if (strcmp(state, candidate) == 0) {
                return candidate;
            }
        }
    }
    return "other";
}

bool set(Config& c, const char* name, std::string& value) {
    if (value.find('\0') != std::string::npos) {
        return false;
    }
    if (!strcmp(name, "ssid") && value.size() <= 32) {
        c.ssid = value;
    } else if (!strcmp(name, "password") && value.size() <= 64) {
        erase(c.password);
        c.password = value;
    } else if (!strcmp(name, "primary_url") && value.size() <= 512) {
        erase(c.primaryUrl);
        c.primaryUrl = value;
    } else if (!strcmp(name, "fallback_url") && value.size() <= 512) {
        erase(c.fallbackUrl);
        c.fallbackUrl = value;
    } else if (!strcmp(name, "owner") && value.size() <= 42) {
        c.owner = value;
    } else if (!strcmp(name, "signer") && value.size() <= 42) {
        c.signer = value;
    } else if (!strcmp(name, "chain_id") && value.size() <= 78) {
        c.chainId = value;
    } else if (!strcmp(name, "gaplo_budget") && value.size() <= 78) {
        c.gaploBudget = value;
    } else if (!strcmp(name, "ntp_primary") && value.size() <= 253) {
        c.ntpPrimary = value;
    } else if (!strcmp(name, "ntp_fallback") && value.size() <= 253) {
        c.ntpFallback = value;
    } else if (!strcmp(name, "mode")) {
        if (value == "session") {
            c.mode = Mode::Session;
        } else if (value == "direct") {
            c.mode = Mode::Direct;
        } else {
            return false;
        }
    } else if (!strcmp(name, "key")) {
        // Hex text representing the private scalar, itself encoded as SET's hex value.
        if (value.empty()) {
            wipe(c.key, 32);
            c.keyPresent = false;
            return true;
        }
        if (value.size() != 64) {
            return false;
        }
        uint8_t bytes[32] = {};
        for (size_t i = 0; i < 32; ++i) {
            int a = nibble(value[i * 2]), b = nibble(value[i * 2 + 1]);
            if (a < 0 || b < 0) {
                wipe(bytes, sizeof(bytes));
                return false;
            }
            bytes[i] = a * 16 + b;
        }
        aplo::SessionKey key;
        bool ok = key.Import(bytes);
        if (ok) {
            wipe(c.key, 32);
            memcpy(c.key, bytes, 32);
            c.keyPresent = true;
        }
        wipe(bytes, sizeof(bytes));
        return ok;
    } else if (!strcmp(name, "operator_token")) {
        uint8_t verifier[32] = {};
        bool ok = DeviceConfig::tokenVerifier(value, verifier);
        if (ok) {
            memcpy(c.operatorVerifier, verifier, 32);
        }
        wipe(verifier, sizeof(verifier));
        return ok;
    } else {
        uint64_t n = 0;
        if (!decimal(value.c_str(), n)) {
            return false;
        }
        if (!strcmp(name, "enabled") && n <= 1) {
            c.enabled = n;
        } else if (!strcmp(name, "expiry")) {
            c.expiry = n;
        } else if (!strcmp(name, "hashes_per_step") && n >= 1 && n <= 2000) {
            c.hashesPerStep = n;
        } else if (!strcmp(name, "interval_ms") && n >= 100 && n <= 60000) {
            c.intervalMs = n;
        } else {
            return false;
        }
    }
    return true;
}
} // namespace

SerialConfig::SerialConfig(
    DeviceConfig& store, DiagnosticsReader diagnostics, const RuntimeSnapshot* snapshot
) : store_(store), diagnostics_(diagnostics), snapshot_(snapshot), bootMs_(millis()) {}

SerialConfig::~SerialConfig() {
    clearStage();
    clearLine();
    clearRecovery();
    wipe(progressReply_, sizeof(progressReply_));
}

void SerialConfig::clearLine() {
    wipe(line_, sizeof(line_));
    length_ = 0;
    frameReady_ = false;
}

void SerialConfig::clearRecovery() {
    wipe(recoveryDigest_, sizeof(recoveryDigest_));
    wipe(recoveryVerifier_, sizeof(recoveryVerifier_));
    recoveryActive_ = false;
}

void SerialConfig::clearStage() {
    if (staged_) {
        clearConfig(*staged_);
        delete staged_;
        staged_ = nullptr;
    }
    erase(upload_);
    upload_.shrink_to_fit();
    uploadLength_ = 0;
    uploadActive_ = false;
}

void SerialConfig::poll(Stream& port, const char* state, bool readOnly) {
    if (progressActive_) {
        return;
    }
    progressActive_ = true;
    // Preserve reply ordering when returning from a TLS progress callback.
    if (port_ == &port) {
        while (progressOffset_ < progressLength_) {
            port.write(static_cast<uint8_t>(progressReply_[progressOffset_++]));
        }
    }
    progressLength_ = progressOffset_ = 0;
    pollInput(port, port, state, readOnly, false);
    progressActive_ = false;
}

void SerialConfig::pollProgress(Stream& port, const char* state) {
    if (progressActive_ || (port_ && port_ != &port)) {
        return;
    }
    progressActive_ = true;
    if (progressOffset_ == progressLength_) {
        progressLength_ = progressOffset_ = 0;
        ProgressStream captured(port, progressReply_, sizeof(progressReply_));
        pollInput(captured, port, state, true, true);
        progressLength_ = captured.length;
        if (captured.overflow) {
            const char error[] = "APLO1 0 ERR unavailable\n";
            memcpy(progressReply_, error, sizeof(error) - 1);
            progressLength_ = sizeof(error) - 1;
        }
    }
    // Even a large TX FIFO cannot make one callback monopolize a core yield.
    const int available = port.availableForWrite();
    unsigned budget = available > 64 ? 64 : (available > 0 ? unsigned(available) : 0);
    while (budget-- && progressOffset_ < progressLength_) {
        if (!port.write(static_cast<uint8_t>(progressReply_[progressOffset_]))) {
            break;
        }
        ++progressOffset_;
    }
    progressActive_ = false;
}

void SerialConfig::pollInput(
    Stream& port, Stream& identity, const char* state, bool readOnly, bool progress
) {
    if (port_ != &identity) {
        if (port_) {
            authenticated_ = false;
            clearStage();
            clearLine();
            clearRecovery();
            discard_ = false;
        }
        port_ = &identity;
    }
    uint32_t now = millis();
    if (uint32_t(now - bootMs_) >= 120000) {
        enrollmentClosed_ = true;
    }
    if (!progress && authenticated_ && uint32_t(now - authMs_) >= 120000) {
        authenticated_ = false;
        clearStage();
    }
    if (!progress && staged_ && uint32_t(now - stageMs_) >= 60000) {
        clearStage();
    }
    if (recoveryActive_ && uint32_t(now - recoveryMs_) >= 120000) {
        clearRecovery();
    }
    if (frameReady_) {
        if (readOnly) {
            return;
        }
        command(port, state);
        clearLine();
    }
    if (length_ && uint32_t(now - lastByteMs_) >= 2000) {
        clearLine();
        discard_ = true;
    }
    // Limits CPU time even when a host floods the port. No readString()/blocking timeout.
    unsigned budget = 256;
    while (budget-- && port.available() > 0) {
        int next = port.read();
        if (next < 0) {
            break;
        }
        char c = static_cast<char>(next);
        lastByteMs_ = now;
        if (c == '\n') {
            if (!discard_ && length_) {
                line_[length_] = 0;
                if (readOnly && !readFrame(line_)) {
                    // A mutating command must run outside the TLS call stack.
                    frameReady_ = true;
                    return;
                }
                command(port, state);
            } else if (discard_) {
                reply(port, 0, "ERR framing");
            }
            clearLine();
            discard_ = false;
            if (progress) {
                return;
            }
            continue;
        }
        if (discard_) {
            continue;
        }
        if (c == '\r') { // Only CR immediately before LF is accepted, never in a token.
            if (length_ < 512) {
                line_[length_++] = c;
            } else {
                clearLine();
                discard_ = true;
            }
            continue;
        }
        if (c < 32 || c > 126 || length_ == 512) {
            clearLine();
            discard_ = true;
            continue;
        }
        line_[length_++] = c;
    }
}

bool SerialConfig::publicCommand(Stream& port, uint32_t id, const char* cmd, unsigned count) {
    if (count != 3) {
        return false;
    }
    if (!strcmp(cmd, "GET_INFO")) {
        if (!snapshot_ || !diagnostics_) {
            reply(port, id, "ERR unavailable");
            return true;
        }
        prefix(port, id, "info version=");
        port.print(snapshot_->version);
        port.print(" board=");
        port.print(snapshot_->board);
        port.print(" layout=");
        port.print(snapshot_->layout);
        port.print(" flash_bytes=");
        port.print(diagnostics_().flashBytes);
        port.print(" profile_flash_bytes=");
        port.print(snapshot_->profileFlashBytes);
        port.print(" storage_offset=");
        port.print(snapshot_->storageOffset);
        port.print(" storage_size=");
        port.print(snapshot_->storageSize);
        port.println(" storage_schema=2");
        return true;
    }
    if (!strcmp(cmd, "GET_CONFIG") || !strcmp(cmd, "GET_WALLET_INFO")) {
        if (store_.locked()) {
            reply(port, id, "ERR unavailable");
            return true;
        }
        const Config& c = store_.config();
        if (!strcmp(cmd, "GET_WALLET_INFO")) {
            const auto& address = store_.walletAddress();
            prefix(port, id, "wallet address=");
            port.print(address.empty() ? "-" : address.c_str());
            port.print(" signer=");
            const auto& signer = c.mode == Mode::Direct ? address : c.signer;
            port.println(signer.empty() ? "-" : signer.c_str());
            return true;
        }
        prefix(port, id, "config mode=");
        port.print(store_.enrolled() ? (c.mode == Mode::Direct ? "direct" : "session") : "unset");
        port.print(" enabled=");
        port.print(c.enabled ? 1 : 0);
        port.print(" chain_id=");
        port.print(c.chainId.c_str());
        port.print(" expiry=");
        number(port, c.expiry);
        port.print(" gaplo_budget=");
        port.print(numeric(c.gaploBudget) ? c.gaploBudget.c_str() : "-");
        port.print(" ssid_set=");
        port.print(c.ssid.empty() ? 0 : 1);
        port.print(" primary_set=");
        port.print(c.primaryUrl.empty() ? 0 : 1);
        port.print(" fallback_set=");
        port.print(c.fallbackUrl.empty() ? 0 : 1);
        port.print(" primary_ca_set=");
        port.print(c.primaryCa.empty() ? 0 : 1);
        port.print(" fallback_ca_set=");
        port.print(c.fallbackCa.empty() ? 0 : 1);
        port.println(" scheduler=adaptive");
        return true;
    }
    if (!strcmp(cmd, "GET_MINING_STATS") || !strcmp(cmd, "GET_NETWORK_STATUS")) {
        if (!snapshot_) {
            reply(port, id, "ERR unavailable");
            return true;
        }
        if (!strcmp(cmd, "GET_NETWORK_STATUS")) {
            prefix(port, id, "network wifi=");
            port.print(snapshot_->wifi);
            port.print(" clock_ready=");
            port.print(snapshot_->clockReady ? 1 : 0);
            port.print(" rpc=");
            port.println(snapshot_->busy ? "busy" : snapshot_->rpc);
            return true;
        }
        prefix(port, id, "stats hashes=");
        number(port, snapshot_->hashes);
        port.print(" hashes_per_second=");
        port.print(snapshot_->hashesPerSecond);
        port.print(" active_hashes_per_second=");
        port.print(snapshot_->activeHashesPerSecond);
        port.print(" batch=");
        port.print(snapshot_->batch);
        port.print(" confirmed=");
        port.print(snapshot_->confirmed);
        port.print(" reverted=");
        port.print(snapshot_->reverted);
        port.print('\n');
        return true;
    }
    return false;
}

void SerialConfig::recoveryCommand(Stream& port, uint32_t id, const char* cmd, const char* input) {
    const uint32_t now = millis();
    const auto& owner = store_.walletAddress();
    if (!store_.enrolled() || owner.empty()) {
        reply(port, id, "ERR recovery");
        return;
    }
    std::string argument;
    if (!strcmp(cmd, "RECOVERY_CHALLENGE")) {
        if (recoveryIssued_ && uint32_t(now - recoveryMs_) < 5000) {
            reply(port, id, "ERR recovery");
            return;
        }
        clearRecovery();
        recoveryIssued_ = true;
        recoveryMs_ = now;
        uint8_t random[32] = {};
        const bool ok = unhex(input, argument, 32) && argument.size() == 32 &&
                        argument.find_first_not_of('\0') != std::string::npos &&
                        aplo::SessionPlatformRandom(random, sizeof(random));
        if (ok) {
            memcpy(recoveryVerifier_, argument.data(), 32);
            const char domain[] = "FirmwareEmbed/OperatorRecovery/v1";
            uint64_t generation = store_.generation();
            uint8_t generationBytes[8];
            for (unsigned i = 0; i < 8; ++i) {
                generationBytes[i] = static_cast<uint8_t>(generation >> (8 * i));
            }
            SHA256_CTX ctx;
            sha256_Init(&ctx);
            sha256_Update(&ctx, reinterpret_cast<const uint8_t*>(domain), sizeof(domain) - 1);
            sha256_Update(&ctx, random, sizeof(random));
            sha256_Update(&ctx, generationBytes, sizeof(generationBytes));
            sha256_Update(&ctx, recoveryVerifier_, sizeof(recoveryVerifier_));
            sha256_Update(&ctx, reinterpret_cast<const uint8_t*>(owner.data()), owner.size());
            sha256_Final(&ctx, recoveryDigest_);
            wipe(&ctx, sizeof(ctx));
        }
        wipe(random, sizeof(random));
        erase(argument);
        if (!ok) {
            reply(port, id, "ERR recovery");
            return;
        }
        recoveryActive_ = true;
        prefix(port, id, "recovery_challenge digest=");
        bytesHex(port, recoveryDigest_, sizeof(recoveryDigest_));
        port.print(" owner=");
        port.println(owner.c_str());
        return;
    }
    const bool ok = recoveryActive_ && unhex(input, argument, 65) && argument.size() == 65 &&
                    aplo::detail::signatureMatches(
                        reinterpret_cast<const uint8_t*>(argument.data()), recoveryDigest_, owner
                    ) && store_.recoverOperator(recoveryVerifier_);
    erase(argument);
    clearRecovery();
    if (ok) {
        clearStage();
        authenticated_ = false;
    }
    reply(port, id, ok ? "OK restart" : "ERR recovery");
}

void SerialConfig::command(Stream& port, const char* state) {
    if (length_ && line_[length_ - 1] == '\r') {
        line_[--length_] = 0;
    }
    // In-place tokens avoid retaining extra copies of secret request lines.
    char* args[7] = {};
    unsigned count = 0;
    char* p = line_;
    while (*p && count < 7) {
        if (*p == ' ') {
            reply(port, 0, "ERR framing");
            return;
        }
        args[count++] = p;
        while (*p && *p != ' ') {
            if (*p < 33 || *p > 126) {
                reply(port, 0, "ERR framing");
                return;
            }
            ++p;
        }
        if (*p) {
            *p++ = 0;
            if (!*p) {
                reply(port, 0, "ERR framing");
                return;
            }
        }
    }
    uint64_t id64 = 0;
    if (*p || count < 3 || strcmp(args[0], "APLO1") || !decimal(args[1], id64) ||
        id64 > UINT32_MAX) {
        reply(port, 0, "ERR framing");
        return;
    }
    uint32_t id = id64, now = millis();
    const char* cmd = args[2];
    if (!strcmp(cmd, "STATUS") && count == 3) {
        port.print("APLO1 ");
        port.print(id);
        port.print(" OK status locked=");
        port.print(store_.locked() ? 1 : 0);
        port.print(" enrolled=");
        port.print(store_.enrolled() ? 1 : 0);
        port.print(" ready=");
        port.print(store_.ready() ? 1 : 0);
        port.print(" pending=");
        port.print(store_.pending() ? 1 : 0);
        port.print(" restart=");
        port.print(store_.restartRequested() ? 1 : 0);
        port.print(" mode=");
        port.print(
            store_.enrolled() ? (store_.config().mode == Mode::Direct ? "direct" : "session")
                              : "unset"
        );
        port.print(" state=");
        port.print(safeState(state));
        port.print(" journal=");
        port.println(store_.pending() ? store_.pending()->hash.c_str() : "NONE");
        return;
    }
    if (!strcmp(cmd, "DIAG") && count == 3) {
        if (!diagnostics_) {
            reply(port, id, "ERR unavailable");
            return;
        }
        const BoardDiagnostics sample = diagnostics_();
        port.print(F("APLO1 "));
        port.print(id);
        port.print(F(" OK diag reset_reason="));
        port.print(sample.resetReason);
        port.print(F(" uptime_ms="));
        port.print(now);
        port.print(F(" cpu_mhz="));
        port.print(sample.cpuMHz);
        port.print(F(" flash_bytes="));
        port.print(sample.flashBytes);
        port.print(F(" psram_bytes="));
        port.print(sample.psramBytes);
        port.print(F(" heap_free="));
        port.print(sample.freeHeapBytes);
        port.print(F(" heap_largest="));
        port.print(sample.largestHeapBlockBytes);
        port.println("");
        return;
    }
    if (publicCommand(port, id, cmd, count)) {
        return;
    }
    if (store_.locked() || store_.restartRequested()) {
        reply(port, id, "ERR unavailable");
        return;
    }
    if ((!strcmp(cmd, "RECOVERY_CHALLENGE") || !strcmp(cmd, "RECOVER")) && count == 4) {
        recoveryCommand(port, id, cmd, args[3]);
        return;
    }
    if (!strcmp(cmd, "ENROLL") && count == 5) {
        if (enrollmentClosed_ || uint32_t(now - bootMs_) >= 120000 ||
            strcmp(args[4], "I_HAVE_PHYSICAL_USB_CONTROL")) {
            reply(port, id, "ERR enrollment");
            return;
        }
        std::string token(args[3]);
        bool ok = store_.enroll(token);
        erase(token);
        reply(port, id, ok ? "OK restart" : "ERR enrollment");
        return;
    }
    if (!strcmp(cmd, "AUTH") && count == 4) {
        clearStage();
        authenticated_ = false;
        if (retryWait_ && uint32_t(now - retryMs_) < 5000) {
            reply(port, id, "ERR auth");
            return;
        }
        std::string token(args[3]);
        bool ok = store_.authenticate(token);
        erase(token);
        if (ok) {
            authenticated_ = true;
            authMs_ = now;
            retryWait_ = false;
        } else {
            retryWait_ = true;
            retryMs_ = now;
        }
        reply(port, id, ok ? "OK authenticated" : "ERR auth");
        return;
    }
    if (!authenticated_) {
        reply(port, id, "ERR auth");
        return;
    }
    // AUTH lifetime is absolute; successful commands do not prolong it indefinitely.
    if (!strcmp(cmd, "LOGOUT") && count == 3) {
        authenticated_ = false;
        clearStage();
        reply(port, id, "OK");
        return;
    }
    if (!strcmp(cmd, "RESET") && count == 5) {
        bool ack = !strcmp(args[4], "ERASE_LOCAL_ONLY_I_HAVE_RECONCILED_CHAIN");
        bool ok = ack && store_.factoryReset(args[3]);
        clearStage();
        reply(port, id, ok ? "OK restart" : "ERR reset");
        return;
    }
    if (!strcmp(cmd, "ABORT") && count == 3) {
        clearStage();
        reply(port, id, "OK");
        return;
    }
    if (!strcmp(cmd, "BEGIN") && count == 3) {
        clearStage();
        staged_ = new (std::nothrow) Config(store_.config());
        stageMs_ = now;
        reply(port, id, staged_ ? "OK" : "ERR memory");
        return;
    }
    if (!staged_) {
        reply(port, id, "ERR transaction");
        return;
    }
    stageMs_ = now;
    if (!strcmp(cmd, "SET") && count == 5) {
        std::string value;
        bool ok = unhex(args[4], value, 224) && set(*staged_, args[3], value);
        erase(value);
        reply(port, id, ok ? "OK" : "ERR value");
        return;
    }
    if (!strcmp(cmd, "CA_BEGIN") && count == 5) {
        uint64_t size = 0;
        if ((strcmp(args[3], "primary") && strcmp(args[3], "fallback")) ||
            !decimal(args[4], size) || size > DeviceConfig::MaxPem) {
            reply(port, id, "ERR value");
            return;
        }
        erase(upload_);
        uploadLength_ = size;
        uploadActive_ = true;
        uploadFallback_ = !strcmp(args[3], "fallback");
        upload_.reserve(size);
        reply(port, id, "OK");
        return;
    }
    if (!strcmp(cmd, "CA_CHUNK") && count == 5) {
        uint64_t offset = 0;
        std::string bytes;
        bool ok = uploadActive_ && uploadLength_ && decimal(args[3], offset) &&
                  unhex(args[4], bytes, 192) && !bytes.empty() && offset <= upload_.size() &&
                  offset + bytes.size() <= uploadLength_ && bytes.find('\0') == std::string::npos;
        if (ok) {
            if (offset == upload_.size()) {
                upload_.append(bytes);
            } else {
                ok = offset + bytes.size() <= upload_.size() &&
                     upload_.compare(offset, bytes.size(), bytes) == 0;
            }
        }
        erase(bytes);
        reply(port, id, ok ? "OK" : "ERR chunk");
        return;
    }
    if (!strcmp(cmd, "CA_END") && count == 3) {
        if (!uploadActive_ || upload_.size() != uploadLength_ ||
            (!upload_.empty() && !Web3::isValidCertificate(upload_.c_str()))) {
            reply(port, id, "ERR certificate");
            return;
        }
        std::string& destination = uploadFallback_ ? staged_->fallbackCa : staged_->primaryCa;
        erase(destination);
        destination.swap(upload_);
        erase(upload_);
        uploadLength_ = 0;
        uploadActive_ = false;
        reply(port, id, "OK");
        return;
    }
    if (!strcmp(cmd, "COMMIT") && count == 3) {
        if (uploadActive_) {
            reply(port, id, "ERR upload");
            return;
        }
        bool ok = DeviceConfig::validate(*staged_) && store_.commit(*staged_);
        if (ok || store_.locked()) {
            clearStage();
        }
        reply(port, id, ok ? "OK restart" : "ERR commit");
        return;
    }
    reply(port, id, "ERR command");
}
} // namespace provisioning
} // namespace miningembed
