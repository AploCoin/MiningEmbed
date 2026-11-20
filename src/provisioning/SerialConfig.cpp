#include "SerialConfig.h"
#include <Arduino.h>
#include <Web3.h>
#include <cstring>
#include <new>

namespace miningembed {
namespace provisioning {
namespace {
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

SerialConfig::SerialConfig(DeviceConfig& store, DiagnosticsReader diagnostics)
    : store_(store), diagnostics_(diagnostics), bootMs_(millis()) {}

SerialConfig::~SerialConfig() {
    clearStage();
    clearLine();
}

void SerialConfig::clearLine() {
    wipe(line_, sizeof(line_));
    length_ = 0;
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

void SerialConfig::poll(Stream& port, const char* state) {
    if (port_ != &port) {
        if (port_) {
            authenticated_ = false;
            clearStage();
            clearLine();
            discard_ = false;
        }
        port_ = &port;
    }
    uint32_t now = millis();
    if (uint32_t(now - bootMs_) >= 120000) {
        enrollmentClosed_ = true;
    }
    if (authenticated_ && uint32_t(now - authMs_) >= 120000) {
        authenticated_ = false;
        clearStage();
    }
    if (staged_ && uint32_t(now - stageMs_) >= 60000) {
        clearStage();
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
                command(port, state);
            } else if (discard_) {
                reply(port, 0, "ERR framing");
            }
            clearLine();
            discard_ = false;
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
    if (store_.locked() || store_.restartRequested()) {
        reply(port, id, "ERR unavailable");
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
