#include "DeviceConfig.h"
#include <Web3.h>
extern "C" {
#include <trezor/sha2.h>
}
#include <trezor/sha3.h>
#include <cstring>
#include <limits>
#include <utility>

namespace miningembed {
namespace provisioning {
void wipe(void* bytes, size_t length) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(bytes);
    while (length--) {
        *p++ = 0;
    }
}

namespace {
void clearString(std::string& s) {
    if (!s.empty()) {
        wipe(&s[0], s.size());
    }
    s.clear();
}

bool any(const uint8_t* p, size_t n) {
    uint8_t v = 0;
    while (n--) {
        v |= *p++;
    }
    return v != 0;
}

bool equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t d = 0;
    while (n--) {
        d |= *a++ ^ *b++;
    }
    return d == 0;
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

bool hex(const std::string& s, size_t bytes, bool prefix = true) {
    size_t start = prefix ? 2 : 0;
    if (s.size() != bytes * 2 + start || (prefix && s.compare(0, 2, "0x") != 0)) {
        return false;
    }
    for (size_t i = start; i < s.size(); ++i) {
        if (nibble(s[i]) < 0) {
            return false;
        }
    }
    return true;
}

std::string lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'F') {
            c += 'a' - 'A';
        }
    }
    return s;
}

bool text(const std::string& s, size_t max) {
    if (s.size() > max) {
        return false;
    }
    for (unsigned char c : s) {
        if (c < 32 || c == 127) {
            return false;
        }
    }
    return true;
}

bool ntp(const std::string& s) {
    if (s.empty() || s.size() > 253) {
        return false;
    }
    for (unsigned char c : s) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-')) {
            return false;
        }
    }
    return true;
}

bool validPending(const miningembed::PendingTransaction& p) {
    if (p.nonce == UINT64_MAX || !hex(p.hash, 32) || p.raw.size() < 4 ||
        p.raw.size() > DeviceConfig::MaxRawTransaction || (p.raw.size() & 1) ||
        p.raw.compare(0, 2, "0x") != 0) {
        return false;
    }
    for (size_t i = 2; i < p.raw.size(); ++i) {
        if (nibble(p.raw[i]) < 0) {
            return false;
        }
    }
    SHA3_CTX ctx;
    keccak_256_Init(&ctx);
    uint8_t bytes[64];
    size_t used = 0;
    for (size_t i = 2; i < p.raw.size(); i += 2) {
        bytes[used++] = nibble(p.raw[i]) * 16 + nibble(p.raw[i + 1]);
        if (used == sizeof(bytes)) {
            keccak_Update(&ctx, bytes, used);
            used = 0;
        }
    }
    keccak_Update(&ctx, bytes, used);
    uint8_t hash[32];
    keccak_Final(&ctx, hash);
    uint8_t difference = 0;
    for (size_t i = 0; i < 32; ++i) {
        difference |= hash[i] ^ (nibble(p.hash[2 + i * 2]) * 16 + nibble(p.hash[3 + i * 2]));
    }
    wipe(bytes, sizeof(bytes));
    wipe(hash, sizeof(hash));
    wipe(&ctx, sizeof(ctx));
    return !difference && p.maxFee != uint256_t(0);
}

void number(std::string& b, uint64_t n, unsigned width) {
    while (width--) {
        b.push_back(static_cast<char>(n & 255));
        n >>= 8;
    }
}

void string(std::string& b, const std::string& s) {
    number(b, s.size(), 2);
    b.append(s);
}

struct Reader {
    const std::string& b;
    size_t at = 0;
    bool ok = true;

    explicit Reader(const std::string& bytes) : b(bytes) {}

    uint64_t number(unsigned width) {
        if (at + width > b.size()) {
            ok = false;
            return 0;
        }
        uint64_t n = 0;
        for (unsigned i = 0; i < width; ++i) {
            n |= uint64_t(uint8_t(b[at++])) << (8 * i);
        }
        return n;
    }

    void bytes(void* p, size_t n) {
        if (at + n > b.size()) {
            ok = false;
            return;
        }
        memcpy(p, b.data() + at, n);
        at += n;
    }

    void string(std::string& s, size_t max) {
        size_t n = number(2);
        if (!ok || n > max || at + n > b.size()) {
            ok = false;
            return;
        }
        s.assign(b.data() + at, n);
        at += n;
    }
};

constexpr size_t Header = 52;

void digest(const std::string& b, uint8_t out[32]) {
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, reinterpret_cast<const uint8_t*>(b.data()), 20);
    sha256_Update(&ctx, reinterpret_cast<const uint8_t*>(b.data() + Header), b.size() - Header);
    sha256_Final(&ctx, out);
    wipe(&ctx, sizeof(ctx));
}

std::string encode(const Config& c, const miningembed::PendingTransaction* p, uint64_t generation) {
    size_t capacity = Header + 3 + 64 + 24 + 17 + c.ssid.size() + c.password.size() +
                      c.primaryUrl.size() + c.fallbackUrl.size() + c.primaryCa.size() +
                      c.fallbackCa.size() + c.owner.size() + c.signer.size() + c.chainId.size() +
                      c.gaploBudget.size() + c.ntpPrimary.size() + c.ntpFallback.size();
    if (p) {
        capacity += 8 + 6 + p->hash.size() + p->raw.size() + 32 + p->maxFee.str(16).size();
    }
    std::string b("APFC", 4);
    b.reserve(capacity);
    number(b, 1, 2);
    number(b, 0, 2);
    number(b, generation, 8);
    number(b, 0, 4);
    b.append(32, '\0');
    number(b, static_cast<uint8_t>(c.mode), 1);
    number(b, c.enabled, 1);
    number(b, c.keyPresent, 1);
    b.append(reinterpret_cast<const char*>(c.key), 32);
    b.append(reinterpret_cast<const char*>(c.operatorVerifier), 32);
    string(b, c.ssid);
    string(b, c.password);
    string(b, c.primaryUrl);
    string(b, c.fallbackUrl);
    string(b, c.primaryCa);
    string(b, c.fallbackCa);
    string(b, c.owner);
    string(b, c.signer);
    string(b, c.chainId);
    string(b, c.gaploBudget);
    string(b, c.ntpPrimary);
    string(b, c.ntpFallback);
    number(b, c.expiry, 8);
    number(b, c.hashesPerStep, 4);
    number(b, c.intervalMs, 4);
    number(b, p != nullptr, 1);
    if (p) {
        number(b, p->nonce, 8);
        string(b, p->hash);
        string(b, p->raw);
        b.append(reinterpret_cast<const char*>(p->proof), 32);
        string(b, p->maxFee.str(16));
    }
    size_t size = b.size() - Header;
    for (unsigned i = 0; i < 4; ++i) {
        b[16 + i] = static_cast<char>(size >> (8 * i));
    }
    uint8_t d[32];
    digest(b, d);
    memcpy(&b[20], d, 32);
    wipe(d, sizeof(d));
    return b;
}

bool decode(
    const std::string& b,
    Config& c,
    miningembed::PendingTransaction& p,
    bool& has,
    uint64_t& gen
) {
    if (b.size() < Header || b.size() > DeviceConfig::MaxRecord || b.compare(0, 4, "APFC") != 0) {
        return false;
    }
    Reader r{b};
    r.at = 4;
    if (r.number(2) != 1 || r.number(2) != 0) {
        return false;
    }
    gen = r.number(8);
    if (!gen || r.number(4) != b.size() - Header) {
        return false;
    }
    uint8_t d[32];
    digest(b, d);
    bool integrity = equal(d, reinterpret_cast<const uint8_t*>(b.data() + 20), 32);
    wipe(d, sizeof(d));
    if (!integrity) {
        return false;
    }
    r.at = Header;
    uint64_t mode = r.number(1), enabled = r.number(1), key = r.number(1);
    if (mode > 1 || enabled > 1 || key > 1) {
        return false;
    }
    c.mode = static_cast<Mode>(mode);
    c.enabled = enabled;
    c.keyPresent = key;
    r.bytes(c.key, 32);
    r.bytes(c.operatorVerifier, 32);
    r.string(c.ssid, 32);
    r.string(c.password, 64);
    r.string(c.primaryUrl, 512);
    r.string(c.fallbackUrl, 512);
    r.string(c.primaryCa, DeviceConfig::MaxPem);
    r.string(c.fallbackCa, DeviceConfig::MaxPem);
    r.string(c.owner, 42);
    r.string(c.signer, 42);
    r.string(c.chainId, 78);
    r.string(c.gaploBudget, 78);
    r.string(c.ntpPrimary, 253);
    r.string(c.ntpFallback, 253);
    c.expiry = r.number(8);
    c.hashesPerStep = r.number(4);
    c.intervalMs = r.number(4);
    uint64_t flag = r.number(1);
    if (flag > 1) {
        return false;
    }
    has = flag;
    if (has) {
        p.nonce = r.number(8);
        r.string(p.hash, 66);
        r.string(p.raw, DeviceConfig::MaxRawTransaction);
        r.bytes(p.proof, 32);
        std::string fee;
        r.string(fee, 64);
        if (fee.empty()) {
            return false;
        }
        for (char v : fee) {
            if (nibble(v) < 0) {
                return false;
            }
        }
        p.maxFee = uint256_t("0x" + fee);
        if (!validPending(p)) {
            return false;
        }
    }
    return r.ok && r.at == b.size() && DeviceConfig::validate(c);
}

} // namespace

void clearConfig(Config& c) {
    wipe(c.key, sizeof(c.key));
    wipe(c.operatorVerifier, sizeof(c.operatorVerifier));
    clearString(c.password);
    clearString(c.primaryUrl);
    clearString(c.fallbackUrl);
    clearString(c.primaryCa);
    clearString(c.fallbackCa);
    c.keyPresent = false;
    c.enabled = false;
}

bool FlashBackend::verify(unsigned slot, const std::string& expected) {
    std::string actual;
    bool ok = read(slot, actual) == Read::Ok && actual == expected;
    clearString(actual);
    return ok;
}

DeviceConfig::DeviceConfig(FlashBackend& backend) : backend_(backend) {}

DeviceConfig::~DeviceConfig() {
    clearConfig(config_);
    clearString(pending_.raw);
}

bool DeviceConfig::validate(const Config& c) {
    uint256_t chainId;
    if ((c.mode != Mode::Session && c.mode != Mode::Direct) || !text(c.ssid, 32) ||
        !text(c.password, 64) || !ntp(c.ntpPrimary) ||
        (!c.ntpFallback.empty() && !ntp(c.ntpFallback)) || c.hashesPerStep < 1 ||
        c.hashesPerStep > 2000 || c.intervalMs < 100 || c.intervalMs > 60000 ||
        !text(c.chainId, 78) || !miningembed::parseMiningChainId(c.chainId.c_str(), chainId) ||
        c.gaploBudget.size() > 78 || c.primaryCa.size() > MaxPem || c.fallbackCa.size() > MaxPem ||
        !text(c.primaryUrl, 512) || !text(c.fallbackUrl, 512)) {
        return false;
    }
    for (const std::string* ca : {&c.primaryCa, &c.fallbackCa}) {
        if (!ca->empty() &&
            (ca->find('\0') != std::string::npos || !Web3::isValidCertificate(ca->c_str()))) {
            return false;
        }
    }
    for (const std::string* url : {&c.primaryUrl, &c.fallbackUrl}) {
        if (!url->empty() && !Web3::isHttpsUrl(url->c_str())) {
            return false;
        }
    }
    if ((!c.owner.empty() && !hex(c.owner, 20)) || (!c.signer.empty() && !hex(c.signer, 20))) {
        return false;
    }
    aplo::SessionKey key;
    if (c.keyPresent) {
        if (!key.Import(c.key)) {
            return false;
        }
        const bool pinOwner = c.mode == Mode::Direct && !c.owner.empty();
        if (pinOwner || !c.signer.empty()) {
            const auto address = key.Address();
            if ((!c.signer.empty() && address != lower(c.signer)) ||
                (pinOwner && address != lower(c.owner))) {
                return false;
            }
        }
    }
    if (!c.keyPresent && any(c.key, 32)) {
        return false;
    }
    if (!c.enabled) {
        return true;
    }
    if (!any(c.operatorVerifier, 32) || c.ssid.empty() || c.primaryUrl.empty() ||
        c.primaryCa.empty() || (!c.fallbackUrl.empty() && c.fallbackCa.empty()) || !c.keyPresent) {
        return false;
    }
    if (c.mode == Mode::Direct) {
        return true;
    }
    miningembed::MiningSession metadata;
    return miningembed::parseMiningSession(
        c.owner.c_str(),
        c.signer.c_str(),
        c.chainId.c_str(),
        c.gaploBudget.c_str(),
        c.expiry,
        metadata
    );
}

bool DeviceConfig::begin() {
    // Only once per instance: all returned borrowed buffers retain their lifetime.
    if (!locked_ || generation_ || restart_) {
        return false;
    }
    if (!backend_.begin()) {
        return false;
    }
    bool found = false;
    unsigned records = 0;
    for (unsigned slot = 0; slot < 2; ++slot) {
        std::string bytes;
        auto result = backend_.read(slot, bytes);
        if (result == FlashBackend::Read::Missing) {
            continue;
        }
        if (result != FlashBackend::Read::Ok) {
            clearString(bytes);
            return false;
        }
        Config c;
        miningembed::PendingTransaction p;
        bool has = false;
        uint64_t gen = 0;
        bool ok = decode(bytes, c, p, has, gen);
        clearString(bytes);
        uint64_t gap = gen > generation_ ? gen - generation_ : generation_ - gen;
        if (!ok || (found && gap != 1)) {
            clearConfig(c);
            clearString(p.raw);
            return false;
        }
        ++records;
        if (!found || gen > generation_) {
            clearConfig(config_);
            clearString(pending_.raw);
            config_ = std::move(c);
            pending_ = std::move(p);
            hasPending_ = has;
            generation_ = gen;
            activeSlot_ = slot;
            found = true;
        }
        clearConfig(c);
        clearString(p.raw);
    }
    // After the second commit both slots must exist. Do not silently accept an
    // NVS blob lost to CRC recovery or a deleted LittleFS slot as an empty journal.
    if (records == 1 && generation_ != 1) {
        return false;
    }
    locked_ = false;
    return true;
}

bool DeviceConfig::enrolled() const {
    return !locked_ && any(config_.operatorVerifier, 32);
}

bool DeviceConfig::ready() const {
    return !locked_ && !restart_ && enrolled() && config_.enabled;
}

const miningembed::PendingTransaction* DeviceConfig::pending() const {
    return !locked_ && hasPending_ ? &pending_ : nullptr;
}

bool DeviceConfig::persist(
    const Config& next,
    const miningembed::PendingTransaction* pending,
    bool immutable
) {
    if (locked_ || restart_ || generation_ == UINT64_MAX || (!immutable && !validate(next)) ||
        (pending && !validPending(*pending))) {
        return false;
    }
    std::string bytes = encode(next, pending, generation_ + 1);
    if (bytes.size() > MaxRecord || !backend_.replace(1 - activeSlot_, bytes)) {
        clearString(bytes);
        locked_ = true;
        return false;
    }
    // Verify exact readback before permitting any broadcast or reporting commit.
    bool ok = backend_.verify(1 - activeSlot_, bytes);
    clearString(bytes);
    if (!ok) {
        locked_ = true;
        return false;
    }
    activeSlot_ = 1 - activeSlot_;
    ++generation_;
    return true;
}

bool DeviceConfig::commit(const Config& next) {
    if (!enrolled() || !any(next.operatorVerifier, 32)) {
        return false;
    }
    if (hasPending_ && (next.mode != config_.mode || next.keyPresent != config_.keyPresent ||
                        !equal(next.key, config_.key, 32) || next.owner != config_.owner ||
                        next.signer != config_.signer || next.chainId != config_.chainId ||
                        next.expiry != config_.expiry || next.gaploBudget != config_.gaploBudget ||
                        next.enabled != config_.enabled || next.primaryUrl != config_.primaryUrl ||
                        next.fallbackUrl != config_.fallbackUrl)) {
        return false;
    }
    if (!persist(next, hasPending_ ? &pending_ : nullptr)) {
        return false;
    }
    restart_ = true;
    return true;
}

bool DeviceConfig::writePending(const miningembed::PendingTransaction* pending, void* context) {
    if (!context) {
        return false;
    }
    auto& store = *static_cast<DeviceConfig*>(context);
    if (!store.enrolled() || !store.config_.enabled ||
        !store.persist(store.config_, pending, true)) {
        return false;
    }
    if (pending != &store.pending_) {
        clearString(store.pending_.raw);
        store.pending_ = pending ? *pending : miningembed::PendingTransaction{};
    }
    store.hasPending_ = pending != nullptr;
    return true;
}

bool DeviceConfig::tokenVerifier(const std::string& token, uint8_t out[32]) {
    if (!hex(token, 32, false)) {
        return false;
    }
    uint8_t secret[32];
    for (size_t i = 0; i < 32; ++i) {
        secret[i] = uint8_t(nibble(token[i * 2]) * 16 + nibble(token[i * 2 + 1]));
    }
    if (!any(secret, 32)) {
        wipe(secret, sizeof(secret));
        return false;
    }
    const char domain[] = "FirmwareEmbed/Operator/v1";
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, reinterpret_cast<const uint8_t*>(domain), sizeof(domain) - 1);
    sha256_Update(&ctx, secret, sizeof(secret));
    sha256_Final(&ctx, out);
    wipe(secret, sizeof(secret));
    wipe(&ctx, sizeof(ctx));
    return true;
}

bool DeviceConfig::authenticate(const std::string& token) const {
    uint8_t verifier[32] = {};
    bool ok = enrolled() && !restart_ && tokenVerifier(token, verifier) &&
              equal(verifier, config_.operatorVerifier, 32);
    wipe(verifier, sizeof(verifier));
    return ok;
}

bool DeviceConfig::enroll(const std::string& token) {
    if (locked_ || enrolled() || hasPending_) {
        return false;
    }
    Config next;
    bool ok = tokenVerifier(token, next.operatorVerifier) && persist(next, nullptr);
    clearConfig(next);
    if (ok) {
        restart_ = true;
    }
    return ok;
}

bool DeviceConfig::factoryReset(const std::string& evidence) {
    if (!enrolled() || evidence != (hasPending_ ? pending_.hash : "NONE")) {
        return false;
    }
    // A fresh tombstone dominates both older slots; never erase the old slot first.
    Config blank;
    if (!persist(blank, nullptr)) {
        return false;
    }
    restart_ = true;
    return true;
}
} // namespace provisioning
} // namespace miningembed
