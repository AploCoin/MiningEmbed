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

std::string header(const char* magic, unsigned version, uint64_t generation, size_t capacity) {
    std::string b(magic, 4);
    b.reserve(capacity);
    number(b, version, 2);
    number(b, 0, 2);
    number(b, generation, 8);
    number(b, 0, 4);
    b.append(32, '\0');
    return b;
}

void seal(std::string& b) {
    size_t size = b.size() - Header;
    for (unsigned i = 0; i < 4; ++i) {
        b[16 + i] = static_cast<char>(size >> (8 * i));
    }
    uint8_t d[32];
    digest(b, d);
    memcpy(&b[20], d, 32);
    wipe(d, sizeof(d));
}

unsigned readHeader(Reader& r, const char* magic, size_t maximum, uint64_t& gen) {
    const auto& b = r.b;
    if (b.size() < Header || b.size() > maximum || b.compare(0, 4, magic) != 0) {
        return 0;
    }
    r.at = 4;
    unsigned version = r.number(2);
    if (r.number(2) != 0) {
        return 0;
    }
    gen = r.number(8);
    if (!gen || r.number(4) != b.size() - Header) {
        return 0;
    }
    uint8_t d[32];
    digest(b, d);
    bool ok = equal(d, reinterpret_cast<const uint8_t*>(b.data() + 20), 32);
    wipe(d, sizeof(d));
    r.at = Header;
    return ok ? version : 0;
}

std::string encodeConfig(const Config& c, uint64_t generation, uint64_t floor) {
    size_t capacity = Header + 3 + 64 + 24 + 24 + c.ssid.size() + c.password.size() +
                      c.primaryUrl.size() + c.fallbackUrl.size() + c.primaryCa.size() +
                      c.fallbackCa.size() + c.owner.size() + c.signer.size() + c.chainId.size() +
                      c.gaploBudget.size() + c.ntpPrimary.size() + c.ntpFallback.size();
    auto b = header("APFC", 2, generation, capacity);
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
    number(b, floor, 8);
    seal(b);
    return b;
}

bool samePending(
    const miningembed::PendingTransaction* a, const miningembed::PendingTransaction* b
) {
    if (!a || !b) {
        return a == b;
    }
    return a->nonce == b->nonce && a->hash == b->hash && a->raw == b->raw &&
           a->maxFee == b->maxFee && equal(a->proof, b->proof, sizeof(a->proof));
}

std::string encodeJournal(const miningembed::PendingTransaction* p, uint64_t generation) {
    auto b = header("APFJ", 1, generation, p ? DeviceConfig::MaxJournalRecord : Header + 1);
    number(b, p != nullptr, 1);
    if (p) {
        number(b, p->nonce, 8);
        string(b, p->hash);
        string(b, p->raw);
        b.append(reinterpret_cast<const char*>(p->proof), 32);
        string(b, p->maxFee.str(16));
    }
    seal(b);
    return b;
}

bool decodePending(Reader& r, miningembed::PendingTransaction& p, bool& has) {
    const uint64_t flag = r.number(1);
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
    return r.ok && r.at == r.b.size();
}

bool decodeConfig(
    const std::string& b, Config& c, miningembed::PendingTransaction& p, bool& has,
    uint64_t& gen, uint64_t& floor, unsigned& version
) {
    Reader r{b};
    version = readHeader(r, "APFC", DeviceConfig::MaxRecord, gen);
    if (version != 1 && version != 2) {
        return false;
    }
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
    if (version == 1) {
        if (!decodePending(r, p, has)) {
            return false;
        }
    } else {
        floor = r.number(8);
    }
    return r.ok && r.at == b.size() && DeviceConfig::validate(c);
}

bool consecutive(uint64_t a, uint64_t b) {
    return a > b ? a - b == 1 : b - a == 1;
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

bool DeviceConfig::loadJournal() {
    unsigned records = 0;
    for (unsigned slot = 2; slot < 4; ++slot) {
        std::string bytes;
        const auto result = backend_.read(slot, bytes);
        if (result == FlashBackend::Read::Missing) {
            continue;
        }
        Reader r(bytes);
        uint64_t gen = 0;
        miningembed::PendingTransaction p;
        bool has = false;
        bool ok = result == FlashBackend::Read::Ok &&
                  readHeader(r, "APFJ", MaxJournalRecord, gen) == 1 &&
                  decodePending(r, p, has) &&
                  (!records || consecutive(gen, journalGeneration_));
        clearString(bytes);
        if (ok && gen > journalGeneration_) {
            clearString(pending_.raw);
            pending_ = std::move(p);
            hasPending_ = has;
            journalGeneration_ = gen;
            journalSlot_ = slot;
        }
        clearString(p.raw);
        if (!ok) {
            return false;
        }
        ++records;
    }
    return records != 1 || journalGeneration_ == 1;
}

bool DeviceConfig::begin() {
    // Only once per instance: all returned borrowed buffers retain their lifetime.
    if (!locked_ || generation_ || restart_ || !backend_.begin()) {
        return false;
    }
    unsigned records = 0, version = 0;
    miningembed::PendingTransaction legacy;
    bool hasLegacy = false;
    for (unsigned slot = 0; slot < 2; ++slot) {
        std::string bytes;
        const auto result = backend_.read(slot, bytes);
        if (result == FlashBackend::Read::Missing) {
            continue;
        }
        Config c;
        miningembed::PendingTransaction p;
        bool has = false;
        uint64_t gen = 0, floor = 0;
        unsigned schema = 0;
        const bool ok = result == FlashBackend::Read::Ok &&
                        decodeConfig(bytes, c, p, has, gen, floor, schema) &&
                        (!records || (consecutive(gen, generation_) &&
                                      (gen > generation_ ? schema >= version : schema <= version)));
        clearString(bytes);
        if (ok && gen > generation_) {
            clearConfig(config_);
            clearString(legacy.raw);
            config_ = std::move(c);
            legacy = std::move(p);
            hasLegacy = has;
            generation_ = gen;
            activeSlot_ = slot;
            journalFloor_ = floor;
            version = schema;
        }
        clearConfig(c);
        clearString(p.raw);
        if (!ok) {
            clearString(legacy.raw);
            return false;
        }
        ++records;
    }
    if ((records == 1 && generation_ != 1) || !loadJournal() ||
        (version == 2 && (journalGeneration_ < 2 || journalFloor_ > journalGeneration_))) {
        clearString(legacy.raw);
        return false;
    }

    if (version != 2) {
        const auto* expected = hasLegacy ? &legacy : nullptr;
        // The journal is written before the new config. A power cut in between leaves
        // a matching initial journal that the next boot can adopt.
        if (journalGeneration_ && (journalGeneration_ > 2 ||
                                   !samePending(expected, hasPending_ ? &pending_ : nullptr))) {
            clearString(legacy.raw);
            return false;
        }
        if (version == 1 && (!initializeJournal(expected) || !persist(config_, 0))) {
            clearString(legacy.raw);
            return false;
        }
        if (hasLegacy) {
            clearString(pending_.raw);
            pending_ = std::move(legacy);
            hasPending_ = true;
        }
    }
    clearString(legacy.raw);
    if (journalGeneration_ <= journalFloor_) {
        clearString(pending_.raw);
        pending_ = miningembed::PendingTransaction{};
        hasPending_ = false;
    }
    if (hasPending_ && !config_.enabled) {
        return false;
    }
    if (config_.keyPresent) {
        if (config_.mode == Mode::Session) {
            walletAddress_ = lower(config_.owner);
        } else {
            aplo::SessionKey key;
            if (!key.Import(config_.key)) {
                return false;
            }
            walletAddress_ = key.Address();
        }
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

bool DeviceConfig::writeRecord(unsigned slot, std::string& bytes, size_t maximum) {
    const bool ok = bytes.size() <= maximum && backend_.replace(slot, bytes) &&
                    backend_.verify(slot, bytes);
    clearString(bytes);
    if (!ok) {
        locked_ = true;
    }
    return ok;
}

bool DeviceConfig::persist(const Config& next, uint64_t journalFloor) {
    if (restart_ || generation_ == UINT64_MAX || !validate(next)) {
        return false;
    }
    auto bytes = encodeConfig(next, generation_ + 1, journalFloor);
    if (!writeRecord(1 - activeSlot_, bytes, MaxRecord)) {
        return false;
    }
    activeSlot_ = 1 - activeSlot_;
    ++generation_;
    return true;
}

bool DeviceConfig::persistJournal(const miningembed::PendingTransaction* pending) {
    if (restart_ || journalGeneration_ == UINT64_MAX || (pending && !validPending(*pending))) {
        return false;
    }
    auto bytes = encodeJournal(pending, journalGeneration_ + 1);
    const unsigned slot = 5 - journalSlot_;
    if (!writeRecord(slot, bytes, MaxJournalRecord)) {
        return false;
    }
    journalSlot_ = slot;
    ++journalGeneration_;
    return true;
}

bool DeviceConfig::initializeJournal(const miningembed::PendingTransaction* pending) {
    // A live store always has both copies, including before its first broadcast.
    while (journalGeneration_ < 2) {
        if (!persistJournal(pending)) {
            return false;
        }
    }
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
    if (!persist(next, journalFloor_)) {
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
    if (!store.enrolled() || !store.config_.enabled || store.restart_) {
        return false;
    }
    const auto* current = store.hasPending_ ? &store.pending_ : nullptr;
    if (samePending(pending, current)) {
        return true;
    }
    if ((pending && current) || !store.persistJournal(pending)) {
        return false;
    }
    clearString(store.pending_.raw);
    store.pending_ = pending ? *pending : miningembed::PendingTransaction{};
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
    const bool ok = tokenVerifier(token, next.operatorVerifier) &&
                    initializeJournal(nullptr) &&
                    persist(next, journalFloor_);
    clearConfig(next);
    if (ok) {
        restart_ = true;
    }
    return ok;
}

bool DeviceConfig::recoverOperator(const uint8_t verifier[32]) {
    if (!enrolled() || !any(verifier, 32)) {
        return false;
    }
    Config next = config_;
    memcpy(next.operatorVerifier, verifier, 32);
    const bool ok = commit(next);
    clearConfig(next);
    return ok;
}

bool DeviceConfig::factoryReset(const std::string& evidence) {
    if (!enrolled() || evidence != (hasPending_ ? pending_.hash : "NONE")) {
        return false;
    }
    // One config commit retires the reconciled journal up to its current generation.
    Config blank;
    if (!persist(blank, journalGeneration_)) {
        return false;
    }
    restart_ = true;
    return true;
}
} // namespace provisioning
} // namespace miningembed
