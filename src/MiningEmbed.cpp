#include "MiningEmbed.h"
#include "MiningPlatform.h"
#include <AploContracts.h>
#include <string.h>

namespace miningembed {
using std::string;

namespace {
constexpr uint64_t cooldownBlocks = 20;
constexpr uint64_t minimumGas = 21000;
constexpr uint64_t gasCeiling = 200000;
constexpr uint64_t gasHeadroom = 10000;

static string lower(string value) {
    for (char& character : value) {
        if (character >= 'A' && character <= 'F') {
            character += 'a' - 'A';
        }
    }
    return value;
}

static string hexBytes(const uint8_t* bytes, size_t length) {
    static const char digits[] = "0123456789abcdef";
    string out(2 + length * 2, '0');
    out[1] = 'x';
    for (size_t i = 0; i < length; ++i) {
        out[2 + 2 * i] = digits[bytes[i] >> 4];
        out[3 + 2 * i] = digits[bytes[i] & 15];
    }
    return out;
}

static bool address(const string& value) {
    uint8_t bytes[20];
    if (value.size() != 42 || value.compare(0, 2, "0x") != 0 ||
        !decodeHex(value.c_str(), bytes, sizeof(bytes), sizeof(bytes))) {
        return false;
    }

    uint8_t any = 0;
    for (uint8_t b : bytes) {
        any |= b;
    }
    return any != 0;
}

bool positiveDecimal(const char* text, uint256_t& out) {
    if (!text || *text < '1' || *text > '9') {
        return false;
    }

    const uint256_t max = ~uint256_t(0);
    const uint256_t ten(10);
    uint256_t value(0);
    size_t length = 0;
    for (; *text; ++text) {
        if (++length > 78 || *text < '0' || *text > '9') {
            return false;
        }

        const uint256_t digit(static_cast<unsigned>(*text - '0'));
        if (value > (max - digit) / ten) {
            return false;
        }

        value = value * ten + digit;
    }
    out = value;
    return true;
}
} // namespace

bool parseMiningSession(
    const char* owner,
    const char* signer,
    const char* chainId,
    const char* gaploBudget,
    uint64_t expiry,
    MiningSession& out
) {
    if (!owner || !signer || !expiry) {
        return false;
    }

    MiningSession parsed;
    parsed.owner = lower(owner);
    parsed.signer = lower(signer);
    if (!address(parsed.owner) || !address(parsed.signer) || parsed.owner == parsed.signer) {
        return false;
    }

    if (!positiveDecimal(chainId, parsed.chainId)) {
        return false;
    }

    if (!positiveDecimal(gaploBudget, parsed.gaploBudget) || parsed.gaploBudget == ~uint256_t(0)) {
        return false;
    }

    parsed.expiry = expiry;
    out = parsed;
    return true;
}

const char* statusName(Status status) {
    switch (status) {
    case Status::Ok:
        return "ok";
    case Status::NoCandidate:
        return "no candidate";
    case Status::InvalidArgument:
        return "invalid argument";
    case Status::RpcUnavailable:
        return "untrusted/unavailable RPC state";
    case Status::SessionInvalid:
        return "session revoked/absent/scope mismatch";
    case Status::Expired:
        return "session expired";
    case Status::BudgetExceeded:
        return "session GAPLO budget exceeded";
    case Status::InsufficientFunds:
        return "owner GAPLO balance insufficient";
    case Status::NotStaked:
        return "owner stake below mining minimum";
    case Status::Cooldown:
        return "mining cooldown";
    case Status::StaleChallenge:
        return "stale challenge";
    case Status::InvalidProof:
        return "invalid proof";
    case Status::RandomUnavailable:
        return "hardware RNG unavailable";
    case Status::Busy:
        return "unresolved transaction";
    case Status::SignFailed:
        return "transaction signing failed";
    case Status::JournalFailed:
        return "journal write failed; sending locked";
    case Status::RecoveryRequired:
        return "pending transaction needs operator reconciliation";
    case Status::BroadcastUncertain:
        return "broadcast uncertain; reconcile receipt";
    }

    return "unknown";
}

MiningEmbed::MiningEmbed(
    aplo::SessionKeys& rpc,
    aplo::SessionKey& key,
    const MiningSession& session,
    JournalWrite write,
    void* context
)
    : rpc_(rpc), key_(key), session_(session), write_(write), context_(context) {
    session_.owner = lower(session_.owner);
    session_.signer = lower(session_.signer);
}

MiningEmbed::MiningEmbed(
    aplo::SessionKeys& rpc,
    aplo::SessionKey& key,
    const uint256_t& chainId,
    JournalWrite write,
    void* context
)
    : rpc_(rpc), key_(key), write_(write), context_(context), direct_(true) {
    session_.owner = session_.signer = lower(key.Address());
    session_.chainId = chainId;
}

Status MiningEmbed::step(uint32_t maxAttempts, Submission& out) {
    if (unresolved()) {
        return receipt(out);
    }

    out = Submission();
    MinerParams params;
    const Status fetched = readParams(params);
    if (fetched != Status::Ok) {
        return fetched;
    }

    Candidate candidate;
    const Status found = findCandidate(params, maxAttempts, candidate);
    return found == Status::Ok ? submit(candidate, out) : found;
}

bool MiningEmbed::configurationValid() const {
    if (!address(session_.owner) || !address(session_.signer) ||
        (direct_ ? session_.owner != session_.signer : session_.owner == session_.signer)) {
        return false;
    }

    if (session_.chainId == 0 || (!direct_ && session_.expiry == 0)) {
        return false;
    }

    if (!direct_ && (session_.gaploBudget == 0 || session_.gaploBudget == ~uint256_t(0))) {
        return false;
    }

    // The borrowed key can be cleared/replaced between calls; never cache its identity here.
    return key_.Address() == session_.signer;
}

bool MiningEmbed::checked(const aplo::SessionResult& result) {
    rpcError_ = result;
    return static_cast<bool>(result);
}

bool MiningEmbed::call(
    const char* target,
    const char* signature,
    const string* argument,
    const string& tag,
    string& result
) {
    const string data = detail::encodeCall(signature, argument);
    if (data.empty()) {
        rpcError_ = {aplo::SessionError::InvalidArgument, "ABI encoding failed"};
        return false;
    }

    return checked(rpc_.Call(session_.owner, target, data, result, tag));
}

Status MiningEmbed::checkSession(aplo::SessionStatus& status, uint64_t& block) {
    if (!configurationValid()) {
        return Status::InvalidArgument;
    }

    uint256_t chain;
    if (!checked(rpc_.ChainId(chain))) {
        return Status::RpcUnavailable;
    }

    if (chain != session_.chainId) {
        return Status::SessionInvalid;
    }

    if (direct_) {
        // A registered session key is never an ordinary wallet, even with a retained secret.
        if (!checked(rpc_.Read(session_.signer, session_.owner, status))) {
            return Status::RpcUnavailable;
        }
        if (status.active) {
            return Status::SessionInvalid;
        }
        status = aplo::SessionStatus();
        status.gaplo = ~uint256_t(0);
        if (!checked(rpc_.BlockNumber(block)) ||
            !checked(rpc_.LatestNonce(session_.signer, status.nonce))) {
            return Status::RpcUnavailable;
        }
        return status.nonce == UINT64_MAX ? Status::InvalidArgument : Status::Ok;
    }

    if (!checked(rpc_.Read(session_.signer, session_.owner, status)) ||
        !checked(rpc_.BlockNumber(block))) {
        return Status::RpcUnavailable;
    }

    if (!status.active || lower(status.owner) != session_.owner ||
        lower(status.target) != APLO_MINING_CONTRACT) {
        return Status::SessionInvalid;
    }

    if (status.aplo != uint256_t(0) || status.gaplo > session_.gaploBudget) {
        return Status::SessionInvalid;
    }

    if (status.expiry != session_.expiry || status.nonce == UINT64_MAX) {
        return Status::SessionInvalid;
    }

    // Inclusive expiry: next block must still be authorized.
    if (block >= status.expiry) {
        return Status::Expired;
    }

    if (status.gaplo == 0) {
        return Status::BudgetExceeded;
    }

    return Status::Ok;
}

Status MiningEmbed::readWork(MinerParams& out, uint64_t block) {
    out = MinerParams();
    string raw;
    const string tag = "0x" + uint256_t(block).str(16);
    if (!call(APLO_MINING_CONTRACT, "miner_params(address)", &session_.signer, tag, raw)) {
        return Status::RpcUnavailable;
    }

    uint8_t words[128];
    if (raw.size() != 258 || !decodeHex(raw.c_str(), words, sizeof(words), sizeof(words))) {
        return Status::RpcUnavailable;
    }

    for (size_t i = 0; i < 24; ++i) {
        if (words[i]) {
            return Status::RpcUnavailable;
        }
    }
    MinerParams parsed;
    for (size_t i = 24; i < 32; ++i) {
        parsed.lastBlock = (parsed.lastBlock << 8) | words[i];
    }
    if (parsed.lastBlock > block) {
        return Status::RpcUnavailable;
    }

    memcpy(parsed.target, words + 32, 32);
    memcpy(parsed.totalMined, words + 64, 32);
    memcpy(parsed.prevHash, words + 96, 32);
    const uint8_t zero[32] = {};
    if (memcmp(parsed.target, zero, 32) == 0) {
        if (!call(APLO_MINING_CONTRACT, "DEFAULT_DIFFICULTY()", nullptr, tag, raw)) {
            return Status::RpcUnavailable;
        }

        if (raw.size() != 66 || !decodeHex(raw.c_str(), parsed.target, 32, 32)) {
            return Status::RpcUnavailable;
        }

        if (memcmp(parsed.target, zero, 32) == 0) {
            return Status::RpcUnavailable;
        }
    }
    if (!decodeHex(session_.signer.c_str(), parsed.signer, 20, 20)) {
        return Status::InvalidArgument;
    }

    parsed.valid = true;
    out = parsed;
    return Status::Ok;
}

Status MiningEmbed::readParams(MinerParams& out) {
    out = MinerParams();
    if (unresolved()) {
        return Status::Busy;
    }

    aplo::SessionStatus status;
    uint64_t block;
    Status result = checkSession(status, block);
    if (result != Status::Ok) {
        return result;
    }

    result = readWork(out, block);
    if (result != Status::Ok) {
        return result;
    }

    return block - out.lastBlock < cooldownBlocks ? Status::Cooldown : Status::Ok;
}

Status MiningEmbed::findCandidate(const MinerParams& params, uint32_t attempts, Candidate& out) {
    out = Candidate();
    if (unresolved()) {
        return Status::Busy;
    }

    uint8_t signer[20];
    if (!configurationValid() || !decodeHex(session_.signer.c_str(), signer, 20, 20) ||
        memcmp(params.signer, signer, 20) != 0) {
        return Status::InvalidArgument;
    }

    switch (search(params, attempts, out, detail::hash, detail::random, detail::cooperate)) {
    case WorkResult::Found:
        return Status::Ok;
    case WorkResult::Exhausted:
        return Status::NoCandidate;
    case WorkResult::RandomUnavailable:
        return Status::RandomUnavailable;
    default:
        return Status::InvalidArgument;
    }
}

Status MiningEmbed::revalidate(const Candidate& candidate) {
    if (!candidate.valid) {
        return Status::InvalidArgument;
    }

    aplo::SessionStatus status;
    uint64_t block;
    Status result = checkSession(status, block);
    if (result != Status::Ok) {
        return result;
    }

    return checkChallenge(candidate, block);
}

Status MiningEmbed::checkChallenge(const Candidate& candidate, uint64_t block) {
    MinerParams fresh;
    const Status status = readWork(fresh, block);
    if (status != Status::Ok) {
        return status;
    }

    if (!sameChallenge(candidate.params, fresh)) {
        return Status::StaleChallenge;
    }

    if (block - fresh.lastBlock < cooldownBlocks) {
        return Status::Cooldown;
    }

    return validProof(fresh, candidate.nonce, 32, detail::hash) ? Status::Ok : Status::InvalidProof;
}

Status MiningEmbed::checkOwner(const uint256_t& maxFee) {
    string raw;
    if (!call(APLO_STAKING_CONTRACT, "getStake(address)", &session_.owner, "latest", raw)) {
        return Status::RpcUnavailable;
    }

    uint8_t word[32];
    if (raw.size() != 66 || !decodeHex(raw.c_str(), word, 32, 32)) {
        return Status::RpcUnavailable;
    }

    // uint256_t's string constructor reads HEX, even without a 0x prefix.
    const uint256_t minimumStake = uint256_t(1000) * uint256_t(UINT64_C(1000000000000000000));
    if (uint256_t(raw) < minimumStake) {
        return Status::NotStaked;
    }

    uint256_t balance;
    if (!checked(rpc_.Balance(session_.owner, balance))) {
        return Status::RpcUnavailable;
    }

    return balance < maxFee ? Status::InsufficientFunds : Status::Ok;
}

Status MiningEmbed::prepareTransaction(
    const Candidate& candidate,
    const uint256_t& budget,
    aplo::NativeTransaction& transaction
) {
    transaction.chainId = session_.chainId;
    transaction.to = APLO_MINING_CONTRACT;
    transaction.value = 0;
    const string nonceHex = hexBytes(candidate.nonce, 32);
    transaction.data = lower(detail::encodeCall("mine(bytes32)", &nonceHex));
    if (transaction.data.size() != 74 || transaction.data.compare(0, 10, "0x2fdc505e") != 0) {
        return Status::InvalidArgument;
    }

    if (!checked(rpc_.GasPrice(transaction.gasPrice))) {
        return Status::RpcUnavailable;
    }

    const uint256_t maximum = ~uint256_t(0);
    if (transaction.gasPrice == 0 || transaction.gasPrice > maximum / uint256_t(gasCeiling)) {
        return Status::BudgetExceeded;
    }

    if (transaction.gasPrice * uint256_t(minimumGas) > budget) {
        return Status::BudgetExceeded;
    }

    // The native node checks ordinary/delegated execution using the actual signer.
    uint64_t estimate;
    const bool estimated = checked(rpc_.EstimateGas(
        session_.signer,
        transaction.to,
        transaction.data,
        transaction.value,
        estimate
    ));
    if (!estimated) {
        return Status::RpcUnavailable;
    }

    // Preserve the 200k ceiling and WebMiner's 10k headroom.
    if (estimate < minimumGas || estimate > gasCeiling - gasHeadroom) {
        return Status::InvalidArgument;
    }

    transaction.gasLimit = estimate + gasHeadroom;
    const uint256_t fee = transaction.gasPrice * uint256_t(transaction.gasLimit);
    if (fee > budget) {
        return Status::BudgetExceeded;
    }

    return checkOwner(fee);
}

Status MiningEmbed::authorizeTransaction(
    const Candidate& candidate,
    aplo::NativeTransaction& transaction
) {
    // Slow estimate/funding calls may have crossed a block or a revocation.
    aplo::SessionStatus authorization;
    uint64_t block;
    const Status status = checkSession(authorization, block);
    if (status != Status::Ok) {
        return status;
    }

    const uint256_t fee = transaction.gasPrice * uint256_t(transaction.gasLimit);
    if (fee > authorization.gaplo) {
        return Status::BudgetExceeded;
    }

    if (!checked(rpc_.PendingNonce(session_.signer, transaction.nonce))) {
        return Status::RpcUnavailable;
    }

    uint64_t latest;
    if (!checked(rpc_.LatestNonce(session_.signer, latest))) {
        return Status::RpcUnavailable;
    }
    if (transaction.nonce != authorization.nonce || latest != transaction.nonce ||
        latest == UINT64_MAX) {
        return Status::Busy; // Another transaction owns this signer's nonce lane.
    }
    return checkChallenge(candidate, block);
}

Status MiningEmbed::broadcast(const aplo::NativeTransaction& transaction, Submission& out) {
    string raw;
    const bool signedTransaction = checked(
        aplo::SessionKeys::SignTransaction(
            transaction,
            aplo::SessionKey::SignDigest,
            &key_,
            session_.signer,
            raw
        )
    );
    if (!signedTransaction) {
        return Status::SignFailed;
    }

    // Commit the exact signed bytes before touching the network, including on write failure.
    uint8_t encoded[256];
    uint8_t digest[32];
    if (raw.size() < 4 || raw.size() > 514 || raw.size() % 2 != 0 ||
        !decodeHex(raw.c_str(), encoded, sizeof(encoded), (raw.size() - 2) / 2)) {
        return Status::SignFailed;
    }
    detail::hash(encoded, (raw.size() - 2) / 2, digest);
    pending_.nonce = transaction.nonce;
    pending_.hash = hexBytes(digest, 32);
    pending_.raw.swap(raw);
    const string proof = "0x" + transaction.data.substr(10);
    if (!decodeHex(proof.c_str(), pending_.proof, 32, 32)) {
        pending_ = PendingTransaction();
        return Status::SignFailed;
    }
    pending_.maxFee = transaction.gasPrice * uint256_t(transaction.gasLimit);
    outstanding_.hash = pending_.hash;
    outstanding_.state = SubmissionState::Uncertain;
    locked_ = true;
    journalReady_ = !write_ || write_(&pending_, context_);
    out = outstanding_;
    if (!journalReady_) {
        return Status::JournalFailed;
    }
    return sendPending(out);
}

Status MiningEmbed::sendPending(Submission& out) {
    // One send per new transaction or valid reboot recovery; never per normal poll.
    retryAfterRestore_ = false;
    string accepted;
    if (!checked(rpc_.SendRaw(pending_.raw, accepted)) || lower(accepted) != pending_.hash) {
        out = outstanding_;
        return Status::BroadcastUncertain;
    }
    outstanding_.state = SubmissionState::Broadcast;
    out = outstanding_;
    return Status::Ok;
}

Status MiningEmbed::submit(const Candidate& candidate, Submission& out) {
    if (unresolved()) {
        out = outstanding_;
        return Status::Busy;
    }

    out = Submission();
    if (!candidate.valid) {
        return Status::InvalidArgument;
    }

    aplo::SessionStatus authorization;
    uint64_t block;
    Status status = checkSession(authorization, block);
    if (status != Status::Ok) {
        return status;
    }

    aplo::NativeTransaction transaction;
    status = prepareTransaction(candidate, authorization.gaplo, transaction);
    if (status != Status::Ok) {
        return status;
    }

    status = authorizeTransaction(candidate, transaction);
    if (status != Status::Ok) {
        return status;
    }

    return broadcast(transaction, out);
}

Status MiningEmbed::receipt(Submission& out) {
    if (!unresolved()) {
        out = Submission();
        return Status::InvalidArgument;
    }
    out = outstanding_;
    if (!recordValid_) {
        return Status::RecoveryRequired;
    }
    uint256_t chain;
    if (!checked(rpc_.ChainId(chain))) {
        return Status::RpcUnavailable;
    }
    if (chain != session_.chainId) {
        return Status::SessionInvalid;
    }

    // Receipt for the exact local hash always precedes nonce or authorization recovery.
    aplo::ReceiptState state;
    if (!checked(rpc_.Receipt(pending_.hash, state))) {
        return Status::RpcUnavailable;
    }
    if (state != aplo::ReceiptState::Pending) {
        // Do not release RAM lock until durable clear succeeds.
        if (write_ && !write_(nullptr, context_)) {
            return Status::JournalFailed;
        }
        out.state = state == aplo::ReceiptState::Succeeded ? SubmissionState::Confirmed
                                                           : SubmissionState::Reverted;
        pending_ = PendingTransaction();
        outstanding_ = Submission();
        locked_ = false;
        retryAfterRestore_ = false;
        journalReady_ = true;
        return Status::Ok;
    }
    if (!journalReady_) {
        return Status::JournalFailed;
    }
    if (outstanding_.state != SubmissionState::Uncertain) {
        outstanding_.state = SubmissionState::Pending;
    }
    out = outstanding_;
    // A null receipt is not proof of absence, acceptance, failure, or success.
    return recover(out);
}

namespace {
// Bounded RLP reader. Canonical encoding and signature are checked by exact re-sign below.
bool rlpItem(
    const uint8_t*& cursor,
    const uint8_t* end,
    const uint8_t*& data,
    size_t& size,
    bool& list
) {
    if (cursor == end) {
        return false;
    }
    const uint8_t prefix = *cursor++;
    list = prefix >= 0xc0;
    if (prefix < 0x80) {
        data = cursor - 1;
        size = 1;
        return true;
    }
    const uint8_t shortBase = list ? 0xc0 : 0x80;
    const uint8_t longBase = list ? 0xf7 : 0xb7;
    if (prefix <= longBase) {
        size = prefix - shortBase;
    } else {
        const size_t count = prefix - longBase;
        if (count > 2 || static_cast<size_t>(end - cursor) < count) {
            return false;
        }
        size = 0;
        for (size_t i = 0; i < count; ++i) {
            size = (size << 8) | *cursor++;
        }
    }
    if (static_cast<size_t>(end - cursor) < size) {
        return false;
    }
    data = cursor;
    cursor += size;
    return true;
}
} // namespace

bool MiningEmbed::decodePending(const PendingTransaction& pending, aplo::NativeTransaction& tx) {
    if (!configurationValid() || pending.nonce == UINT64_MAX || pending.raw.size() < 4 ||
        pending.raw.size() > 514 || pending.raw.size() % 2 || pending.hash.size() != 66) {
        return false;
    }
    uint8_t encoded[256];
    const size_t bytes = (pending.raw.size() - 2) / 2;
    if (!decodeHex(pending.raw.c_str(), encoded, sizeof(encoded), bytes)) {
        return false;
    }
    uint8_t digest[32];
    detail::hash(encoded, bytes, digest);
    if (lower(pending.hash) != hexBytes(digest, 32)) {
        return false;
    }
    const uint8_t* cursor = encoded;
    const uint8_t* end = encoded + bytes;
    const uint8_t* data;
    size_t size;
    bool list;
    if (!rlpItem(cursor, end, data, size, list) || !list || cursor != end) {
        return false;
    }
    cursor = data;
    end = data + size;
    tx = aplo::NativeTransaction();
    tx.chainId = session_.chainId;
    for (unsigned field = 0; field < 9; ++field) {
        if (!rlpItem(cursor, end, data, size, list) || list) {
            return false;
        }
        if (field == 0 || field == 2) {
            if (size > 8) {
                return false;
            }
            uint64_t value = 0;
            for (size_t i = 0; i < size; ++i) {
                value = (value << 8) | data[i];
            }
            if (field == 0) {
                tx.nonce = value;
            } else {
                tx.gasLimit = value;
            }
        } else if (field == 1) {
            if (size > 32) {
                return false;
            }
            tx.gasPrice = size ? uint256_t(hexBytes(data, size)) : uint256_t(0);
        } else if (field == 3) {
            if (size != 20) {
                return false;
            }
            tx.to = hexBytes(data, size);
        } else if (field == 4) {
            if (size != 0) {
                return false;
            }
        } else if (field == 5) {
            if (size != 36) {
                return false;
            }
            tx.data = hexBytes(data, size);
        } else if (size == 0 || size > (field == 6 ? 33u : 32u)) {
            return false;
        }
    }
    const uint256_t maximum = ~uint256_t(0);
    if (cursor != end || tx.nonce != pending.nonce || tx.to != APLO_MINING_CONTRACT ||
        tx.data != "0x2fdc505e" + hexBytes(pending.proof, 32).substr(2) ||
        tx.gasLimit < minimumGas || tx.gasLimit > gasCeiling || tx.gasPrice == 0 ||
        tx.gasPrice > maximum / uint256_t(tx.gasLimit) ||
        tx.gasPrice * uint256_t(tx.gasLimit) != pending.maxFee) {
        return false;
    }
    string signedRaw;
    return checked(
               aplo::SessionKeys::SignTransaction(
                   tx,
                   aplo::SessionKey::SignDigest,
                   &key_,
                   session_.signer,
                   signedRaw
               )
           ) &&
           signedRaw == lower(pending.raw);
}

bool MiningEmbed::restore(const PendingTransaction& pending) {
    if (unresolved()) {
        return false;
    }
    // Even a corrupt record must prevent signing a replacement.
    locked_ = true;
    outstanding_.hash = pending.hash.size() == 66 ? pending.hash : string();
    outstanding_.state = SubmissionState::Uncertain;
    aplo::NativeTransaction tx;
    recordValid_ = decodePending(pending, tx);
    if (!recordValid_) {
        return false;
    }
    pending_ = pending;
    pending_.raw = lower(pending_.raw);
    pending_.hash = lower(pending_.hash);
    outstanding_.hash = pending_.hash;
    retryAfterRestore_ = true;
    return true;
}

Status MiningEmbed::recover(Submission& out) {
    uint64_t latest, pending;
    if (!checked(rpc_.LatestNonce(session_.signer, latest)) ||
        !checked(rpc_.PendingNonce(session_.signer, pending))) {
        return Status::RpcUnavailable;
    }
    // Even an advanced nonce cannot identify which transaction executed.
    if (latest != pending_.nonce || pending < latest) {
        return Status::RecoveryRequired;
    }
    if (!retryAfterRestore_ || pending != latest) {
        return Status::Ok;
    }

    aplo::NativeTransaction tx;
    if (!decodePending(pending_, tx)) {
        return Status::RecoveryRequired;
    }
    aplo::SessionStatus authorization;
    uint64_t block;
    Status status = checkSession(authorization, block);
    if (status != Status::Ok) {
        return status;
    }
    if (tx.gasPrice * uint256_t(tx.gasLimit) > authorization.gaplo) {
        return Status::BudgetExceeded;
    }
    Candidate candidate;
    status = readWork(candidate.params, block);
    if (status != Status::Ok) {
        return status;
    }
    memcpy(candidate.nonce, pending_.proof, 32);
    candidate.valid = true;
    status = checkChallenge(candidate, block);
    if (status != Status::Ok) {
        return status;
    }
    // Simulate the original calldata; never raise its fee, change gas or sign a replacement.
    uint256_t price;
    uint64_t estimate;
    if (!checked(rpc_.GasPrice(price)) ||
        !checked(rpc_.EstimateGas(session_.signer, tx.to, tx.data, tx.value, estimate))) {
        return Status::RpcUnavailable;
    }
    if (price == 0 || price > tx.gasPrice || estimate < minimumGas || estimate > tx.gasLimit) {
        return Status::RecoveryRequired;
    }
    status = checkOwner(pending_.maxFee);
    if (status != Status::Ok) {
        return status;
    }
    const uint64_t originalNonce = tx.nonce;
    status = authorizeTransaction(candidate, tx);
    if (status != Status::Ok) {
        return status;
    }
    if (tx.nonce != originalNonce) {
        return Status::RecoveryRequired;
    }
    return sendPending(out);
}
} // namespace miningembed
