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
        return "session signing failed";
    case Status::BroadcastUncertain:
        return "broadcast uncertain; reconcile receipt";
    }

    return "unknown";
}

MiningEmbed::MiningEmbed(
    aplo::SessionKeys& rpc,
    aplo::SessionKey& key,
    const MiningSession& session
)
    : rpc_(rpc), key_(key), session_(session) {
    session_.owner = lower(session_.owner);
    session_.signer = lower(session_.signer);
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
        session_.owner == session_.signer) {
        return false;
    }

    if (session_.chainId == 0 || session_.expiry == 0) {
        return false;
    }

    if (session_.gaploBudget == 0 || session_.gaploBudget == ~uint256_t(0)) {
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

    // The native node checks the selector whitelist with SESSION as sender.
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

    if (transaction.nonce != authorization.nonce) {
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

    // Lock before the only send. A lost response never authorizes a retry.
    uint8_t encoded[256];
    uint8_t digest[32];
    if (raw.size() < 4 || raw.size() > 514 ||
        !decodeHex(raw.c_str(), encoded, sizeof(encoded), (raw.size() - 2) / 2)) {
        return Status::SignFailed;
    }

    detail::hash(encoded, (raw.size() - 2) / 2, digest);
    outstanding_.hash = hexBytes(digest, 32);
    outstanding_.state = SubmissionState::Uncertain;
    string accepted;
    if (!checked(rpc_.SendRaw(raw, accepted)) || lower(accepted) != outstanding_.hash) {
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
    uint256_t chain;
    if (!checked(rpc_.ChainId(chain))) {
        return Status::RpcUnavailable;
    }

    if (chain != session_.chainId) {
        return Status::SessionInvalid;
    }

    aplo::ReceiptState state;
    if (!checked(rpc_.Receipt(outstanding_.hash, state))) {
        return Status::RpcUnavailable;
    }

    if (state == aplo::ReceiptState::Pending) {
        // null does not prove a previously uncertain broadcast was accepted.
        if (outstanding_.state != SubmissionState::Uncertain) {
            outstanding_.state = SubmissionState::Pending;
        }
        out = outstanding_;
    } else {
        out.state = state == aplo::ReceiptState::Succeeded ? SubmissionState::Confirmed
                                                           : SubmissionState::Reverted;
        outstanding_ = Submission();
    }
    return Status::Ok;
}
} // namespace miningembed
