#ifndef MININGEMBED_H
#define MININGEMBED_H
#include "MiningWork.h"
#include <SessionKeys.h>

namespace miningembed {
enum class Status {
    Ok,
    NoCandidate,
    InvalidArgument,
    RpcUnavailable,
    SessionInvalid,
    Expired,
    BudgetExceeded,
    InsufficientFunds,
    NotStaked,
    Cooldown,
    StaleChallenge,
    InvalidProof,
    RandomUnavailable,
    Busy,
    SignFailed,
    BroadcastUncertain,
    JournalFailed,
    RecoveryRequired
};
const char* statusName(Status status);
enum class SubmissionState { NotSent, Broadcast, Pending, Reverted, Confirmed, Uncertain };

struct Submission {
    SubmissionState state = SubmissionState::NotSent;
    std::string hash;
};

struct PendingTransaction {
    uint64_t nonce = 0;
    std::string hash;
    std::string raw;
    uint8_t proof[32] = {};
    uint256_t maxFee = 0;
};

// Must atomically persist before returning true. nullptr clears a resolved record.
using JournalWrite = bool (*)(const PendingTransaction* pending, void* context);

// Copy public authorization from an owner-approved, confirmed registration.
// Only GAplo / mine(bytes32), zero APLO, finite GAPLO are accepted.
struct MiningSession {
    std::string owner;
    std::string signer;
    uint256_t chainId = 0;
    uint256_t gaploBudget = 0;
    uint64_t expiry = 0;
};

// Parse a positive, canonical decimal chain ID at full EIP-155 width.
bool parseMiningChainId(const char* text, uint256_t& out);

// Parse owner-approved public metadata. Chain ID and GAPLO use decimal base units.
bool parseMiningSession(
    const char* owner,
    const char* signer,
    const char* chainId,
    const char* gaploBudget,
    uint64_t expiry,
    MiningSession& out
);

class MiningEmbed {
public:
    // Both borrowed references must outlive this object. No implicit owner key.
    MiningEmbed(
        aplo::SessionKeys& rpc,
        aplo::SessionKey& key,
        const MiningSession& session,
        JournalWrite write = nullptr,
        void* context = nullptr
    );
    // Ordinary EIP155 signing: owner and miner are derived from the retained key.
    MiningEmbed(
        aplo::SessionKeys& rpc,
        aplo::SessionKey& key,
        const uint256_t& chainId,
        JournalWrite write = nullptr,
        void* context = nullptr
    );
    MiningEmbed(const MiningEmbed&) = delete;
    MiningEmbed& operator=(const MiningEmbed&) = delete;
    // Poll the outstanding share or run one bounded read/search/submit cycle.
    // nowMs is a monotonic uint32_t clock; millis rollover is supported.
    Status step(uint32_t maxAttempts, Submission& out);
    Status step(uint32_t maxAttempts, Submission& out, uint32_t nowMs);
    // Actual search hashes in the latest step/findCandidate, excluding RPC and
    // validation hashes. Clock durations use wrap-safe uint32_t subtraction.
    uint32_t hashesTested() const { return hashesTested_; }
    uint32_t searchMicros() const { return searchMicros_; }
    Status readParams(MinerParams& out);
    Status findCandidate(const MinerParams& params, uint32_t maxAttempts, Candidate& out);
    Status revalidate(const Candidate& candidate);
    Status submit(const Candidate& candidate, Submission& out);
    // Poll once; caller controls timing. RPC failure retains unresolved state/hash.
    // If the nonce lane is empty, retry identical journaled bytes no more than
    // once per 30 seconds, after fresh authorization/proof/funding checks.
    Status receipt(Submission& out);
    Status receipt(Submission& out, uint32_t nowMs);
    // Restore before step(). False leaves a fail-closed lock; operator must reconcile.
    bool restore(const PendingTransaction& pending);

    const aplo::SessionResult& rpcError() const {
        return rpcError_;
    }

    bool unresolved() const {
        return locked_;
    }

private:
    Status checkSession(aplo::SessionStatus& status, uint64_t& block);
    Status checkOwner(const uint256_t& maxFee);
    Status checkChallenge(const Candidate& candidate, uint64_t block);
    Status prepareTransaction(
        const Candidate& candidate,
        const uint256_t& budget,
        aplo::NativeTransaction& transaction
    );
    Status authorizeTransaction(const Candidate& candidate, aplo::NativeTransaction& transaction);
    Status broadcast(const aplo::NativeTransaction& transaction, Submission& out);
    Status sendPending(Submission& out, uint32_t nowMs);
    Status recover(Submission& out, uint32_t nowMs);
    bool decodePending(const PendingTransaction& pending, aplo::NativeTransaction& tx);
    Status readWork(MinerParams& out, uint64_t block);
    bool configurationValid() const;
    bool checked(const aplo::SessionResult& result);
    bool call(
        const char* target,
        const char* signature,
        const std::string* argument,
        const std::string& blockTag,
        std::string& result
    );
    aplo::SessionKeys& rpc_;
    aplo::SessionKey& key_;
    MiningSession session_;
    aplo::SessionResult rpcError_;
    Submission outstanding_;
    PendingTransaction pending_;
    JournalWrite write_;
    void* context_;
    bool direct_ = false;
    bool locked_ = false;
    bool journalReady_ = true;
    bool recordValid_ = true;
    bool retryImmediately_ = false;
    bool retryClockStarted_ = false;
    uint32_t lastRetryMs_ = 0;
    uint32_t nowMs_ = 0, stepStartedMs_ = 0;
    bool callerClock_ = false;
    MinerParams cachedWork_;
    SearchCursor searchCursor_;
    uint32_t workFetchedMs_ = 0;
    uint32_t hashesTested_ = 0;
    uint32_t searchMicros_ = 0;
};
} // namespace miningembed
#endif
