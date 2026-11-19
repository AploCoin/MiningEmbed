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
    BroadcastUncertain
};
const char* statusName(Status status);
enum class SubmissionState { NotSent, Broadcast, Pending, Reverted, Confirmed, Uncertain };

struct Submission {
    SubmissionState state = SubmissionState::NotSent;
    std::string hash;
};

// Copy public authorization from an owner-approved, confirmed registration.
// Only GAplo / mine(bytes32), zero APLO, finite GAPLO are accepted.
struct MiningSession {
    std::string owner;
    std::string signer;
    uint256_t chainId = 0;
    uint256_t gaploBudget = 0;
    uint64_t expiry = 0;
};

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
    MiningEmbed(aplo::SessionKeys& rpc, aplo::SessionKey& key, const MiningSession& session);
    MiningEmbed(const MiningEmbed&) = delete;
    MiningEmbed& operator=(const MiningEmbed&) = delete;
    // Poll the outstanding share or run one bounded read/search/submit cycle.
    Status step(uint32_t maxAttempts, Submission& out);
    Status readParams(MinerParams& out);
    Status findCandidate(const MinerParams& params, uint32_t maxAttempts, Candidate& out);
    Status revalidate(const Candidate& candidate);
    Status submit(const Candidate& candidate, Submission& out);
    // Poll once; caller controls timing. RPC failure retains unresolved state/hash.
    Status receipt(Submission& out);

    const aplo::SessionResult& rpcError() const {
        return rpcError_;
    }

    bool unresolved() const {
        return !outstanding_.hash.empty();
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
};
} // namespace miningembed
#endif
