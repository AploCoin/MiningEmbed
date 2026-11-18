#include "MiningEmbed.h"
#include "MiningPlatform.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
using namespace miningembed;
using std::string;
static const string owner = "0x1111111111111111111111111111111111111111";
static const string target = "0x0000000000000000000000000000000000001234";
static string quoted(const string& value) {
    return "\"" + value + "\"";
}
static string result(const string& value) {
    return "{\"result\":" + value + "}";
}
static string word(const uint256_t& n) {
    return n.str(16, 64);
}
// Inspect signed wire fields independently of the base's RLP implementation.
static const uint8_t* item(const uint8_t*& cursor, const uint8_t* end, size_t& size, bool& list) {
    assert(cursor < end);
    uint8_t prefix = *cursor++;
    list = prefix >= 0xc0;
    if (prefix < 0x80) {
        size = 1;
        return cursor - 1;
    }
    const uint8_t shortBase = list ? 0xc0 : 0x80;
    const uint8_t longBase = list ? 0xf7 : 0xb7;
    if (prefix <= longBase) {
        size = prefix - shortBase;
    } else {
        size = 0;
        size_t count = prefix - longBase;
        assert(static_cast<size_t>(end - cursor) >= count);
        for (size_t i = 0; i < count; ++i) {
            size = (size << 8) | *cursor++;
        }
    }
    assert(static_cast<size_t>(end - cursor) >= size);
    const uint8_t* payload = cursor;
    cursor += size;
    return payload;
}
static uint64_t integer(const uint8_t* data, size_t size) {
    assert(size <= 8);
    uint64_t value = 0;
    for (size_t i = 0; i < size; ++i) {
        value = (value << 8) | data[i];
    }
    return value;
}
static void checkWire(const uint8_t* raw, size_t n, uint64_t nonce, const uint256_t& chain,
                      uint64_t limit) {
    const uint8_t* cursor = raw;
    const uint8_t* end = raw + n;
    size_t size;
    bool list;
    const uint8_t* payload = item(cursor, end, size, list);
    assert(list && cursor == end);
    cursor = payload;
    end = payload + size;
    const uint8_t* fields[9];
    size_t lengths[9];
    for (int i = 0; i < 9; ++i) {
        fields[i] = item(cursor, end, lengths[i], list);
        assert(!list);
    }
    assert(cursor == end);
    assert(integer(fields[0], lengths[0]) == nonce);
    assert(integer(fields[1], lengths[1]) == 1 && integer(fields[2], lengths[2]) == limit);
    uint8_t destination[20];
    assert(decodeHex(target.c_str(), destination, 20, 20));
    assert(lengths[3] == 20 && memcmp(fields[3], destination, 20) == 0 && lengths[4] == 0);
    const uint8_t selector[4] = {0x2f, 0xdc, 0x50, 0x5e};
    assert(lengths[5] == 36 && memcmp(fields[5], selector, 4) == 0);
    if (chain == ~uint256_t(0)) {
        // 2*(2^256-1)+35+recovery = 2^257+33+recovery (33-byte wire integer).
        assert(lengths[6] == 33 && fields[6][0] == 2);
        for (size_t i = 1; i < 32; ++i) {
            assert(fields[6][i] == 0);
        }
        assert(fields[6][32] == 33 || fields[6][32] == 34);
    } else {
        const uint64_t v = integer(fields[6], lengths[6]);
        const uint64_t domain = static_cast<uint64_t>(chain);
        assert(v == domain * 2 + 35 || v == domain * 2 + 36);
    }
}
struct Fixture {
    string signer;
    string fail;
    string lastRaw;
    string returnedHash;
    uint256_t chain = 424242;
    uint256_t aplo = 0;
    uint256_t budget = uint256_t("0xde0b6b3a7640000");
    uint256_t proofTarget = ~uint256_t(0);
    // Independent hex vectors: 1 GAPLO and exactly 1000 APLO in 18-decimal base units.
    uint256_t ownerBalance = uint256_t("0xde0b6b3a7640000");
    uint256_t stake = uint256_t("0x3635c9adc5dea00000");
    uint64_t head = 100;
    uint64_t expiry = 300;
    uint64_t nonce = UINT64_C(1) << 40;
    uint64_t pending = UINT64_C(1) << 40;
    uint256_t gasPrice = 1;
    uint64_t estimate = 50000;
    uint64_t lastBlock = 0;
    bool active = true;
    bool badOwner = false;
    bool badTarget = false;
    bool freshZero = false;
    bool stale = false;
    bool badParams = false;
    bool failSend = false;
    bool badHash = false;
    unsigned revokeAtRead = 0;
    bool receiptError = false;
    unsigned sends = 0;
    unsigned reads = 0;
    unsigned estimates = 0;
    int receipt = -1;
    string handleCall(const string& parameters) {
        assert(parameters.find("\"from\":\"" + owner + "\"") != string::npos);
        const string getSession = detail::encodeCall("getSession(address)", &signer);
        if (parameters.find(getSession) != string::npos) {
            ++reads;
            const bool live = active && (revokeAtRead == 0 || reads < revokeAtRead);
            string registeredOwner(40, '0');
            if (live) {
                registeredOwner = badOwner ? string(40, '3') : owner.substr(2);
            }
            string body = string(24, '0') + registeredOwner;
            body += string(24, '0') + (badTarget ? string(40, '4') : target.substr(2));
            body += word(aplo) + word(budget) + word(nonce) + word(expiry);
            return result(quoted("0x" + body));
        }
        if (parameters.find(detail::encodeCall("miner_params(address)", &signer)) != string::npos) {
            assert(parameters.find("\"0x64\"") != string::npos); // pinned height 100
            if (badParams) {
                return result(quoted("0x01"));
            }
            return result(
                quoted("0x" + word(lastBlock) + word(freshZero ? uint256_t(0) : proofTarget) +
                       word(uint256_t(
                           "0x8000000000000000000000000000000000000000000000000000000000000001")) +
                       word(stale ? 1 : 0)));
        }
        if (parameters.find(detail::encodeCall("DEFAULT_DIFFICULTY()", nullptr)) != string::npos) {
            return result(quoted("0x" + word(~uint256_t(0))));
        }
        if (parameters.find(detail::encodeCall("getStake(address)", &owner)) != string::npos) {
            return result(quoted("0x" + word(stake)));
        }
        assert(false);
        return "";
    }

    string estimateGas(const string& parameters) {
        ++estimates;
        assert(parameters.find("\"from\":\"" + signer + "\"") != string::npos);
        assert(parameters.find("\"to\":\"" + target + "\"") != string::npos);
        assert(parameters.find("0x2fdc505e") != string::npos &&
               parameters.find("\"value\":\"0x0\"") != string::npos);
        return result(quoted("0x" + uint256_t(estimate).str(16)));
    }

    string sendRaw(const string& parameters) {
        ++sends;
        lastRaw = parameters.substr(2, parameters.size() - 4);
        uint8_t raw[256];
        uint8_t digest[32];
        const size_t rawSize = (lastRaw.size() - 2) / 2;
        assert(decodeHex(lastRaw.c_str(), raw, sizeof(raw), rawSize));
        detail::hash(raw, rawSize, digest);
        checkWire(raw, rawSize, pending, chain, estimate + 10000);
        returnedHash = "0x";
        const char* digits = "0123456789abcdef";
        for (uint8_t byte : digest) {
            returnedHash += digits[byte >> 4];
            returnedHash += digits[byte & 15];
        }
        if (failSend) {
            return "";
        }
        return result(quoted(badHash ? "0x" + string(64, 'a') : returnedHash));
    }

    string readReceipt(const string& parameters) {
        assert(parameters.find(returnedHash) != string::npos);
        if (receiptError) {
            return R"({"error":{"code":-1,"message":"offline"}})";
        }
        return result(receipt < 0 ? "null"
                                  : string("{\"status\":\"0x") + (receipt ? "1" : "0") + "\"}");
    }

    static string transport(const string& method, const string& parameters, void* context) {
        Fixture& fixture = *static_cast<Fixture*>(context);
        if (method == fixture.fail) {
            return "";
        }
        if (method == "eth_chainId") {
            return result(quoted("0x" + fixture.chain.str(16)));
        }
        if (method == "eth_blockNumber") {
            return result(quoted("0x" + uint256_t(fixture.head).str(16)));
        }
        if (method == "eth_gasPrice") {
            return result(quoted("0x" + fixture.gasPrice.str(16)));
        }
        if (method == "eth_getTransactionCount") {
            assert(parameters.find(fixture.signer) != string::npos &&
                   parameters.find("pending") != string::npos);
            assert(parameters.find(owner) == string::npos);
            return result(quoted("0x" + uint256_t(fixture.pending).str(16)));
        }
        if (method == "eth_getBalance") {
            assert(parameters.find(owner) != string::npos &&
                   parameters.find(fixture.signer) == string::npos);
            return result(quoted("0x" + fixture.ownerBalance.str(16)));
        }
        if (method == "eth_call") {
            return fixture.handleCall(parameters);
        }
        if (method == "eth_estimateGas") {
            return fixture.estimateGas(parameters);
        }
        if (method == "eth_sendRawTransaction") {
            return fixture.sendRaw(parameters);
        }
        if (method == "eth_getTransactionReceipt") {
            return fixture.readReceipt(parameters);
        }
        assert(false);
        return "";
    }
};
struct Test {
    Fixture fixture;
    aplo::SessionKey key;
    aplo::SessionKeys rpc;
    MiningSession session;
    Test() : rpc(Fixture::transport, &fixture) {
        uint8_t secret[32];
        memset(secret, 0x22, 32);
        assert(key.Import(secret));
        fixture.signer = key.Address();
        session.owner = owner;
        session.signer = fixture.signer;
        session.chainId = fixture.chain;
        session.gaploBudget = fixture.budget;
        session.expiry = fixture.expiry;
    }
};
static Candidate candidate(MiningEmbed& miner) {
    MinerParams parameters;
    Candidate proof;
    assert(miner.readParams(parameters) == Status::Ok);
    assert(parameters.totalMined[0] == 0x80);
    assert(miner.findCandidate(parameters, 2000, proof) == Status::Ok);
    return proof;
}
static void testFullChainDomain() {
    Test test;
    test.fixture.chain = ~uint256_t(0);
    test.session.chainId = test.fixture.chain;
    MiningEmbed miner(test.rpc, test.key, test.session);
    auto proof = candidate(miner);
    Submission submission;
    assert(miner.submit(proof, submission) == Status::Ok &&
           submission.state == SubmissionState::Broadcast);
    assert(submission.hash ==
           test.fixture.returnedHash); // bounded local raw buffer handles full uint256 domain
}

static void testStakeBoundary() {
    Test test;
    assert(test.fixture.stake.str(10) == "1000000000000000000000");
    assert(test.fixture.budget.str(10) == "1000000000000000000");
    MiningEmbed miner(test.rpc, test.key, test.session);
    auto proof = candidate(miner);
    Submission submission;
    // Exactly 1000 APLO succeeds; 999 APLO and one wei below 1000 stop before broadcast.
    test.fixture.stake = uint256_t("0x3627e8f712373c0000"); // 999 APLO, Python integer vector
    assert(test.fixture.stake.str(10) == "999000000000000000000");
    assert(miner.submit(proof, submission) == Status::NotStaked && test.fixture.sends == 0);
    test.fixture.stake = uint256_t("0x3635c9adc5de9fffff");
    assert(miner.submit(proof, submission) == Status::NotStaked && test.fixture.sends == 0);
    test.fixture.stake += 1;
    assert(miner.submit(proof, submission) == Status::Ok && test.fixture.sends == 1);
}

static void testReceiptLifecycle() {
    Test test;
    test.fixture.freshZero = true;
    MiningEmbed miner(test.rpc, test.key, test.session);
    auto proof = candidate(miner);
    assert(miner.revalidate(proof) == Status::Ok);
    Submission submission;
    assert(miner.submit(proof, submission) == Status::Ok &&
           submission.state == SubmissionState::Broadcast);
    assert(submission.hash == test.fixture.returnedHash && miner.unresolved() &&
           test.fixture.sends == 1);
    assert(miner.submit(proof, submission) == Status::Busy && test.fixture.sends == 1);
    assert(miner.receipt(submission) == Status::Ok && submission.state == SubmissionState::Pending);
    // Timeout/expiry/revocation cannot prove that a sent transaction disappeared.
    test.fixture.head = test.fixture.expiry;
    test.fixture.active = false;
    assert(miner.receipt(submission) == Status::Ok &&
           submission.state == SubmissionState::Pending && miner.unresolved());
    assert(miner.submit(proof, submission) == Status::Busy && test.fixture.sends == 1);
    test.fixture.head = 100;
    test.fixture.active = true;
    test.fixture.chain = 28282;
    assert(miner.receipt(submission) == Status::SessionInvalid &&
           submission.state == SubmissionState::Pending && miner.unresolved());
    test.fixture.chain = test.session.chainId;
    test.fixture.receiptError = true;
    assert(miner.receipt(submission) == Status::RpcUnavailable &&
           submission.state == SubmissionState::Pending && miner.unresolved());
    test.fixture.receiptError = false;
    test.fixture.receipt = 0;
    assert(miner.receipt(submission) == Status::Ok &&
           submission.state == SubmissionState::Reverted && !miner.unresolved());
    assert(miner.submit(proof, submission) == Status::Ok);
    test.fixture.receipt = 1;
    assert(miner.receipt(submission) == Status::Ok &&
           submission.state == SubmissionState::Confirmed && !miner.unresolved());
}

enum class Fault {
    Absent,
    WrongOwner,
    WrongTarget,
    AploAllowance,
    ExpiryMismatch,
    WrongChain,
    Expired,
    EmptyBudget,
    IncreasedBudget,
    FeeExceedsBudget,
    PendingNonce,
    StaleChallenge,
    OwnerFunds,
    OwnerStake,
    MalformedParams,
    EstimateFailure,
    FeeOverflow,
    RevokedDuringPreparation,
    FutureChallengeBlock
};

static void testRejectedSubmissions() {
    for (Fault fault :
         {Fault::Absent, Fault::WrongOwner, Fault::WrongTarget, Fault::AploAllowance,
          Fault::ExpiryMismatch, Fault::WrongChain, Fault::Expired, Fault::EmptyBudget,
          Fault::IncreasedBudget, Fault::FeeExceedsBudget, Fault::PendingNonce,
          Fault::StaleChallenge, Fault::OwnerFunds, Fault::OwnerStake, Fault::MalformedParams,
          Fault::EstimateFailure, Fault::FeeOverflow, Fault::RevokedDuringPreparation,
          Fault::FutureChallengeBlock}) {
        Test test;
        MiningEmbed miner(test.rpc, test.key, test.session);
        auto proof = candidate(miner);
        Status expected = Status::SessionInvalid;
        switch (fault) {
        case Fault::Absent:
            test.fixture.active = false;
            break;
        case Fault::WrongOwner:
            test.fixture.badOwner = true;
            break;
        case Fault::WrongTarget:
            test.fixture.badTarget = true;
            break;
        case Fault::AploAllowance:
            test.fixture.aplo = 1;
            break;
        case Fault::ExpiryMismatch:
            test.fixture.expiry = 301;
            break;
        case Fault::WrongChain:
            test.fixture.chain = 28282;
            break; // never use fixed legacy APLO_ID
        case Fault::Expired:
            test.fixture.head = 300;
            expected = Status::Expired;
            break;
        case Fault::EmptyBudget:
            test.fixture.budget = 0;
            expected = Status::BudgetExceeded;
            break;
        case Fault::IncreasedBudget:
            test.fixture.budget += 1;
            break;
        case Fault::FeeExceedsBudget:
            test.fixture.budget = 21000;
            expected = Status::BudgetExceeded;
            break;
        case Fault::PendingNonce:
            test.fixture.pending += 1;
            expected = Status::Busy;
            break;
        case Fault::StaleChallenge:
            test.fixture.stale = true;
            expected = Status::StaleChallenge;
            break;
        case Fault::OwnerFunds:
            test.fixture.ownerBalance = 0;
            expected = Status::InsufficientFunds;
            break;
        case Fault::OwnerStake:
            test.fixture.stake = 0;
            expected = Status::NotStaked;
            break;
        case Fault::MalformedParams:
            test.fixture.badParams = true;
            expected = Status::RpcUnavailable;
            break;
        case Fault::EstimateFailure:
            test.fixture.fail = "eth_estimateGas";
            expected = Status::RpcUnavailable;
            break;
        case Fault::FeeOverflow:
            test.fixture.gasPrice = ~uint256_t(0);
            expected = Status::BudgetExceeded;
            break;
        case Fault::FutureChallengeBlock:
            test.fixture.lastBlock = test.fixture.head + 1;
            expected = Status::RpcUnavailable;
            break;
        case Fault::RevokedDuringPreparation:
            test.fixture.revokeAtRead = test.fixture.reads + 2;
            break;
        }
        Submission submission;
        Status actual = miner.submit(proof, submission);
        if (actual != expected) {
            printf("fault %u: expected %s, got %s\n", static_cast<unsigned>(fault),
                   statusName(expected), statusName(actual));
            assert(false);
        }
        assert(test.fixture.sends == 0 && submission.state == SubmissionState::NotSent);
        if (fault == Fault::RevokedDuringPreparation) {
            assert(test.fixture.estimates == 1);
            assert(test.fixture.reads == 3); // Initial search, preflight, then final authorization.
        }
    }
}

static void testUncertainBroadcast() {
    for (bool wrongHash : {false, true}) {
        Test test;
        MiningEmbed miner(test.rpc, test.key, test.session);
        auto proof = candidate(miner);
        test.fixture.failSend = !wrongHash;
        test.fixture.badHash = wrongHash;
        Submission submission;
        assert(miner.submit(proof, submission) == Status::BroadcastUncertain);
        assert(submission.state == SubmissionState::Uncertain &&
               submission.hash == test.fixture.returnedHash && miner.unresolved());
        assert(miner.receipt(submission) == Status::Ok &&
               submission.state == SubmissionState::Uncertain);
        assert(miner.submit(proof, submission) == Status::Busy && test.fixture.sends == 1);
        test.fixture.receipt = 1;
        assert(miner.receipt(submission) == Status::Ok &&
               submission.state == SubmissionState::Confirmed);
    }
}

static void testKeyReplacement() {
    for (bool clear : {false, true}) {
        Test test;
        MiningEmbed miner(test.rpc, test.key, test.session);
        Candidate proof = candidate(miner);
        if (clear) {
            test.key.Clear();
        } else {
            uint8_t replacement[32];
            memset(replacement, 0x33, sizeof(replacement));
            assert(test.key.Import(replacement));
        }
        Submission submission;
        assert(miner.submit(proof, submission) == Status::InvalidArgument);
        assert(test.fixture.sends == 0);
    }
}

static void testInvalidProof() {
    Test test;
    MiningEmbed miner(test.rpc, test.key, test.session);
    Candidate proof = candidate(miner);
    // Both snapshots agree, but the nonce fails the strict target check.
    test.fixture.proofTarget = 1;
    memset(proof.params.target, 0, sizeof(proof.params.target));
    proof.params.target[31] = 1;
    assert(miner.revalidate(proof) == Status::InvalidProof);
    Submission submission;
    assert(miner.submit(proof, submission) == Status::InvalidProof);
    assert(test.fixture.sends == 0);
}

static void testApplicationCycle() {
    Test test;
    MiningSession session;
    assert(parseMiningSession(test.session.owner.c_str(), test.session.signer.c_str(),
                              "1337", "1000000000000000000", test.session.expiry, session));
    assert(session.chainId == 1337 && session.gaploBudget == uint256_t(UINT64_C(1000000000000000000)));
    for (const char* invalid : {"01", "0x10", "-1", "0", "10a",
                                "115792089237316195423570985008687907853269984665640564039457584007913129639936"}) {
        assert(!parseMiningSession(session.owner.c_str(), session.signer.c_str(), invalid,
                                   "1000", session.expiry, session));
    }
    assert(!parseMiningSession(session.owner.c_str(), session.owner.c_str(), "1337",
                               "1000", session.expiry, session));
    assert(!parseMiningSession(session.owner.c_str() + 2, session.signer.c_str(), "1337",
                               "1000", session.expiry, session));
    assert(!parseMiningSession(session.owner.c_str(), session.signer.c_str(), "1337",
                               "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                               session.expiry, session));

    MiningEmbed miner(test.rpc, test.key, test.session);
    Submission submission;
    assert(miner.step(1, submission) == Status::Ok && submission.state == SubmissionState::Broadcast);
    assert(miner.step(1, submission) == Status::Ok && submission.state == SubmissionState::Pending);
    assert(test.fixture.sends == 1 && miner.unresolved());
    test.fixture.receipt = 1;
    assert(miner.step(1, submission) == Status::Ok && submission.state == SubmissionState::Confirmed);
    assert(test.fixture.sends == 1 && !miner.unresolved());
}

int main() {
    testApplicationCycle();
    testFullChainDomain();
    testStakeBoundary();
    testReceiptLifecycle();
    testRejectedSubmissions();
    testUncertainBroadcast();
    testKeyReplacement();
    testInvalidProof();
    puts("facade: owner/session identity, domain, nonce, policy/funding/revocation, "
         "proof, key replacement and broadcast/receipt states passed");
}
