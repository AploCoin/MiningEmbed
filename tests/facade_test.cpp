#include "MiningEmbed.h"
#include "MiningPlatform.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <memory>
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

static void
checkWire(const uint8_t* raw, size_t n, uint64_t nonce, const uint256_t& chain, uint64_t limit) {
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
    string accountOwner = owner;
    uint64_t latest = UINT64_C(1) << 40;
    unsigned receipts = 0;
    string events;
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
    bool advanceAtEstimate = false;
    int receipt = -1;

    string handleCall(const string& parameters) {
        assert(parameters.find("\"from\":\"" + accountOwner + "\"") != string::npos);
        const string getSession = detail::encodeCall("getSession(address)", &signer);
        if (parameters.find(getSession) != string::npos) {
            ++reads;
            const bool live = active && (revokeAtRead == 0 || reads < revokeAtRead);
            string registeredOwner(40, '0');
            if (live) {
                registeredOwner = badOwner ? string(40, '3') : accountOwner.substr(2);
            }
            string body = string(24, '0') + registeredOwner;
            body += string(24, '0') + (badTarget ? string(40, '4') : target.substr(2));
            body += word(aplo) + word(budget) + word(nonce) + word(expiry);
            return result(quoted("0x" + body));
        }
        if (parameters.find(detail::encodeCall("miner_params(address)", &signer)) != string::npos) {
            assert(parameters.find("\"0x" + uint256_t(head).str(16) + "\"") != string::npos);
            if (badParams) {
                return result(quoted("0x01"));
            }
            return result(quoted(
                "0x" + word(lastBlock) + word(freshZero ? uint256_t(0) : proofTarget) +
                word(
                    uint256_t("0x8000000000000000000000000000000000000000000000000000000000000001")
                ) +
                word(stale ? 1 : 0)
            ));
        }
        if (parameters.find(detail::encodeCall("DEFAULT_DIFFICULTY()", nullptr)) != string::npos) {
            return result(quoted("0x" + word(~uint256_t(0))));
        }
        if (parameters.find(detail::encodeCall("getStake(address)", &accountOwner)) !=
            string::npos) {
            return result(quoted("0x" + word(stake)));
        }
        assert(false);
        return "";
    }

    string estimateGas(const string& parameters) {
        ++estimates;
        if (advanceAtEstimate) {
            ++nonce;
            ++latest;
            ++pending;
        }
        assert(parameters.find("\"from\":\"" + signer + "\"") != string::npos);
        assert(parameters.find("\"to\":\"" + target + "\"") != string::npos);
        assert(
            parameters.find("0x2fdc505e") != string::npos &&
            parameters.find("\"value\":\"0x0\"") != string::npos
        );
        return result(quoted("0x" + uint256_t(estimate).str(16)));
    }

    string sendRaw(const string& parameters) {
        ++sends;
        events += "S";
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
        ++receipts;
        events += "R";
        assert(parameters.find(returnedHash) != string::npos);
        if (receiptError) {
            return R"({"error":{"code":-1,"message":"offline"}})";
        }
        return result(
            receipt < 0 ? "null"
                        : string("{\"transactionHash\":") + quoted(returnedHash) +
                              ",\"status\":\"0x" + (receipt ? "1" : "0") + "\"}"
        );
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
            assert(parameters.find(fixture.signer) != string::npos);
            const bool pending = parameters.find("pending") != string::npos;
            assert(pending || parameters.find("latest") != string::npos);
            fixture.events += pending ? "P" : "L";
            return result(
                quoted("0x" + uint256_t(pending ? fixture.pending : fixture.latest).str(16))
            );
        }
        if (method == "eth_getBalance") {
            assert(parameters.find(fixture.accountOwner) != string::npos);
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
    assert(
        miner.submit(proof, submission) == Status::Ok &&
        submission.state == SubmissionState::Broadcast
    );
    assert(
        submission.hash == test.fixture.returnedHash
    ); // bounded local raw buffer handles full uint256 domain
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
    assert(
        miner.submit(proof, submission) == Status::Ok &&
        submission.state == SubmissionState::Broadcast
    );
    assert(
        submission.hash == test.fixture.returnedHash && miner.unresolved() &&
        test.fixture.sends == 1
    );
    assert(miner.submit(proof, submission) == Status::Busy && test.fixture.sends == 1);
    assert(miner.receipt(submission) == Status::Ok && submission.state == SubmissionState::Pending);
    // Timeout/expiry/revocation cannot prove that a sent transaction disappeared.
    test.fixture.head = test.fixture.expiry;
    test.fixture.active = false;
    assert(
        miner.receipt(submission) == Status::Ok && submission.state == SubmissionState::Pending &&
        miner.unresolved()
    );
    assert(miner.submit(proof, submission) == Status::Busy && test.fixture.sends == 1);
    test.fixture.head = 100;
    test.fixture.active = true;
    test.fixture.chain = 28282;
    assert(
        miner.receipt(submission) == Status::SessionInvalid &&
        submission.state == SubmissionState::Pending && miner.unresolved()
    );
    test.fixture.chain = test.session.chainId;
    test.fixture.receiptError = true;
    assert(
        miner.receipt(submission) == Status::RpcUnavailable &&
        submission.state == SubmissionState::Pending && miner.unresolved()
    );
    test.fixture.receiptError = false;
    test.fixture.receipt = 0;
    assert(
        miner.receipt(submission) == Status::Ok && submission.state == SubmissionState::Reverted &&
        !miner.unresolved()
    );
    assert(miner.submit(proof, submission) == Status::Ok);
    test.fixture.receipt = 1;
    assert(
        miner.receipt(submission) == Status::Ok && submission.state == SubmissionState::Confirmed &&
        !miner.unresolved()
    );
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
         {Fault::Absent,
          Fault::WrongOwner,
          Fault::WrongTarget,
          Fault::AploAllowance,
          Fault::ExpiryMismatch,
          Fault::WrongChain,
          Fault::Expired,
          Fault::EmptyBudget,
          Fault::IncreasedBudget,
          Fault::FeeExceedsBudget,
          Fault::PendingNonce,
          Fault::StaleChallenge,
          Fault::OwnerFunds,
          Fault::OwnerStake,
          Fault::MalformedParams,
          Fault::EstimateFailure,
          Fault::FeeOverflow,
          Fault::RevokedDuringPreparation,
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
            printf(
                "fault %u: expected %s, got %s\n",
                static_cast<unsigned>(fault),
                statusName(expected),
                statusName(actual)
            );
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
        assert(
            submission.state == SubmissionState::Uncertain &&
            submission.hash == test.fixture.returnedHash && miner.unresolved()
        );
        assert(
            miner.receipt(submission) == Status::Ok &&
            submission.state == SubmissionState::Uncertain
        );
        assert(miner.submit(proof, submission) == Status::Busy && test.fixture.sends == 1);
        test.fixture.receipt = 1;
        assert(
            miner.receipt(submission) == Status::Ok &&
            submission.state == SubmissionState::Confirmed
        );
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
    assert(parseMiningSession(
        test.session.owner.c_str(),
        test.session.signer.c_str(),
        "1337",
        "1000000000000000000",
        test.session.expiry,
        session
    ));
    assert(
        session.chainId == 1337 && session.gaploBudget == uint256_t(UINT64_C(1000000000000000000))
    );
    for (const char* invalid :
         {"01",
          "0x10",
          "-1",
          "0",
          "10a",
          "115792089237316195423570985008687907853269984665640564039457584007913129639936"}) {
        assert(!parseMiningSession(
            session.owner.c_str(),
            session.signer.c_str(),
            invalid,
            "1000",
            session.expiry,
            session
        ));
    }
    assert(!parseMiningSession(
        session.owner.c_str(),
        session.owner.c_str(),
        "1337",
        "1000",
        session.expiry,
        session
    ));
    assert(!parseMiningSession(
        session.owner.c_str() + 2,
        session.signer.c_str(),
        "1337",
        "1000",
        session.expiry,
        session
    ));
    assert(!parseMiningSession(
        session.owner.c_str(),
        session.signer.c_str(),
        "1337",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        session.expiry,
        session
    ));

    MiningEmbed miner(test.rpc, test.key, test.session);
    Submission submission;
    assert(
        miner.step(1, submission) == Status::Ok && submission.state == SubmissionState::Broadcast
    );
    assert(miner.step(1, submission) == Status::Ok && submission.state == SubmissionState::Pending);
    assert(test.fixture.sends == 1 && miner.unresolved());
    test.fixture.receipt = 1;
    assert(
        miner.step(1, submission) == Status::Ok && submission.state == SubmissionState::Confirmed
    );
    assert(test.fixture.sends == 1 && !miner.unresolved());
}

struct Journal {
    PendingTransaction saved;
    Fixture* fixture = nullptr;
    bool occupied = false;
    bool failWrite = false;
    bool failClear = false;
    bool powerLoss = false;
    unsigned writes = 0;
    unsigned clears = 0;

    struct PowerLoss {};

    static bool write(const PendingTransaction* pending, void* context) {
        Journal& journal = *static_cast<Journal*>(context);
        if (pending) {
            ++journal.writes;
            journal.fixture->events += "W";
            if (journal.failWrite) {
                return false;
            }
            journal.saved = *pending;
            journal.occupied = true;
            if (journal.powerLoss) {
                throw PowerLoss();
            }
        } else {
            ++journal.clears;
            journal.fixture->events += "C";
            if (journal.failClear) {
                return false;
            }
            journal.occupied = false;
            journal.saved = PendingTransaction();
        }
        return true;
    }
};

static std::unique_ptr<MiningEmbed> makeMiner(Test& test, Journal& journal, bool direct) {
    journal.fixture = &test.fixture;
    if (direct) {
        test.fixture.accountOwner = test.fixture.signer;
        test.fixture.active = false;
        return std::unique_ptr<MiningEmbed>(
            new MiningEmbed(test.rpc, test.key, test.fixture.chain, Journal::write, &journal)
        );
    }
    return std::unique_ptr<MiningEmbed>(
        new MiningEmbed(test.rpc, test.key, test.session, Journal::write, &journal)
    );
}

static void testDirect() {
    for (unsigned fault = 0; fault < 9; ++fault) {
        Test test;
        Journal journal;
        auto miner = makeMiner(test, journal, true);
        Candidate proof = candidate(*miner);
        Status expected = Status::Ok;
        switch (fault) {
        case 1:
            test.fixture.ownerBalance = 0;
            expected = Status::InsufficientFunds;
            break;
        case 2:
            test.fixture.stake = 0;
            expected = Status::NotStaked;
            break;
        case 3:
            ++test.fixture.pending;
            expected = Status::Busy;
            break;
        case 4:
            ++test.fixture.latest;
            expected = Status::Busy;
            break;
        case 5:
            ++test.fixture.chain;
            expected = Status::SessionInvalid;
            break;
        case 6:
            test.key.Clear();
            expected = Status::InvalidArgument;
            break;
        case 7:
            test.fixture.active = true;
            expected = Status::SessionInvalid;
            break;
        case 8:
            test.fixture.pending = test.fixture.latest = UINT64_MAX;
            expected = Status::InvalidArgument;
            break;
        }
        Submission submission;
        assert(miner->submit(proof, submission) == expected);
        assert(test.fixture.sends == (fault == 0 ? 1u : 0u));
        if (fault == 0) {
            assert(journal.saved.nonce == test.fixture.latest);
            assert(journal.saved.hash == test.fixture.returnedHash);
            assert(journal.saved.raw == test.fixture.lastRaw);
            assert(memcmp(journal.saved.proof, proof.nonce, 32) == 0);
            assert(journal.saved.maxFee == 60000);
            assert(test.fixture.events.find("WS") != string::npos);
            test.fixture.receipt = 1;
            assert(
                miner->receipt(submission) == Status::Ok &&
                submission.state == SubmissionState::Confirmed && !journal.occupied
            );
        }
    }
}

static void testJournalFailures() {
    for (bool direct : {false, true}) {
        Test test;
        Journal journal;
        auto miner = makeMiner(test, journal, direct);
        auto proof = candidate(*miner);
        journal.failWrite = true;
        Submission submission;
        assert(miner->submit(proof, submission) == Status::JournalFailed);
        assert(miner->unresolved() && test.fixture.sends == 0 && journal.writes == 1);
        test.fixture.returnedHash = submission.hash;
        assert(miner->receipt(submission) == Status::JournalFailed);
        assert(miner->submit(proof, submission) == Status::Busy);
        // Definitive exact-hash receipt still requires a successful durable clear.
        test.fixture.receipt = 1;
        journal.failClear = true;
        assert(miner->receipt(submission) == Status::JournalFailed && miner->unresolved());
        journal.failClear = false;
        assert(miner->receipt(submission) == Status::Ok && !miner->unresolved());
        assert(test.fixture.sends == 0);
    }
}

static void testReboot() {
    for (bool direct : {false, true}) {
        for (unsigned loss = 0; loss < 3; ++loss) {
            Test test;
            Journal journal;
            auto miner = makeMiner(test, journal, direct);
            Candidate proof = candidate(*miner);
            Submission submission;
            // Power loss after journal commit / after send with lost response / after accepted
            // send.
            journal.powerLoss = loss == 0;
            test.fixture.failSend = loss == 1;
            if (loss == 0) {
                try {
                    miner->submit(proof, submission);
                    assert(false);
                } catch (const Journal::PowerLoss&) {
                }
                assert(test.fixture.sends == 0);
            } else {
                assert(
                    miner->submit(proof, submission) ==
                    (loss == 1 ? Status::BroadcastUncertain : Status::Ok)
                );
            }
            assert(journal.occupied && journal.writes == 1);
            test.fixture.returnedHash = journal.saved.hash;
            const string originalRaw = journal.saved.raw;
            miner.reset();
            miner = makeMiner(test, journal, direct);
            journal.powerLoss = false;
            test.fixture.failSend = false;
            assert(miner->restore(journal.saved));
            test.fixture.events.clear();
            assert(miner->receipt(submission) == Status::Ok);
            assert(test.fixture.events[0] == 'R');
            assert(submission.state == SubmissionState::Broadcast);
            assert(test.fixture.lastRaw == originalRaw);
            const unsigned sends = test.fixture.sends;
            for (unsigned i = 0; i < 4; ++i) {
                assert(miner->step(1, submission) == Status::Ok);
            }
            assert(test.fixture.sends == sends && journal.writes == 1 && journal.clears == 0);
            test.fixture.receipt = loss == 1 ? 0 : 1;
            assert(miner->receipt(submission) == Status::Ok && !miner->unresolved());
            assert(
                submission.state ==
                (loss == 1 ? SubmissionState::Reverted : SubmissionState::Confirmed)
            );
            assert(!journal.occupied && journal.clears == 1);
        }
    }
}

static void testRecoveryGuards() {
    for (bool direct : {false, true}) {
        for (unsigned fault = 0; fault < 20; ++fault) {
            Test test;
            Journal journal;
            auto miner = makeMiner(test, journal, direct);
            auto proof = candidate(*miner);
            Submission submission;
            assert(miner->submit(proof, submission) == Status::Ok);
            const PendingTransaction saved = journal.saved;
            miner = makeMiner(test, journal, direct);
            assert(miner->restore(saved));
            Status expected = Status::Ok;
            switch (fault) {
            case 0:
                ++test.fixture.pending;
                break; // Cannot identify the pending occupant.
            case 1:
                ++test.fixture.latest;
                ++test.fixture.pending;
                expected = Status::RecoveryRequired;
                break;
            case 2:
                --test.fixture.latest;
                expected = Status::RecoveryRequired;
                break;
            case 3:
                --test.fixture.pending;
                expected = Status::RecoveryRequired;
                break;
            case 4:
                test.fixture.active = direct;
                expected = Status::SessionInvalid;
                break;
            case 5:
                ++test.fixture.chain;
                expected = Status::SessionInvalid;
                break;
            case 6:
                test.fixture.stale = true;
                test.fixture.proofTarget = 1;
                expected = Status::InvalidProof;
                break;
            case 7:
                test.fixture.lastBlock = test.fixture.head;
                expected = Status::Cooldown;
                break;
            case 8:
                test.fixture.gasPrice = 2;
                expected = Status::RecoveryRequired;
                break;
            case 9:
                test.fixture.ownerBalance = 0;
                expected = Status::InsufficientFunds;
                break;
            case 10:
                test.fixture.stake = 0;
                expected = Status::NotStaked;
                break;
            case 11:
                test.fixture.estimate = 60001;
                expected = Status::RecoveryRequired;
                break;
            case 12:
                test.fixture.fail = "eth_getTransactionCount";
                expected = Status::RpcUnavailable;
                break;
            case 13:
                test.fixture.receiptError = true;
                expected = Status::RpcUnavailable;
                break;
            case 14:
                test.key.Clear();
                expected = Status::RecoveryRequired;
                break;
            case 15:
                test.fixture.advanceAtEstimate = true;
                expected = Status::RecoveryRequired;
                break;
            case 16:
                if (direct) {
                    test.fixture.active = true;
                } else {
                    test.fixture.head = test.fixture.expiry;
                }
                expected = direct ? Status::SessionInvalid : Status::Expired;
                break;
            case 17:
                if (direct) {
                    test.fixture.ownerBalance = 0;
                } else {
                    test.fixture.budget = 100;
                }
                expected = direct ? Status::InsufficientFunds : Status::BudgetExceeded;
                break;
            case 18:
                test.fixture.fail = "eth_estimateGas";
                expected = Status::RpcUnavailable;
                break;
            case 19:
                test.fixture.failSend = true;
                expected = Status::BroadcastUncertain;
                break;
            }
            Status actual = miner->receipt(submission);
            if (actual != expected) {
                printf(
                    "recovery direct=%d fault=%u: expected %s got %s\n",
                    direct,
                    fault,
                    statusName(expected),
                    statusName(actual)
                );
                assert(false);
            }
            const unsigned expectedSends = fault == 19 ? 2 : 1;
            assert(miner->unresolved() && journal.occupied && test.fixture.sends == expectedSends);
            if (fault == 19) {
                for (unsigned i = 0; i < 3; ++i) {
                    assert(miner->receipt(submission) == Status::Ok);
                }
                assert(test.fixture.sends == expectedSends);
            }
            assert(miner->submit(proof, submission) == Status::Busy);
            // Exact receipt resolves even with revoked authorization, conflicting nonce or changed
            // key.
            test.fixture.chain = test.session.chainId;
            test.fixture.receiptError = false;
            test.fixture.receipt = 1;
            assert(miner->receipt(submission) == Status::Ok && !miner->unresolved());
        }
    }
}

static void testRestoreValidation() {
    for (bool direct : {false, true}) {
        Test test;
        Journal journal;
        auto miner = makeMiner(test, journal, direct);
        auto proof = candidate(*miner);
        Submission submission;
        assert(miner->submit(proof, submission) == Status::Ok);
        const PendingTransaction saved = journal.saved;
        for (unsigned fault = 0; fault < 10; ++fault) {
            auto restored = makeMiner(test, journal, direct);
            PendingTransaction damaged = saved;
            switch (fault) {
            case 0:
                damaged.hash[2] = damaged.hash[2] == 'a' ? 'b' : 'a';
                break;
            case 1:
                damaged.raw = "0x";
                break;
            case 2:
                damaged.raw += "0";
                break;
            case 3:
                damaged.raw = "0x" + string(514, '0');
                break;
            case 4:
                ++damaged.nonce;
                break;
            case 5:
                ++damaged.maxFee;
                break;
            case 6:
                damaged.proof[0] ^= 1;
                break;
            case 7:
                damaged.raw[2] = '0';
                break;
            case 8:
                damaged.nonce = UINT64_MAX;
                break;
            case 9:
                damaged.hash.clear();
                break;
            }
            assert(!restored->restore(damaged));
            assert(restored->unresolved());
            assert(restored->step(1, submission) == Status::RecoveryRequired);
            assert(!restored->restore(saved)); // Cannot silently replace a corrupt lock.
        }
        // Correct hash over modified raw still cannot pass the retained-key signature binding.
        PendingTransaction damaged = saved;
        damaged.raw[damaged.raw.size() - 1] = damaged.raw.back() == 'a' ? 'b' : 'a';
        uint8_t raw[256], digest[32];
        assert(decodeHex(damaged.raw.c_str(), raw, sizeof(raw), (damaged.raw.size() - 2) / 2));
        detail::hash(raw, (damaged.raw.size() - 2) / 2, digest);
        damaged.hash = "0x";
        const char digits[] = "0123456789abcdef";
        for (uint8_t byte : digest) {
            damaged.hash += digits[byte >> 4];
            damaged.hash += digits[byte & 15];
        }
        auto restored = makeMiner(test, journal, direct);
        assert(!restored->restore(damaged));
        // Recompute the hash for every truncated RLP so the parser, not just hash checking,
        // must reject incomplete records under ASan/UBSan.
        for (size_t length = 1; length < (saved.raw.size() - 2) / 2; ++length) {
            damaged = saved;
            damaged.raw.resize(2 + length * 2);
            assert(decodeHex(damaged.raw.c_str(), raw, sizeof(raw), length));
            detail::hash(raw, length, digest);
            damaged.hash = "0x";
            for (uint8_t byte : digest) {
                damaged.hash += digits[byte >> 4];
                damaged.hash += digits[byte & 15];
            }
            auto truncated = makeMiner(test, journal, direct);
            assert(!truncated->restore(damaged) && truncated->unresolved());
        }
        // A different chain domain and a different retained key cannot restore the record.
        test.session.chainId += 1;
        MiningEmbed wrongChain(test.rpc, test.key, direct ? test.session.chainId : uint256_t(1));
        assert(!wrongChain.restore(saved));
        uint8_t other[32];
        memset(other, 0x33, 32);
        assert(test.key.Import(other));
        auto wrongKey = makeMiner(test, journal, direct);
        assert(!wrongKey->restore(saved));
        assert(test.fixture.sends == 1);
    }
}

static void testTerminalReboot() {
    for (bool direct : {false, true}) {
        Test test;
        Journal journal;
        auto miner = makeMiner(test, journal, direct);
        Submission submission;
        assert(miner->step(1, submission) == Status::Ok);
        test.fixture.receipt = 1;
        journal.failClear = true;
        assert(miner->receipt(submission) == Status::JournalFailed && journal.occupied);
        miner = makeMiner(test, journal, direct);
        assert(miner->restore(journal.saved));
        journal.failClear = false;
        assert(
            miner->step(1, submission) == Status::Ok &&
            submission.state == SubmissionState::Confirmed && !journal.occupied
        );
        assert(test.fixture.sends == 1);
    }
}

static void testDirectFullDomain() {
    Test test;
    test.fixture.chain = ~uint256_t(0);
    test.fixture.nonce = test.fixture.latest = test.fixture.pending = UINT64_MAX - 1;
    Journal journal;
    auto miner = makeMiner(test, journal, true);
    Submission submission;
    assert(miner->step(1, submission) == Status::Ok && test.fixture.sends == 1);
    miner = makeMiner(test, journal, true);
    assert(miner->restore(journal.saved));
    test.fixture.receipt = 1;
    assert(
        miner->receipt(submission) == Status::Ok && submission.state == SubmissionState::Confirmed
    );
}

static void testRuntimeRetry() {
    for (bool direct : {false, true}) {
        for (unsigned response = 0; response < 3; ++response) {
            Test test;
            Journal journal;
            auto miner = makeMiner(test, journal, direct);
            test.fixture.failSend = response == 1;
            test.fixture.badHash = response == 2;
            Submission submission;
            const uint32_t start = UINT32_MAX - 1000; // cadence survives millis wrap
            assert(miner->step(2000, submission, start) ==
                   (response ? Status::BroadcastUncertain : Status::Ok));
            assert(miner->hashesTested() == 1 && journal.writes == 1);
            const string originalRaw = journal.saved.raw;
            const string originalHash = journal.saved.hash;
            assert(miner->step(2000, submission, start + 29999U) == Status::Ok);
            assert(miner->hashesTested() == 0 && test.fixture.sends == 1);
            test.fixture.events.clear();
            test.fixture.failSend = test.fixture.badHash = false;
            assert(miner->step(2000, submission, start + 30000U) == Status::Ok);
            assert(test.fixture.events[0] == 'R' && test.fixture.sends == 2);
            assert(submission.state == SubmissionState::Broadcast);
            assert(submission.hash == originalHash && test.fixture.lastRaw == originalRaw);
            assert(journal.writes == 1 && journal.clears == 0);
            assert(miner->step(1, submission, start + 30001U) == Status::Ok);
            assert(test.fixture.sends == 2 && submission.state == SubmissionState::Pending);
            assert(miner->step(1, submission, start + 60000U) == Status::Ok);
            assert(test.fixture.sends == 3 && test.fixture.lastRaw == originalRaw);
            test.fixture.receipt = 1;
            assert(miner->step(1, submission, start + 90000U) == Status::Ok);
            assert(submission.state == SubmissionState::Confirmed && !miner->unresolved());
            assert(test.fixture.sends == 3 && journal.clears == 1);
        }
    }
}

static void testRuntimeRetryGuards() {
    for (bool direct : {false, true}) {
        for (unsigned fault = 0; fault < 10; ++fault) {
            Test test;
            Journal journal;
            auto miner = makeMiner(test, journal, direct);
            Submission submission;
            assert(miner->step(1, submission, 0) == Status::Ok);
            switch (fault) {
            case 0: ++test.fixture.pending; break;
            case 1: ++test.fixture.latest; ++test.fixture.pending; break;
            case 2: ++test.fixture.chain; break;
            case 3: test.fixture.active = direct; break;
            case 4: test.fixture.receiptError = true; break;
            case 5: test.fixture.ownerBalance = 0; break;
            case 6: test.fixture.stale = true; test.fixture.proofTarget = 1; break;
            case 7: test.fixture.advanceAtEstimate = true; break;
            case 8: test.fixture.gasPrice = 2; break;
            case 9:
                if (direct) {
                    test.fixture.stake = 0;
                } else {
                    test.fixture.head = test.fixture.expiry;
                }
                break;
            }
            miner->step(1, submission, 30000);
            assert(miner->unresolved() && test.fixture.sends == 1);
            assert(journal.occupied && journal.writes == 1 && journal.clears == 0);
            const unsigned estimates = test.fixture.estimates;
            miner->step(1, submission, 30001);
            assert(test.fixture.sends == 1 && test.fixture.estimates == estimates);
        }
    }
}

static void testWorkCacheAndAccounting() {
    Test test;
    test.fixture.proofTarget = 1;
    MiningEmbed miner(test.rpc, test.key, test.session);
    Submission submission;
    assert(miner.step(2000, submission, 0) == Status::NoCandidate);
    assert(miner.hashesTested() == 2000 && test.fixture.reads == 1);
    assert(miner.step(123, submission, 999) == Status::NoCandidate);
    assert(miner.hashesTested() == 123 && test.fixture.reads == 1);
    test.fixture.head = test.fixture.expiry;
    assert(miner.step(123, submission, 1000) == Status::Expired);
    assert(miner.hashesTested() == 0 && test.fixture.reads == 2 && test.fixture.sends == 0);
    assert(miner.step(0, submission, 1001) == Status::InvalidArgument);
    assert(miner.hashesTested() == 0);
}

int main() {
    testWorkCacheAndAccounting();
    testRuntimeRetry();
    testRuntimeRetryGuards();
    testTerminalReboot();
    testDirectFullDomain();
    testDirect();
    testJournalFailures();
    testReboot();
    testRecoveryGuards();
    testRestoreValidation();
    testApplicationCycle();
    testFullChainDomain();
    testStakeBoundary();
    testReceiptLifecycle();
    testRejectedSubmissions();
    testUncertainBroadcast();
    testKeyReplacement();
    testInvalidProof();
    puts(
        "facade: owner/session identity, domain, nonce, policy/funding/revocation, "
        "proof, direct EIP155, durable journal, runtime/reboot retry, work cache, "
        "actual hash counts and receipt states passed"
    );
}
