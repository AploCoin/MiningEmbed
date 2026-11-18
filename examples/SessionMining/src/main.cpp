#include <Arduino.h>
#include <AploPlatform.h>
#include <Web3.h>
#include <MiningEmbed.h>

using namespace miningembed;

// Replace this provider with your application-controlled provisioning flow.
// Return only a confirmed, owner-approved authorization and its matching RAM key.
// The default zero secret deliberately prevents mining until provisioned.
static bool loadConfirmedSession(aplo::SessionKey& key, MiningSession& session) {
    uint8_t secret[32] = {}; // Fill from your provisioning source, never a committed real key.
    session.owner = "0x1111111111111111111111111111111111111111";
    session.signer = "0x2222222222222222222222222222222222222222";
    session.chainId = uint256_t(28282);
    session.gaploBudget = uint256_t(UINT64_C(1000000000000000000));
    session.expiry = 1; // Copy the confirmed inclusive expiry, not a relative duration.
    const bool imported = key.Import(secret);
    // Volatile writes prevent removal of this temporary-secret wipe.
    volatile uint8_t* bytes = secret;
    for (size_t index = 0; index < sizeof(secret); ++index) {
        bytes[index] = 0;
    }
    if (!imported || key.Address() != session.signer) {
        key.Clear();
        return false;
    }
    return true;
}

void setup() {
    Serial.begin(115200);
    // Configure Wi-Fi and trusted TLS here before the loop creates Web3.
}

void loop() {
    if (WiFi.status() != WL_CONNECTED) {
        delay(100);
        return;
    }
    // ESP8266 needs network readiness before constructing TLS state.
    static Web3 web3;
    static aplo::SessionKeys rpc(web3);
    static aplo::SessionKey key;
    static MiningSession authorization;
    static bool provisioned = false;
    if (!provisioned) {
        if (!loadConfirmedSession(key, authorization)) {
            delay(1000);
            return;
        }
        provisioned = true;
    }
    static MiningEmbed miner(rpc, key, authorization);
    Submission submission;
    Status status;
    if (miner.unresolved()) {
        status = miner.receipt(submission);
        Serial.printf("receipt status=%u state=%u hash=%s\n", static_cast<unsigned>(status),
                      static_cast<unsigned>(submission.state), submission.hash.c_str());
    } else {
        MinerParams params;
        Candidate candidate;
        status = miner.readParams(params);
        if (status == Status::Ok) {
            status = miner.findCandidate(params, 2000, candidate);
        }
        // submit() repeats authorization, funding, nonce and challenge checks.
        if (status == Status::Ok) {
            status = miner.submit(candidate, submission);
        }
        Serial.println(statusName(status));
    }
    delay(1000); // The application owns cadence and unresolved-transaction recovery.
}
