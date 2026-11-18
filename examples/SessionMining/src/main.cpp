#include <Arduino.h>
#include <AploPlatform.h>
#include <Web3.h>
#include <MiningEmbed.h>

#if __has_include("AploTrustProfile.h")
#include "AploTrustProfile.h"
#endif

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
    // Connect Wi-Fi and synchronize time before running the mining loop.
}

void loop() {
    if (WiFi.status() != WL_CONNECTED) {
        delay(100);
        return;
    }
    // ESP8266 needs network readiness before constructing TLS state.
#if __has_include("AploTrustProfile.h")
    static Web3 web3(APLO_TRUST_PRIMARY_URL, APLO_TRUST_FALLBACK_URL);
#else
    static Web3 web3; // For manual CA setup, call setCertificate before using RPC.
#endif
    static aplo::SessionKeys rpc(web3);
    static aplo::SessionKey key;
    static MiningSession authorization;
    static bool provisioned = false;
    if (!provisioned) {
        if (!loadConfirmedSession(key, authorization)) {
            delay(1000);
            return;
        }
#if __has_include("AploTrustProfile.h")
        web3.setCertificate(APLO_TRUST_PRIMARY_CA, APLO_TRUST_FALLBACK_CA);
#endif
        provisioned = true;
    }
    static MiningEmbed miner(rpc, key, authorization);
    Submission submission;
    const Status status = miner.step(2000, submission);
    Serial.println(statusName(status));
    if (!submission.hash.empty()) {
        Serial.printf("state=%u hash=%s\n", static_cast<unsigned>(submission.state),
                      submission.hash.c_str());
    }
    delay(1000); // The application owns cadence and unresolved-transaction recovery.
}
