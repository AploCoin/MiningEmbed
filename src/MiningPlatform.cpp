#include "MiningPlatform.h"
#include <Contract.h>
#include <Crypto.h>
#include <Arduino.h>
namespace miningembed {
namespace detail {
std::string encodeCall(const char* signature, const std::string* argument) {
    // ABI-only borrowed context; this object never owns/creates an RPC client.
    Contract abi(nullptr, "");
    return argument ? abi.SetupContractData(signature, argument) : abi.SetupContractData(signature);
}
void hash(const uint8_t* data, size_t length, uint8_t* output) {
    Crypto::Keccak256(data, length, output);
}
bool random(uint8_t* data, size_t length) {
    return Crypto::RandomBytes(data, length);
}
void cooperate() {
    delay(0);
}
} // namespace detail
} // namespace miningembed
