#include "MiningPlatform.h"
#include <Crypto.h>
#include <Arduino.h>

namespace miningembed {
namespace detail {
void hash(const uint8_t* data, size_t length, uint8_t* output) {
    Crypto::Keccak256(data, length, output);
}

bool random(uint8_t* data, size_t length) {
    return Crypto::RandomBytes(data, length);
}

void cooperate() {
    delay(0);
}
uint32_t milliseconds() { return millis(); }
uint32_t microseconds() { return micros(); }
} // namespace detail
} // namespace miningembed
