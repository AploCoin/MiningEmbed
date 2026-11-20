// Host adapter only: production uses Contract/Crypto/Arduino in MiningPlatform.cpp.
#include "MiningPlatform.h"
#include "sha3.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

namespace miningembed {
namespace detail {
void hash(const uint8_t* bytes, size_t length, uint8_t* output) {
    keccak_256(bytes, length, output);
}

bool random(uint8_t* bytes, size_t length) {
    memset(bytes, 0x22, length);
    return true;
}

void cooperate() {}
uint32_t milliseconds() { return 0; }
uint32_t microseconds() { return 0; }
} // namespace detail
} // namespace miningembed

extern "C" uint32_t random32(void) {
    uint32_t value;
    arc4random_buf(&value, sizeof(value));
    return value;
}

namespace aplo {
bool SessionPlatformRandom(uint8_t* bytes, size_t length) {
    arc4random_buf(bytes, length);
    return true;
}
} // namespace aplo
