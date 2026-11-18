// Host adapter only: production uses Contract/Crypto/Arduino in MiningPlatform.cpp.
#include "MiningPlatform.h"
#include "sha3.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

namespace miningembed {
namespace detail {
static std::string hex(const uint8_t* bytes, size_t length) {
    static const char digits[] = "0123456789abcdef";
    std::string output = "0x";
    for (size_t index = 0; index < length; ++index) {
        output += digits[bytes[index] >> 4];
        output += digits[bytes[index] & 15];
    }
    return output;
}

std::string encodeCall(const char* signature, const std::string* argument) {
    uint8_t digest[32];
    keccak_256(reinterpret_cast<const uint8_t*>(signature), strlen(signature), digest);
    std::string output = hex(digest, 4);
    if (argument) {
        assert(argument->compare(0, 2, "0x") == 0);
        assert(argument->size() == 42 || argument->size() == 66);
        output += std::string(64 - (argument->size() - 2), '0') + argument->substr(2);
    }
    // Preserve the physically verified production Contract selector spelling.
    if (strcmp(signature, "mine(bytes32)") == 0) {
        for (size_t i = 2; i < 10; ++i) {
            if (output[i] >= 'a' && output[i] <= 'f') {
                output[i] -= 'a' - 'A';
            }
        }
    }
    return output;
}

void hash(const uint8_t* bytes, size_t length, uint8_t* output) {
    keccak_256(bytes, length, output);
}

bool random(uint8_t* bytes, size_t length) {
    memset(bytes, 0x22, length);
    return true;
}

void cooperate() {}
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
