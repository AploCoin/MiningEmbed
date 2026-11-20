#include "MiningPlatform.h"
#include "MiningWork.h"
#include <string.h>

namespace miningembed {
namespace detail {
std::string encodeCall(const char* signature, const std::string* argument) {
    if (!signature) {
        return {};
    }
    // Mining needs only these fixed ABI calls. Keep the general Contract encoder
    // and its dynamic-array/string machinery out of small mining applications.
    size_t bytes = 0;
    if (!strcmp(signature, "miner_params(address)") || !strcmp(signature, "getStake(address)")) {
        bytes = 20;
    } else if (!strcmp(signature, "mine(bytes32)")) {
        bytes = 32;
    } else if (strcmp(signature, "DEFAULT_DIFFICULTY()")) {
        return {};
    }
    uint8_t value[32];
    if ((bytes && (!argument || argument->size() != 2 + bytes * 2 ||
                   argument->compare(0, 2, "0x") ||
                   !decodeHex(argument->c_str(), value, sizeof(value), bytes))) ||
        (!bytes && argument)) {
        return {};
    }
    uint8_t digest[32];
    hash(reinterpret_cast<const uint8_t*>(signature), strlen(signature), digest);
    const char digits[] = "0123456789ABCDEF";
    std::string encoded(bytes ? 74 : 10, '0');
    encoded[1] = 'x';
    for (size_t i = 0; i < 4; ++i) {
        encoded[2 + 2 * i] = digits[digest[i] >> 4];
        encoded[3 + 2 * i] = digits[digest[i] & 15];
    }
    if (bytes) {
        // Preserve argument spelling, as Contract::SetupContractData does.
        encoded.replace(74 - bytes * 2, bytes * 2, *argument, 2, bytes * 2);
    }
    return encoded;
}
} // namespace detail
} // namespace miningembed
