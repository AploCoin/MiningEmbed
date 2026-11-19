#include "MiningWork.h"
#include <string.h>

namespace miningembed {
namespace {

int nibble(char character) {
    if (character >= '0' && character <= '9') {
        return character - '0';
    }

    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }

    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }

    return -1;
}

// Nonce occupies bytes 20..51 and is filled by the caller.
void packChallenge(const MinerParams& params, uint8_t (&packed)[148]) {
    memcpy(packed, params.signer, 20);
    memcpy(packed + 52, params.target, 32);
    memcpy(packed + 84, params.prevHash, 32);
    memcpy(packed + 116, params.totalMined, 32);
}

} // namespace

bool decodeHex(const char* hex, uint8_t* output, size_t capacity, size_t bytes) {
    if (!hex || !output || bytes > capacity || bytes > SIZE_MAX / 2) {
        return false;
    }

    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
    }
    if (strlen(hex) != bytes * 2) {
        return false;
    }

    // Validate first: malformed input must not partially overwrite the output.
    for (size_t index = 0; index < bytes * 2; ++index) {
        if (nibble(hex[index]) < 0) {
            return false;
        }
    }
    for (size_t index = 0; index < bytes; ++index) {
        output[index] =
            static_cast<uint8_t>((nibble(hex[2 * index]) << 4) | nibble(hex[2 * index + 1]));
    }
    return true;
}

bool sameChallenge(const MinerParams& first, const MinerParams& second) {
    return first.valid && second.valid && first.lastBlock == second.lastBlock &&
           memcmp(first.signer, second.signer, 20) == 0 &&
           memcmp(first.target, second.target, 32) == 0 &&
           memcmp(first.totalMined, second.totalMined, 32) == 0 &&
           memcmp(first.prevHash, second.prevHash, 32) == 0;
}

bool hashNonce(
    const MinerParams& params,
    const uint8_t* nonce,
    size_t nonceSize,
    uint8_t* output,
    size_t capacity,
    HashFunction hash
) {
    if (!params.valid || !nonce || nonceSize != 32 || !output || capacity < 32 || !hash) {
        return false;
    }

    uint8_t packed[148];
    packChallenge(params, packed);
    memcpy(packed + 20, nonce, 32);
    hash(packed, sizeof(packed), output);
    return true;
}

bool validProof(
    const MinerParams& params,
    const uint8_t* nonce,
    size_t nonceSize,
    HashFunction hash
) {
    uint8_t digest[32];
    return hashNonce(params, nonce, nonceSize, digest, sizeof(digest), hash) &&
           memcmp(digest, params.target, 32) < 0;
}

WorkResult search(
    const MinerParams& params,
    uint32_t attempts,
    Candidate& out,
    HashFunction hash,
    RandomFunction random,
    YieldFunction cooperate
) {
    out = Candidate();
    if (!params.valid || !hash || !random || !cooperate) {
        return WorkResult::InvalidArgument;
    }

    constexpr uint32_t maxAttempts = 2000;
    if (attempts == 0 || attempts > maxAttempts) {
        return WorkResult::InvalidArgument;
    }

    uint8_t packed[148];
    uint8_t digest[32];
    packChallenge(params, packed);
    uint8_t* nonce = packed + 20;
    for (uint32_t attempt = 0; attempt < attempts; ++attempt) {
        if ((attempt & 63U) == 0) {
            cooperate();
        }
        if (!random(nonce, 32)) {
            return WorkResult::RandomUnavailable;
        }

        hash(packed, sizeof(packed), digest);
        if (memcmp(digest, params.target, 32) < 0) {
            out.params = params;
            memcpy(out.nonce, nonce, 32);
            memcpy(out.hash, digest, 32);
            out.valid = true;
            cooperate();
            return WorkResult::Found;
        }
    }
    cooperate();
    return WorkResult::Exhausted;
}
} // namespace miningembed
