// Mining algorithm extracted from AploEmbed 1d16a91 (MIT).
#ifndef MININGEMBED_WORK_H
#define MININGEMBED_WORK_H
#include <stddef.h>
#include <stdint.h>

namespace miningembed {
struct MinerParams {
    uint64_t lastBlock = 0;
    uint8_t target[32] = {};
    uint8_t totalMined[32] = {};
    uint8_t prevHash[32] = {};
    uint8_t signer[20] = {};
    bool valid = false;
};

struct Candidate {
    MinerParams params;
    uint8_t nonce[32] = {};
    uint8_t hash[32] = {};
    bool valid = false;
};

enum class WorkResult { Found, Exhausted, InvalidArgument, RandomUnavailable };
using HashFunction = void (*)(const uint8_t*, size_t, uint8_t*);
using RandomFunction = bool (*)(uint8_t*, size_t);
using YieldFunction = void (*)();

// Big-endian ABI words. Buffer capacities are checked before any write.
bool decodeHex(const char* hex, uint8_t* output, size_t capacity, size_t bytes);
bool sameChallenge(const MinerParams& a, const MinerParams& b);
bool hashNonce(
    const MinerParams& params,
    const uint8_t* nonce,
    size_t nonceSize,
    uint8_t* output,
    size_t capacity,
    HashFunction hash
);
bool validProof(
    const MinerParams& params,
    const uint8_t* nonce,
    size_t nonceSize,
    HashFunction hash
);
// At most 2,000 nonces; caller re-reads params between batches. No heap allocation.
WorkResult search(
    const MinerParams& params,
    uint32_t attempts,
    Candidate& out,
    HashFunction hash,
    RandomFunction random,
    YieldFunction cooperate
);
} // namespace miningembed
#endif
