#ifndef MININGEMBED_PLATFORM_H
#define MININGEMBED_PLATFORM_H
#include <stddef.h>
#include <stdint.h>
#include <string>
namespace miningembed {
namespace detail {
std::string encodeCall(const char* signature, const std::string* argument);
void hash(const uint8_t* data, size_t length, uint8_t* output);
bool random(uint8_t* data, size_t length);
void cooperate();
} // namespace detail
} // namespace miningembed
#endif
