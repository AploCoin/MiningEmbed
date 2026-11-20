#pragma once
#include <stdint.h>
#include <cstdlib>
#include <string>
#define F(s) s
extern uint32_t testMillis;
inline uint32_t millis() { return testMillis; }
inline void delay(unsigned long) {}
class Stream {
public:
    virtual ~Stream() = default;
    virtual int available() = 0;
    virtual int read() = 0;
    virtual int availableForWrite() { return 0; }
    virtual size_t write(uint8_t) = 0;
    void print(const char* text) { while (*text) { write(static_cast<uint8_t>(*text++)); } }
    void print(char c) { write(static_cast<uint8_t>(c)); }
    void print(unsigned long n) { print(std::to_string(n).c_str()); }
    void print(unsigned n) { print(std::to_string(n).c_str()); }
    void print(int n) { print(std::to_string(n).c_str()); }
    void println(const char* text) { print(text); print('\n'); }
};
struct NativeSerial { template <typename T> void println(T) {} };
extern NativeSerial Serial;
