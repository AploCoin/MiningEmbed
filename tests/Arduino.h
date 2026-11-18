#pragma once
#include <cstdlib>
struct NativeSerial {
    void println(const char*) {}
};
static NativeSerial Serial;
