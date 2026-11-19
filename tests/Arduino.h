#pragma once
#include <cstdlib>
#define F(text) text

struct NativeSerial {
    void println(const char*) {}
};

static NativeSerial Serial;
