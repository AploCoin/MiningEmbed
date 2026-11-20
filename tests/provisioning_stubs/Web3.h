#pragma once
#include <cstring>
// The native progress test does not exercise URL or certificate validation.
class Web3 {
public:
    static bool isHttpsUrl(const char* text) {
        return text && !strncmp(text, "https://", 8) && strlen(text) > 8;
    }
    static bool isValidCertificate(const char* text) {
        return text && !strncmp(text, "-----BEGIN CERTIFICATE-----\n", 28) &&
               strstr(text, "-----END CERTIFICATE-----\n");
    }
};
