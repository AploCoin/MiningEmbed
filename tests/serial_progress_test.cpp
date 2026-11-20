#include <provisioning/SerialConfig.h>
#include <Arduino.h>
#include <assert.h>
#include <stdio.h>
#include <string>

using namespace miningembed::provisioning;
uint32_t testMillis = 0;
NativeSerial Serial;

class MemoryFlash : public FlashBackend {
public:
    std::string slots[4];
    unsigned writes = 0;
    bool begin() override { return true; }
    Read read(unsigned slot, std::string& out) override {
        out = slots[slot];
        return out.empty() ? Read::Missing : Read::Ok;
    }
    bool replace(unsigned slot, const std::string& bytes) override {
        ++writes;
        slots[slot] = bytes;
        return true;
    }
};

class Port : public Stream {
public:
    std::string input, output;
    size_t cursor = 0;
    int space = 0;
    bool progress = true, recurse = false;
    SerialConfig* parser = nullptr;
    int available() override { return int(input.size() - cursor); }
    int read() override { return available() ? input[cursor++] : -1; }
    int availableForWrite() override { return space; }
    size_t write(uint8_t byte) override {
        // A real UART can yield if the FIFO is full. That is forbidden here.
        assert(!progress || space > 0);
        if (progress) { --space; }
        output += static_cast<char>(byte);
        if (recurse) { parser->pollProgress(*this, "mining"); }
        return 1;
    }
    void feed(const std::string& text) { input += text; }
    void pump(SerialConfig& serial, int quota = 7) {
        parser = &serial;
        space = quota;
        progress = true;
        const size_t written = output.size(), consumed = cursor;
        serial.pollProgress(*this, "mining");
        assert(output.size() - written <= 64);
        assert(cursor - consumed <= 256);
    }
    void finish(SerialConfig& serial) {
        for (unsigned i = 0; i < 100; ++i) { pump(serial); }
    }
    void normal(SerialConfig& serial) {
        progress = false;
        serial.poll(*this, "mining");
    }
};

int main() {
    MemoryFlash flash;
    {
        DeviceConfig initial(flash);
        assert(initial.begin());
        assert(initial.enroll(std::string(64, '1')));
    }
    DeviceConfig store(flash);
    assert(store.begin() && store.enrolled());
    const unsigned initialWrites = flash.writes;
    RuntimeSnapshot snapshot;
    snapshot.busy = true;
    SerialConfig serial(store, nullptr, &snapshot);
    Port port;

    port.feed("APLO1 1 GET_NETWORK_STATUS\nAPLO1 2 GET_MINING_STATS\n");
    port.pump(serial, 0);
    assert(port.output.empty());
    // Only one frame is consumed until its response has drained.
    assert(port.available() > 0);
    const size_t consumed = port.cursor;
    port.pump(serial, 0);
    assert(port.cursor == consumed);
    port.recurse = true;
    port.finish(serial);
    assert(port.output.find("APLO1 1 OK network wifi=inactive clock_ready=0 rpc=busy\n") == 0);
    assert(port.output.find("APLO1 2 OK stats hashes=0 ") != std::string::npos);
    assert(flash.writes == initialWrites);

    // Authentication and BEGIN remain queued until the ordinary loop, while
    // using the same physical console preserves the authentication binding.
    port.feed("APLO1 3 AUTH " + std::string(64, '1') + "\n");
    port.pump(serial);
    assert(port.output.find("APLO1 3 ") == std::string::npos);
    port.normal(serial);
    assert(port.output.find("APLO1 3 OK authenticated\n") != std::string::npos);
    port.feed("APLO1 4 BEGIN\n");
    port.pump(serial);
    assert(!serial.provisioningActive());
    port.normal(serial);
    assert(serial.provisioningActive());
    assert(port.output.find("APLO1 4 OK\n") != std::string::npos);
    assert(flash.writes == initialWrites);

    // Backlogged replies are emitted before a later normal-loop reply.
    port.feed("APLO1 5 STATUS\n");
    port.pump(serial, 1);
    port.feed("APLO1 6 DIAG\n");
    port.normal(serial);
    const auto first = port.output.find("APLO1 5 OK status");
    const auto second = port.output.find("APLO1 6 ERR unavailable");
    assert(first != std::string::npos && second > first);
    printf("serial progress: TX backpressure, bounded frames, reentrancy, deferred mutation and reply order passed\n");
}
