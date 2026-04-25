// INSTALL THE POLITICIAN LIBRARY IN THE ARDUINO IDE
// ITS THE ONLY LIBRARY YOU NEED plus esp32 board manager ofc

#include <Arduino.h>
#include "Politician.h"
#include "PoliticianFormat.h"

using namespace politician;
using namespace politician::format;

Politician engine;
uint8_t pcapBuffer[4096];

void setup() {
    // Serial.setTxBufferSize(4096);
    Serial.begin(921600);
    delay(3000); 

    // Silence text logs to prevent PCAP corruption
    engine.setLogger([](const char* msg) {});

    // Send the PCAPNG headers to start the file
    size_t header_len = writePcapngGlobalHeader(pcapBuffer);
    Serial.write(pcapBuffer, header_len);

    Config cfg;
    // CRITICAL FIX: Allow EVERY frame to pass through the filter
    cfg.capture_filter = LOG_FILTER_ALL; 
    cfg.hop_dwell_ms = 550; 
    
    if (engine.begin(cfg) != politician::OK) {
        while(1) delay(100);
    }
    
    // Passive listening only, hopping across all channels
    engine.setAttackMask(ATTACK_ALL);
    engine.startHopping();
    // engine.lockChannel(9);

    // Hook the raw packet logger (captures everything)
    engine.setPacketLogger([](const uint8_t* payload, uint16_t len, int8_t rssi, uint32_t ts_usec) {
    
    // Discard short frames
    // if (len < 10) return;  // too short to be a valid frame even without FCS
    len -= 4;

    // Only write when the TX FIFO can accept the ENTIRE block atomically.
    // A partial write splits an EPB across two reads on the Python side, which
    // shifts every subsequent block's boundary means cascading malformed packets.
    // Dropping a frame is far better than corrupting the stream.
    size_t block_len = writePcapngPacket(payload, len, rssi, ts_usec, pcapBuffer, sizeof(pcapBuffer));
    if (block_len == 0) return;

    // if (Serial.availableForWrite() >= (int)block_len) {
        Serial.write(pcapBuffer, block_len);
        Serial.flush(); // Ensure delivery before resuming the attack loop

    // }
});


}

void loop() {
    // engine.tick();
    delay(1000);
}