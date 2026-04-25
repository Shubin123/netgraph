#!/usr/bin/env python3
import serial
import sys
import os
import time

if len(sys.argv) < 2:
    print("Usage: python3 listener.py <PORT>")
    print("Example: python3 listener.py /dev/cu.usbmodem11401")
    sys.exit(1)

SERIAL_PORT = sys.argv[1]
BAUD_RATE = 921600   
OUTPUT_FILE = "live_capture.pcapng"

print(f"[*] Attaching Listener to {SERIAL_PORT} @ {BAUD_RATE} baud...")

try:
    # timeout=0.1 is critical on MacOS to allow Ctrl+C to work without freezing
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1)
except Exception as e:
    print(f"[-] FATAL: Failed to open port {SERIAL_PORT}.")
    print(f"    Error: {e}")
    sys.exit(1)

# CRITICAL FIX: Reboot the ESP32 immediately upon connection.
# This guarantees we catch the PCAPNG Global Headers from setup()!
print("[*] Rebooting ESP32 via DTR/RTS to synchronize stream...")
ser.dtr = False
ser.rts = False
time.sleep(0.1)
ser.dtr = True
ser.rts = True
time.sleep(0.5)

if os.path.exists(OUTPUT_FILE):
    os.remove(OUTPUT_FILE)

MAGIC_NUMBER = b'\n\r\r\n'
synced = False
buffer = bytearray()
bytes_written = 0

print(f"[+] Listener Online. Writing binary stream to {OUTPUT_FILE}")
print("[!] Press CTRL+C at any time to safely terminate.\n")

try:
    with open(OUTPUT_FILE, "wb") as f:
        while True:
            if ser.in_waiting > 0:
                chunk = ser.read(ser.in_waiting)
                
                # We must find the headers before we write anything to disk
                if not synced:
                    buffer.extend(chunk)
                    idx = buffer.find(MAGIC_NUMBER)
                    if idx != -1:
                        print("\n[+] PCAPNG Magic Number detected! Synchronized.")
                        synced = True
                        
                        # Discard garbage/boot logs, keep everything from header onward
                        valid_data = buffer[idx:]
                        f.write(valid_data)
                        f.flush()
                        os.fsync(f.fileno()) # Force MacOS to update the file on disk
                        
                        bytes_written += len(valid_data)
                    else:
                        # Prevent RAM explosion if the ESP32 isn't sending headers
                        if len(buffer) > 50000:
                            print("\n[-] Still waiting for headers. Try pressing the physical RST button on the board!")
                            buffer = buffer[-4096:] 
                else:
                    # We are synced! Dump everything straight to disk.
                    f.write(chunk)
                    f.flush()
                    os.fsync(f.fileno())
                    
                    bytes_written += len(chunk)
                    sys.stdout.write(f"\r[*] Captured: {bytes_written} bytes  ")
                    sys.stdout.flush()
            else:
                time.sleep(0.01)

except KeyboardInterrupt:
    print("\n\n[+] Stream Terminated Safely.")
    print(f"[+] Saved {bytes_written} bytes to: {OUTPUT_FILE}")
finally:
    if 'ser' in locals() and ser.is_open:
        ser.close()