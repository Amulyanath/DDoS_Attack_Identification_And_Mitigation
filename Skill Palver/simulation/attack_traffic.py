import socket
import time
import random
import threading

UDP_IP = "127.0.0.1"
UDP_PORT = 9999

print(f"Starting ATTACK traffic simulation to {UDP_IP}:{UDP_PORT}")
print("Press Ctrl+C to stop.")

def attack():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        # Attack traffic (high speed)
        # Spoofed IPs (odd number last octet to fail mock RPF check)
        last_octet = random.choice([1, 3, 5, 7, 9, 11, 101, 255])
        src_ip = f"10.0.0.{last_octet}"
        
        msg = f"ATTACK_PAYLOAD|{src_ip}".encode()
        try:
            sock.sendto(msg, (UDP_IP, UDP_PORT))
        except:
            pass
        # No sleep = flood

# Launch multiple threads for higher volume
for i in range(5):
    t = threading.Thread(target=attack)
    t.daemon = True
    t.start()
    
# Keep main thread alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Stopping attack...")
