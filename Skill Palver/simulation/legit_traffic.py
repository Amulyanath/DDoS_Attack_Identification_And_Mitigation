import socket
import time
import random

UDP_IP = "127.0.0.1"
UDP_PORT = 9999

print(f"Starting LEGITIMATE traffic simulation to {UDP_IP}:{UDP_PORT}")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    # Simulate normal traffic (random intervals, normal IPs)
    # 10-20 packets per second
    delay = random.uniform(0.05, 0.1)
    
    # Legit IPs (e.g., even number last octet to pass our mock RPF check)
    last_octet = random.choice([2, 4, 6, 8, 10, 12, 100, 200])
    src_ip = f"192.168.1.{last_octet}"
    
    # We can't easily spoof source IP with standard socket without root/raw sockets.
    # So we will just send data and let the server see 127.0.0.1 or we wrap the packet.
    # Since we are using standard sockets, the server sees loopback.
    # To fix this for simulation, we will send the "IP" inside the payload,
    # and modify the server to read it from payload if strictly testing logic.
    # OR better: The server `addr` will be used. 
    # Since we can't spoof `addr` easily on windows without raw sockets (requires admin),
    # I will modify the server.py to read a simulated IP from the payload if present, 
    # otherwise use real IP.
    
    msg = f"LEGIT_PAYLOAD|{src_ip}".encode()
    sock.sendto(msg, (UDP_IP, UDP_PORT))
    
    time.sleep(delay)
