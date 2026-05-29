import socket
import time

# Based on your 'ip addr' output, your WSL IP is 172.19.125.0
TARGET_IP = "196.168.1.30" 
PORT = 502

def send_modbus_command(fc, register, value=1):
    """
    Constructs a Modbus TCP packet and sends it using standard Python sockets.
    """
    # MBAP Header: Transaction ID (00 01), Protocol (00 00), Length (00 06), Unit (01)
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"
    
    # PDU: Function Code, Register Address (2 bytes), Data (2 bytes)
    pdu = bytes([fc]) + register.to_bytes(2, 'big') + value.to_bytes(2, 'big')
    
    payload = mbap + pdu

    try:
        # Standard TCP socket is best for WSL-to-WSL communication
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            # Even if the connection is refused, the SYN packet is sent and the sniffer sees it
            s.connect_ex((TARGET_IP, PORT))
            s.sendall(payload)
            print(f"[*] Sent FC={fc} to Register {register}")
    except Exception as e:
        # We ignore errors because we just want the sniffer to see the traffic
        pass

def simulate():
    print(f"--- Starting Continuous Modbus Simulation on {TARGET_IP} ---")
    print("[*] Press Ctrl+C to stop.")
    
    while True:
        try:
            # 1. Safe Read
            send_modbus_command(3, 10)
            time.sleep(2)
            
            # 2. Attack Write (Register 100)
            send_modbus_command(6, 100)
            time.sleep(2)
        except KeyboardInterrupt:
            print("\n[*] Stopping Simulation.")
            break

if __name__ == "__main__":
    simulate()
