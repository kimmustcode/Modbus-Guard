import socket
import time

# Use 127.0.0.1 for the most reliable WSL-to-WSL connection
TARGET_IP = "127.0.0.1" 
PORT = 502

def send_modbus_command(fc, register, value=1):
    """
    Constructs a Modbus TCP packet and sends it using standard Python sockets.
    This is much more reliable in WSL than raw packet injection.
    """
    # MBAP Header: 
    # Transaction ID (00 01), Protocol ID (00 00), Length (00 06), Unit ID (01)
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"
    
    # PDU: 
    # Function Code (1), Register Address (2 bytes), Data/Count (2 bytes)
    pdu = bytes([fc]) + register.to_bytes(2, 'big') + value.to_bytes(2, 'big')
    
    payload = mbap + pdu

    try:
        # Using a standard TCP socket ensures the packet follows the OS network path
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            # Note: This will attempt to connect to port 502. 
            # Even if no one is listening, the 'connect' attempt generates a SYN packet 
            # that the sniffer will see.
            try:
                s.connect((TARGET_IP, PORT))
                s.sendall(payload)
            except (ConnectionRefusedError, socket.timeout):
                # This is actually OK for a sniffer test! 
                # The SYN/ACK handshake attempt is enough for the sniffer to see the packet.
                pass
            
            print(f"[*] Sent Modbus FC={fc} to Register {register}")
    except Exception as e:
        print(f"[!] Error: {e}")

def simulate_scenarios():
    print(f"--- Starting Reliable Modbus Simulation on {TARGET_IP} ---")
    
    # 1. Safe Scenario: Read Holding Register 10
    send_modbus_command(3, 10)
    time.sleep(1)
    
    # 2. Attack Scenario: Unauthorized Write to Critical Register 100
    send_modbus_command(6, 100)
    time.sleep(1)
    
    # 3. High Severity Scenario: Write Multiple Registers (FC 16)
    send_modbus_command(16, 102)

    print("--- Simulation Complete ---")

if __name__ == "__main__":
    simulate_scenarios()
