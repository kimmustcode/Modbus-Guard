from scapy.all import IP, TCP, Raw, send
import time

# Target IP (The IP of the computer running Modbus-Guard)
TARGET_IP = "127.0.0.1" # Change this to the actual IP of the other machine

def send_modbus_packet(fc, register, value=1):
    """
    Manually constructs a Modbus TCP packet using Scapy.
    """
    # MBAP Header: Transaction ID (2), Protocol ID (2), Length (2), Unit ID (1)
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"
    
    # PDU: Function Code (1), Register Address (2), Data/Count (2)
    # Using big-endian (struct.pack style)
    pdu = bytes([fc]) + register.to_bytes(2, 'big') + value.to_bytes(2, 'big')
    
    payload = mbap + pdu
    
    # Construct Packet: IP -> TCP -> Modbus Data
    pkt = IP(dst=TARGET_IP)/TCP(sport=54321, dport=502)/Raw(load=payload)
    
    print(f"[*] Sending Modbus FC={fc} to Register {register}...")
    send(pkt, verbose=False)

def simulate_scenarios():
    print(f"--- Starting Modbus Simulation targeting {TARGET_IP} ---")
    
    # 1. Safe Scenario: Read Holding Register 10
    send_modbus_packet(3, 10)
    time.sleep(1)
    
    # 2. Attack Scenario: Unauthorized Write to Critical Register 100
    send_modbus_packet(6, 100)
    time.sleep(1)
    
    # 3. High Severity Scenario: Write Multiple Registers
    # (Simplified as single packet for this test)
    send_modbus_packet(16, 102)

    print("--- Simulation Complete ---")

if __name__ == "__main__":
    # If running from another computer, change TARGET_IP above.
    simulate_scenarios()
