import socket
import time
import random

# Change this to the IP of your Guard machine (e.g., 127.0.0.1 or your 192.x.x.x IP)
TARGET_IP = "127.0.0.1" 
PORT = 502

# Define our pools based on rules.yaml
ALLOWED_FCS = [1, 2, 3, 4]
ALERT_FCS = [5, 6, 15, 16]
CRITICAL_REGISTERS = [100, 101, 102, 103, 104, 105]

def send_modbus_command(fc, register, value=1):
    """Constructs and sends a Modbus TCP packet."""
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"
    pdu = bytes([fc]) + register.to_bytes(2, 'big') + value.to_bytes(2, 'big')
    payload = mbap + pdu

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect_ex((TARGET_IP, PORT))
            s.sendall(payload)
    except Exception:
        pass

def simulate_random_traffic():
    print(f"--- Starting Randomized Modbus Traffic on {TARGET_IP} ---")
    print("[*] Generating 1 packet every 2 seconds. Press Ctrl+C to stop.")
    
    while True:
        try:
            # Randomly decide if we want an 'Allow' or 'Alert' packet
            scenario = random.choice(["allow", "alert"])
            
            if scenario == "allow":
                fc = random.choice(ALLOWED_FCS)
                register = random.randint(1, 99) # Non-critical range
                print(f"[SAFE] Sending Allowed Packet: FC {fc}, Reg {register}")
            
            else:
                # Randomly pick between a bad Function Code or a bad Register
                sub_scenario = random.choice(["bad_fc", "bad_reg"])
                
                if sub_scenario == "bad_fc":
                    fc = random.choice(ALERT_FCS)
                    register = random.randint(1, 99)
                    print(f"[WARN] Sending Alert Packet (Bad FC): FC {fc}, Reg {register}")
                else:
                    fc = random.choice([6, 16]) # FCs that trigger critical register rule
                    register = random.choice(CRITICAL_REGISTERS)
                    print(f"[CRIT] Sending Alert Packet (Critical Reg): FC {fc}, Reg {register}")

            send_modbus_command(fc, register)
            time.sleep(2)

        except KeyboardInterrupt:
            print("\n[*] Stopping Traffic Generator.")
            break

if __name__ == "__main__":
    simulate_random_traffic()
