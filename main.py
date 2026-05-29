import argparse
import sys
import os
from src.py_engine.wrapper import SnifferWrapper
from src.py_engine.engine import PolicyEngine

def main():
    parser = argparse.ArgumentParser(description="Modbus Guard - ICS Security Monitor")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to sniff (e.g., eth0, lo, any)")
    parser.add_argument("-r", "--rules", default="config/rules.yaml", help="Path to YAML rules file")
    args = parser.parse_args()

    # 1. Initialize Engine and Wrapper
    print(f"[*] Loading rules from {args.rules}...")
    try:
        if not os.path.exists(args.rules):
            print(f"[!] Error: Rules file '{args.rules}' not found.")
            sys.exit(1)
        engine = PolicyEngine(args.rules)
    except Exception as e:
        print(f"[!] Error loading rules: {e}")
        sys.exit(1)

    sniffer = SnifferWrapper()

    # 2. Define the callback
    def packet_handler(packet_ptr):
        # packet_ptr is a pointer to the ModbusPacket struct
        packet = packet_ptr.contents
        # Evaluate against security policy
        engine.evaluate(packet)

    # 3. Start the sniffer
    print(f"[*] Starting sniffer on {args.interface}...")
    print("[*] Press Ctrl+C to stop.")
    
    try:
        sniffer.start(args.interface, packet_handler)
    except KeyboardInterrupt:
        print("\n[*] Stopping Modbus Guard...")
    except Exception as e:
        print(f"[!] Runtime error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
