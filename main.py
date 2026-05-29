from src.py_engine.wrapper import SnifferWrapper
from src.py_engine.engine import PolicyEngine

def main():
    engine = PolicyEngine("config/rules.yaml")
    sniffer = SnifferWrapper()

    def packet_handler(packet_ptr):
        engine.evaluate(packet_ptr.contents)

    print("Starting sniffer on eth0...")
    sniffer.start("eth0", packet_handler)

if __name__ == "__main__":
    main()
