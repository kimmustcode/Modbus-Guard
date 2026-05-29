import ctypes
import pytest
from src.py_engine.wrapper import ModbusPacket, PACKET_CALLBACK
from src.py_engine.engine import PolicyEngine

@pytest.fixture
def engine():
    return PolicyEngine("config/rules.yaml")

def test_sniffer_pickup_simulation(engine):
    """
    This test simulates the sniffer "picking up" a packet and 
    passing it to the Python callback logic.
    """
    results = []

    def mock_callback(packet_ptr):
        # This simulates the function that SnifferWrapper would call
        packet = packet_ptr.contents
        action = engine.evaluate(packet)
        results.append(action)

    # 1. Simulate a 'safe' Read Holding Register packet
    safe_packet = ModbusPacket()
    safe_packet.function_code = 3
    safe_packet.register_address = 50
    
    mock_callback(ctypes.pointer(safe_packet))
    assert results[-1] == "allow"

    # 2. Simulate an 'alert' Critical Register Write packet
    alert_packet = ModbusPacket()
    alert_packet.function_code = 6
    alert_packet.register_address = 100 # In 'critical-register-protection' rule
    
    mock_callback(ctypes.pointer(alert_packet))
    assert results[-1] == "alert"

    # 3. Simulate an 'alert' Single Write packet (even if not critical)
    write_packet = ModbusPacket()
    write_packet.function_code = 5 # In 'alert-on-single-write' rule
    write_packet.register_address = 10
    
    mock_callback(ctypes.pointer(write_packet))
    assert results[-1] == "alert"

    print("\nSniffer 'pickup' simulation successful!")
