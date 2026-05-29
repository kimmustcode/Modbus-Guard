import pytest 
from src.py_engine.engine import PolicyEngine
from src.py_engine.wrapper import ModbusPacket

def test_critical_register():
    engine = PolicyEngine("config/rules.yaml")

    packet = ModbusPacket()
    packet.function_code = 6
    packet.register_address = 100 
    packet.src_ip = 0x0100007F # 127.0.0.1 in little-endian for socket.inet_ntoa(struct.pack("<L", ...))

    result = engine.evaluate(packet)

    assert result == "alert"

def test_allow_read():
    engine = PolicyEngine("config/rules.yaml")
    
    packet = ModbusPacket()
    packet.function_code = 3 
    packet.register_address = 10
    packet.src_ip = 0x0100007F

    result = engine.evaluate(packet)
    assert result == "allow"
