import pytest 
from src.py_engine.engine import PolicyEngine
from src.py_engine.wrapper import ModbusPacket


def test_critical_register(){ 
    engine = PolicyEngine("config/rules.yaml")

    packet = ModbusPacket()
    packet.function_code = 6
    packet.register_address = 100 

    result = engine.evaluate(packet)
    assert result["action"] == "alert"
    assert result["severity"] == "critical"
}