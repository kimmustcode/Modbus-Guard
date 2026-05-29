import ctypes
import os

# TODO: Define the ModbusPacket struct matching the C header
class ModbusPacket(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),

        ("transaction_id", ctypes.c_uint16),
        ("protocol_id", ctypes.c_uint16),
        ("length", ctypes.c_uint16),
        ("unit_id", ctypes.c_uint8),

        ("function_code", ctypes.c_uint8),
        ("register_address", ctypes.c_uint16),
        ("register_count", ctypes.c_uint16),

        ("payload", ctypes.c_uint8 * 256), 
        ("payload_len", ctypes.c_uint16),
    ]

# Define the CFUNCTYPE for the callback
PACKET_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(ModbusPacket))

class SnifferWrapper:
    def __init__(self, lib_path="./build/libsniffer.so"):
        abs_path = os.path.abspath(lib_path)

        self.lib = ctypes.CDLL(abs_path)

        self.lib.start_sniffer.argtypes = [
            ctypes.c_char_p,
            PACKET_CALLBACK
        ]

        self.lib.start_sniffer.restype = ctypes.c_int 

    def start(self, interface, callback):
        self._c_callback = PACKET_CALLBACK(callback)
        interface_bytes = interface.encode('utf-8')
        return self.lib.start_sniffer(interface_bytes, self._c_callback)
