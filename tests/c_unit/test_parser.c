#include "../../src/c_core/modbus.h"
#include <assert.h>
#include <stdio.h>

void test_read_holding() {
    // The parser expects at least 61 bytes (Eth+IP+TCP+MBAP)
    // We provide 70 bytes to be safe.
    unsigned char mock_packet[70] = {0}; 
    
    // Set minimal headers so the parser doesn't return early
    // Ethernet is 14 bytes
    // IP header starts at 14
    mock_packet[14 + 0] = 0x45;       // IP Version 4, Header Length 5 (20 bytes)
    
    // Source IP: 192.168.1.28
    mock_packet[26] = 192; mock_packet[27] = 168; mock_packet[28] = 1; mock_packet[29] = 28; 
    
    // Destination IP: 192.168.1.100
    mock_packet[30] = 192; mock_packet[31] = 168; mock_packet[32] = 1; mock_packet[33] = 100;

    // TCP header starts at 34 (14 Eth + 20 IP)
    // Source Port: 502 (0x01F6)
    mock_packet[34] = 0x01; mock_packet[35] = 0xF6;
    // Destination Port: 502 (0x01F6)
    mock_packet[36] = 0x01; mock_packet[37] = 0xF6;

    // Data offset is at offset 12 in TCP header (34 + 12 = 46)
    mock_packet[46] = 0x50;           // TCP Data Offset 5 (20 bytes)
    mock_packet[47] = 199;
    mock_packet[48] = 129;
    mock_packet[49] = 1; 
    mock_packet[50] = 25; 

    mock_packet[54] = 0x00; mock_packet[55] = 0x01; // Transaction ID: 1
    mock_packet[56] = 0x00; mock_packet[57] = 0x00; // Protocol ID: 0
    mock_packet[58] = 0x00; mock_packet[59] = 0x06; // Length: 6
    mock_packet[60] = 0x01;                         // Unit ID: 1
    
    mock_packet[61] = 0x03;                         // Function Code: 3 (Read Holding)
    mock_packet[62] = 0x00; mock_packet[63] = 0x64; // Register Address: 100
    mock_packet[64] = 0x00; mock_packet[65] = 0x01; // Register Count: 1

    modbus_packet_t result = {0}; 
    parse_modbus(mock_packet, 70, &result); 

    assert(result.transaction_id == 1);
    assert(result.unit_id == 1); 
    assert(result.function_code == 3);
    assert(result.register_address == 100); 
    
    printf("C Parser Unit Test: PASSED\n");
}

int main() {
    test_read_holding(); 
    return 0; 
}
