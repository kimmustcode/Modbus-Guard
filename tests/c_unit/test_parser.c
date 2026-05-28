#include "../../src/c_core/modbus.h"
#include <assert.h>
#include <string.h> 

void test_read_holding() {
    u_char modbus_packet[] = {
        0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 
        0x00, 0x00,
        0x00, 0x06,
        0x01, 
        0x03,
        0x00, 0x64,
        0x00, 0x01 
    }; 

    modbus_packet_t result = {0}; 
    parse_modbus(mock_packet, sizeof(mock_packet), &result); 

    assert(result.function_code == 3);
    assert(result.transaction_id == 1);
    assert(result.unit_id == 1); 
}

int main() {
    test_read_holding(); 
    return 0; 
}