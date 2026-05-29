#ifndef MODBUS_H
#define MODBUS_H

#include <stdint.h>
#include <string.h>


typedef struct {
    uint32_t src_ip;         
    uint32_t dst_ip;         
    uint16_t src_port;       
    uint16_t dst_port;       
    
    // MBAP Header
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t length;
    uint8_t  unit_id;
    
    // PDU
    uint8_t  function_code;
    uint16_t register_address; 
    uint16_t register_count;   
    
    // Raw Payload 
    uint8_t  payload[256];
    uint16_t payload_len;
} __attribute__((packed)) modbus_packet_t;

typedef void (*packet_callback_t)(const modbus_packet_t*);

void parse_modbus(const unsigned char *packet, int len, modbus_packet_t *out);

#endif // MODBUS_H
