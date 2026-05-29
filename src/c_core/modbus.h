#ifndef MODBUS_H
#define MODBUS_H

#include <stdint.h>
#include <string.h>

/**
 * Structure representing a parsed Modbus TCP packet.
 * This will be passed to the Python callback.
 */
typedef struct {
    uint32_t src_ip;         // Source IP address (big-endian)
    uint32_t dst_ip;         // Destination IP address (big-endian)
    uint16_t src_port;       // Source Port
    uint16_t dst_port;       // Destination Port
    
    // MBAP Header
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t length;
    uint8_t  unit_id;
    
    // PDU
    uint8_t  function_code;
    uint16_t register_address; // Extracted if applicable (big-endian)
    uint16_t register_count;   // Extracted if applicable (big-endian)
    
    // Raw Payload (for deeper inspection in Python if needed)
    uint8_t  payload[256];
    uint16_t payload_len;
} __attribute__((packed)) modbus_packet_t;

/**
 * Function pointer type for the Python callback.
 */
typedef void (*packet_callback_t)(const modbus_packet_t*);

/**
 * Pure parsing function to extract Modbus data from a raw packet.
 */
void parse_modbus(const unsigned char *packet, int len, modbus_packet_t *out);

#endif // MODBUS_H
