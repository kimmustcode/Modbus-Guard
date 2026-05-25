#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "modbus.h"

/**
 * TODO: Implement the packet handler callback for libpcap.
 * 
 * Architecture Hint:
 * 1. Cast 'packet' to Ethernet header.
 * 2. Verify IP and TCP protocols.
 * 3. Calculate payload offset (Eth + IP + TCP headers).
 * 4. Parse MBAP Header (7 bytes) and PDU.
 * 5. Populate the modbus_packet_t struct.
 * 6. Call the g_callback function pointer.
 */
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Your code here
}

/**
 * TODO: Implement the entry point for the C library.
 * 
 * Architecture Hint:
 * 1. Store the callback pointer globally.
 * 2. Use pcap_open_live() to open the interface.
 * 3. Use pcap_compile() and pcap_setfilter() for "tcp port 502".
 * 4. Enter pcap_loop().
 */
int start_sniffer(const char *device, packet_callback_t callback) {
    printf("Initializing sniffer on %s...\n", device);


    
    // Your code here
    return 0;
}
