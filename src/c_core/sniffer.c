#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip>
#include <netinet/tcp> 
#include "modbus.h"

/**
 * TODO: Implement the packet handler callback for libpcap.
 * 
 * Architecture Hint:
 * 2. Verify IP and TCP protocols.
 * 3. Calculate payload offset (Eth + IP + TCP headers).
 * 4. Parse MBAP Header (7 bytes) and PDU.
 * 5. Populate the modbus_packet_t struct.
 * 6. Call the g_callback function pointer.
 */
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Captured packet with length: %u", header->len);

    // Verify that its modbus and not other type? 

    struct modbus_packet_t *modbus_packet = {0};


    // Grab the headers from packet 
    struct ip *ip_header = (struct ip *)(packet + 14);
    int ip_len = ip_header->ip_hl; 

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_len); 
    int tcp_len = tcp_header->doff * 4; 

    u_char *modbus_data =  (u_char *)(packet + 14 + ip_len + tcp_len); 

    // Map the packet to the modbus packet structure 
    modbus_packet.src_ip = ip_header->ip_src.s_addr; 
    modbus_packet.dst_ip = ip_header->ip_dst.s_addr; 
    modbus_packet.src_port = ntohs(tcp_header->source);
    modbus_packet.dst_port = ntohs(tcp_header->dest);

    modbus_packet.transaction_id = ntohs(*(uint16_t*)(modbus_data));
    modbus_packet.product_id = ntohs(*(uint16_t*)(modbus_data + 2));
    modbus_packet.length = ntohs(*(uint16_t*)(modbus_data + 4));
    modbus_packet.unit_id = ntohs(*(uint16_t*)(modbus_data + 6));

    modbus_packet.function_code = *(uint8_t*)(modbus_data + 7);



}

/**
 * TODO: Implement the entry point for the C library.
 * 
 * Architecture Hint:
 * 1. Store the callback pointer globally.
 * 3. Use pcap_compile() and pcap_setfilter() for "tcp port 502".
 * 4. Enter pcap_loop().
 */
int start_sniffer(const char *device, packet_callback_t callback) {
    printf("Initializing sniffer on %s...\n", device);

    char errBuff = [PCAP_ERRBUF_SIZE]; 
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ 1, 1000, errBuff); 

    if (handle == NULL){
        fprintf(stderr, "Unable to open device: %n", errBuff);
        return 1;
    }

    pcap_loop(handle, 10, handle_packet, NULL);
    pcap_close(handle); 


    return 0;
}
