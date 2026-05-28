#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h> 
#include <arpa/inet.h>
#include "modbus.h"

// Global callback pointer
static packet_callback_t g_callback = debug_packet;

void debug_packet(const modbus_packet_t *packet){
    struct in_addr src, dst; 
    src.s_addr = packet->src_ip; 
    dst.s_addr = packet->src_ip; 

    printf("Modbus packet captured");
    printf("source: %s:%d\n", inet_ntoa(src), packet->src_port);
    printf("destination: %s:%d\n", inet_ntoa(dst), packet->dst_port);
    printf("unit id: %d\n", packet->unit_id);
    printf("function: %d\n", packet->function_code);

    if(pkt->function_code <= 6){
        printf("register: %d\n", packet->register_address);
        printf("register: %d\n", packet->register_count);
    }
}


/**
 * Pure parsing function to extract Modbus data from a raw packet.
 * This is decoupled from libpcap for easier testing.
 */
void parse_modbus(const unsigned char *packet, int len, modbus_packet_t *out) {
    if (len < 14 + 20 + 20 + 7) return; // Basic check: Eth + IP + TCP + MBAP

    struct ip *ip_header = (struct ip *)(packet + 14);
    int ip_len = ip_header->ip_hl * 4; 

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_len); 
    int tcp_len = tcp_header->doff * 4; 

    unsigned char *modbus_data = (unsigned char *)(packet + 14 + ip_len + tcp_len); 
    int payload_len = len - (14 + ip_len + tcp_len);

    if (payload_len < 7) return; // MBAP header is 7 bytes

    out->src_ip = ip_header->ip_src.s_addr; 
    out->dst_ip = ip_header->ip_dst.s_addr; 
    out->src_port = ntohs(tcp_header->source);
    out->dst_port = ntohs(tcp_header->dest);

    out->transaction_id = ntohs(*(uint16_t*)(modbus_data));
    out->protocol_id = ntohs(*(uint16_t*)(modbus_data + 2));
    out->length = ntohs(*(uint16_t*)(modbus_data + 4));
    out->unit_id = *(uint8_t*)(modbus_data + 6);
    out->function_code = *(uint8_t*)(modbus_data + 7);

    // Extract register address/count for common function codes
    if (payload_len >= 12 && (out->function_code <= 6 || out->function_code == 15 || out->function_code == 16)) {
        out->register_address = ntohs(*(uint16_t*)(modbus_data + 8));
        out->register_count = ntohs(*(uint16_t*)(modbus_data + 10));
    }

    // Copy raw payload
    int copy_len = payload_len > 256 ? 256 : payload_len;
    memcpy(out->payload, modbus_data, copy_len);
    out->payload_len = copy_len;

    debug_packet(&out);
}


void handle_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (!g_callback) return;

    modbus_packet_t modbus_packet = {0};
    parse_modbus(packet, header->len, &modbus_packet);
    
    g_callback(&modbus_packet);
}

int start_sniffer(const char *device, packet_callback_t callback) {
    g_callback = callback;
    char errBuff[PCAP_ERRBUF_SIZE]; 
    pcap_t *handle = pcap_open_live(devicest, BUFSIZ, 1, 1000, errBuff); 

    if (handle == NULL) {
        fprintf(stderr, "Unable to open device %s: %s\n", device, errBuff);
        return 1;
    }

    // Filter for Modbus TCP (port 502)
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp port 502", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    printf("Sniffer started on %s. Listening for Modbus traffic...\n", device);
    pcap_loop(handle, 0, handle_packet, NULL);
    
    pcap_freecode(&fp);
    pcap_close(handle); 
    return 0;
}
