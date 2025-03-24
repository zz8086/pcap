#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/in.h>
#include <string.h>

struct Ethernet_Header {
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    unsigned short type;
};

struct IP_Header {
    unsigned char iph_inl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int flag:3, iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

struct TCP_Header {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char data_offset;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
};

void print_mac(const unsigned char *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(const u_char *payload, int length) {
    printf("\nPayload:\n");
    for (int i = 0; i < length; i++) {
        if (payload[i] >= 32 && payload[i] <= 126) { 
            printf("%c", payload[i]); 
        } else {
            printf(".");  
        }
    }
    printf("\n");
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct Ethernet_Header *eth = (struct Ethernet_Header *)packet;
    struct IP_Header *ip = (struct IP_Header *)(packet + sizeof(struct Ethernet_Header));

    int ip_header_length = ip->iph_inl * 4; 
    struct TCP_Header *tcp = (struct TCP_Header *)(packet + sizeof(struct Ethernet_Header) + ip_header_length);

    int tcp_header_length = (tcp->data_offset >> 4) * 4; 
    int data_length = header->caplen - (sizeof(struct Ethernet_Header) + ip_header_length + tcp_header_length);

    printf("Src MAC: ");
    print_mac(eth->src_mac);
    printf("\n");

    printf("Dst MAC: ");
    print_mac(eth->dst_mac);
    printf("\n");

    printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));
    printf("Src Port: %d\n", ntohs(tcp->src_port));
    printf("Dst Port: %d\n", ntohs(tcp->dst_port));

    if (data_length > 0) {
        const u_char *payload = packet + sizeof(struct Ethernet_Header) + ip_header_length + tcp_header_length;
        print_payload(payload, data_length);
    }
}

int main() {
    pcap_t *handle;
    struct pcap_pkthdr header;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "tcp";  
    struct bpf_program fp; 
    bpf_u_int32 net;

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("No devices\n");
        return 0;
    }

    printf("Packet Capture!!! \n");

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        printf("Error compiling filter\n");
        return 0;
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error setting filter:");
        return 0;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}
