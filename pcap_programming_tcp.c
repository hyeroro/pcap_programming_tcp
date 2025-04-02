#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

#define MAX_PAYLOAD_LEN 200  // 출력할 메시지 최대 길이

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP header */
struct ipheader {
    unsigned char      iph_ihl : 4, iph_ver : 4; //IP header length, version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag : 3, iph_offset : 13; //Fragmentation flags, Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void print_mac_address(const u_char* addr) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void print_payload(const u_char* payload, int len) {
    if (len <= 0) return;

    printf("Message: ");
    for (int i = 0; i < len && i < MAX_PAYLOAD_LEN; i++) {
        printf("%c", (payload[i] >= 32 && payload[i] <= 126) ? payload[i] : '.');
    }
    printf("\n");
}

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    struct ethheader* eth = (struct ethheader*)packet;

    printf("\n== Packet Captured ==\n");

    // Ethernet 헤더 출력
    printf("Ethernet Header:\n");
    printf("  Src MAC: ");
    print_mac_address(eth->ether_shost);
    printf("\n");
    printf("  Dst MAC: ");
    print_mac_address(eth->ether_dhost);
    printf("\n");

    // IP 패킷인지 확인
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader* ip = (struct ipheader*)(packet + sizeof(struct ethheader));
        int ip_header_len = ip->iph_ihl * 4;

        // IP 헤더 출력
        printf("IP Header:\n");
        printf("  Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("  Dst IP: %s\n", inet_ntoa(ip->iph_destip));

        // TCP 패킷인지 확인
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = TH_OFF(tcp) * 4;

            // TCP 헤더 출력
            printf("TCP Header:\n");
            printf("  Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("  Dst Port: %d\n", ntohs(tcp->tcp_dport));

            // 페이로드 계산 및 출력
            int payload_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_length = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

            if (payload_length > 0) {
                const u_char* payload = packet + payload_offset;
                print_payload(payload, payload_length);
            }
        }
    }
    printf("====================\n");
}

int main()
{
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    // eth0 인터페이스 열기
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    // TCP 필터 설정
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        return -1;
    }

    printf("패킷 캡처 시작... (종료하려면 Ctrl+C)\n");
    printf("TCP 프로토콜만 캡처합니다.\n");

    // 패킷 캡처 시작
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}