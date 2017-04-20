#include "routing_thread.h"
#include <QCoreApplication>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netdb.h>
#include <libnet.h>
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

void mac_filter(char *get, u_char *my);
void mac_filter_ipv(char *get, u_char *my);
u_char *hex_filter(char *get, u_char *my);
void ip_filter(char *get, u_char *my);
int flag_check_mac(u_char *a, u_char *b);
int flag_check_ip(u_char *a, u_char *b);
void send_broad(u_char *p, int l);
u_char getHex(int i);
QString getString(u_char *s);
QString getMacString(u_char *s);

QStringList list, length, macv;
QString sys, sys_ipv;
pcap_t *pcap;

bool cancel;

u_char *pkt;

u_char my_mac[6] = {0,};
u_char my_ip[4] = {0,};
u_char router_mac[6] = {0,};
u_char router_ip[4] = {0,};
u_char victim_mac[256][6] = {0,};
u_char victim_ip[256][4] = {0,};
int broad_cnt = 0, break_point = 0;

// broadcast address define
u_char br_f[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
u_char br_0[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

struct arphdr {		// arp_header structure. Libnet don't have mac or ip address in arp header, so declare it.
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

routing_thread::routing_thread(QObject *parent) : QThread(parent)
{
    this->set_stop(false);
}

void routing_thread::run() {
    int s = 0, i = 0, d = 0;
    bpf_u_int32 netp, maskp;
    struct bpf_program filter;
    struct ifreq ifr, ifaddr;
    QByteArray mac;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    struct pcap_pkthdr *pkthdr;
    u_char *packet;
    struct arphdr *arpheader;
    struct libnet_ethernet_hdr *eth;
    u_char tmp_ip[4] = {0,};
    QString str_list;

    dev = pcap_lookupdev(errbuf);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for(i = 0; i < ETHER_ADDR_LEN; i++) mac.append(ifr.ifr_hwaddr.sa_data[i]);
    mac_filter(mac.toHex().data(), my_mac);
    close(s);

    d = socket(AF_INET, SOCK_DGRAM, 0);
    ifaddr.ifr_addr.sa_family = AF_INET;
    strncpy(ifaddr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(d, SIOCGIFADDR, &ifaddr);
    close(d);
    ip_filter(inet_ntoa(((struct sockaddr_in *)&ifaddr.ifr_addr)->sin_addr), my_ip);
    ip_filter(sys_ipv.toLatin1().data(), router_ip);
    sys_ipv.clear();

    // Look up info from the capture device.
    if(pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) exit(1);
    pcap = pcap_open_live(dev, 65535, NONPROMISCUOUS, -1, errbuf);
    // Compiles the filter expression into a BPF filter program
    if (pcap_compile(pcap, &filter, "arp", 0, maskp) == -1) exit(1);
    if (pcap_setfilter(pcap, &filter) == -1) exit(1);

    this->set_stop(false);

    while(1) {
        if(!sys.isEmpty()) {
            system(sys.toStdString().c_str());
            sys.clear();
            system("arp -a >/dev/null");
        }
        while(pcap_next_ex(pcap, &pkthdr, (const u_char**)&packet) > 0) {
            eth = (struct libnet_ethernet_hdr *)packet;
            arpheader = (struct arphdr *)(packet + sizeof(struct libnet_ethernet_hdr));

            if(ntohs(arpheader->oper) == ARPOP_REPLY && flag_check_mac(eth->ether_dhost, my_mac) != 1 && flag_check_mac(arpheader->sha, arpheader->tha) == 1 && flag_check_ip(arpheader->tpa, my_ip) != 1 && *(router_mac+1) == 0 && flag_check_ip(arpheader->spa, router_ip) != 1 && flag_check_mac(router_mac, br_0) != 1) {
                for(i = 0; i < ETHER_ADDR_LEN; i++) *(router_mac+i) = *(packet + ETHER_ADDR_LEN + i);
                macv << getMacString(router_mac) << getMacString(my_mac);
                list << getString(router_ip) << getString(my_ip);
                length.append(QString::number(pkthdr->len));
                pkt = packet;
                emit setList(list);
                send_broad(packet, pkthdr->len);
            }

            if(flag_check_mac(eth->ether_shost, my_mac) == 1 && flag_check_mac(eth->ether_shost, router_mac) == 1 && flag_check_ip(arpheader->spa, my_ip) == 1 && flag_check_ip(arpheader->spa, router_ip) == 1)
                for(i = 0; i < list.length(); i++)
                    if(!list.isEmpty()) {
                        str_list = list.at(i);
                        ip_filter(str_list.toLatin1().data(), tmp_ip);
                        if(flag_check_ip(arpheader->spa, tmp_ip) != 1) break_point = 1;
                    }

            if(ntohs(arpheader->oper) == ARPOP_REPLY && flag_check_mac(eth->ether_dhost, my_mac) != 1 && flag_check_mac(arpheader->tha, my_mac) != 1 && flag_check_mac(arpheader->sha, router_mac) == 1 && flag_check_mac(eth->ether_shost, my_mac) == 1 && flag_check_mac(arpheader->sha, my_mac) == 1 && flag_check_ip(arpheader->spa, my_ip) == 1 && flag_check_ip(arpheader->spa, arpheader->tpa) == 1 && flag_check_mac(router_mac, br_0) == 1 && flag_check_ip(arpheader->spa, router_ip) == 1 && break_point == 0) {
                for(i = 0; i < ETHER_ADDR_LEN; i++) *(*(victim_mac+broad_cnt)+i) = *(eth->ether_shost+i);
                macv << getMacString(*(victim_mac+broad_cnt));
                for(i = 0; i < 4; i++) *(*(victim_ip+broad_cnt)+i) = *(arpheader->spa+i);		// save to victim ip address
                list << getString(*(victim_ip+broad_cnt));
                length.append(QString::number(pkthdr->len));
                emit setList(list);
                broad_cnt++;
                if(broad_cnt%10 == 0) send_broad(packet, pkthdr->len);
            }

            if(ntohs(arpheader->oper) == ARPOP_REQUEST && flag_check_mac(eth->ether_dhost, br_f) != 1 && flag_check_mac(arpheader->tha, br_0) != 1 && flag_check_mac(arpheader->sha, my_mac) == 1 && flag_check_mac(eth->ether_shost, router_mac) == 1 && flag_check_ip(arpheader->spa, my_ip) == 1 && flag_check_ip(arpheader->spa, arpheader->tpa) == 1 && flag_check_mac(router_mac, br_0) == 1 && flag_check_ip(arpheader->spa, router_ip) == 1 && break_point == 0 && *(arpheader->spa) != 0 && *(arpheader->spa+3) != 0) {
                for(i = 0; i < ETHER_ADDR_LEN; i++) *(*(victim_mac+broad_cnt)+i) = *(eth->ether_shost+i);
                macv << getMacString(*(victim_mac+broad_cnt));
                for(i = 0; i < 4; i++) *(*(victim_ip+broad_cnt)+i) = *(arpheader->spa+i);
                list << getString(*(victim_ip+broad_cnt));
                length.append(QString::number(pkthdr->len));
                emit setList(list);
                broad_cnt++;
                if(broad_cnt%10 == 0) send_broad(packet, pkthdr->len);
            }
        }
        if(cancel) break;
    }
    emit setLength(length);
    emit setMacPacket(macv);
    emit packet_info(pkt);
    emit dump_pcap(pcap);
}

void mac_filter(char *get, u_char *my) {	// owner mac address save at my_mac variable
    int i, j = 0;
    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        if(*(get+j) - '0' < 0x10) {
            *(my+i) = (*(get+j) - '0') * 0x10;
            if(*(get+j+1) - '0' < 0x10) *(my+i) += (*(get+j+1) - '0') * 0x01;
            else *(my+i) += (*(get+j+1) - '0' == 0x31) ? 0x0a : ((*(get+j+1) - '0' == 0x32) ? 0x0b : ((*(get+j+1) - '0' == 0x33) ? 0x0c : ((*(get+j+1) - '0' == 0x34) ? 0x0d : ((*(get+j+1) - '0' == 0x35) ? 0x0e : 0x0f))));
        }
        else {
            *(my+i) = (*(get+j) - '0' == 0x31) ? 0xa0 : ((*(get+j) - '0' == 0x32) ? 0xb0 : ((*(get+j) - '0' == 0x33) ? 0xc0 : ((*(get+j) - '0' == 0x34) ? 0xd0 : ((*(get+j) - '0' == 0x35) ? 0xe0 : 0xf0))));
            if(*(get+j+1) - '0' < 0x10) *(my+i) += (*(get+j+1) - '0') * 0x01;
            else *(my+i) += (*(get+j+1) - '0' == 0x31) ? 0x0a : ((*(get+j+1) - '0' == 0x32) ? 0x0b : ((*(get+j+1) - '0' == 0x33) ? 0x0c : ((*(get+j+1) - '0' == 0x34) ? 0x0d : ((*(get+j+1) - '0' == 0x35) ? 0x0e : 0x0f))));
        }
        j += 2;
    }
}

void mac_filter_ipv(char *get, u_char *my) {	// owner mac address save at my_mac variable
    int i, j = 0;
    for(i = 0; i < 4; i++) {
        if(*(get+j) - '0' < 0x10) {
            *(my+i) = (*(get+j) - '0') * 0x10;
            if(*(get+j+1) - '0' < 0x10) *(my+i) += (*(get+j+1) - '0') * 0x01;
            else *(my+i) += (*(get+j+1) - '0' == 0x31) ? 0x0a : ((*(get+j+1) - '0' == 0x32) ? 0x0b : ((*(get+j+1) - '0' == 0x33) ? 0x0c : ((*(get+j+1) - '0' == 0x34) ? 0x0d : ((*(get+j+1) - '0' == 0x35) ? 0x0e : 0x0f))));
        }
        else {
            *(my+i) = (*(get+j) - '0' == 0x31) ? 0xa0 : ((*(get+j) - '0' == 0x32) ? 0xb0 : ((*(get+j) - '0' == 0x33) ? 0xc0 : ((*(get+j) - '0' == 0x34) ? 0xd0 : ((*(get+j) - '0' == 0x35) ? 0xe0 : 0xf0))));
            if(*(get+j+1) - '0' < 0x10) *(my+i) += (*(get+j+1) - '0') * 0x01;
            else *(my+i) += (*(get+j+1) - '0' == 0x31) ? 0x0a : ((*(get+j+1) - '0' == 0x32) ? 0x0b : ((*(get+j+1) - '0' == 0x33) ? 0x0c : ((*(get+j+1) - '0' == 0x34) ? 0x0d : ((*(get+j+1) - '0' == 0x35) ? 0x0e : 0x0f))));
        }
        j += 2;
    }
}

u_char hex_filter(char *get, u_char my) {
    int j = 0;
    if(*(get+j) - '0' < 0x10) {
        my = (*(get+j) - '0') * 0x10;
        if(*(get+j+1) - '0' < 0x10) my += (*(get+j+1) - '0') * 0x01;
        else my += (*(get+j+1) - '0' == 0x31) ? 0x0a : ((*(get+j+1) - '0' == 0x32) ? 0x0b : ((*(get+j+1) - '0' == 0x33) ? 0x0c : ((*(get+j+1) - '0' == 0x34) ? 0x0d : ((*(get+j+1) - '0' == 0x35) ? 0x0e : 0x0f))));
    }
    else {
        my = (*(get+j) - '0' == 0x31) ? 0xa0 : ((*(get+j) - '0' == 0x32) ? 0xb0 : ((*(get+j) - '0' == 0x33) ? 0xc0 : ((*(get+j) - '0' == 0x34) ? 0xd0 : ((*(get+j) - '0' == 0x35) ? 0xe0 : 0xf0))));
        if(*(get+j+1) - '0' < 0x10) my += (*(get+j+1) - '0') * 0x01;
        else my += (*(get+j+1) - '0' == 0x31) ? 0x0a : ((*(get+j+1) - '0' == 0x32) ? 0x0b : ((*(get+j+1) - '0' == 0x33) ? 0x0c : ((*(get+j+1) - '0' == 0x34) ? 0x0d : ((*(get+j+1) - '0' == 0x35) ? 0x0e : 0x0f))));
    }
    return my;
}

void ip_filter(char *get, u_char *my) {
    int i = 0, j = 0, imsi = 0;
    QByteArray tmp;
    while(1) {
        j++;
        if(get[j] == '.') {
            while(1) {
                imsi += (get[i++] - '0');
                if(i == j) {
                    i++;
                    break;
                }
                imsi *= 10;
            }
            tmp.append(imsi);
            imsi = 0;
        }
        else if(get[j] == 0) {
            while(1) {
                imsi += (get[i++] - '0');
                if(i == j) {
                    i++;
                    break;
                }
                imsi *= 10;
            }
            tmp.append(imsi);
            break;
        }
    }
    mac_filter_ipv(tmp.toHex().data(), my);
}

int flag_check_mac(u_char *a, u_char *b) {	// compare with mac address
    int value = 0;
    value = (*a != *b ? 1 : ((*(a+1) != *(b+1)) ? 1 : ((*(a+2) != *(b+2)) ? 1 : ((*(a+3) != *(b+3)) ? 1 : ((*(a+4) != *(b+4)) ? 1 : ((*(a+5) != *(b+5)) ? 1 : -1))))));
    return value;
}

int flag_check_ip(u_char *a, u_char *b) {	// compare with mac address
    int value = 0;
    value = (*a != *b ? 1 : ((*(a+1) != *(b+1)) ? 1 : ((*(a+2) != *(b+2)) ? 1 : ((*(a+3) != *(b+3)) ? 1 : -1))));
    return value;
}

void send_broad(u_char *p, int l) {
    int i = 0, j = 0;
    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        *(p+i) = *(br_f+i);
        *(p+ETHER_ADDR_LEN+i) = *(my_mac+i);
        *(p+sizeof(struct libnet_ethernet_hdr)+8+i) = *(my_mac+i);
        *(p+sizeof(struct libnet_ethernet_hdr)+18+i) = *(br_0+i);
        if(i < 4) {
            *(p+sizeof(struct libnet_ethernet_hdr)+14+i) = *(my_ip+i);
            *(p+sizeof(struct libnet_ethernet_hdr)+24+i) = *(my_ip+i);
        }
    }
    *(p+sizeof(struct libnet_ethernet_hdr)+7) = ARPOP_REQUEST;
    for(i = 0; i < 256; i++) {
        *(p+40) = getHex(i);
        for(j = 0; j < 256; j++) {
            *(p+41) = getHex(j);
            pcap_sendpacket(pcap, p, l);
        }
    }
}

u_char getHex(int i) {
    QByteArray tmp;
    u_char imsi = 0;
    tmp.append(i);
    return hex_filter(tmp.toHex().data(), imsi);;
}

QString getString(u_char *s) {
    QString a, str;
    for(int i = 0; i < 4; i++) {
        a = QString("%1").arg(s[i], 0, 10);
        if(i < 3) a += ".";
        str.append(a);
    }
    a.clear();
    return str;
}

QString getMacString(u_char *s) {
    QString str, result = "";
    for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        str = QString("%1").arg(s[i],0,16);
        if(str == "0" || str == "1" || str == "2" || str == "3" || str == "4" || str == "5" || str == "6" || str == "7" || str == "8" || str == "9" || str == "a" || str == "b" || str == "c" || str == "d" || str == "e" || str == "f")
            (str == "0") ? str = "00" : ((str == "1") ? str = "01" : ((str == "2") ? str = "02" : ((str == "3") ? str = "03" : ((str == "4") ? str = "04" : ((str == "5") ? str = "05" : ((str == "6") ? str = "06" : ((str == "7") ? str = "07" : ((str == "8") ? str = "08" : ((str == "9") ? str = "09" : ((str == "a") ? str = "0a" : ((str == "b") ? str = "0b" : ((str == "c") ? str = "0c" : ((str == "d") ? str = "0d" : ((str == "e") ? str = "0e" : str = "0f"))))))))))))));
        result.append(str);
    }
    str.clear();
    return result;
}

void routing_thread::set_stop(bool s) {
    QMutex mut;
    mut.lock();
    cancel = s;
    mut.unlock();
}

void routing_thread::set_sys(QString s, QString ip_s) {
    sys = s;
    sys_ipv = ip_s;
}
