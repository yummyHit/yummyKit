#include "scanning_thread.h"
#include <QCoreApplication>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

void ip_filter(char *get, u_char *my);

void send_broad(u_char *packet, int len, pcap_t *pcap);
u_char getHex(int i);
QString getIPString(u_char *s);
QString getMacString(u_char *s);

QString sys, sys_ipv;
QStringList scan_ip_list, scan_length_list;
pcap_if_t *alldevs;

bool pcap_stop;
unsigned if_num;
u_char *pkt;

// Each of IP and MAC address define
u_char my_mac[6] = {0,}, my_ip[4] = {0,};
u_char router_mac[6] = {0,}, router_ip[4] = {0,};
u_char victim_mac[256][6] = {0,}, victim_ip[256][4] = {0,};

// broadcast address define
u_char br_f[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
u_char br_0[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

scanning_thread::scanning_thread(QObject *parent) : QThread(parent) {
	pcap_stop = false;
	host_name = new hostname();
}

void scanning_thread::run() {
	QTime time_scan;
	bool break_point;
	int s = 0;
	unsigned i = 0, broad_cnt = 0;
	bpf_u_int32 netp, maskp;
	struct bpf_program filtering;
	struct ifreq ifr, ifaddr;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;
	struct pcap_pkthdr *pkthdr;
	u_char *packet, tmp_ip[4] = {0,};
	struct libnet_ethernet_hdr *eth;
	struct libnet_arp_hdr *arh;
	QString str_list, scan_ip;
	QByteArray mac;

	while(1) if(if_num == ++i) break; else alldevs = alldevs->next;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, alldevs->name, IFNAMSIZ-1);
	ioctl(s, SIOCGIFHWADDR, &ifr);
	for(i = 0; i < ETHER_ADDR_LEN; i++) mac.append(ifr.ifr_hwaddr.sa_data[i]);
	pre_filter(mac.toHex().data(), my_mac, mac.size(), "lower");
	ifaddr.ifr_addr.sa_family = AF_INET;
	strncpy(ifaddr.ifr_name, alldevs->name, IFNAMSIZ-1);
	ioctl(s, SIOCGIFADDR, &ifaddr);
	close(s);

	ip_filter(inet_ntoa(((struct sockaddr_in *)&ifaddr.ifr_addr)->sin_addr), my_ip);
	ip_filter(sys_ipv.toLatin1().data(), router_ip);
	sys_ipv.clear();

	// Look up info from the capture device.
	if(pcap_lookupnet(alldevs->name, &netp, &maskp, errbuf) == -1) perror("pcap_lookupnet");
	pcap = pcap_open_live(alldevs->name, 65535, NONPROMISCUOUS, -1, errbuf);

	// Compiles the filter expression into a BPF filter program
	if(pcap_compile(pcap, &filtering, "arp", 0, maskp) == -1) perror("pcap_compile");
	if(pcap_setfilter(pcap, &filtering) == -1) perror("pcap_setfilter");

	if(!host_name->host_stop) host_name->start();
	time_scan.start();

	while(!pcap_stop && !host_name->host_stop && !host_name->host_err) {
		break_point = false;

		if(!sys.isEmpty()) {
			system(sys.toStdString().c_str());
			sys.clear();
			usleep(50000);
			system("ping 8.8.8.8 -c 1 >/dev/null 2>&1");
			usleep(50000);
			system("arp -a >/dev/null");
		}

		while(pcap_next_ex(pcap, &pkthdr, (const u_char**)&packet) > 0) {
			eth = (struct libnet_ethernet_hdr *)packet;
			arh = (struct libnet_arp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));

			// Router to me with packet. ARP Reply, Ether Destination Mac Addr == My Mac Addr, ARP Source Mac Addr != ARP Destination Mac Addr, ARP Destination IP Addr == My IP Addr, Router Mac Addr is empty, ARP Source IP Addr == Router IP
			if(ntohs(arh->ar_op) == ARPOP_REPLY && flag_check(eth->ether_dhost, my_mac, ETHER_ADDR_LEN) != 1 && flag_check(arh->ar_sha, arh->ar_dha, ETHER_ADDR_LEN) == 1 && flag_check(arh->ar_dpa, my_ip, IP_ADDR_LEN) != 1 && flag_check(arh->ar_spa, router_ip, IP_ADDR_LEN) != 1 && flag_check(router_mac, br_0, ETHER_ADDR_LEN) != 1) {
				for(i = 0; i < ETHER_ADDR_LEN; i++) *(router_mac + i) = *(packet + ETHER_ADDR_LEN + i);
				emit scanThreadSetMacList(getMacString(router_mac));
				emit scanThreadSetIPList(getIPString(router_ip));
				emit scanThreadSetMacList(getMacString(my_mac));
				emit scanThreadSetIPList(getIPString(my_ip));
				scan_ip_list << getIPString(router_ip) << getIPString(my_ip);
				scan_length_list.append(QString::number(pkthdr->len));
				pkt = packet;
				host_name->getArgu(router_ip, true);
				host_name->getArgu(my_ip, true);
				send_broad(packet, pkthdr->len, pcap);
			}

			// When packet is Not Me, Not Router, then check a IP equals to IP List
			if(flag_check(eth->ether_shost, my_mac, ETHER_ADDR_LEN) == 1 && flag_check(eth->ether_shost, router_mac, ETHER_ADDR_LEN) == 1 && flag_check(arh->ar_spa, my_ip, IP_ADDR_LEN) == 1 && flag_check(arh->ar_spa, router_ip, IP_ADDR_LEN) == 1)
				for(int j = 0; j < scan_ip_list.length(); j++)
					if(!scan_ip_list.isEmpty()) {
						str_list = scan_ip_list.at(j);
						ip_filter(str_list.toLatin1().data(), tmp_ip);
						if(flag_check(arh->ar_spa, tmp_ip, IP_ADDR_LEN) != 1) break_point = true;
					}

			// Victim to me with packet. ARP Reply, Ether Destination Mac Addr == My Mac Addr, ARP Destination Mac Addr == My Mac Addr, ARP Source Mac Addr != Router Mac Addr, Ether Source Mac Addr != My Mac Addr, ARP Source Mac Addr != My Mac Addr, ARP Source IP Addr != My IP Addr, ARP Source IP Addr != ARP Destination IP Addr, Router Mac Addr is not empty, ARP Source IP Addr != Router IP Addr
			if(ntohs(arh->ar_op) == ARPOP_REPLY && flag_check(eth->ether_dhost, my_mac, ETHER_ADDR_LEN) != 1 && flag_check(arh->ar_dha, my_mac, ETHER_ADDR_LEN) != 1 && flag_check(arh->ar_sha, router_mac, ETHER_ADDR_LEN) == 1 && flag_check(eth->ether_shost, my_mac, ETHER_ADDR_LEN) == 1 && flag_check(arh->ar_sha, my_mac, ETHER_ADDR_LEN) == 1 && flag_check(arh->ar_spa, my_ip, IP_ADDR_LEN) == 1 && flag_check(arh->ar_spa, arh->ar_dpa, IP_ADDR_LEN) == 1 && flag_check(router_mac, br_0, ETHER_ADDR_LEN) == 1 && flag_check(arh->ar_spa, router_ip, IP_ADDR_LEN) == 1 && !break_point) {
				for(i = 0; i < ETHER_ADDR_LEN; i++) *(*(victim_mac + broad_cnt) + i) = *(eth->ether_shost + i);
				emit scanThreadSetMacList(getMacString(*(victim_mac + broad_cnt)));
				for(i = 0; i < IP_ADDR_LEN; i++) *(*(victim_ip + broad_cnt) + i) = *(arh->ar_spa + i);		// save to victim ip address
				scan_ip = getIPString(*(victim_ip + broad_cnt));
				emit scanThreadSetIPList(scan_ip);
				scan_ip_list << scan_ip;
				scan_length_list.append(QString::number(pkthdr->len));
				host_name->getArgu(*(victim_ip + broad_cnt), true);
				broad_cnt++;
				if(((time_scan.elapsed() / 1000) % 10) < 15) send_broad(packet, pkthdr->len, pcap);
			}

			// Victim to broadcast with packet. ARP Request, Ether Destination Mac Addr == Broadcast Mac Addr, ARP Destination Mac Addr == Broadcast Mac Addr, ARP Source Mac Addr != My Mac Addr, Ether Source Mac Addr != Router Mac Addr, ARP Source IP Addr != My IP Addr, ARP Source IP Addr != ARP Destination IP Addr, Router Mac Addr is not empty, ARP Source IP Addr != Router IP Addr, ARP Source IP Addr is not empty
			if(ntohs(arh->ar_op) == ARPOP_REQUEST && flag_check(eth->ether_dhost, br_f, ETHER_ADDR_LEN) != 1 && flag_check(arh->ar_dha, br_0, ETHER_ADDR_LEN) != 1 && flag_check(arh->ar_sha, my_mac, ETHER_ADDR_LEN) == 1 && flag_check(eth->ether_shost, router_mac, ETHER_ADDR_LEN) == 1 && flag_check(arh->ar_spa, my_ip, IP_ADDR_LEN) == 1 && flag_check(arh->ar_spa, arh->ar_dpa, IP_ADDR_LEN) == 1 && flag_check(router_mac, br_0, ETHER_ADDR_LEN) == 1 && flag_check(arh->ar_spa, router_ip, IP_ADDR_LEN) == 1 && !break_point && *(arh->ar_spa) != 0 && *(arh->ar_spa+3) != 0) {
				for(i = 0; i < ETHER_ADDR_LEN; i++) *(*(victim_mac + broad_cnt) + i) = *(eth->ether_shost + i);
				emit scanThreadSetMacList(getMacString(*(victim_mac + broad_cnt)));
				for(i = 0; i < IP_ADDR_LEN; i++) *(*(victim_ip + broad_cnt) + i) = *(arh->ar_spa + i);
				scan_ip = getIPString(*(victim_ip + broad_cnt));
				emit scanThreadSetIPList(scan_ip);
				scan_ip_list << scan_ip;
				scan_length_list.append(QString::number(pkthdr->len));
				host_name->getArgu(*(victim_ip + broad_cnt), true);
				broad_cnt++;
				if(((time_scan.elapsed() / 1000) % 10) < 15) send_broad(packet, pkthdr->len, pcap);
			}
		}
	}

	if(!scan_ip_list.isEmpty()) {
		emit scanThreadSetLength(scan_length_list);
		emit scanThreadPacket(pkt);
		emit scanThreadPcap(pcap);
		if(host_name->isRunning()) host_name->hostStop(true);
	}
	else if(host_name->host_err){
		scan_length_list.append("Host_Error");
		emit scanThreadSetLength(scan_length_list);
	}
	else if(pcap_stop && !host_name->host_stop) {
		scan_length_list.append("root_squash");
		emit scanThreadSetLength(scan_length_list);
	}
	else {
		emit scanThreadSetLength(scan_length_list);
	}
}

void ip_filter(char *get, u_char *my) {
	unsigned i = 0, j = 0, imsi = 0;
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
		else if(get[j] == 0 || isspace(get[j])) {
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
	pre_filter(tmp.toHex().data(), my, tmp.size(), "lower");
}

void send_broad(u_char *packet, int len, pcap_t *pcap) {
	unsigned i;
	struct libnet_ethernet_hdr eth_h;
	struct libnet_arp_hdr arp_h;

	for(i = 0; i < ETHER_ADDR_LEN; i++) {
		*(packet + i) = *(br_f + i);
		*(packet + ETHER_ADDR_LEN + i) = *(my_mac + i);
		*(packet + sizeof(eth_h) + sizeof(arp_h) - sizeof(arp_h.ar_dpa) - sizeof(arp_h.ar_dha) - sizeof(arp_h.ar_spa) - sizeof(arp_h.ar_sha) + i) = *(my_mac + i);
		*(packet + sizeof(eth_h) + sizeof(arp_h) - sizeof(arp_h.ar_dpa) - sizeof(arp_h.ar_dha) + i) = *(br_0 + i);
		if(i < IP_ADDR_LEN) {
			*(packet + sizeof(eth_h) + sizeof(arp_h) - sizeof(arp_h.ar_dpa) - sizeof(arp_h.ar_dha) - sizeof(arp_h.ar_spa) + i) = *(my_ip + i);
			*(packet + sizeof(eth_h) + sizeof(arp_h) - sizeof(arp_h.ar_dpa) + i) = *(my_ip + i);
		}
	}

	*(packet + sizeof(eth_h) + sizeof(arp_h.ar_hrd) + sizeof(arp_h.ar_pro) + sizeof(arp_h.ar_hln) + sizeof(arp_h.ar_pln) + 1) = ARPOP_REQUEST;

	for(i = 0; i < 0xFF; i++) {
		*(packet + sizeof(eth_h) + sizeof(arp_h) - 1) = getHex(i);
		pcap_sendpacket(pcap, packet, len);
	}
}

u_char getHex(int i) {
	QByteArray tmp;
	u_char imsi = 0;
	tmp.append(i);
	return filter(tmp.toHex().data(), &imsi, "lower");
}

QString getIPString(u_char *s) {
	QString str, result = "";

	for(unsigned i = 0; i < IP_ADDR_LEN; i++) {
		if(i == 3) str.sprintf("%d", s[i]);
		else str.sprintf("%d.", s[i]);
		result.append(str);
	}
	str.clear();
	return result;
}

QString getMacString(u_char *s) {
	QString str, result = "";

	for(int i = 0; i < ETHER_ADDR_LEN; i++) {
		str.sprintf("%02X", s[i]);
		result.append(str);
	}
	str.clear();
	return result;
}

void scanning_thread::scanThreadSetStop(bool s) {
	QMutex mut;
	mut.lock();
	pcap_stop = s;
	mut.unlock();
}

void scanning_thread::scanThreadSetSys(QString s, QString ip_s, int num, pcap_if_t *devs) {
	sys = s;
	sys_ipv = ip_s;
	if_num = num;
	alldevs = devs;
}
