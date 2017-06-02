#include "routing_thread.h"
//#include "statusq.h"
#include <QCoreApplication>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <libnet.h>
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

void mac_filter(char *get, u_char *my, int size);
u_char filter(char *get, u_char *my);
void ip_filter(char *get, u_char *my);

int flag_check(u_char *a, u_char *b, int size);
void send_broad(u_char *p, int l);
u_char getHex(int i);
QString getString(u_char *s);
QString getMacString(u_char *s);

QStringList list, length, macv;
QString sys, sys_ipv;
pcap_t *pcap;

bool pcap_stop;

u_char *pkt;

u_char my_mac[6] = {0,}, my_ip[4] = {0,};
u_char router_mac[6] = {0,}, router_ip[4] = {0,};
u_char victim_mac[256][6] = {0,}, victim_ip[256][4] = {0,};
int broad_cnt = 0;

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
/*
struct list_item {
    struct list_item* next;
    struct list_item* prev;
    unsigned long content;
};

struct nbt_list {
    struct list_item* head;
};

void host_name_print();
void l_print_hostinfo(struct in_addr addr, struct nb_host_info* hostinfo);
int compare(struct list_item* item1, struct list_item* item2);
int insert(struct nbt_list* lst, unsigned long content);
void delete_list(struct nbt_list* list);
uint16_t get16(void* data);
uint32_t get32(void* data);
struct nb_host_info* parse_response(char* buff, int buffsize);

struct nbt_list* new_list();
struct list_item* new_list_item(unsigned long content);
*/
routing_thread::routing_thread(QObject *parent) : QThread(parent)
{
    pcap_stop = false;
    host_name = new hostname();
}

void routing_thread::run() {
    int s = 0, i = 0;
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
    mac_filter(mac.toHex().data(), my_mac, mac.size());
    ifaddr.ifr_addr.sa_family = AF_INET;
    strncpy(ifaddr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(s, SIOCGIFADDR, &ifaddr);
    close(s);

    ip_filter(inet_ntoa(((struct sockaddr_in *)&ifaddr.ifr_addr)->sin_addr), my_ip);
    ip_filter(sys_ipv.toLatin1().data(), router_ip);
    sys_ipv.clear();

//    host_name_print();

    // Look up info from the capture device.
    if(pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) perror("pcap_lookupnet");
    pcap = pcap_open_live(dev, 65535, NONPROMISCUOUS, -1, errbuf);

    // Compiles the filter expression into a BPF filter program
    if (pcap_compile(pcap, &filter, "arp", 0, maskp) == -1) perror("pcap_compile");
    if (pcap_setfilter(pcap, &filter) == -1) perror("pcap_setfilter");
//    int pcap_fd = pcap_get_selectable_fd(pcap_handler);

    host_name->start();

    while(!pcap_stop && !host_name->host_stop) {
        bool break_point = false;
        if(!sys.isEmpty()) {
            system(sys.toStdString().c_str());
            sys.clear();
            system("arp -a >/dev/null");
        }
        while(pcap_next_ex(pcap, &pkthdr, (const u_char**)&packet) > 0) {
            eth = (struct libnet_ethernet_hdr *)packet;
            arpheader = (struct arphdr *)(packet + sizeof(struct libnet_ethernet_hdr));

            if(ntohs(arpheader->oper) == ARPOP_REPLY && flag_check(eth->ether_dhost, my_mac, 6) != 1 && flag_check(arpheader->sha, arpheader->tha, 6) == 1 && flag_check(arpheader->tpa, my_ip, 4) != 1 && *(router_mac+1) == 0 && flag_check(arpheader->spa, router_ip, 4) != 1 && flag_check(router_mac, br_0, 6) != 1) {
                for(i = 0; i < ETHER_ADDR_LEN; i++) *(router_mac+i) = *(packet + ETHER_ADDR_LEN + i);
                macv << getMacString(router_mac) << getMacString(my_mac);
                list << getString(router_ip) << getString(my_ip);
                length.append(QString::number(pkthdr->len));
                pkt = packet;
                emit setList(list);
                host_name->getArgu(router_ip);
                host_name->getArgu(my_ip);
                send_broad(packet, pkthdr->len);
            }

            if(flag_check(eth->ether_shost, my_mac, 6) == 1 && flag_check(eth->ether_shost, router_mac, 6) == 1 && flag_check(arpheader->spa, my_ip, 4) == 1 && flag_check(arpheader->spa, router_ip, 4) == 1)
                for(i = 0; i < list.length(); i++)
                    if(!list.isEmpty()) {
                        str_list = list.at(i);
                        ip_filter(str_list.toLatin1().data(), tmp_ip);
                        if(flag_check(arpheader->spa, tmp_ip, 4) != 1) break_point = true;
                    }

            if(ntohs(arpheader->oper) == ARPOP_REPLY && flag_check(eth->ether_dhost, my_mac, 6) != 1 && flag_check(arpheader->tha, my_mac, 6) != 1 && flag_check(arpheader->sha, router_mac, 6) == 1 && flag_check(eth->ether_shost, my_mac, 6) == 1 && flag_check(arpheader->sha, my_mac, 6) == 1 && flag_check(arpheader->spa, my_ip, 4) == 1 && flag_check(arpheader->spa, arpheader->tpa, 4) == 1 && flag_check(router_mac, br_0, 6) == 1 && flag_check(arpheader->spa, router_ip, 4) == 1 && !break_point) {
                for(i = 0; i < ETHER_ADDR_LEN; i++) *(*(victim_mac+broad_cnt)+i) = *(eth->ether_shost+i);
                macv << getMacString(*(victim_mac+broad_cnt));
                for(i = 0; i < 4; i++) *(*(victim_ip+broad_cnt)+i) = *(arpheader->spa+i);		// save to victim ip address
                list << getString(*(victim_ip+broad_cnt));
                length.append(QString::number(pkthdr->len));
                emit setList(list);
                host_name->getArgu(*(victim_ip+broad_cnt));
                broad_cnt++;
                if(broad_cnt%10 == 0) send_broad(packet, pkthdr->len);
            }

            if(ntohs(arpheader->oper) == ARPOP_REQUEST && flag_check(eth->ether_dhost, br_f, 6) != 1 && flag_check(arpheader->tha, br_0, 6) != 1 && flag_check(arpheader->sha, my_mac, 6) == 1 && flag_check(eth->ether_shost, router_mac, 6) == 1 && flag_check(arpheader->spa, my_ip, 4) == 1 && flag_check(arpheader->spa, arpheader->tpa, 4) == 1 && flag_check(router_mac, br_0, 6) == 1 && flag_check(arpheader->spa, router_ip, 4) == 1 && !break_point && *(arpheader->spa) != 0 && *(arpheader->spa+3) != 0) {
                for(i = 0; i < ETHER_ADDR_LEN; i++) *(*(victim_mac+broad_cnt)+i) = *(eth->ether_shost+i);
                macv << getMacString(*(victim_mac+broad_cnt));
                for(i = 0; i < 4; i++) *(*(victim_ip+broad_cnt)+i) = *(arpheader->spa+i);
                list << getString(*(victim_ip+broad_cnt));
                length.append(QString::number(pkthdr->len));
                emit setList(list);
                host_name->getArgu(*(victim_ip+broad_cnt));
                broad_cnt++;
                if(broad_cnt%10 == 0) send_broad(packet, pkthdr->len);
            }
        }
    }
    emit setLength(length);
    emit setMacPacket(macv);
    emit packet_info(pkt);
    emit dump_pcap(pcap);
    if(host_name->isRunning()) host_name->hostStop(true);
}

void mac_filter(char *get, u_char *my, int size) {	// mac address or ip address filter
    int i, j;
    if(size == ETHER_ADDR_LEN) for(i = 0, j = 0; i < ETHER_ADDR_LEN; i++, j+=2) filter(get+j, my+i);
    else for(i = 0, j = 0; i < (ETHER_ADDR_LEN - 2); i++, j+=2) filter(get+j, my+i);
}

u_char filter(char *get, u_char *my) {
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
    return *my;
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
    mac_filter(tmp.toHex().data(), my, tmp.size());
}



int flag_check(u_char *a, u_char *b, int size) {	// compare address and check flags
    int value = 0;
    if(size == ETHER_ADDR_LEN) value = (*a != *b ? 1 : ((*(a+1) != *(b+1)) ? 1 : ((*(a+2) != *(b+2)) ? 1 : ((*(a+3) != *(b+3)) ? 1 : ((*(a+4) != *(b+4)) ? 1 : ((*(a+5) != *(b+5)) ? 1 : -1))))));
    else value = (*a != *b ? 1 : ((*(a+1) != *(b+1)) ? 1 : ((*(a+2) != *(b+2)) ? 1 : ((*(a+3) != *(b+3)) ? 1 : -1))));
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
    return filter(tmp.toHex().data(), &imsi);;
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
    pcap_stop = s;
    mut.unlock();
}

void routing_thread::set_sys(QString s, QString ip_s) {
    sys = s;
    sys_ipv = ip_s;
}



// It is part of nbtscan command. parse_response() function in statusq.c, nb_host_info structure in statusq.h
// This way use select() function, UDP protocol, recvfrom() to destination address after bind() to local address
/*
void host_name_print(){
    int sock = 0, timeout = 1000, size = 0;
    socklen_t addr_size = 0;
    uint32_t rtt_base;
    struct sockaddr_in src_sockaddr, dest_sockaddr;
    struct nb_host_info* hostinfo;
    fd_set fdsr, fdsw;
    void *buff;
    char errmsg[80];
    float rtt, srtt = 0, rttvar = 0.75;
    double delta;
    struct timeval select_timeout, last_send_time, send_interval;
    struct timeval transmit_started,  recv_time;
    struct nbt_list* scanned;
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    bzero((void*)&src_sockaddr, sizeof(src_sockaddr));
    src_sockaddr.sin_family = AF_INET;
    if(bind(sock, (struct sockaddr *)&src_sockaddr, sizeof(src_sockaddr)) == -1) qDebug() << "bind() Error!";
//    fdsr=(fd_set *)malloc(sizeof(fd_set));
//    if(!fdsr) qDebug() << "fdsr :: Malloc failed";
    FD_ZERO(&fdsr);
    FD_SET(sock, &fdsr);
//    fdsw=(fd_set *)malloc(sizeof(fd_set));
//    if(!fdsw) qDebug() << "fdsw :: Malloc failed";
    FD_ZERO(&fdsw);
    FD_SET(sock, &fdsw);
    select_timeout.tv_sec = timeout / 1000;
    select_timeout.tv_usec = (timeout % 1000) * 1000;
    addr_size = sizeof(struct sockaddr_in);
    buff = malloc(1024);
    timerclear(&send_interval);
    send_interval.tv_usec = 1;
    if(send_interval.tv_usec >= 1000000) {
        send_interval.tv_sec = send_interval.tv_usec / 1000000;
        send_interval.tv_usec = send_interval.tv_usec % 1000000;
    }
    gettimeofday(&last_send_time, NULL);
    rtt_base = last_send_time.tv_sec;
    gettimeofday(&transmit_started, NULL);
    scanned = new_list();
    int test;
    while((select(sock+1, &fdsr, &fdsw, NULL, &select_timeout)) > 0) {
        FD_SET(sock, &fdsr);
        if(test = FD_ISSET(sock, &fdsr)) {
            qDebug() << "3";
            if((size = recvfrom(sock, buff, 1024, 0, (struct sockaddr*)&dest_sockaddr, &addr_size)) <= 0 ) {
                snprintf(errmsg, 80, "%s\tRecvfrom failed", inet_ntoa(dest_sockaddr.sin_addr));
                qDebug() << errmsg;
                continue;
            }
            qDebug() << "4";
            gettimeofday(&recv_time, NULL);
            hostinfo = (struct nb_host_info*)parse_response((char*)buff, size);
            if(!hostinfo) {
                qDebug() << "hostinfo initialize error!";
                continue;
            }
                    // If this packet isn't a duplicate
            if(insert(scanned, ntohl(dest_sockaddr.sin_addr.s_addr))) {
                qDebug() << "5";
                rtt = recv_time.tv_sec + recv_time.tv_usec/1000000 - rtt_base - hostinfo->header->transaction_id/1000;
                  // Using algorithm described in Stevens' Unix Network Programming
                delta = rtt - srtt;
                srtt += delta / 8;
                if(delta < 0.0) delta = - delta;
                rttvar += (delta - rttvar) / 4 ;
                l_print_hostinfo(dest_sockaddr.sin_addr, hostinfo);
            }
            qDebug() << "6";
            free(hostinfo);
        }
        else {
            qDebug() << test;
            break;
        }
        FD_ZERO(&fdsr);
        FD_SET(sock, &fdsr);
    }
    delete_list(scanned);
}

void l_print_hostinfo(struct in_addr addr, struct nb_host_info* hostinfo) {
    int i, unique, first_name=1;
    u_char service; // 16th byte of NetBIOS name
    char comp_name[16];
    strncpy(comp_name,"<unknown>",15);

    if(hostinfo->header && hostinfo->names) {
        for(i=0; i< hostinfo->header->number_of_names; i++) {
            service = hostinfo->names[i].ascii_name[15];
            unique = ! (hostinfo->names[i].rr_flags & 0x0080);
            if(service == 0  && unique && first_name) {
                // Unique name, workstation service - this is computer name
                strncpy(comp_name, hostinfo->names[i].ascii_name, 15);
                comp_name[15]=0;
                first_name = 0;
            }
        }
    }
    qDebug() << inet_ntoa(addr) << comp_name;
}

struct nbt_list* new_list() {
    struct nbt_list* lst;
    if((lst = (struct nbt_list*) malloc(sizeof(struct nbt_list))) == NULL) qDebug() << "new_list() error!";
    lst->head = NULL;
    return lst;
}

struct list_item* new_list_item(unsigned long content) {
    struct list_item* lst_item;

    if((lst_item = (struct list_item*) malloc(sizeof(struct list_item)))==NULL) qDebug() << "Malloc failed";
    lst_item->next = NULL;
    lst_item->prev = NULL;
    lst_item->content = content;
    return lst_item;
}

int compare(struct list_item* item1, struct list_item* item2) {
    if(item2==NULL) return -1;
    if(item1==NULL) return 1;
    if(item1->content == item2->content) return 0;
    if(item1->content > item2->content) return 1;
    if(item1->content < item2->content) return -1;
}

int insert(struct nbt_list* lst, unsigned long content) {
    struct list_item *temp_item, *item;
    int cmp;

    item = new_list_item(content);

    cmp = compare(lst->head, item);
    if(lst->head==NULL) {
        lst->head=item;
        return 1;
    } else if (cmp==1) {
        item->next=lst->head;
        lst->head = item;
        item->prev = NULL;
        return 1;
    } else if (cmp==0) {
        free(item);
        return 0;
    } else if (cmp==-1) {
        temp_item = lst->head;
        while(compare(temp_item->next, item)==-1) {
            temp_item = temp_item->next;
        }
        // temp_item points to last list element less then item
        // we shall insert item after temp_item
        if(compare(temp_item->next, item)==0) {
            free(item);
            return 0;
        } else if(compare(temp_item->next, item)==-1) {
            free(item);
            return -1;
        } else if(compare(temp_item->next, item)==1) {
            item->next=temp_item->next;
            item->prev=temp_item;
            if(temp_item->next) temp_item->next->prev = item;
            temp_item->next = item;
            return 1;
        }
    } else if (compare(lst->head, item)==-1) {
        free(item);
        return -1;
    }
}

void delete_list(struct nbt_list* list) {
    struct list_item* pointer;
    pointer = list->head;
    if (pointer) {
        while(pointer->next) pointer = pointer->next; // Find last list element
        // Go back from tail to head deleteing list items on the way
        while(pointer->prev) {
            pointer = pointer->prev;
            free(pointer->next);
        }
        free(pointer);
    }
    free(list);
}

uint32_t get32(void* data) {
    union {
        char bytes[4];
        uint32_t all;
    } x;

    memcpy(x.bytes, data, 4);
    return(ntohl(x.all));
}

uint16_t get16(void* data) {
        union {
                char bytes[2];
                uint16_t all;
        } x;

        memcpy(x.bytes, data, 2);
        return(ntohs(x.all));
}

struct nb_host_info* parse_response(char* buff, int buffsize) {
    struct nb_host_info* hostinfo = NULL;
    nbname_response_footer_t* response_footer;
    nbname_response_header_t* response_header;
    int name_table_size;
    int offset = 0;

    if((response_header = (nbname_response_header_t *)malloc(sizeof(nbname_response_header_t)))==NULL) return NULL;
    if((response_footer = (nbname_response_footer_t *)malloc(sizeof(nbname_response_footer_t)))==NULL) return NULL;
    bzero(response_header, sizeof(nbname_response_header_t));
    bzero(response_footer, sizeof(nbname_response_footer_t));

    if((hostinfo = (struct nb_host_info *)malloc(sizeof(struct nb_host_info)))==NULL) return NULL;
    hostinfo->header = NULL;
        hostinfo->names = NULL;
    hostinfo->footer = NULL;

    // Parsing received packet
    // Start with header
    if( offset+sizeof(response_header->transaction_id) >= buffsize) goto broken_packet;
    response_header->transaction_id = get16(buff+offset);
    //Move pointer to the next structure field
    offset+=sizeof(response_header->transaction_id);
        hostinfo->header = response_header;

    // Check if there is room for next field in buffer
    if( offset+sizeof(response_header->flags) >= buffsize) goto broken_packet;
    response_header->flags = get16(buff+offset);
        offset+=sizeof(response_header->flags);

    if( offset+sizeof(response_header->question_count) >= buffsize) goto broken_packet;
    response_header->question_count = get16(buff+offset);
        offset+=sizeof(response_header->question_count);

    if( offset+sizeof(response_header->answer_count) >= buffsize) goto broken_packet;
    response_header->answer_count = get16(buff+offset);
        offset+=sizeof(response_header->answer_count);

    if( offset+sizeof(response_header->name_service_count) >= buffsize) goto broken_packet;
    response_header->name_service_count = get16(buff+offset);
        offset+=sizeof(response_header->name_service_count);

    if( offset+sizeof(response_header->additional_record_count) >= buffsize) goto broken_packet;
    response_header->additional_record_count = get16(buff+offset);
        offset+=sizeof(response_header->additional_record_count);

    if( offset+sizeof(response_header->question_name) >= buffsize) goto broken_packet;
    strncpy(response_header->question_name, buff+offset, sizeof(response_header->question_name));
        offset+=sizeof(response_header->question_name);

    if( offset+sizeof(response_header->question_type) >= buffsize) goto broken_packet;
    response_header->question_type = get16(buff+offset);
        offset+=sizeof(response_header->question_type);

    if( offset+sizeof(response_header->question_class) >= buffsize) goto broken_packet;
    response_header->question_class = get16(buff+offset);
        offset+=sizeof(response_header->question_class);

    if( offset+sizeof(response_header->ttl) >= buffsize) goto broken_packet;
        response_header->ttl = get32(buff+offset);
        offset+=sizeof(response_header->ttl);

    if( offset+sizeof(response_header->rdata_length) >= buffsize) goto broken_packet;
        response_header->rdata_length = get16(buff+offset);
        offset+=sizeof(response_header->rdata_length);

    if( offset+sizeof(response_header->number_of_names) >= buffsize) goto broken_packet;
    response_header->number_of_names = *(typeof(response_header->number_of_names)*)(buff+offset);
        offset+=sizeof(response_header->number_of_names);

    // Done with packet header - it is okay

    name_table_size = (response_header->number_of_names) * (sizeof(struct nbname));
    if( offset+name_table_size >= buffsize) goto broken_packet;

    if((hostinfo->names = (struct nbname*)malloc(name_table_size))==NULL) return NULL;
    memcpy(hostinfo->names, buff + offset, name_table_size);

    offset+=name_table_size;

    // Done with name table - it is okay

        // Now parse response footer

    if( offset+sizeof(response_footer->adapter_address) >= buffsize) goto broken_packet;
    memcpy(response_footer->adapter_address,
           (buff+offset),
           sizeof(response_footer->adapter_address));
    offset+=sizeof(response_footer->adapter_address);

    hostinfo->footer=response_footer;

    if( offset+sizeof(response_footer->version_major) >= buffsize) goto broken_packet;
    response_footer->version_major = *(typeof(response_footer->version_major)*)(buff+offset);
    offset+=sizeof(response_footer->version_major);

    if( offset+sizeof(response_footer->version_minor) >= buffsize) goto broken_packet;
    response_footer->version_minor = *(typeof(response_footer->version_minor)*)(buff+offset);
    offset+=sizeof(response_footer->version_minor);

    if( offset+sizeof(response_footer->duration) >= buffsize) goto broken_packet;
    response_footer->duration = get16(buff+offset);
    offset+=sizeof(response_footer->duration);

    if( offset+sizeof(response_footer->frmps_received) >= buffsize) goto broken_packet;
    response_footer->frmps_received= get16(buff+offset);
    offset+=sizeof(response_footer->frmps_received);

    if( offset+sizeof(response_footer->frmps_transmitted) >= buffsize) goto broken_packet;
    response_footer->frmps_transmitted = get16(buff+offset);
    offset+=sizeof(response_footer->frmps_transmitted);

    if( offset+sizeof(response_footer->iframe_receive_errors) >= buffsize) goto broken_packet;
    response_footer->iframe_receive_errors = get16(buff+offset);
    offset+=sizeof(response_footer->iframe_receive_errors);

    if( offset+sizeof(response_footer->transmit_aborts) >= buffsize) goto broken_packet;
    response_footer->transmit_aborts =  get16(buff+offset);
    offset+=sizeof(response_footer->transmit_aborts);

    if( offset+sizeof(response_footer->transmitted) >= buffsize) goto broken_packet;
    response_footer->transmitted = get32(buff+offset);
    offset+=sizeof(response_footer->transmitted);

    if( offset+sizeof(response_footer->received) >= buffsize) goto broken_packet;
    response_footer->received = get32(buff+offset);
    offset+=sizeof(response_footer->received);

    if( offset+sizeof(response_footer->iframe_transmit_errors) >= buffsize) goto broken_packet;
    response_footer->iframe_transmit_errors = get16(buff+offset);
    offset+=sizeof(response_footer->iframe_transmit_errors);

    if( offset+sizeof(response_footer->no_receive_buffer) >= buffsize) goto broken_packet;
    response_footer->no_receive_buffer = get16(buff+offset);
    offset+=sizeof(response_footer->no_receive_buffer);

    if( offset+sizeof(response_footer->tl_timeouts) >= buffsize) goto broken_packet;
    response_footer->tl_timeouts = get16(buff+offset);
    offset+=sizeof(response_footer->tl_timeouts);

    if( offset+sizeof(response_footer->ti_timeouts) >= buffsize) goto broken_packet;
    response_footer->ti_timeouts = get16(buff+offset);
    offset+=sizeof(response_footer->ti_timeouts);

    if( offset+sizeof(response_footer->free_ncbs) >= buffsize) goto broken_packet;
    response_footer->free_ncbs = get16(buff+offset);
    offset+=sizeof(response_footer->free_ncbs);

    if( offset+sizeof(response_footer->ncbs) >= buffsize) goto broken_packet;
    response_footer->ncbs = get16(buff+offset);
    offset+=sizeof(response_footer->ncbs);

    if( offset+sizeof(response_footer->max_ncbs) >= buffsize) goto broken_packet;
    response_footer->max_ncbs = get16(buff+offset);
    offset+=sizeof(response_footer->max_ncbs);

    if( offset+sizeof(response_footer->no_transmit_buffers) >= buffsize) goto broken_packet;
    response_footer->no_transmit_buffers = get16(buff+offset);
    offset+=sizeof(response_footer->no_transmit_buffers);

    if( offset+sizeof(response_footer->max_datagram) >= buffsize) goto broken_packet;
    response_footer->max_datagram = get16(buff+offset);
    offset+=sizeof(response_footer->max_datagram);

    if( offset+sizeof(response_footer->pending_sessions) >= buffsize) goto broken_packet;
    response_footer->pending_sessions = get16(buff+offset);
    offset+=sizeof(response_footer->pending_sessions);

    if( offset+sizeof(response_footer->max_sessions) >= buffsize) goto broken_packet;
    response_footer->max_sessions = get16(buff+offset);
    offset+=sizeof(response_footer->max_sessions);

    if( offset+sizeof(response_footer->packet_sessions) >= buffsize) goto broken_packet;
    response_footer->packet_sessions = get16(buff+offset);
    offset+=sizeof(response_footer->packet_sessions);

    // Done with packet footer and the whole packet

    return hostinfo;

    broken_packet:
        hostinfo->is_broken = offset;
        return hostinfo;
}
*/
