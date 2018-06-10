#ifndef COMMON_FUNC_H
#define COMMON_FUNC_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <iconv.h>
#define IP_ADDR_LEN 4

int popen_used(char *cmd, char *buf, size_t buf_len);
void pre_filter(char *get, u_char *my, int size, char *cap);
u_char filter(char *get, u_char *my, char *cap);
int flag_check(u_char *a, u_char *b, int size);
void print_packet(int len, u_char *packet);

#endif // COMMON_FUNC_H
