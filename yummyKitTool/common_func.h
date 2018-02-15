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
//#include <iostream>
//#include <fstream>

int popen_used(char *cmd, char *buf, size_t buf_len);

#endif // COMMON_FUNC_H
