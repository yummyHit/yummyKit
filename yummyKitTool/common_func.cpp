#include "common_func.h"

// popen function is execute command and get return value
int popen_used(char *cmd, char *buf, size_t buf_len) {
    FILE *fp = NULL;

    memset(buf, 0x00, buf_len);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("errno : ");
        exit(0);
    }

    char *p = buf;
    int len = 0;
    int remain = buf_len;

    while (!feof(fp) && remain > 0)  {
        len = fread(p, 1, remain, fp);
        p+=len;
        remain -= len;
    }
    *p = 0;
    pclose(fp);

    return len;
}

// mac address has 6 bytes and ipv4 address has 4 bytes
void pre_filter(char *get, u_char *my, int size, char *cap) {
    if(size == ETHER_ADDR_LEN) for(int i = 0, j = 0; i < ETHER_ADDR_LEN; i++, j+=2) filter(get + j, my + i, cap);
    else if(size == IP_ADDR_LEN) for(int i = 0, j = 0; i < IP_ADDR_LEN; i++, j+=2) filter(get + j, my + i, cap);
}

// uppercase is 'A', so 65 - '0' ==> 0x11 / lowercase is 'a', so 97 - '0' ==> 0x31
u_char filter(char *get, u_char *my, char *cap) {
    if(!strncmp(cap, "upper", 5)) {
        if(*get - '0' < 0x10) {
            *my = (*get - '0') * 0x10;
            if(*(get+1) - '0' < 0x10) *my += (*(get+1) - '0') * 0x01;
            else *my += (*(get+1) - '0' == 0x11) ? 0x0A : ((*(get+1) - '0' == 0x12) ? 0x0B : ((*(get+1) - '0' == 0x13) ? 0x0C : ((*(get+1) - '0' == 0x14) ? 0x0D : ((*(get+1) - '0' == 0x15) ? 0x0E : 0x0F))));
        }
        else {
            *my = (*get - '0' == 0x11) ? 0xA0 : ((*get - '0' == 0x12) ? 0xB0 : ((*get - '0' == 0x13) ? 0xC0 : ((*get - '0' == 0x14) ? 0xD0 : ((*get - '0' == 0x15) ? 0xE0 : 0xF0))));
            if(*(get+1) - '0' < 0x10) *my += (*(get+1) - '0') * 0x01;
            else *my += (*(get+1) - '0' == 0x11) ? 0x0A : ((*(get+1) - '0' == 0x12) ? 0x0B : ((*(get+1) - '0' == 0x13) ? 0x0C : ((*(get+1) - '0' == 0x14) ? 0x0D : ((*(get+1) - '0' == 0x15) ? 0x0E : 0x0F))));
        }
	}
    else if(!strncmp(cap, "lower", 5)) {
        if(*get - '0' < 0x10) {
            *my = (*get - '0') * 0x10;
            if(*(get+1) - '0' < 0x10) *my += (*(get+1) - '0') * 0x01;
            else *my += (*(get+1) - '0' == 0x31) ? 0x0A : ((*(get+1) - '0' == 0x32) ? 0x0B : ((*(get+1) - '0' == 0x33) ? 0x0C : ((*(get+1) - '0' == 0x34) ? 0x0D : ((*(get+1) - '0' == 0x35) ? 0x0E : 0x0F))));
        }
        else {
            *my = (*get - '0' == 0x31) ? 0xA0 : ((*get - '0' == 0x32) ? 0xB0 : ((*get - '0' == 0x33) ? 0xC0 : ((*get - '0' == 0x34) ? 0xD0 : ((*get - '0' == 0x35) ? 0xE0 : 0xF0))));
            if(*(get+1) - '0' < 0x10) *my += (*(get+1) - '0') * 0x01;
            else *my += (*(get+1) - '0' == 0x31) ? 0x0A : ((*(get+1) - '0' == 0x32) ? 0x0B : ((*(get+1) - '0' == 0x33) ? 0x0C : ((*(get+1) - '0' == 0x34) ? 0x0D : ((*(get+1) - '0' == 0x35) ? 0x0E : 0x0F))));
        }
	}
    return *my;
}

// compare address and check flags
int flag_check(u_char *a, u_char *b, int size) {
    int value = 0;
    if(size == ETHER_ADDR_LEN) value = (*a != *b ? 1 : ((*(a+1) != *(b+1)) ? 1 : ((*(a+2) != *(b+2)) ? 1 : ((*(a+3) != *(b+3)) ? 1 : ((*(a+4) != *(b+4)) ? 1 : ((*(a+5) != *(b+5)) ? 1 : -1))))));
    else value = (*a != *b ? 1 : ((*(a+1) != *(b+1)) ? 1 : ((*(a+2) != *(b+2)) ? 1 : ((*(a+3) != *(b+3)) ? 1 : -1))));
    return value;
}

void print_packet(int len, u_char *packet) {
    int cnt = 0;
    printf("\n");
    while(--len != 0) {
        printf("%02x ", *(packet++));
        if ((++cnt % 16) == 0) printf("\n");
    }
    printf("%02x\n", *packet);
}
