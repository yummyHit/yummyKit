#include "get_gateway.h"
#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#define BUFSIZE 8192

char gateway[255] = {0,};

enum {
	U = 0x01, // This flag signifies that the route is up
	G = 0x02, // This flag signifies that the route is to a gateway. If this flag is not present then we can say that the route is to a directly connected destination
	H = 0x04, // This flag signifies that the route is to a host which means that the destination is a complete host address. If this flag is not present then it can be assumed that the route is to a network and destination would be a network address.
	D = 0x08, // This flag signifies that this route is created by a redirect.
	M = 0x10 // This flag signifies that this route is modified by a redirect.
};

const char * real_flag[16] = {
	"",
	"U",
	"G",
	"UG",
	"H",
	"UH",
	"GH",
	"UGH",
	"D",
	"UD",
	"GD",
	"UGD",
	"HD",
	"UHD",
	"GHD",
	"UGHD"
};

struct route_info {
	struct in_addr dstAddr;
	struct in_addr srcAddr;
	struct in_addr gateWay;
	struct in_addr netmask;
	int flags;
	int metric;
	int reference;
	char ifName[IF_NAMESIZE];
};

int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId) {
	struct nlmsghdr *nlHdr;
	int readLen = 0, msgLen = 0;

	do {
		// Recieve response from the kernel
		if((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0) {
			perror("SOCK READ: ");
			return -1;
		}

		nlHdr = (struct nlmsghdr *) bufPtr;

		// Check if the header is valid
		if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)) {
			perror("Error in recieved packet");
			return -1;
		}

		// Check if the its the last message Else move the pointer to buffer appropriately
		if(nlHdr->nlmsg_type == NLMSG_DONE) {
			break;
		} else {
			bufPtr += readLen;
			msgLen += readLen;
		}

		// Check if its a multi part message
		if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
			break;
		}
	} while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));
	return msgLen;
}

#if 0
// For printing the routes.
void printRoute(struct route_info *rtInfo) {
	char tempBuf[512] = {0,};
	char *ptr = NULL, *rptr = NULL;
	int classCnt = 0;

	// Print Destination address
	memset(tempBuf, 0, sizeof(tempBuf));
	if(rtInfo->dstAddr.s_addr != 0) {
		strncpy(tempBuf, (char *)inet_ntoa(rtInfo->dstAddr), sizeof(tempBuf));
		rtInfo->flags |= U;
	}
	else sprintf(tempBuf, "0.0.0.0\t");
	fprintf(stdout, "%s\t", tempBuf);

	// Print Gateway address
	memset(tempBuf, 0, sizeof(tempBuf));
	if(rtInfo->gateWay.s_addr != 0) {
		strncpy(tempBuf, (char *)inet_ntoa(rtInfo->gateWay), sizeof(tempBuf));
		rtInfo->flags |= U;
		rtInfo->flags |= G;
	}
	else sprintf(tempBuf, "0.0.0.0\t");
	fprintf(stdout, "%s\t", tempBuf);

	// Print Subnet Mask
	memset(tempBuf, 0, sizeof(tempBuf));
	if(rtInfo->netmask.s_addr != 0) strncpy(tempBuf, (char *)inet_ntoa(rtInfo->netmask), sizeof(tempBuf));

	if(rtInfo->dstAddr.s_addr != 0) {
		for(ptr = strtok_r((char *)inet_ntoa(rtInfo->dstAddr), ".", &rptr); ptr; ptr = strtok_r(NULL, ".", &rptr))
			if(*ptr != '0') 
				classCnt++;
		if(classCnt == 3 && tempBuf == NULL) sprintf(tempBuf, "255.255.255.0");
		else if(classCnt == 2 && strncmp((char *)inet_ntoa(rtInfo->gateWay), tempBuf, 6)) sprintf(tempBuf, "255.255.0.0");
		else if(classCnt == 1) sprintf(tempBuf, "255.0.0.0");
	}
	else sprintf(tempBuf, "0.0.0.0\t");
	fprintf(stdout, "%s\t", tempBuf);

	// Print Flags
	if(rtInfo->flags > 0 && rtInfo->flags < 16) fprintf(stdout, "%-5s ", real_flag[rtInfo->flags]);
	else fprintf(stdout, "%-5s ", real_flag[1]);

	// Print Metrics
	fprintf(stdout, "%-6d ", rtInfo->metric);

	// Print Reference
	fprintf(stdout, "%-8d ", rtInfo->reference);

	// Print Use
	fprintf(stdout, "%d ", 0);

	// Print Interface Name
	fprintf(stdout, "%s\n", rtInfo->ifName);

/*
	// Print Source address
	if(rtInfo->srcAddr.s_addr != 0) strcpy(tempBuf, inet_ntoa(rtInfo->srcAddr));
	else sprintf(tempBuf, "*.*.*.*\t");
	fprintf(stdout, "%s\n", tempBuf);
*/
}

void printGateway() {
	printf("%s\n", gateway);
}
#endif

// For parsing the route info returned
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo) {
	struct rtmsg *rtMsg;
	struct rtattr *rtAttr;
	int rtLen = 0;

	struct ifreq ifr;
	int fd = 0;

	rtMsg = (struct rtmsg *) NLMSG_DATA(nlHdr);

	// If the route is not for AF_INET or does not belong to main routing table then return.
	if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN)) return;

	// get the rtattr field
	rtAttr = (struct rtattr *) RTM_RTA(rtMsg);
	rtLen = RTM_PAYLOAD(nlHdr);
	for(; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
		switch(rtAttr->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int *) RTA_DATA(rtAttr), rtInfo->ifName);
				break;
			case RTA_GATEWAY:
				rtInfo->gateWay.s_addr = *(u_int *) RTA_DATA(rtAttr);
				break;
			case RTA_PREFSRC:
				rtInfo->srcAddr.s_addr = *(u_int *) RTA_DATA(rtAttr);
				break;
			case RTA_DST:
				rtInfo->dstAddr.s_addr = *(u_int *) RTA_DATA(rtAttr);
				break;
			case RTA_PRIORITY:
			case RTA_METRICS:
				rtInfo->metric = *((int*) RTA_DATA(rtAttr));
				break;
		}
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	if(rtInfo->ifName != 0) strncpy(ifr.ifr_name, rtInfo->ifName, IFNAMSIZ-1);
	if(!ioctl(fd, SIOCGIFNETMASK, &ifr))
		rtInfo->netmask.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

	if(rtInfo->dstAddr.s_addr == 0) sprintf(gateway, "%s", (char *) inet_ntoa(rtInfo->gateWay));
//	printRoute(rtInfo);

	return;
}

void get_gateway::get_route_ip(char *route, int route_len) {
	strncpy(route, gateway, route_len);
}

get_gateway::get_gateway() {
	struct nlmsghdr *nlMsg;
	struct route_info *rtInfo;
	char msgBuf[BUFSIZE] = {0,};

	int sock = 0, len = 0, msgSeq = 0;

	// Create Socket
	if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) perror("Socket Creation: ");

	memset(msgBuf, 0, BUFSIZE);

	// point the header and the msg structure pointers into the buffer
	nlMsg = (struct nlmsghdr *) msgBuf;

	// Fill in the nlmsg header
	nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));  // Length of message.
	nlMsg->nlmsg_type = RTM_GETROUTE;   // Get the routes from kernel routing table .

	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;	// The message is a request for dump.
	nlMsg->nlmsg_seq = msgSeq++;	// Sequence of the message packet.
	nlMsg->nlmsg_pid = getpid();	// PID of process sending the request.

	// Send the request
	if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0)
		perror("Write To Socket Failed...\n");

	// Read the response
	if((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0)
		perror("Read From Socket Failed...\n");

	// Parse and print the response
	rtInfo = (struct route_info *) malloc(sizeof(struct route_info));
//	fprintf(stdout, "Kernel IP routing table\nDestination	 Gateway		 Genmask		 Flags Metric Ref	Use Iface\n");
	for(; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
		memset(rtInfo, 0, sizeof(struct route_info));
		parseRoutes(nlMsg, rtInfo);
	}
	free(rtInfo);
	close(sock);
}
