#include "hostname.h"
#include <QCoreApplication>

QStringList hostIPList, hostName;
u_char *hostIP;

void host_filter(u_char*);
QString getHex2String(u_char *s);

hostname::hostname(QObject *parent) : QThread(parent) {
	char buf[10] = {0,};

	this->idx = 0;
	if(hostIPList.length() > 1 && this->host_stop && !this->start_flag) this->idx = hostIPList.length();
	this->host_stop = false;
	this->start_flag = true;
	this->host_err = false;
	popen_used("sudo nbtscan -h 2>/dev/null | wc -l", buf, sizeof(buf));
	if(!strncmp(buf, "0", 1)) {
		popen_used("if [ \"$(cat /etc/*-release | egrep -i '(ubuntu|suse|debian|oracle linux)')\" != \"\" ]; then if [ \"$(cat /etc/*-release | grep -i 'ubuntu')\" != \"\" ]; then echo \"Ubuntu\"; elif [ \"$(cat /etc/*-release | grep -i 'suse')\" != \"\" ]; then echo \"SuSE\"; elif [ \"$(cat /etc/*-release | grep -i 'debian')\" != \"\" ]; then echo \"Debian\"; else echo \"Oracle\"; fi; elif [ \"$(cat /etc/*-release | egrep -i '(centos|fedora|red hat enterprise)')\" != \"\" ]; then if [ \"$(cat /etc/*-release | grep -i 'centos')\" != \"\" ]; then echo \"CentOS\"; elif [ \"$(cat /etc/*-release | grep -i 'fedora')\" != \"\" ]; then echo \"Fedora\"; else echo \"RHEL\"; fi; fi", buf, sizeof(buf));
		if(!strncmp(buf, "Ubuntu", 6) || !strncmp(buf, "Debian", 6)) popen_used("sudo apt-get install -y nbtscan >/dev/null 2>&1 && if [ $? -eq 0 ]; then echo success; else echo fail; fi;", buf, sizeof(buf));
		else if(!strncmp(buf, "CentOS", 6) || !strncmp(buf, "Fedora", 6) || !strncmp(buf, "Oracle", 6) || !strncmp(buf, "RHEL", 4)) popen_used("sudo yum install -y nbtscan >/dev/null 2>&1 && if [ $? -eq 0 ]; then echo success; else echo fail; fi;", buf, sizeof(buf));

		if(!strncmp(buf, "success", 7)) {
			this->host_stop = true;
			this->start_flag = false;
		} else {
			this->host_err = true;
		}
	}
}

void hostname::run() {
	char cmd[256] = {0,};
	char in_buf[256] = {0,};
	while(1) {
		if(!hostIPList.isEmpty() && this->idx == 0) {
			hostName << "Router";
			emit hostnameSetHostList(hostName);
			this->idx++;
		} else if (!hostIPList.isEmpty() && this->idx > 0 && this->idx < hostIPList.length()) {
			memset(in_buf, 0, 256);
			QString hostIP_tmp = hostIPList.at(this->idx);
			const char *str_to_ip = hostIP_tmp.toLatin1().data();
			sprintf(cmd, "sudo nbtscan %s | awk '/^[0-9].*.[0-9].*.[0-9].*.[0-9]/ { print $2 }'", str_to_ip);
			popen_used(cmd, in_buf, sizeof(in_buf));
			size_t in_size = strlen(in_buf);
			if(in_size != 0) {
				size_t out_size = sizeof(wchar_t) * in_size * 4;
				char *out_buf = (char *)malloc(out_size);
				memset(out_buf, 0x00, out_size);
				iconv_t ic = iconv_open("EUC-KR" /*tocode*/, "UTF-8" /*fromcode*/ );
				if(ic == (iconv_t) - 1) {
					fprintf(stderr, "not supported code \n");
					exit(1);
				}
				// in_buf & out_buf is double pointer. So their address give to another pointer.
				char* in_ptr = in_buf;
				char* out_ptr = out_buf;
				size_t out_buf_left = out_size;
				int result = iconv(ic, &in_ptr, &in_size, &out_ptr, &out_buf_left);
				iconv_close(ic);
				if(result == -1) {
//					perror("iconv failed : ");
					break;
				}
				hostName << out_buf;
				emit hostnameSetHostList(hostName);
			}
			else {
				host_filter(hostIP);
				emit hostnameSetHostList(hostName);
			}
			this->idx++;
		}
		if(this->idx == hostIPList.length() && this->host_stop && !this->start_flag) break;
	}
}

void host_filter(u_char *ip) {
	struct sockaddr_in host_addr;
	char host_buf[NI_MAXHOST] = {0,};
//	struct hostent *hptr;
	char host_tmp[15] = {0,};
	for(unsigned i = 0, j = 0; i < IP_ADDR_LEN; i++) {
		if((ip[i] / 100) != 0) {
			host_tmp[j] = (ip[i] / 100) + '0';
			host_tmp[j+1] = (ip[i] / 10) - ((ip[i] / 100) * 10) + '0';
			host_tmp[j+2] = ip[i] - ((ip[i] / 10) * 10) + '0';
			host_tmp[j+3] = '.';
			j += 4;
		}
		else if((ip[i] / 10) != 0) {
			host_tmp[j] = ip[i] / 10 + '0';
			host_tmp[j+1] = ip[i] - ((ip[i] / 10) * 10) + '0';
			host_tmp[j+2] = '.';
			j += 3;
		}
		else {
			host_tmp[j] = ip[i] + '0';
			if(i != 3) host_tmp[j+1] = '.';
			j += 2;
		}
	}
/*
	// I wanna get NetBIOS name. But it is very difficult work!
	// I try to use many function such as gethostbyaddr() / getaddrinfo() / getnameinfo() / gethostname() / gethostbyname()
	// And I try to use many argument such as NI_NAMEREQD / NI_NOFQDN / NI_IDN / NI_DGRAM / NI_NUMERICHOST / AF_NETBEUI / AF_LLC
	memset(&host_addr, 0, sizeof(host_addr));
	host_addr.sin_family = AF_INET;
	host_addr.sin_addr.s_addr = inet_addr(host_tmp);
	hptr = gethostbyaddr((char *)&host_addr.sin_addr, 4, AF_INET);
	if(hptr == NULL) {
		switch (h_errno) {
				case HOST_NOT_FOUND:
					hostName << "HOST_NOT_FOUND";
					break;
				case NO_ADDRESS:
					hostName << "NO_ADDRESS";
					break;
				case NO_RECOVERY:
					hostName << "NO_RECOVERY";
					break;
				case TRY_AGAIN:
					hostName << "TRY_AGAIN";
					break;
		}
	}
	else hostName << hptr->h_name;
*/
	memset(&host_addr, 0, sizeof(host_addr));
	inet_pton(AF_INET, host_tmp, &(host_addr.sin_addr));
	host_addr.sin_family = AF_INET;
//	host_addr.sin_addr.s_addr = inet_addr(host_tmp);
//	host_addr.sin_port = 80;
	if(getnameinfo((struct sockaddr *)&host_addr, sizeof(host_addr), host_buf, sizeof(host_buf), NULL, 0, NI_NAMEREQD)) {
//		qDebug() <<  gai_strerror(test);
		switch (h_errno) {
				case NO_ADDRESS:
					hostName << "NO_ADDRESS";
					break;
				case NO_RECOVERY:
					hostName << "NO_RECOVERY";
					break;
				case TRY_AGAIN:
					hostName << "TRY_AGAIN";
					break;
				case HOST_NOT_FOUND:
				default:
					hostName << "HOST_NOT_FOUND";
					break;
		}
	}
	else hostName << host_buf;
}

QString getHex2String(u_char *s) {
	QString str, result;
	for(unsigned i = 0; i < IP_ADDR_LEN; i++) {
		if(i == 3) str.sprintf("%d", s[i]);
		else str.sprintf("%d.", s[i]);
		result.append(str);
	}
	str.clear();
	return result;
}

void hostname::hostStop(bool s) {
	QMutex mut;
	mut.lock();
	this->host_stop = s;
	this->start_flag = false;
	mut.unlock();
}

void hostname::getArgu(u_char *list, bool flag) {
	hostIPList << getHex2String(list);
	hostIP = list;
	this->start_flag = flag;
}
