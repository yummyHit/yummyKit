#ifndef SSLSTRIP_H
#define SSLSTRIP_H

#include <QtCore>
#include <QThread>
#include "common_func.h"
#include <sys/poll.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <pcre.h>
#include <stdint.h>
#include <linux/netfilter_ipv4.h>

class sslstrip : public QThread
{
	Q_OBJECT
public:
	explicit sslstrip(QObject *parent);

	// global variable
	static int main_fd, main_fd6;
	static struct pollfd poll_fd[2];
	static uint16_t bind_port;
	static pcre *https_url_pcre;
	static regex_t find_cookie_re;

	// protocols
	int plugin_load(void *);
	static int sslstrip_init(void *);
	static int sslstrip_fini(void *);
	static void sslstrip_ex(struct packet_object *po);
	static int sslstrip_is_http(struct packet_object *po);
	void safe_free_http_redirect(char **param, int *param_length, char *command, char *orig_command);
};

#endif // SSLSTRIP_H
