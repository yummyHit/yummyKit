#include "sslstrip.h"
#include <QCoreApplication>
#include <QHostAddress>

#define HTTP_PATTERN "(http://[\x21-\x7E]*)"
#define COOKIE_PATTERN "Set-Cookie: ([\x20-\x7E]+); ?Secure"

#define HTTP_RETRY 500
#define HTTP_WAIT 10 /* milliseconds */

#define PROTO_HTTP 1
#define PROTO_HTTPS 2

#define HTTP_GET (1<<16)
#define HTTP_POST (1<<24)

#define HTTP_MAX (1024*200) //200KB max for HTTP requests.

struct ip_addr {
   uint16_t addr_type;
   uint16_t addr_len;
   /* this must be aligned in memory */
   union {
      uint8_t addr[MAX_IP_ADDR_LEN];
      uint16_t addr16[MAX_IP_ADDR_LEN/2];
      uint32_t addr32[MAX_IP_ADDR_LEN/4];
   };
};

struct http_ident {
    uint32_t magic;
	#define HTTP_MAGIC 0x0501e77f
	struct ip_addr L3_src;
    uint16_t L4_src;
    uint16_t L4_dst;
};

#define HTTP_IDENT_LEN sizeof(struct http_ident)

struct https_link {
	char *url;
	time_t last_used;
	LIST_ENTRY (https_link) next;   
};

struct http_request {
	int method;
	struct curl_slist *headers;
	char *url;
	char *payload;
};

struct http_response {
	char *html;
	unsigned long int len;
};

struct http_connection {
	int fd;
    uint16_t port[2];
	struct ip_addr ip[2];
	CURL *handle;
	struct http_request *request;
	struct http_response *response;
	char curl_err_buffer[CURL_ERROR_SIZE];
	#define HTTP_CLIENT 0
	#define HTTP_SERVER 1
};

sslstrip::sslstrip(QObject *parent) : QThread(parent)
{

}
