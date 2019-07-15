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
#include <unistd.h>
#include <time.h>
#include <iconv.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/time.h>
#include <curl/curl.h>

#define IP_ADDR_LEN sizeof(uint32_t)
#define IP6_ADDR_LEN 16
#define MAX_IP_ADDR_LEN IP6_ADDR_LEN
#define MAX_PACKET_SIZE 65536
#ifndef PATH_MAX
	#define PATH_MAX 1024
#endif

/*
 * List definitions.
 */
#define LIST_HEAD(name, type)                                           \
struct name {                                                           \
        struct type *lh_first;  /* first element */                     \
}

#define LIST_HEAD_INITIALIZER(head)                                     \
        { NULL }

#define LIST_ENTRY(type)                                                \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
}

/*
 * List access methods
 */
#define LIST_FIRST(head)                ((head)->lh_first)
#define LIST_END(head)                  NULL
#define LIST_EMPTY(head)                (LIST_FIRST(head) == LIST_END(head))
#define LIST_NEXT(elm, field)           ((elm)->field.le_next)

#define LIST_FOREACH(var, head, field)                                  \
        for((var) = LIST_FIRST(head);                                   \
            (var)!= LIST_END(head);                                     \
            (var) = LIST_NEXT(var, field))

#define LIST_FOREACH_SAFE(var, head, field, tvar)                       \
        for ((var) = LIST_FIRST((head));                                \
             (var) && ((tvar) = LIST_NEXT((var), field), 1);            \
             (var) = (tvar))

   

/*
 * List functions.
 */
#define LIST_INIT(head) do {                                            \
        LIST_FIRST(head) = LIST_END(head);                              \
} while (0)

#define LIST_INSERT_AFTER(listelm, elm, field) do {                     \
        if (((elm)->field.le_next = (listelm)->field.le_next) != NULL)  \
                (listelm)->field.le_next->field.le_prev =               \
                    &(elm)->field.le_next;                              \
        (listelm)->field.le_next = (elm);                               \
        (elm)->field.le_prev = &(listelm)->field.le_next;               \
} while (0)

#define LIST_INSERT_BEFORE(listelm, elm, field) do {                    \
        (elm)->field.le_prev = (listelm)->field.le_prev;                \
        (elm)->field.le_next = (listelm);                               \
        *(listelm)->field.le_prev = (elm);                              \
        (listelm)->field.le_prev = &(elm)->field.le_next;               \
} while (0)

#define LIST_INSERT_HEAD(head, elm, field) do {                         \
        if (((elm)->field.le_next = (head)->lh_first) != NULL)          \
                (head)->lh_first->field.le_prev = &(elm)->field.le_next;\
        (head)->lh_first = (elm);                                       \
        (elm)->field.le_prev = &(head)->lh_first;                       \
} while (0)

#define LIST_REMOVE(elm, field) do {                                    \
        if ((elm)->field.le_next != NULL)                               \
                (elm)->field.le_next->field.le_prev =                   \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = (elm)->field.le_next;                   \
} while (0)

#define LIST_REPLACE(elm, elm2, field) do {                             \
        if (((elm2)->field.le_next = (elm)->field.le_next) != NULL)     \
                (elm2)->field.le_next->field.le_prev =                  \
                    &(elm2)->field.le_next;                             \
        (elm2)->field.le_prev = (elm)->field.le_prev;                   \
        *(elm2)->field.le_prev = (elm2);                                \
} while (0)

int popen_used(char *cmd, char *buf, size_t buf_len);
void pre_filter(char *get, u_char *my, int size, char *cap);
u_char filter(char *get, u_char *my, char *cap);
int flag_check(u_char *a, u_char *b, int size);
void print_packet(int len, u_char *packet);
void print_headers(u_char *packet);
void mac_print(u_int8_t *eth);

#endif // COMMON_FUNC_H
