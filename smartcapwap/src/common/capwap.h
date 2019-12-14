#ifndef __CAPWAP_HEADER__
#define __CAPWAP_HEADER__

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Endian */
#if __BYTE_ORDER == __BIG_ENDIAN
	#define CAPWAP_BIG_ENDIAN
#else
	#define CAPWAP_LITTLE_ENDIAN
#endif

/* Min & Max */
#ifndef max
	#define max(a,b) ((a) >= (b) ? (a) : (b))
#endif

#ifndef min
	#define min(a,b) ((a) <= (b) ? (a) : (b))
#endif

/* Opaque type */
#define DECLARE_OPAQUE_TYPE(name) struct name##__opaque__ { int unused; }; typedef struct name##__opaque__* name

/* UDPLite */
#ifdef HAVE_NETINET_UDPLITE_H
#include <netinet/udplite.h>
#else
#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE			136
#endif
#ifndef SOL_UDPLITE
#define SOL_UDPLITE				136
#endif
#ifndef UDPLITE_SEND_CSCOV
#define UDPLITE_SEND_CSCOV		10
#endif
#endif

/* standard include */
#include "capwap_rfc.h"
#include "capwap_logging.h"
#include "capwap_debug.h"
#include "capwap_error.h"
#include "capwap_timeout.h"

/* Helper exit */
void capwap_exit(int errorcode);

/* Random generator */
int capwap_get_rand(int max);

/* */
#define capwap_outofmemory()						do {																	\
														log_printf(LOG_EMERG, "Out of memory %s(%d)", __FILE__, __LINE__);	\
														capwap_exit(CAPWAP_OUT_OF_MEMORY); 									\
													} while(0)

/* Helper buffer copy */
char* capwap_duplicate_string(const char* source);
void* capwap_clone(const void* buffer, int buffersize);

/* */
char* capwap_itoa(int input, char* output);
char* capwap_ltoa(long input, char* output);

#endif /* __CAPWAP_HEADER__ */
