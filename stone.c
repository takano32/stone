/*
 * stone.c	simple repeater
 * Copyright(c)1995-2004 by Hiroaki Sengoku <sengoku@gcd.org>
 * Version 1.0	Jan 28, 1995
 * Version 1.1	Jun  7, 1995
 * Version 1.2	Aug 20, 1995
 * Version 1.3	Feb 16, 1996	relay UDP
 * Version 1.5	Nov 15, 1996	for Win32
 * Version 1.6	Jul  5, 1997	for SSL
 * Version 1.7	Aug 20, 1997	return packet of UDP
 * Version 1.8	Oct 18, 1997	pseudo parallel using SIGALRM
 * Version 2.0	Nov  3, 1997	http proxy & over http
 * Version 2.1	Nov 14, 1998	respawn & pop
 * Version 2.2	May 25, 2003	Posix Thread, XferBufMax, no ALRM, SSL verify
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Emacs; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Usage: stone [-d] [-n] [-u <max>] [-f <n>] [-a <file>] [-L <file>] [-l]
 *              [-o <n>] [-g <n>] [-t <dir>] [-z <SSL>] [-D]
 *              [-C <file>] [-P <command>]
 *              <st> [-- <st>]...
 * <st> := <display> [<xhost>...]
 *        | <host>:<port> <sport> [<xhost>...]
 *        | proxy <sport> [<xhost>...]
 *        | <host>:<port#>/http <sport> <request> [<xhost>...]
 *        | <host>:<port#>/proxy <sport> <header> [<xhost>...]
 * <port>  := <port#>[/udp | /ssl | /apop]
 * <sport> := [<host>:]<port#>[/udp | /ssl | /http]
 * <xhost> := <host>[/<mask>]
 *
 *     Any packets received by <display> are passed to DISPLAY
 *     Any packets received by <sport> are passed to <host>:<port>
 *     as long as these packets are sent from <xhost>...
 *     if <xhost> are not given, any hosts are welcome.
 *
 * Make:
 * gcc -o stone stone.c
 * or
 * cl -DWINDOWS stone.c /MT wsock32.lib
 * or
 * gcc -DWINDOWS -o stone.exe stone.c -lwsock32
 *
 * POP -> APOP conversion
 * gcc -DUSE_POP -o stone stone.c md5c.c
 * or
 * cl -DWINDOWS -DUSE_POP stone.c md5c.c /MT wsock32.lib
 * or
 * gcc -DWINDOWS -DUSE_POP -o stone.exe stone.c md5c.c -lwsock32
 *
 * md5c.c global.h md5.h are contained in RFC1321
 *
 * Using OpenSSL
 * gcc -DUSE_SSL -I/usr/local/ssl/include -o stone stone.c \
 *               -L/usr/local/ssl/lib -lssl -lcrypto
 * or
 * cl -DWINDOWS -DUSE_SSL stone.c /MT wsock32.lib ssleay32.lib libeay32.lib
 * or
 * gcc -DWINDOWS -DUSE_SSL -o stone.exe stone.c -lwsock32 -lssl32 -leay32
 *
 * -DUSE_POP	  use POP -> APOP conversion
 * -DUSE_SSL	  use OpenSSL
 * -DCPP	  preprocessor for reading config. file
 * -DH_ERRNO	  h_errno is not defined in header files
 * -DIGN_SIGTERM  ignore SIGTERM signal
 * -DINET_ADDR	  use custom inet_addr(3)
 * -DNO_BCOPY	  without bcopy(3)
 * -DNO_SNPRINTF  without snprintf(3)
 * -DNO_SYSLOG	  without syslog(2)
 * -DNO_THREAD	  without thread
 * -DPTHREAD      use Posix Thread
 * -DOS2	  OS/2 with EMX
 * -DWINDOWS	  Windows95/98/NT
 * -DNT_SERVICE	  WindowsNT/2000 native service
 * -DUNIX_DAEMON  fork into background and become a UNIX Daemon
 * -DPRCTL	  with prctl(2) - operations on a process
 */
#define VERSION	"2.2c"
static char *CVS_ID =
"@(#) $Id: stone.c,v 1.131 2004/07/20 10:10:30 hiroaki_sengoku Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdarg.h>
#include <signal.h>
typedef void (*FuncPtr)(void*);

#ifdef WINDOWS
#define FD_SETSIZE	256
#include <process.h>
#include <winsock.h>
#include <time.h>
#ifdef NT_SERVICE
#include "service.h"
#include "svcbody.h"
#endif
#define NO_SYSLOG
#define NO_FORK
#define NO_SETHOSTENT
#define NO_SETUID
#define NO_CHROOT
#define ValidSocket(sd)		((sd) != INVALID_SOCKET)
#define FD_SET_BUG
#undef EINTR
#define EINTR	WSAEINTR
#define NO_BCOPY
#define bzero(b,n)	memset(b,0,n)
#define	usleep(usec)	sleep(1)
#define ASYNC(func,arg)	\
    waitMutex(AsyncMutex);\
    if (Debug > 7) message(LOG_DEBUG,"ASYNC: %d",AsyncCount);\
    AsyncCount++;\
    freeMutex(AsyncMutex);\
    if (_beginthread((FuncPtr)func,0,arg) < 0) {\
	message(LOG_ERR,"_beginthread error err=%d",errno);\
	func(arg);\
    }
#else	/* ! WINDOWS */
#include <sys/param.h>
#ifdef OS2
#define INCL_DOSSEMAPHORES
#define INCL_DOSERRORS
#include <process.h>
#include <os2.h>
#define NO_SYSLOG
#define ASYNC(func,arg)	\
    waitMutex(AsyncMutex);\
    if (Debug > 7) message(LOG_DEBUG,"ASYNC: %d",AsyncCount);\
    AsyncCount++;\
    freeMutex(AsyncMutex);\
    if (_beginthread((FuncPtr)func,NULL,32768,arg) < 0) {\
	message(LOG_ERR,"_beginthread error err=%d",errno);\
	func(arg);\
    }
#else	/* ! WINDOWS & ! OS2 */
#ifdef PTHREAD
#include <pthread.h>
pthread_attr_t thread_attr;
typedef void *(*aync_start_routine) (void *);
#define ASYNC(func,arg)	\
    waitMutex(AsyncMutex);\
    if (Debug > 7) message(LOG_DEBUG,"ASYNC: %d",AsyncCount);\
    AsyncCount++;\
    freeMutex(AsyncMutex);\
    if (err=pthread_create(&thread,&thread_attr,\
			   (aync_start_routine)func,arg)) {\
	message(LOG_ERR,"pthread_create error err=%d",err);\
	func(arg);\
    } else if (Debug > 7) {\
	message(LOG_DEBUG,"pthread ID=%d",thread);\
    }
#else	/* ! PTHREAD */
#define ASYNC(func,arg)	\
    waitMutex(AsyncMutex);\
    AsyncCount++;\
    freeMutex(AsyncMutex);\
    func(arg)
#define NO_THREAD
#endif	/* ! PTHREAD */
#endif	/* ! WINDOWS & ! OS2 */
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#ifdef PRCTL
#include <sys/prctl.h>
#endif
typedef int SOCKET;
#define INVALID_SOCKET		-1
#define ValidSocket(sd)		((sd) >= 0)
#define closesocket(sd)		close(sd)
#endif	/* ! WINDOWS */
#define InvalidSocket(sd)	(!ValidSocket(sd))
#ifdef FD_SET_BUG
int FdSetBug = 0;
#define FdSet(fd,set)		do{if (!FdSetBug || !FD_ISSET((fd),(set))) \
					FD_SET((fd),(set));}while(0)
#else
#define FdSet(fd,set)		FD_SET((fd),(set))
#endif

#ifdef NO_THREAD
#define ASYNC_BEGIN		/* */
#define ASYNC_END		/* */
#else
#define ASYNC_BEGIN	\
    if (Debug > 7) message(LOG_DEBUG,"ASYNC_BEGIN: %d",AsyncCount)
#define ASYNC_END	\
    waitMutex(AsyncMutex);\
    if (Debug > 7) message(LOG_DEBUG,"ASYNC_END: %d",AsyncCount);\
    AsyncCount--;\
    freeMutex(AsyncMutex)
#endif

#ifdef NO_SYSLOG
#define LOG_CRIT	2	/* critical conditions */
#define LOG_ERR		3	/* error conditions */
#define LOG_WARNING	4	/* warning conditions */
#define LOG_NOTICE	5	/* normal but signification condition */
#define LOG_INFO	6	/* informational */
#define LOG_DEBUG	7	/* debug-level messages */
#else	/* SYSLOG */
#include <syslog.h>
#endif

#ifndef EISCONN
#define EISCONN		56		/* Socket is already connected */
#endif
#ifndef EADDRINUSE
#define EADDRINUSE	48		/* Address already in use */
#endif

#define BACKLOG_MAX	5
#define XPORT		6000
#define BUFMAX		2048
#define STRMAX		30	/* > 16 */
#define NTRY_MAX	10
#define CONN_TIMEOUT	60	/* 1 min */
#define	LB_MAX		100

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	255
#endif

#define TICK_SELECT	100000	/* 0.1 sec */
#define SPIN_MAX	10	/* 1 sec */
#define	NERRS_MAX	10	/* # of select errors */
#define	REF_UNIT	10	/* unit of pair->count */

#ifdef USE_SSL
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <regex.h>

#define NMATCH_MAX	9	/* \1 ... \9 */
#define DEPTH_MAX	10

typedef struct {
    int verbose;
    int depth;
    long serial;
    SSL_CTX *ctx;
    regex_t *re[DEPTH_MAX];
    unsigned char lbmod;
    unsigned char lbparm;
} StoneSSL;

typedef struct {
    int verbose;
    int mode;
    int depth;
    long off;
    long serial;
    int (*callback)(int, X509_STORE_CTX *);
    char *keyFile;
    char *certFile;
    char *caFile;
    char *caPath;
    char *cipherList;
    char *regexp[DEPTH_MAX];
    unsigned char lbmod;
    unsigned char lbparm;
} SSLOpts;

SSLOpts ServerOpts;
SSLOpts ClientOpts;
int PairIndex;
#ifdef WINDOWS
HANDLE *SSLMutex = NULL;
#else
#ifdef PTHREAD
pthread_mutex_t *SSLMutex = NULL;
#endif
#endif
int NSSLMutexs = 0;

#include <openssl/md5.h>
#define MD5Init		MD5_Init
#define MD5Update	MD5_Update
#define MD5Final	MD5_Final
#else
#ifdef USE_POP
#include "global.h"
#include "md5.h"
#endif
#endif
#ifdef CPP
char *CppCommand = CPP;
char *CppOptions = NULL;
#endif

typedef struct {
    struct in_addr addr;
    struct in_addr mask;
} XHost;

typedef struct _Backup {
    struct _Backup *next;
    struct sockaddr_in master;
    struct sockaddr_in backup;
    int proto;
    short interval;	/* interval of health check */
    short bn;		/* 0: health, 1: backup */
    short used;		/* 0: not used, 1: assigned, 2: used */
    time_t last;	/* last health check */
} Backup;

typedef struct _LBSet {
    struct _LBSet *next;
    int proto;
    short nsins;
    struct sockaddr_in sins[0];
} LBSet;

typedef struct _Stone {
    SOCKET sd;			/* socket descriptor to listen */
    short port;
    short nsins;		/* # of destinations */
    struct sockaddr_in *sins;	/* destinations */
    int proto;
    Backup **backups;
    char *p;
    int timeout;
    struct _Stone *next;
#ifdef USE_SSL
    StoneSSL *ssl_server;
    StoneSSL *ssl_client;
#endif
    int nhosts;			/* # of hosts */
    XHost xhosts[0];		/* hosts permitted to connect */
} Stone;

typedef struct _TimeLog {
    time_t clock;		/* time of beginning */
    int pri;			/* log priority */
    char str[0];		/* Log message */
} TimeLog;

typedef struct _Pair {
    struct _Pair *pair;
    struct _Pair *prev;
    struct _Pair *next;
    Stone *stone;	/* parent */
#ifdef USE_SSL
    SSL *ssl;		/* SSL handle */
    char **match;
#endif
    time_t clock;
    int timeout;
    SOCKET sd;		/* socket descriptor */
    int proto;
    int count;		/* reference counter */
    char *p;
    TimeLog *log;
    int tx;		/* sent bytes */
    int rx;		/* received bytes */
    int start;		/* index of buf */
    int len;
    int bufmax;		/* buffer size */
    char buf[BUFMAX];
} Pair;

typedef struct _Conn {
    struct sockaddr_in sin;	/* destination */
    Pair *pair;
    int lock;
    struct _Conn *next;
} Conn;

typedef struct _Origin {
    SOCKET sd;			/* peer */
    Stone *stone;
    struct sockaddr_in sin;	/* origin */
    int lock;
    time_t clock;
    struct _Origin *next;
} Origin;

typedef struct _Comm {
    char *str;
    int (*func)(Pair*, fd_set*, fd_set*, char*, int);
} Comm;

Stone *stones = NULL;
Stone *oldstones = NULL;
int ReuseAddr = 0;
Backup *backups = NULL;
LBSet *lbsets = NULL;
int MinInterval = 0;
time_t lastScanBackups = 0;
time_t lastEstablished = 0;
time_t lastReadWrite = 0;
Pair pairs;
Pair *trash = NULL;
Conn conns;
Origin origins;
int OriginMax = 10;
fd_set rin, win, ein;
int PairTimeOut = 10 * 60;	/* 10 min */
int AsyncCount = 0;
#ifdef H_ERRNO
extern int h_errno;
#endif

const state_mask =	    0x00ff;
const proto_command =	    0x0f00;	/* command (destination only) */
const proto_tcp	=	    0x1000;	/* transmission control protocol */
const proto_udp =	    0x2000;	/* user datagram protocol */
const proto_source =	    0x4000;	/* source flag */
					/* only for Stone */
const proto_ident =         0x8000;	  /* need ident */
const proto_ssl_s =    	 0x1000000;	  /* SSL source */
const proto_ssl_d =	 0x2000000;	  /*     destination */
					/* only for Pair */
const proto_connect =	    0x8000;	  /* connection established */
const proto_first_r =	   0x10000;	  /* first read packet */
const proto_first_w =	   0x20000;	  /* first written packet */
const proto_select_r =	   0x40000;	  /* select to read */
const proto_select_w =	   0x80000;	  /* select to write */
const proto_shutdown =	  0x100000;	  /* sent shutdown */
const proto_close =	  0x200000;	  /* request to close */
const proto_eof =	  0x400000;	  /* EOF */
const proto_ssl_intr =	  0x800000;	  /* SSL accept/connect interrupted */
const proto_ohttp_s =	 0x4000000;	/* over http source */
const proto_ohttp_d =	 0x8000000;	/*           destination */
const proto_base_s =	0x10000000;	/* base64 source */
const proto_base_d =	0x20000000;	/*        destination */
#define command_proxy	    0x0100	/* http proxy */
#define command_ihead	    0x0200	/* insert header */
#define command_pop	    0x0300	/* POP -> APOP conversion */
#define command_health	    0x0400	/* is stone healthy ? */

#define proto_ssl	(proto_ssl_s|proto_ssl_d)
#define proto_ohttp	(proto_ohttp_s|proto_ohttp_d)
#define proto_base	(proto_base_s|proto_base_d)
#define proto_src	(proto_tcp|proto_udp|proto_first_r|proto_first_w|\
			 proto_ohttp_s|proto_base_s|\
			 proto_source)
#define proto_dest	(proto_tcp|proto_udp|proto_first_r|proto_first_w|\
			 proto_ohttp_d|proto_base_d|\
			 proto_command)
#define proto_all	(proto_src|proto_dest)

int XferBufMax = 1000;	/* TCP packet buffer initial size (must < 1024 ?) */
char *pkt_buf;		/* UDP packet buffer */
int pkt_len_max;	/* size of pkt_buf */
#define PKT_LEN_INI	2048	/* initial size */
int AddrFlag = 0;
#ifndef NO_SYSLOG
int Syslog = 0;
char SyslogName[STRMAX];
#endif
FILE *LogFp = NULL;
char *LogFileName = NULL;
FILE *AccFp = NULL;
char *AccFileName = NULL;
char *ConfigFile = NULL;
char *PidFile = NULL;
int DryRun = 0;
int ConfigArgc = 0;
int OldConfigArgc = 0;
char **ConfigArgv = NULL;
char **OldConfigArgv = NULL;
char *DispHost;
int DispPort;
#ifdef UNIX_DAEMON
int DaemonMode = 0;
#endif
#ifndef NO_CHROOT
char *RootDir = NULL;
#endif
#ifndef NO_SETUID
unsigned long SetUID = 0;
unsigned long SetGID = 0;
#endif
char *CoreDumpDir = NULL;
pid_t MyPid;
#ifndef NO_FORK
int NForks = 0;
pid_t *Pid;
#endif
int Debug = 0;		/* debugging level */
int PacketDump = 0;
#ifdef PTHREAD
pthread_mutex_t FastMutex = PTHREAD_MUTEX_INITIALIZER;
char FastMutexs[7];
#define PairMutex	0
#define ConnMutex	1
#define OrigMutex	2
#define AsyncMutex	3
#define FdRinMutex	4
#define FdWinMutex	5
#define FdEinMutex	6
#endif
#ifdef WINDOWS
HANDLE PairMutex, ConnMutex, OrigMutex, AsyncMutex;
HANDLE FdRinMutex, FdWinMutex, FdEinMutex;
#endif
#ifdef OS2
HMTX PairMutex, ConnMutex, OrigMutex, AsyncMutex;
HMTX FdRinMutex, FdWinMutex, FdEinMutex;
#endif

#ifdef NO_VSNPRINTF
int vsnprintf(char *str, size_t len, char *fmt, va_list ap) {
    int ret;
    ret = vsprintf(str, fmt, ap);
    if (strlen(str) >= len) {
	fprintf(stderr, "Buffer overrun\n");
	exit(1);
    }
}
#endif

#ifdef NO_SNPRINTF
int snprintf(char *str, size_t len, char *fmt, ...) {
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(str, len, fmt, ap);
    va_end(ap);
    return ret;
}
#endif

#ifdef NO_BCOPY
void bcopy(void *b1, void *b2, int len) {
    if (b1 < b2 && (char*)b2 < (char*)b1 + len) {	/* overlapping */
	char *p;
	b2 = (char*)b2 + len - 1;
	for (p=(char*)b1+len-1; (char*)b1 <= p; p--, ((char*)b2)--)
	    *(char*)b2 = *p;
    } else {
	memcpy(b2, b1, len);
    }
}
#endif

char *strntime(char *str, int len, time_t *clock) {
    char *p, *q;
    int i;
    p = ctime(clock);
    if (p) {
	q = p + strlen(p);
	while (*p++ != ' ')	;
	while (*--q != ' ')	;
	i = 0;
	len--;
	while (p <= q && i < len) str[i++] = *p++;
	str[i] = '\0';
    } else {
	snprintf(str, len, "%lu ", *clock);
    }
    return str;
}

void message(int pri, char *fmt, ...) {
    char str[BUFMAX];
    va_list ap;
#ifndef NO_SYSLOG
    if (Syslog) {
	va_start(ap, fmt);
	vsnprintf(str, BUFMAX, fmt, ap);
	va_end(ap);
	if (Syslog == 1
	    || pri != LOG_DEBUG) syslog(pri, "%s", str);
	if (Syslog > 1) fprintf(stdout, "%s\n", str);	/* daemontools */
    } else {
#endif
	time_t clock;
	int i;
	time(&clock);
	strntime(str, BUFMAX, &clock);
	i = strlen(str);
#ifndef NO_FORK
	if (NForks) {
	    snprintf(&str[i], BUFMAX-i, "[%d] ", MyPid);
	    i = strlen(str);
	}
#endif
	va_start(ap, fmt);
	vsnprintf(&str[i], BUFMAX-i-2, fmt, ap);
	va_end(ap);
#ifdef NT_SERVICE
	if (FALSE == bSvcDebug) AddToMessageLog(str);
	else
#endif
	if (LogFp) fprintf(LogFp, "%s\n", str);
#ifndef NO_SYSLOG
    }
#endif
}

TimeLog *message_time(int pri, char *fmt, ...) {
    char str[BUFMAX];
    TimeLog *log;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(str, BUFMAX-1, fmt, ap);
    va_end(ap);
    log = (TimeLog*)malloc(sizeof(TimeLog)+strlen(str)+1);
    if (log) {
	time(&log->clock);
	log->pri = pri;
	strcpy(log->str, str);
    }
    return log;
}

char *addr2ip(struct in_addr *addr, char *str) {
    union {
	u_long	l;
	unsigned char	c[4];
    } u;
    u.l = addr->s_addr;
    sprintf(str, "%d.%d.%d.%d", u.c[0], u.c[1], u.c[2], u.c[3]);
    return str;
}

char *addr2str(struct in_addr *addr) {
    static char str[STRMAX];
    struct hostent *ent;
    int ntry = NTRY_MAX;
    addr2ip(addr, str);
    if (!AddrFlag) {
	do {
#ifndef NO_SETHOSTENT
	    sethostent(0);
#endif
	    ent = gethostbyaddr((char*)&addr->s_addr,
				sizeof(addr->s_addr), AF_INET);
	    if (ent) return ent->h_name;
	} while (h_errno == TRY_AGAIN && ntry-- > 0);
	message(LOG_ERR, "Unknown address err=%d: %s", h_errno, str);
    }
    return str;
}

char *port2str(int port, int flag, int mask) {	/* network byte order */
    static char str[STRMAX];
    struct servent *ent;
    char *p;
    char sep = '/';
    if (flag & proto_udp) {
	p = "udp";
    } else {
	p = "tcp";
    }
    str[0] = '\0';
    if (!AddrFlag) {
	ent = getservbyport(port, p);
	if (ent) strncpy(str, ent->s_name, STRMAX-5);
    }
    if (str[0] == '\0') {
	sprintf(str, "%d", ntohs((unsigned short)port));
    }
    p = str + strlen(str);
    if (flag & proto_udp) {
	*p++ = sep;
	sep = ',';
	strcpy(p, "udp");
	p += 3;
    }
    if (flag & proto_ohttp & mask) {
	*p++ = sep;
	sep = ',';
	strcpy(p, "http");
	p += 4;
    }
    if (flag & proto_ssl & mask) {
	*p++ = sep;
	sep = ',';
	strcpy(p, "ssl");
	p += 3;
    }
    if (flag & proto_base & mask) {
	*p++ = sep;
	sep = ',';
	strcpy(p, "base");
	p += 4;
    }
    switch(flag & proto_command & mask) {
    case command_ihead:
	*p++ = sep;
	sep = ',';
	strcpy(p, "proxy");
	p += 5;
	break;
    case command_pop:
	*p++ = sep;
	sep = ',';
	strcpy(p, "apop");
	p += 4;
	break;
    }
    return str;
}

int isdigitstr(char *str) {
    while (*str && !isspace(*str)) {
	if (!isdigit(*str)) return 0;
	str++;
    }
    return 1;
}

int str2port(char *str, int flag) {	/* host byte order */
    struct servent *ent;
    char *proto;
    if (flag & proto_udp) {
	proto = "udp";
    } else {
	proto = "tcp";
    }
    ent = getservbyname(str, proto);
    if (ent) {
	return ntohs(ent->s_port);
    } else if (isdigitstr(str)) {
	return atoi(str);
    } else {
	return -1;
    }
}

int isdigitaddr(char *name) {
    int ndigits = 0;
    int isdot = 1;
    while(*name) {
	if (*name == '.') {
	    if (isdot) return 0;	/* `.' appears twice */
	    isdot = 1;
	} else if (isdigit(*name)) {
	    if (isdot) ndigits++;
	    isdot = 0;
	} else {
	    return 0;	/* not digit nor dot */
	}
	name++;
    }
    return ndigits;
}

#ifdef INET_ADDR
unsigned long inet_addr(char *name) {	/* inet_addr(3) is too tolerant */
    unsigned long ret;
    int d[4];
    int i;
    char c;
    if (sscanf(name, "%d.%d.%d.%d%c", &d[0], &d[1], &d[2], &d[3], &c) != 4)
	return -1;
    ret = 0;
    for (i=0; i < 4; i++) {
	if (d[i] < 0 || 255 < d[i]) return -1;
	ret <<= 8;
	ret |= d[i];
    }
    return htonl(ret);
}
#endif

int host2addr(char *name, struct in_addr *addrp, short *familyp) {
    struct hostent *hp;
    int ntry = NTRY_MAX;
    if (isdigitaddr(name)) {
	if ((addrp->s_addr=inet_addr(name)) != -1) {
	    if (familyp) *familyp = AF_INET;
	    return 1;
	}
    } else {
	do {
#ifndef NO_SETHOSTENT
	    sethostent(0);
#endif
	    hp = gethostbyname(name);
	    if (hp) {
		bcopy(hp->h_addr, (char *)addrp, hp->h_length);
		if (familyp) *familyp = hp->h_addrtype;
		return 1;
	    }
	} while (h_errno == TRY_AGAIN && ntry-- > 0);
    }
    message(LOG_ERR, "Unknown host err=%d: %s", h_errno, name);
    return 0;
}

/* *addrp is permitted to connect to *stonep ? */
int checkXhost(Stone *stonep, struct in_addr *addrp, char *ident) {
    int i;
    int match = 1;
    if (!stonep->nhosts) return 1; /* any hosts can access */
    for (i=0; i < stonep->nhosts; i++) {
	if ((stonep->xhosts[i].addr.s_addr == (u_long)~0)
	    && ! stonep->xhosts[i].mask.s_addr)
	    match = !match;
	else if ((addrp->s_addr & stonep->xhosts[i].mask.s_addr)
	    == (stonep->xhosts[i].addr.s_addr & stonep->xhosts[i].mask.s_addr))
	    return match;
    }
    return !match;
}

#ifdef WINDOWS
void waitMutex(HANDLE h) {
    DWORD ret;
    if (h) {
	ret = WaitForSingleObject(h, 500);	/* 0.5 sec */
	if (ret == WAIT_FAILED) {
	    message(LOG_ERR, "Fail to wait mutex err=%d", GetLastError());
	} else if (ret == WAIT_TIMEOUT) {
	    message(LOG_WARNING, "timeout to wait mutex");
	}
    }
}

void freeMutex(HANDLE h) {
    if (h) {
	if (!ReleaseMutex(h)) {
	    message(LOG_ERR, "Fail to release mutex err=%d", GetLastError());
	}
    }
}
#else	/* ! WINDOWS */
#ifdef OS2
void waitMutex(HMTX h) {
    APIRET ret;
    if (h) {
	ret = DosRequestMutexSem(h, 500);	/* 0.5 sec */
	if (ret == ERROR_TIMEOUT) {
	    message(LOG_WARNING, "timeout to wait mutex");
	} else if (ret) {
	    message(LOG_ERR, "Fail to request mutex err=%d", ret);
	}
    }
}

void freeMutex(HMTX h) {
    APIRET ret;
    if (h) {
	ret = DosReleaseMutexSem(h);
	if (ret) {
	    message(LOG_ERR, "Fail to release mutex err=%d", ret);
	}
    }
}
#else	/* ! OS2 & ! WINDOWS */
#ifdef PTHREAD
void waitMutex(int h) {
    int err;
    for (;;) {
	if (err=pthread_mutex_lock(&FastMutex)) {
	    message(LOG_ERR, "Mutex %d err=%d.", h, err);
	}
	if (FastMutexs[h] == 0) {
	    FastMutexs[h]++;
	    if (Debug > 20) message(LOG_DEBUG, "Lock Mutex %d = %d",
				    h, FastMutexs[h]);
	    pthread_mutex_unlock(&FastMutex);
	    break;
	}
	pthread_mutex_unlock(&FastMutex);
	usleep(100);
    }
}

void freeMutex(int h) {
    int err;
    if (err=pthread_mutex_lock(&FastMutex)) {
	message(LOG_ERR, "Mutex %d err=%d.", h, err);
    }
    if (FastMutexs[h] > 0) {
	if (FastMutexs[h] > 1)
	    message(LOG_ERR, "Mutex %d Locked Recursively (%d)",
		    h, FastMutexs[h]);
	FastMutexs[h]--;
	if (Debug > 20) message(LOG_DEBUG, "Unlock Mutex %d = %d",
				h, FastMutexs[h]);
    }
    pthread_mutex_unlock(&FastMutex);
}
#else	/* ! OS2 & ! WINDOWS & PTHREAD */
#define waitMutex(sem)	/* */
#define freeMutex(sem)	/* */
#endif
#endif
#endif

/* backup */

int healthCheck(struct sockaddr_in *sinp, int proto) {
    SOCKET sd;
    int ret;
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (InvalidSocket(sd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR, "health check: can't create socket err=%d.",
		sd, errno);
	return 1;	/* I can't tell the master is healthy or not */
    }
    if (Debug > 2)
	message(LOG_DEBUG, "health check: %s:%s",
		addr2str(&sinp->sin_addr),
		port2str(sinp->sin_port, proto, proto_dest));
    ret = connect(sd, (struct sockaddr*)sinp, sizeof(*sinp));
    if (ret == 0) shutdown(sd, 2);
    closesocket(sd);
    if (ret == 0) return 1;	/* healthy ! */
    return 0;	/* fail */
}

int scanBackups(void) {
    Backup *b;
    time_t now;
    time(&now);
    for (b=backups; b != NULL; b=b->next) {
	if (b->used < 2) continue;		/* not used */
	if (now - b->last < b->interval) continue;
	if (healthCheck(&b->master, b->proto)) {	/* healthy ? */
	    if (b->bn) {
		if (Debug > 1)
		    message(LOG_DEBUG, "health check %s:%s success",
			    addr2str(&b->master.sin_addr),
			    port2str(b->master.sin_port,
				     b->proto, proto_dest));
		b->bn = 0;
	    }
	} else {	/* unhealthy */
	    if (b->bn == 0) {
		if (Debug > 0)
		    message(LOG_DEBUG, "health check %s:%s fail",
			    addr2str(&b->master.sin_addr),
			    port2str(b->master.sin_port,
				     b->proto, proto_dest));
		b->bn++;
	    }
	}
	b->last = now;
    }
}

void asyncScanBackups(Backup *backup) {
    ASYNC_BEGIN;
    scanBackups();
    ASYNC_END;
}

int hostPort(char *str, struct sockaddr_in *sinp, int proto) {
    char host[STRMAX];
    int i;
    for (i=0; i < STRMAX-1; i++) {
	if (! str[i]) return 0;	/* illegal format */
	if (str[i] == ':') {
	    short family;
	    host[i] = '\0';
	    if (!host2addr(host, &sinp->sin_addr, &family)) {
		return 0;	/* unknown host */
	    }
	    sinp->sin_family = family;
	    sinp->sin_port = htons(str2port(&str[++i], proto));
	    return 1;	/* success */
	}
	host[i] = str[i];
    }
    return 0;	/* fail */
}

Backup *findBackup(struct sockaddr_in *sinp, int proto) {
    Backup *b;
    for (b=backups; b != NULL; b=b->next) {
	if (b->master.sin_addr.s_addr == sinp->sin_addr.s_addr
	    && b->master.sin_port == sinp->sin_port
	    && (b->proto & proto)) {	/* found */
	    if (Debug > 1) {
		char mhost[STRMAX];
		char mport[STRMAX];
		strcpy(mhost, addr2str(&b->master.sin_addr));
		strcpy(mport, port2str(b->master.sin_port,
				       b->proto, proto_dest));
		message(LOG_DEBUG, "master %s:%s backup %s:%s interval %d",
			mhost, mport,
			addr2str(&b->backup.sin_addr),
			port2str(b->backup.sin_port, b->proto, proto_dest),
			b->interval);
	    }
	    return b;
	}
    }
    return NULL;
}

int gcd(int a, int b) {
    int m;
    if (a > b) {
	m = a % b;
	if (m == 0) return b;
	return gcd(m, b);
    } else {
	m = b % a;
	if (m == 0) return a;
	return gcd(m, a);
    }
}

void mkBackup(int interval, char *master, char *backup) {
    Backup *b = malloc(sizeof(Backup));
    if (!b) {
	message(LOG_ERR, "Out of memory, no backup for %s", master);
	return;
    }
    b->proto = proto_tcp;
    b->interval = interval;
    if (MinInterval > 0) {
	MinInterval = gcd(MinInterval, interval);
    } else {
	MinInterval = interval;
    }
    if (!hostPort(master, &b->master, b->proto)) {
	message(LOG_ERR, "Illegal master: %s", master);
	free(b);
	return;
    }
    if (!hostPort(backup, &b->backup, b->proto)) {
	message(LOG_ERR, "Illegal backup: %s", backup);
	free(b);
	return;
    }
    b->last = 0;
    b->bn = 0;	/* healthy */
    b->used = 0;
    b->next = backups;
    backups = b;
}

LBSet *findLBSet(struct sockaddr_in *sinp, int proto) {
    LBSet *s;
    for (s=lbsets; s != NULL; s=s->next) {
	if (s->sins[0].sin_addr.s_addr == sinp->sin_addr.s_addr
	    && s->sins[0].sin_port == sinp->sin_port
	    && (s->proto & proto)) {	/* found */
	    if (Debug > 1) {
		char buf[BUFMAX];
		int len;
		int i;
		strcpy(buf, "LB set:");
		len = strlen(buf);
		for (i=0; i < s->nsins; i++) {
		    snprintf(buf+len, BUFMAX-1-len, " %s:%s",
			     addr2str(&s->sins[i].sin_addr),
			     port2str(s->sins[i].sin_port,
				      s->proto, proto_dest));
		    len += strlen(buf+len);
		}
		message(LOG_DEBUG, "%s", buf);
	    }
	    return s;
	}
    }
    return NULL;
}

int lbsopts(int argc, int i, char *argv[]) {
    struct sockaddr_in sins[LB_MAX];
    LBSet *lbs;
    int proto = proto_tcp;
    int nsins = 0;
    i++;
    for ( ; i < argc; i++) {
	if (argv[i][0] == '-' && argv[i][1] == '-') break;
	if (nsins >= LB_MAX) {
	    message(LOG_ERR, "Too many load balancing hosts");
	    exit(1);
	}
	if (!hostPort(argv[i], &sins[nsins], proto)) {
	    message(LOG_ERR, "Illegal load balancing host: %s", argv[i]);
	    exit(1);
	}
	nsins++;
    }
    lbs = malloc(sizeof(LBSet) + sizeof(struct sockaddr_in) * nsins);
    if (lbs) {
	int j;
	lbs->next = lbsets;
	lbs->proto = proto;
	lbs->nsins = nsins;
	for (j=0; j < nsins; j++) lbs->sins[j] = sins[j];
	lbsets = lbs;
    } else {
	message(LOG_ERR, "Out of memory, can't make LB set");
	exit(1);
    }
    return i;
}

/* relay UDP */

void message_origin(Origin *origin) {
    struct sockaddr_in name;
    SOCKET sd;
    Stone *stone;
    int len, i;
    char str[BUFMAX];
    strntime(str, BUFMAX, &origin->clock);
    i = strlen(str);
    if (ValidSocket(origin->sd)) {
	len = sizeof(name);
	if (getsockname(origin->sd, (struct sockaddr*)&name, &len) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (Debug > 3)
		message(LOG_DEBUG, "UDP %d: Can't get socket's name err=%d",
			origin->sd, errno);
	} else {
	    strncpy(&str[i], port2str(name.sin_port, proto_udp, 0), BUFMAX-i);
	    i = strlen(str);
	    if (i < BUFMAX-2) str[i++] = ' ';
	}
    }
    if (i >= BUFMAX) i = BUFMAX-1;
    str[i] = '\0';
    stone = origin->stone;
    if (stone) sd = stone->sd;
    else sd = INVALID_SOCKET;
    message(LOG_INFO, "UDP%3d:%3d %s%s:%s",
	    origin->sd, sd, str,
	    addr2str(&origin->sin.sin_addr),
	    port2str(origin->sin.sin_port, proto_udp, proto_all));
}

/* enlarge packet buffer */
static void enlarge_buf(SOCKET sd) {
    char *buf;
    buf = malloc(pkt_len_max << 1);
    if (buf) {
	char *old = pkt_buf;
	pkt_buf = buf;
	pkt_len_max = (pkt_len_max << 1);
	free(old);
	message(LOG_INFO, "UDP %d: Packet buffer is enlarged: %d bytes",
		sd, pkt_len_max);
    }
}

static int recvUDP(SOCKET sd, struct sockaddr_in *from) {
    struct sockaddr_in sin;
    int len, pkt_len;
    if (!from) from = &sin;
    len = sizeof(*from);
    pkt_len = recvfrom(sd, pkt_buf, pkt_len_max, 0,
		       (struct sockaddr*)from, &len);
    if (Debug > 4) message(LOG_DEBUG, "UDP %d: %d bytes received from %s:%s",
			   sd, pkt_len,
			   addr2str(&from->sin_addr),
			   port2str(from->sin_port, proto_udp, proto_all));
    if (pkt_len > pkt_len_max) {
	message(LOG_NOTICE,
		"UDP %d: recvfrom failed: larger packet (%d bytes) "
		"arrived from %s:%s",
		sd, pkt_len,
		addr2str(&from->sin_addr),
		port2str(from->sin_port, proto_udp, 0));
	enlarge_buf(sd);
	pkt_len = 0;		/* drop */
    }
    return pkt_len;
}   

static int sendUDP(SOCKET sd, struct sockaddr_in *sinp, int len) {
    if (sendto(sd, pkt_buf, len, 0,
	       (struct sockaddr*)sinp, sizeof(*sinp))
	!= len) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR, "UDP %d: sendto failed err=%d: to %s:%s",
		sd, errno,
		addr2str(&sinp->sin_addr),
		port2str(sinp->sin_port, proto_udp, 0));
	return -1;
    }
    if (Debug > 4)
	message(LOG_DEBUG, "UDP %d: %d bytes sent to %s:%s",
		sd, len,
		addr2str(&sinp->sin_addr),
		port2str(sinp->sin_port, proto_udp, 0));
    return len;
}

static Origin *getOrigins(struct in_addr *addr,
			  int port) {	/* network byte order */
    Origin *origin;
    for (origin=origins.next; origin != NULL; origin=origin->next) {
	if (InvalidSocket(origin->sd)) continue;
	if (origin->sin.sin_addr.s_addr == addr->s_addr
	    && origin->sin.sin_port == port) {
	    origin->lock = 1;	/* lock origin */
	    return origin;
	}
    }
    return NULL;
}

void docloseUDP(Origin *origin, int wait) {
    if (Debug > 2) message(LOG_DEBUG, "UDP %d: close", origin->sd);
    if (wait) {
	waitMutex(FdRinMutex);
	waitMutex(FdEinMutex);
    }
    FD_CLR(origin->sd, &rin);
    FD_CLR(origin->sd, &ein);
    if (wait) {
	freeMutex(FdEinMutex);
	freeMutex(FdRinMutex);
    }
    origin->lock = -1;	/* request to close */
}

void asyncOrg(Origin *origin) {
    int len;
    Stone *stone = origin->stone;
    ASYNC_BEGIN;
    if (Debug > 8) message(LOG_DEBUG, "asyncOrg...");
    len = recvUDP(origin->sd, NULL);
    if (Debug > 4) {
	SOCKET sd;
	if (stone) sd = stone->sd;
	else sd = INVALID_SOCKET;
	message(LOG_DEBUG, "UDP %d: send %d bytes to %d",
		origin->sd, len, origin->stone->sd);
    }
    if (len > 0 && stone) sendUDP(stone->sd, &origin->sin, len);
    time(&origin->clock);
    if (len > 0) {
	waitMutex(FdRinMutex);
	waitMutex(FdEinMutex);
	FdSet(origin->sd, &ein);
	FdSet(origin->sd, &rin);
	freeMutex(FdEinMutex);
	freeMutex(FdRinMutex);
    } else if (len < 0) {
	docloseUDP(origin, 1);	/* wait mutex */
    }
    ASYNC_END;
}

int scanUDP(fd_set *rop, fd_set *eop) {
#ifdef PTHREAD
    pthread_t thread;
    int err;
#endif
    Origin *origin, *prev;
    int n = 0;
    prev = &origins;
    for (origin=origins.next; origin != NULL;
	 prev=origin, origin=origin->next) {
	int isset;
	if (InvalidSocket(origin->sd) || origin->lock > 0) {
	    Origin *old = origin;
	    waitMutex(OrigMutex);
	    if (prev->next == origin) {
		origin = prev;
		origin->next = old->next;	/* remove `old' from list */
		if (InvalidSocket(old->sd)) {
		    free(old);
		} else {
		    old->lock = 0;
		    old->next = origins.next;	/* insert old on top */
		    origins.next = old;
		}
	    }
	    freeMutex(OrigMutex);
	    goto next;
	}
	if (origin->lock < 0) {
	    waitMutex(FdRinMutex);
	    waitMutex(FdEinMutex);
	    isset = (FD_ISSET(origin->sd, &rin) ||
		     FD_ISSET(origin->sd, &ein));
	    if (isset) {
		FD_CLR(origin->sd, &rin);
		FD_CLR(origin->sd, &ein);
	    }
	    freeMutex(FdEinMutex);
	    freeMutex(FdRinMutex);
	    if (!isset) {
		closesocket(origin->sd);
		origin->sd = INVALID_SOCKET;
	    }
	    goto next;
	}
	waitMutex(FdEinMutex);
	isset = (FD_ISSET(origin->sd, eop) && FD_ISSET(origin->sd, &ein));
	if (isset) FD_CLR(origin->sd, &ein);
	freeMutex(FdEinMutex);
	if (isset) {
	    message(LOG_ERR, "UDP %d: exception", origin->sd);
	    message_origin(origin);
	    docloseUDP(origin, 1);	/* wait mutex */
	    goto next;
	}
	waitMutex(FdRinMutex);
	isset = (FD_ISSET(origin->sd, rop) && FD_ISSET(origin->sd, &rin));
	if (isset) FD_CLR(origin->sd, &rin);
	freeMutex(FdRinMutex);
	if (isset) {
	    ASYNC(asyncOrg, origin);
	    goto next;
	}
	if (++n >= OriginMax) docloseUDP(origin, 1);	/* wait mutex */
      next:
	;
    }
    return 1;
}

/* *stonep repeat UDP connection */
Origin *doUDP(Stone *stonep) {
    struct sockaddr_in from;
    SOCKET dsd;
    int len;
    Origin *origin;
    len = recvUDP(stonep->sd, &from);
    waitMutex(FdRinMutex);
    FdSet(stonep->sd, &rin);
    freeMutex(FdRinMutex);
    if (len <= 0) return NULL;	/* drop */
    if (!checkXhost(stonep, &from.sin_addr, NULL)) {
	message(LOG_WARNING, "stone %d: recv UDP denied: from %s:%s",
		stonep->sd,
		addr2str(&from.sin_addr),
		port2str(from.sin_port, stonep->proto, proto_src));
	return NULL;
    }
    origin = getOrigins(&from.sin_addr, from.sin_port);
    if (origin) {
	dsd = origin->sd;
	if (Debug > 5)
	    message(LOG_DEBUG, "UDP %d: reuse %d to send", stonep->sd, dsd);
    } else if (InvalidSocket(dsd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR, "UDP: can't create datagram socket err=%d.",
		errno);
	return NULL;
    }
    if (Debug > 4)
	message(LOG_DEBUG, "UDP %d: send %d bytes to %d",
		stonep->sd, len, dsd);
    if (sendUDP(dsd, stonep->sins, len) <= 0) {
	if (origin) {
	    docloseUDP(origin, 1);	/* wait mutex */
	} else {
	    closesocket(dsd);
	}
	return NULL;
    }
    if (!origin) {
	origin = malloc(sizeof(Origin));
	if (!origin) {
	    message(LOG_ERR, "UDP %d: Out of memory, closing socket", dsd);
	    return NULL;
	}
	origin->sd = dsd;
	origin->stone = stonep;
	bcopy(&from, &origin->sin, sizeof(origin->sin));
	origin->lock = 0;
	waitMutex(OrigMutex);
	origin->next = origins.next;	/* insert origin */
	origins.next = origin;
	freeMutex(OrigMutex);
    }
    return origin;
}

void asyncUDP(Stone *stone) {
    Origin *origin;
    ASYNC_BEGIN;
    if (Debug > 8) message(LOG_DEBUG, "asyncUDP...");
    origin = doUDP(stone);
    if (origin) {
	time(&origin->clock);
	waitMutex(FdRinMutex);
	waitMutex(FdEinMutex);
	FdSet(origin->sd, &rin);
	FdSet(origin->sd, &ein);
	freeMutex(FdEinMutex);
	freeMutex(FdRinMutex);
    }
    ASYNC_END;
}

/* relay TCP */

void message_pair(Pair *pair) {
    struct sockaddr_in name;
    SOCKET sd, psd;
    Pair *p;
    int len, i;
    char str[BUFMAX];
    strntime(str, BUFMAX, &pair->clock);
    i = strlen(str);
    sd = pair->sd;
    if (ValidSocket(sd)) {
	len = sizeof(name);
	if (getsockname(sd, (struct sockaddr*)&name, &len) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (Debug > 3)
		message(LOG_DEBUG, "TCP %d: Can't get socket's name err=%d",
			sd, errno);
	} else {
	    strncpy(&str[i], port2str(name.sin_port, pair->proto, 0),
		    BUFMAX-i);
	    i = strlen(str);
	    if (i < BUFMAX-2) str[i++] = ' ';
	}
	len = sizeof(name);
	if (getpeername(sd, (struct sockaddr*)&name, &len) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (Debug > 3)
		message(LOG_DEBUG, "TCP %d: Can't get peer's name err=%d",
			sd, errno);
	} else {
	    strncpy(&str[i], addr2str(&name.sin_addr), BUFMAX-i);
	    i = strlen(str);
	    if (i < BUFMAX-2) str[i++] = ':';
	    strncpy(&str[i], port2str(name.sin_port, pair->proto, proto_all),
		    BUFMAX-i);
	    i = strlen(str);
	}
    }
    if (i >= BUFMAX) i = BUFMAX-1;
    str[i] = '\0';
    p = pair->pair;
    if (p) psd = p->sd;
    else psd = INVALID_SOCKET;
    if (p && p->p) {
	message(LOG_INFO, "TCP%3d:%3d %08x %d %s %s tx:%d rx:%d",
		sd, psd, pair->proto, pair->count, str, p->p,
		pair->tx, pair->rx);
    } else {
	message(LOG_INFO, "TCP%3d:%3d %08x %d %s tx:%d rx:%d",
		sd, psd, pair->proto, pair->count, str,
		pair->tx, pair->rx);
    }
}

#ifdef USE_SSL
static void printSSLinfo(SSL *ssl) {
    X509 *peer;
    char *p = (char *)SSL_get_cipher(ssl);
    if (p == NULL) p = "<NULL>";
    message(LOG_INFO, "[SSL cipher=%s]", p);
    peer = SSL_get_peer_certificate(ssl);
    if (peer) {
	ASN1_INTEGER *n = X509_get_serialNumber(peer);
	if (n) message(LOG_INFO, "[SSL serial=%lx]", ASN1_INTEGER_get(n));
	p = X509_NAME_oneline(X509_get_subject_name(peer), NULL, 0);
	if (p) message(LOG_INFO, "[SSL subject=%s]", p);
	free(p);
	p = X509_NAME_oneline(X509_get_issuer_name(peer), NULL, 0);
	if (p) message(LOG_INFO, "[SSL issuer=%s]", p);
	free(p);
	X509_free(peer);
    }
}

void rmMatch(Pair *pair) {
    if (pair->match) {
	int i;
	char **match = pair->match;
	pair->match = NULL;
	for (i=0; i <= NMATCH_MAX; i++) {
	    if (match[i]) free(match[i]);
	}
	free(match);
    }
}

int trySSL_accept(Pair *pair) {
    int ret;
    unsigned long err;
    if (pair->proto & proto_ssl_intr) {
	if (SSL_want_nothing(pair->ssl)) goto finished;
    }
    ret = SSL_accept(pair->ssl);
    if (Debug > 4)
	message(LOG_DEBUG, "TCP %d: SSL_accept ret=%d, state=%x, "
		"finished=%x, in_init=%x/%x",
		pair->sd, ret,
		SSL_state(pair->ssl),
		SSL_is_init_finished(pair->ssl),
		SSL_in_init(pair->ssl),
		SSL_in_accept_init(pair->ssl));
    if (ret < 0) {
	err = SSL_get_error(pair->ssl, ret);
	if (err== SSL_ERROR_NONE
		|| err == SSL_ERROR_WANT_READ
		|| err == SSL_ERROR_WANT_WRITE) {
	    if (Debug > 4)
		message(LOG_DEBUG, "TCP %d: SSL_accept interrupted WANT=%d",
			pair->sd, err);
	    pair->proto |= proto_ssl_intr;
	    return 0;	/* EINTR */
	} else if (err) {
	    SSL *ssl = pair->ssl;
	    pair->ssl = NULL;
	    message(LOG_ERR, "TCP %d: SSL_accept error err=%d", pair->sd, err);
	    if (pair->stone->ssl_server->verbose)
		message(LOG_INFO, "TCP %d: %s",
			pair->sd, ERR_error_string(err, NULL));
	    message_pair(pair);
	    SSL_free(ssl);
	    rmMatch(pair);
	    return -1;
	}
    }
    if (SSL_in_accept_init(pair->ssl)) {
	SSL *ssl = pair->ssl;
	pair->ssl = NULL;
	if (pair->stone->ssl_server->verbose) {
	    message(LOG_NOTICE, "TCP %d: SSL_accept unexpected EOF", pair->sd);
	    message_pair(pair);
	}
	SSL_free(ssl);
	rmMatch(pair);
	return -1;	/* unexpected EOF */
    }
 finished:
    if (pair->stone->ssl_server->verbose) printSSLinfo(pair->ssl);
    pair->proto &= ~proto_ssl_intr;
    return 1;
}

int doSSL_accept(Pair *pair) {
    int ret;
    pair->ssl = SSL_new(pair->stone->ssl_server->ctx);
    SSL_set_ex_data(pair->ssl, PairIndex, pair);
    SSL_set_fd(pair->ssl, pair->sd);
    ret = trySSL_accept(pair);
    return ret;
}

int doSSL_connect(Pair *pair) {
    int err, ret;
    if (!(pair->proto & proto_ssl_intr)) {
	pair->ssl = SSL_new(pair->stone->ssl_client->ctx);
	SSL_set_ex_data(pair->ssl, PairIndex, pair);
	SSL_set_fd(pair->ssl, pair->sd);
    } else {
	if (SSL_want_nothing(pair->ssl)) goto finished;
    }
    ret = SSL_connect(pair->ssl);
    if (ret < 0) {
	err = SSL_get_error(pair->ssl, ret);
	if (err== SSL_ERROR_NONE
		|| err == SSL_ERROR_WANT_READ
		|| err == SSL_ERROR_WANT_WRITE) {
	    if (Debug > 4)
		message(LOG_DEBUG, "TCP %d: SSL_connect interrupted WANT=%d",
			pair->sd, err);
	    pair->proto |= proto_ssl_intr;
	    return 0;	/* EINTR */
	} else if (err) {
	    SSL *ssl = pair->ssl;
	    pair->ssl = NULL;
	    message(LOG_ERR, "TCP %d: SSL_connect error err=%d",
		    pair->sd, err);
	    if (pair->stone->ssl_client->verbose)
		message(LOG_INFO, "TCP %d: %s",
			pair->sd, ERR_error_string(err, NULL));
	    message_pair(pair);
	    SSL_free(ssl);
	    rmMatch(pair);
	    return -1;
	}
    }
 finished:
    if (pair->stone->ssl_client->verbose) printSSLinfo(pair->ssl);
    pair->proto &= ~proto_ssl_intr;
    if (Debug > 3) {
	message(LOG_DEBUG, "TCP %d: SSL_connect succeeded", pair->sd);
	message_pair(pair);
    }
    return 1;
}

int SSL_smart_shutdown(SSL *ssl) {
    int ret = 0;
    int i;
    for (i=0; i < 4; i++) {
	ret = SSL_shutdown(ssl);
	if (ret) break;
    }
    return ret;
}
#endif	/* USE_SSL */

void freePair(Pair *pair) {
    SOCKET sd;
#ifdef USE_SSL
    SSL *ssl;
#endif
    if (!pair) return;
    sd = pair->sd;
    pair->sd = INVALID_SOCKET;
    if (ValidSocket(sd)) closesocket(sd);
#ifdef USE_SSL
    ssl = pair->ssl;
    pair->ssl = NULL;
    if (ssl) SSL_free(ssl);
    rmMatch(pair);
#endif
    free(pair);
}

void message_time_log(Pair *pair) {
    TimeLog *log = pair->log;
    if (log && log->clock) {
	struct tm *t = localtime(&log->clock);
	time_t now;
	time(&now);
	message(log->pri, "%02d:%02d:%02d %d %s",
		t->tm_hour, t->tm_min, t->tm_sec,
		(int)(now - log->clock), log->str);
	log->clock = 0;
    }
}

int doshutdown(Pair *pair, int how) {
    int ret = 0;
    int err;
    if (!pair || (pair->proto & proto_close)
	|| InvalidSocket(pair->sd) || !(pair->proto & proto_connect))
	return -1;	/* no connection */
    if (pair->proto & proto_shutdown)
	return 0;	/* no need to shutdown */
    pair->proto |= proto_shutdown;
    if (Debug > 2) message(LOG_DEBUG, "TCP %d: shutdown %d", pair->sd, how);
#ifdef USE_SSL
    if (pair->ssl) {
	ret = SSL_smart_shutdown(pair->ssl);
	if (ret < 0) {
	    err = SSL_get_error(pair->ssl, ret);
	    message(LOG_ERR, "TCP %d: SSL_shutdown err=%d",
		    pair->sd, err);
	}
    }
#endif
    err = shutdown(pair->sd, how);
    if (err < 0) {
	ret = err;
	message(LOG_ERR, "TCP %d: shutdown %d err=%d", pair->sd, how, errno);
    }
    if (pair->proto & proto_eof) {
	pair->proto |= proto_close;
	if (Debug > 2)
	    message(LOG_DEBUG, "TCP %d: EOF & shutdown, so closing... "
		    "tx:%d rx:%d", pair->sd, pair->tx, pair->rx);
    }
    if (ret < 0) {
	pair->proto |= (proto_eof | proto_close);
	if (Debug > 2)
	    message(LOG_DEBUG, "TCP %d: fail to shutdown, so closing... "
		    "tx:%d rx:%d", pair->sd, pair->tx, pair->rx);
    }
    return ret;
}

void doclose(Pair *pair) {	/* close pair */
    Pair *p = pair->pair;
    SOCKET sd = pair->sd;
    message_time_log(pair);
    if (!(pair->proto & proto_close)) {		/* request to close */
	pair->proto |= (proto_eof | proto_shutdown | proto_close);
	if (ValidSocket(sd))
	    if (Debug > 2) message(LOG_DEBUG, "TCP %d: closing... "
				   "tx:%d rx:%d", sd, pair->tx, pair->rx);
    }
    doshutdown(p, 2);
}

/* pair connect to destination */
int doconnect(Pair *pair, struct sockaddr_in *sinp) {	/* connect to */
    int ret;
    Pair *p = pair->pair;
    if (!(pair->proto & proto_ssl_intr)) {
	if (Debug > 2)
	    message(LOG_DEBUG, "TCP %d: connecting to TCP %d %s:%s ...",
		    p->sd, pair->sd,
		    addr2str(&sinp->sin_addr),
		    port2str(sinp->sin_port, pair->proto, proto_all));
	ret = connect(pair->sd, (struct sockaddr*)sinp, sizeof(*sinp));
#ifndef WINDOWS
	fcntl(pair->sd, F_SETFL, O_NONBLOCK);
#endif
	if (pair->proto & proto_close) return -1;
	if (ret < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (errno == EINTR) {
		if (Debug > 4)
		    message(LOG_DEBUG, "TCP %d: connect interrupted",
			    pair->sd);
		return 0;
	    } else if (errno == EISCONN || errno == EADDRINUSE
#ifdef EALREADY
			|| errno == EALREADY
#endif
		) {
		if (Debug > 4) {	/* SunOS's bug ? */
		    message(LOG_DEBUG, "TCP %d: connect bug err=%d",
			    pair->sd, errno);
		    message_pair(pair);
		}
	    } else {
		message(LOG_ERR, "TCP %d: can't connect err=%d: to %s:%s",
			pair->sd,
			errno,
			addr2str(&sinp->sin_addr),
			port2str(sinp->sin_port, pair->proto, proto_all));
		return -1;
	    }
	}
	pair->proto |= proto_connect;	/* pair & dst is connected */
	if (Debug > 2)
	    message(LOG_DEBUG, "TCP %d: established to %d",
		    p->sd, pair->sd);
	time(&lastEstablished);
    }
    ret = 1;
#ifdef USE_SSL
    if (pair->stone->proto & proto_ssl_d) ret = doSSL_connect(pair);
#endif
    return ret;
}

void message_conn(Conn *conn) {
    SOCKET sd = INVALID_SOCKET;
    Pair *p1, *p2;
    int proto = 0;
    int i = 0;
    char str[BUFMAX];
    p1 = conn->pair;
    if (p1) {
	p2 = p1->pair;
	strntime(str, BUFMAX, &p1->clock);
	i = strlen(str);
	proto = p1->proto;
	if (p2) sd = p2->sd;
    }
    strncpy(&str[i], addr2str(&conn->sin.sin_addr), BUFMAX-i);
    i = strlen(str);
    if (i < BUFMAX-2) str[i++] = ':';
    strncpy(&str[i], port2str(conn->sin.sin_port, proto, proto_all), BUFMAX-i);
    i = strlen(str);
    if (i >= BUFMAX) i = BUFMAX-1;
    str[i] = '\0';
    message(LOG_INFO, "Conn %d: %08x %s", sd, proto, str);
}

int reqconn(Pair *pair,		/* request pair to connect to destination */
	    fd_set *rinp,
	    struct sockaddr_in *sinp) {	/* connect to */
    Conn *conn;
    Pair *p = pair->pair;
    if ((pair->proto & proto_command) == command_proxy
	|| (pair->proto & proto_command) == command_health) {
	if (p && !(p->proto & (proto_eof | proto_close))) {
	    if (rinp) {
		FdSet(p->sd, rinp);	/* must read request header */
	    } else {
		waitMutex(FdRinMutex);
		FdSet(p->sd, &rin);	/* must read request header */
		freeMutex(FdRinMutex);
	    }
	}
	return 0;
    }
    conn = malloc(sizeof(Conn));
    if (!conn) {
	message(LOG_ERR, "TCP %d: out of memory", (p ? p->sd : -1));
	return -1;
    }
    time(&pair->clock);
    p->clock = pair->clock;
    pair->count += REF_UNIT;	/* request to connect */
    conn->pair = pair;
    conn->sin = *sinp;
    conn->lock = 0;
    waitMutex(ConnMutex);
    conn->next = conns.next;
    conns.next = conn;
    freeMutex(ConnMutex);
    return 0;
}

void asyncConn(Conn *conn) {
    int ret;
    Pair *p1, *p2;
    Backup *backup = NULL;
    time_t clock;
    ASYNC_BEGIN;
    p1 = conn->pair;
    if (p1 == NULL) goto finish;
    p2 = p1->pair;
    if (p2 == NULL) goto finish;
    time(&clock);
    if (Debug > 8) message(LOG_DEBUG, "asyncConn...");
    if (p1->stone->backups) {
	int ofs = p1->clock % p1->stone->nsins;	/* round robin */
	conn->sin = p1->stone->sins[ofs];
	backup = p1->stone->backups[ofs];
    }
#ifdef USE_SSL
    if (p2->proto & proto_ssl_intr)
	ret = trySSL_accept(p2);	/* accept not completed */
    else ret = 1;
    if (ret > 0) {
	if (p2->match && p2->stone->ssl_server) {
	    int lbparm = p2->stone->ssl_server->lbparm;
	    int lbmod = p2->stone->ssl_server->lbmod;
	    int ofs = 0;
	    unsigned char *s;
	    if (0 <= lbparm && lbparm <= 9) s = p2->match[lbparm];
	    else s = p2->match[1];
	    if (lbmod) {
		while (*s) {
		    ofs <<= 6;
		    ofs += (*s & 0x3f);
		    s++;
		}
		ofs %= lbmod;
		if (Debug > 2)
		    message(LOG_DEBUG, "TCP %d: pair %d lb%d=%d",
			    p1->sd, p2->sd, lbparm, ofs);
		conn->sin = p1->stone->sins[ofs];
		if (p1->stone->backups) {
		    backup = p1->stone->backups[ofs];
		}
	    }
	}
#endif
	if (backup) {
	    backup->used = 2;
	    if (backup->bn) conn->sin = backup->backup;
	}
	ret = doconnect(p1, &conn->sin);
#ifdef USE_SSL
    }
#endif
    if (ret == 0) {	/* EINTR */
	if (clock - p1->clock < CONN_TIMEOUT) {
	    conn->lock = 0;	/* unlock conn */
	    ASYNC_END;
	    return;
	}
#ifdef USE_SSL
	if (p2->proto & proto_ssl_intr)
	    message(LOG_ERR, "TCP %d: SSL_accept timeout", p2->sd);
	else
#endif
	message(LOG_ERR, "TCP %d: connect timeout to %s:%s",
		p2->sd,
		addr2str(&conn->sin.sin_addr),
		port2str(conn->sin.sin_port, p1->proto, proto_all));
	ret = -1;
    }
    if (ret < 0		/* fail to connect */
	|| (p1->proto & proto_close)
	|| (p2->proto & proto_close)) {	
	doclose(p2);
	doclose(p1);
    } else {	/* success to connect */
	int set1 = 0;
	int set2 = 0;
	waitMutex(FdRinMutex);
	waitMutex(FdWinMutex);
	if (p1->len > 0) {
	    if (Debug > 8)
		message(LOG_DEBUG, "TCP %d: waiting %d bytes to write",
			p1->sd, p1->len);
	    if (!(p1->proto & proto_shutdown)) {
		FdSet(p1->sd, &win);
		set1 = 1;
	    }
	} else {
	    if (Debug > 8)
		message(LOG_DEBUG, "TCP %d: request to read", p2->sd);
	    if (!(p2->proto & proto_eof)) {
		FdSet(p2->sd, &rin);
		set2 = 1;
	    }
	}
	if (!(p2->proto & proto_ohttp_s)) {
	    if (p2->len > 0) {
		if (Debug > 8)
		    message(LOG_DEBUG, "TCP %d: waiting %d bytes to write",
			    p2->sd, p2->len);
		if (!(p2->proto & proto_shutdown)) {
		    FdSet(p2->sd, &win);
		    set2 = 1;
		}
	    } else {
		if (Debug > 8)
		    message(LOG_DEBUG, "TCP %d: request to read", p1->sd);
		if (!(p1->proto & proto_eof)) {
		    FdSet(p1->sd, &rin);
		    set1 = 1;
		}
	    }
	}
	freeMutex(FdWinMutex);
	freeMutex(FdRinMutex);
	waitMutex(FdEinMutex);
	if (set2) FdSet(p2->sd, &ein);
	if (set1) FdSet(p1->sd, &ein);
	freeMutex(FdEinMutex);
    }
 finish:
    if (p1) p1->count -= REF_UNIT;	/* no more request to connect */
    conn->pair = NULL;
    conn->lock = -1;
    ASYNC_END;
}

/* scan conn request */
int scanConns(void) {
#ifdef PTHREAD
    pthread_t thread;
    int err;
#endif
    Conn *conn, *pconn;
    Pair *p1, *p2;
    time_t now;
    time(&now);
    pconn = &conns;
    for (conn=conns.next; conn != NULL; conn=conn->next) {
	p1 = conn->pair;
	if (p1) p2 = p1->pair;
	if (p1 && !(p1->proto & proto_close) &&
	    p2 && !(p2->proto & proto_close)) {
	    if (conn->lock == 0) {
		conn->lock = 1;		/* lock conn */
		if (Debug > 4) message_conn(conn);
		ASYNC(asyncConn, conn);
	    }
	} else {
	    waitMutex(ConnMutex);
	    if (pconn->next == conn) {
		pconn->next = conn->next;	/* remove conn */
		free(conn);
		conn = pconn;
	    }
	    freeMutex(ConnMutex);
	}
	pconn = conn;
    }
    if (backups && now - lastScanBackups >= MinInterval) {
	lastScanBackups = now;
	ASYNC(asyncScanBackups, NULL);
    }
    return 1;
}

int getident(char *str, struct sockaddr_in *sinp, int cport) {
    SOCKET sd;
    struct sockaddr_in sin = *sinp;
    int sport = ntohs(sinp->sin_port);
    char buf[BUFMAX];
    char c;
    int len;
    int ret;
    if (str) {
	str[0] = '\0';
    }
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (InvalidSocket(sd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (Debug > 0)
	    message(LOG_DEBUG, "ident: can't create socket err=%d.",
		    sd, errno);
	return 0;
    }
    sin.sin_port = htons(113);	/* ident protocol */
    if (connect(sd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (Debug > 0)
	    message(LOG_DEBUG, "ident: can't connect to %s, err=%d",
		    addr2str(&sin.sin_addr), errno);
	closesocket(sd);
	return 0;
    }
    snprintf(buf, BUFMAX-1, "%d, %d%c%c", sport, cport, '\r', '\n');
    len = strlen(buf);
    ret = send(sd, buf, len, 0);
    if (ret != len) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (Debug > 0)
	    message(LOG_DEBUG,
		    "ident: can't send  to %s, ret=%d, err=%d, buf=%s",
		    addr2str(&sin.sin_addr), ret, errno, buf);
	closesocket(sd);
	return 0;
    }
    ret = recv(sd, buf, BUFMAX-1, 0);
    if (ret <= 0) {
	if (Debug > 0)
	    message(LOG_DEBUG,
		    "ident: can't read from %s, ret=%d",
		    addr2str(&sin.sin_addr), ret);
	closesocket(sd);
	return 0;
    }
    do {
	ret--;
	c = buf[ret];
    } while (ret > 0 && (c == '\r' || c == '\n'));
    ret++;
    buf[ret] = '\0';
    if (Debug > 2)
	message(LOG_DEBUG, "ident: sent %s:%d, %d got %s",
		addr2str(&sin.sin_addr), sport, cport, buf);
    if (str) {
	char *p;
	p = rindex(buf, ':');
	if (p) {
	    int i;
	    do {
		p++;
	    } while (*p == ' ');
	    for (i=0; i < STRMAX-1 && *p; i++) str[i] = *p++;
	    str[i] = '\0';
	}
    }
    closesocket(sd);
    return 1;
}

/* *stonep accept connection */
Pair *doaccept(Stone *stonep) {
    struct sockaddr_in from;
    SOCKET nsd;
    int len;
    Pair *pair1, *pair2;
    int prevXferBufMax = XferBufMax;
    int ret;
    char ident[STRMAX];
    char fromstr[STRMAX*2];
    nsd = INVALID_SOCKET;
    pair1 = pair2 = NULL;
    len = sizeof(from);
    nsd = accept(stonep->sd, (struct sockaddr*)&from, &len);
#ifndef WINDOWS
    fcntl(nsd, F_SETFL, O_NONBLOCK);
#endif
    waitMutex(FdRinMutex);
    FdSet(stonep->sd, &rin);
    freeMutex(FdRinMutex);
    if (InvalidSocket(nsd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (errno == EINTR) {
	    if (Debug > 4)
		message(LOG_DEBUG, "stone %d: accept interrupted", stonep->sd);
	    return NULL;
	} else if (errno == EAGAIN) {
	    if (Debug > 4)
		message(LOG_DEBUG, "stone %d: accept no connection",
			stonep->sd);
	    return NULL;
	}
#ifndef NO_FORK
	else if (errno == EBADF && Debug < 5) {
	    return NULL;
	}
#endif
	message(LOG_ERR, "stone %d: accept error err=%d.", stonep->sd, errno);
	return NULL;
    }
    if ((stonep->proto & proto_ident)
	&& getident(ident, &from, stonep->port)) {
	snprintf(fromstr, STRMAX*2-1, "%s@%s",
		 ident, addr2str(&from.sin_addr));
    } else {
	snprintf(fromstr, STRMAX*2-1, "%s", addr2str(&from.sin_addr));
	ident[0] = '\0';
    }
    if (!checkXhost(stonep, &from.sin_addr, ident)) {
	message(LOG_WARNING, "stone %d: access denied: from %s:%s",
		stonep->sd, fromstr,
		port2str(from.sin_port, stonep->proto, proto_src));
	shutdown(nsd, 2);
	closesocket(nsd);
	return NULL;
    }
    if (AccFp) {
	char buf[BUFMAX], str[STRMAX];
	time_t clock;
	time(&clock);
	fprintf(AccFp, "%s%d[%d] %s[%s]%d\n",
		strntime(buf, BUFMAX, &clock),
		stonep->port, stonep->sd, fromstr,
		addr2ip(&from.sin_addr, str),
		ntohs(from.sin_port));
    }
    if (Debug > 1) {
	message(LOG_DEBUG, "stone %d: accepted TCP %d from %s:%s",
		stonep->sd, nsd, fromstr,
		port2str(from.sin_port, stonep->proto, proto_src));
    }
    do {
	pair1 = malloc(sizeof(Pair) + XferBufMax - BUFMAX);
    } while (!pair1 && XferBufMax > BUFMAX && (XferBufMax /= 2));
    if (pair1) pair1->bufmax = XferBufMax;
    do {
	pair2 = malloc(sizeof(Pair) + XferBufMax - BUFMAX);
    } while (!pair2 && XferBufMax > BUFMAX && (XferBufMax /= 2));
    if (pair2) pair2->bufmax = XferBufMax;
#ifdef ENLARGE
    if (XferBufMax < prevXferBufMax) {
	message(LOG_NOTICE, "stone %d TCP %d: XferBufMax becomes %d byte",
		stonep->sd, nsd, XferBufMax);
    }
#endif
    if (!pair1 || !pair2) {
	message(LOG_ERR, "stone %d: out of memory, closing TCP %d",
		stonep->sd, nsd);
	closesocket(nsd);
	if (pair1) free(pair1);
	if (pair2) free(pair2);
	return NULL;
    }
    pair1->stone = pair2->stone = stonep;
    pair1->sd = nsd;
    pair2->sd = INVALID_SOCKET;
    pair1->proto = ((stonep->proto & proto_src) |
		    proto_first_r | proto_first_w | proto_source |
		    proto_connect);	/* src & pair1 is connected */
    pair2->proto = ((stonep->proto & proto_dest) |
		    proto_first_r | proto_first_w);
    pair1->count = pair2->count = 0;
    pair1->start = pair2->start = 0;
    pair1->len = pair2->len = 0;
    pair1->p = pair2->p = NULL;
    pair1->log = pair2->log = NULL;
    pair1->tx = pair2->tx = 0;
    pair1->rx = pair2->rx = 0;
    time(&pair1->clock);
    time(&pair2->clock);
    pair1->timeout = pair2->timeout = stonep->timeout;
    pair1->pair = pair2->pair = NULL;
#ifdef USE_SSL
    pair1->ssl = pair2->ssl = NULL;
    pair1->match = pair2->match = NULL;
    if (stonep->proto & proto_ssl_s) {
	ret = doSSL_accept(pair1);
	if (ret < 0) goto error;
    }
#endif
    pair2->sd = socket(AF_INET, SOCK_STREAM, 0);
    if (InvalidSocket(pair2->sd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR, "TCP %d: can't create socket err=%d.",
		pair1->sd, errno);
      error:
	freePair(pair1);
	freePair(pair2);
	return NULL;
    }
    pair2->pair = pair1;
    pair1->pair = pair2;
    return pair1;
}

int strnPeerAddr(char *buf, int limit, SOCKET sd, int isport) {
    int i = 0;
    struct sockaddr_in name;
    int len;
    char str[STRMAX];
    len = sizeof(name);
    if (getpeername(sd, (struct sockaddr*)&name, &len) < 0) {
	if (isport) {
	    strcpy(str, "0.0.0.0:0");
	} else {
	    strcpy(str, "0.0.0.0");
	}
    } else {
	addr2ip(&name.sin_addr, str);
	if (isport) {
	    len = strlen(str);
	    snprintf(str+len, STRMAX-1-len, ":%d",
		     ntohs((unsigned short)name.sin_port));
	}
    }
    len = strlen(str);
    if (len > limit) len = limit;
    strncpy(buf, str, len);
    return len;
}

int strnparse(char *buf, int limit, char *p, Pair *pair) {
    int i = 0;
    char c;
    while (i < limit && (c = *p++)) {
	if (c == '\\') {
	    c = *p++;
#ifdef USE_SSL
	    if ('0' <= c && c <= '9') {
		if (pair->match) {
		    char **match = pair->match;
		    c -= '0';
		    if (match[c]) {
			int len = strlen(match[c]);
			if (len >= limit - i) len = limit - i;
			strncpy(buf+i, match[c], len);
			i += len;
		    }
		}
		continue;
	    }
#endif
	    switch(c) {
	    case 'n':  c = '\n';  break;
	    case 'r':  c = '\r';  break;
	    case 't':  c = '\t';  break;
	    case 'a':
		i += strnPeerAddr(buf+i, limit-i, pair->sd, 0);
		continue;
	    case 'A':
		i += strnPeerAddr(buf+i, limit-i, pair->sd, 1);
		continue;
	    case '\0':
		c = '\\';
		p--;
	    }
	}
	buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

void asyncAccept(Stone *stone) {
    Pair *p1, *p2;
    ASYNC_BEGIN;
    if (Debug > 8) message(LOG_DEBUG, "asyncAccept...");
    p1 = doaccept(stone);
    if (p1 == NULL) {
	ASYNC_END;
	return;
    }
    p2 = p1->pair;
    p1->next = p2;	/* link pair each other */
    p2->prev = p1;
    if (p2->proto & proto_ohttp_d) {
	int i = strnparse(p2->buf, p2->bufmax - 5, stone->p, p1);
	p2->buf[i++] = '\r';
	p2->buf[i++] = '\n';
	p2->buf[i++] = '\r';
	p2->buf[i++] = '\n';
	p2->len = i;
    }
    if (reqconn(p2, NULL, &stone->sins[p1->clock % stone->nsins]) < 0) {
	freePair(p2);
	freePair(p1);
	ASYNC_END;
	return;
    }
    waitMutex(PairMutex);
    p2->next = pairs.next;	/* insert pair */
    if (pairs.next != NULL) pairs.next->prev = p2;
    p1->prev = &pairs;
    pairs.next = p1;
    freeMutex(PairMutex);
    if (Debug > 4) {
	message(LOG_DEBUG, "TCP %d: pair %d inserted", p1->sd, p2->sd);
	message_pair(p1);
    }
    ASYNC_END;
}

int scanClose(void) {	/* scan close request */
    Pair *p1, *p2, *t;
    p1 = trash;
    trash = NULL;
    while (p1 != NULL) {
	p2 = p1;
	p1 = p1->next;
	if (p2->p) {
	    char *p = p2->p;
	    p2->p = NULL;
	    free(p);
	}
	if (p2->log) {
	    TimeLog *log = p2->log;
	    p2->log = NULL;
	    free(log);
	}
	freePair(p2);
    }
    p1 = pairs.next;
    while (p1 != NULL) {
	p2 = p1;
	p1 = p1->next;
	if (InvalidSocket(p2->sd)) {
	    Pair *p;
	    waitMutex(PairMutex);
	    p = p2->prev;
	    if (p) p->next = p1;	/* remove `p2' from list */
	    if (p1) p1->prev = p;
	    p = p2->pair;
	    if (p) {
		p->pair = NULL;
		doclose(p);
	    }
	    freeMutex(PairMutex);
	    p2->next = trash;		/* push `p2' to trash */
	    trash = p2;
	} else if (p2->proto & proto_close) {
	    if (p2->count > 0) {
		p2->count--;
	    } else {
		waitMutex(FdRinMutex);
		waitMutex(FdWinMutex);
		waitMutex(FdEinMutex);
		if (!FD_ISSET(p2->sd, &rin) &&
		    !FD_ISSET(p2->sd, &win) &&
		    !FD_ISSET(p2->sd, &ein)) {
		    SOCKET sd;
#ifdef USE_SSL
		    SSL *ssl;
#endif
		    sd = p2->sd;
		    p2->sd = INVALID_SOCKET;
		    if (ValidSocket(sd)) closesocket(sd);
		    if (Debug > 3)
			message(LOG_DEBUG, "TCP %d: closesocket", sd);
#ifdef USE_SSL
		    ssl = p2->ssl;
		    p2->ssl = NULL;
		    if (ssl) SSL_free(ssl);
		    rmMatch(p2);
#endif
		} else {
		    FD_CLR(p2->sd, &rin);
		    FD_CLR(p2->sd, &win);
		    FD_CLR(p2->sd, &ein);
		}
		freeMutex(FdEinMutex);
		freeMutex(FdWinMutex);
		freeMutex(FdRinMutex);
	    }
	}
    }
    return 1;
}

void message_buf(Pair *pair, int len, char *str) {	/* dump for debug */
    int i, j, k, l;
    char buf[BUFMAX];
    Pair *p = pair->pair;
    if (p == NULL) return;
    k = 0;
    for (i=pair->start; i < pair->start+len; i += j) {
	l = 0;
	buf[l++] = ' ';
	for (j=0; k <= j/10 && i+j < pair->start+len && l < BUFMAX-10;
	     j++) {
	    if (' ' <= pair->buf[i+j]
		&& pair->buf[i+j] <= '~')
		buf[l++] = pair->buf[i+j];
	    else {
		sprintf(&buf[l], "<%02x>", pair->buf[i+j]);
		l += strlen(&buf[l]);
		if (pair->buf[i+j] == '\n') {
		    k = 0;
		    j++;
		    break;
		}
		if (pair->buf[i+j] != '\t' && pair->buf[i+j] != '\r' &&
		    pair->buf[i+j] != '\033')
		    k++;
	    }
	}
	if (k > j/10) {
	    j = l = 0;
	    for (j=0; j < 16 && i+j < pair->start+len; j++) {
		if (' ' <= pair->buf[i+j]
		    && pair->buf[i+j] <= '~')
		    sprintf(&buf[l], " %c ", pair->buf[i+j]);
		else {
		    sprintf(&buf[l], " %02x",
			    (unsigned char)pair->buf[i+j]);
		    if (pair->buf[i+j] == '\n') k = 0; else k++;
		}
		l += strlen(&buf[l]);
	    }
	}
	buf[l] = '\0';
	if (pair->proto & proto_source) {
	    message(LOG_DEBUG, "%s%d<%d%s", str, pair->sd, p->sd, buf);
	} else {
	    message(LOG_DEBUG, "%s%d>%d%s", str, p->sd, pair->sd, buf);
	}
    }
}

void message_pairs(void) {	/* dump for debug */
    Pair *pair;
    for (pair=pairs.next; pair != NULL; pair=pair->next) message_pair(pair);
}

void message_origins(void) {	/* dump for debug */
    Origin *origin;
    for (origin=origins.next; origin != NULL; origin=origin->next)
	message_origin(origin);
}

void message_conns(void) {	/* dump for debug */
    Conn *conn;
    for (conn=conns.next; conn != NULL; conn=conn->next)
	message_conn(conn);
}

/* read write thread */
/* no Mutex are needed because in the single thread */

int dowrite(Pair *pair) {	/* write from buf from pair->start */
    SOCKET sd = pair->sd;
    Pair *p;
    int len;
    if (Debug > 5) message(LOG_DEBUG, "TCP %d: write %d bytes ...",
			   sd, pair->len);
    if (InvalidSocket(sd)) return -1;
#ifdef USE_SSL
    if (pair->ssl) {
	len = SSL_write(pair->ssl, &pair->buf[pair->start], pair->len);
	if (pair->proto & proto_close) return -1;
	if (len <= 0) {
	    int err;
	    err = SSL_get_error(pair->ssl, len);
	    if (err == SSL_ERROR_NONE
		|| err == SSL_ERROR_WANT_READ
		|| err == SSL_ERROR_WANT_WRITE) {
		if (Debug > 4)
		    message(LOG_DEBUG, "TCP %d: SSL_write interrupted err=%d",
			    sd, err);
		return 0;	/* EINTR */
	    }
	    if (err != SSL_ERROR_ZERO_RETURN) {
		message(LOG_ERR, "TCP %d: SSL_write error err=%d, closing",
			sd, err);
		message_pair(pair);
		return len;	/* error */
	    }
	}
    } else {
#endif
	len = send(sd, &pair->buf[pair->start], pair->len, 0);
	if (pair->proto & proto_close) return -1;
	if (len < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (errno == EINTR) {
		if (Debug > 4)
		    message(LOG_DEBUG, "TCP %d: write interrupted", sd);
		return 0;
	    }
	    message(LOG_ERR, "TCP %d: write error err=%d, closing", sd, errno);
	    message_pair(pair);
	    return len;	/* error */
	}
#ifdef USE_SSL
    }
#endif
    if (Debug > 4) message(LOG_DEBUG, "TCP %d: %d bytes written", sd, len);
    if (PacketDump > 0 || ((pair->proto & proto_first_w) && Debug > 3))
	message_buf(pair, len, "");
    time(&pair->clock);
    p = pair->pair;
    if (p) p->clock = pair->clock;
    if (pair->len <= len) {
	pair->start = 0;
    } else {
	pair->start += len;
	message(LOG_NOTICE,
		"TCP %d: write %d bytes, but only %d bytes written",
		sd, pair->len, len);
	message_pair(pair);
    }
    pair->len -= len;
    pair->tx += len;
    if ((p->proto & proto_command) != command_health)
	lastReadWrite = pair->clock;
    return len;
}

static unsigned char basis_64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int baseEncode(unsigned char *buf, int len, int max) {
    unsigned char *org = buf + max - len;
    unsigned char c1, c2, c3;
    int blen = 0;
    int i;
    bcopy(buf, org, len);
    for (i=0; i < len; i += 3) {
	switch (len - i) {
	case 1:
	    c2 = '\0';
	    buf[blen+2] = '=';
	case 2:
	    c3 = '\0';
	    buf[blen+3] = '=';
	}
	switch (len - i) {
	default:
	    c3 = org[i+2];
	    buf[blen+3] = basis_64[c3 & 0x3F];
	case 2:
	    c2 = org[i+1];
	    buf[blen+2] = basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)];
	case 1:
	    c1 = org[i];
	    buf[blen+1] = basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)];
	    buf[blen] = basis_64[c1>>2];
	}
	blen += 4;
    }
    if (buf[blen-1] != '=') buf[blen++] = '=';
    return blen;
}

#define XX      255	/* illegal base64 char */
#define EQ      254	/* padding */

static unsigned char index_64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,EQ,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,

    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};

int baseDecode(unsigned char *buf, int len, char *rest) {
    int blen = 0;
    unsigned char c[4], o[4];
    int i, j;
    j = 0;
    for (i=0; i < len; i++) {
	c[j] = index_64[buf[i]];
	if (c[j] == XX) continue;
	if (j == 0 && c[j] == EQ) continue;
	o[j++] = buf[i];
	if (j == 4) {
	    j = 0;
	    buf[blen++] = (c[0] << 2) | ((c[1] & 0x30) >> 4);
	    if (c[2] == EQ) continue;
	    buf[blen++] = ((c[1] & 0x0F) << 4) | ((c[2] & 0x3C) >> 2);
	    if (c[3] == EQ) continue;
	    buf[blen++] = ((c[2] & 0x03) << 6) | c[3];
	}
    }
    *rest = j;
    for (i=0; i < j; i++) *(rest-1-i) = o[i];
    return blen;
}

int doread(Pair *pair) {	/* read into buf from pair->pair->start */
    SOCKET sd = pair->sd;
    Pair *p;
    int len, i;
    int bufmax, start;
    if (InvalidSocket(sd)) return -1;
    if (Debug > 5) message(LOG_DEBUG, "TCP %d: read ...", sd);
    p = pair->pair;
    if (p == NULL) {	/* no pair, no more read */
	char buf[BUFMAX];
#ifdef USE_SSL
	if (pair->ssl) {
	    len = SSL_read(pair->ssl, buf, BUFMAX);
	} else
#endif
	    len = recv(sd, buf, BUFMAX, 0);
	if (pair->proto & proto_close) return -1;
	if (Debug > 4) message(LOG_DEBUG, "TCP %d: read %d bytes", sd, len);
	if (len == 0) return -1;	/* EOF w/o pair */
	if (len > 0) {
	    message(LOG_ERR, "TCP %d: no pair, closing", sd);
	    message_pair(pair);
	    len = -1;
	}
	return len;
    }
    bufmax = p->bufmax - p->start;
    start = p->start;
    if (p->proto & proto_base) bufmax = (bufmax - 1) / 4 * 3;
    else if (pair->proto & proto_base) {
	if (!(pair->proto & proto_first_r)) {
	    len = *(p->buf+p->bufmax-1);
	    for (i=0; i < len; i++) {
		p->buf[start++] = p->buf[p->bufmax-2-i];
	    }
	    bufmax -= len;
	}
	*(p->buf+p->bufmax-1) = 0;
	bufmax -= 5;
    }
    if ((p->proto & proto_command) == command_ihead) bufmax = bufmax / 2;
#ifdef USE_SSL
    if (pair->ssl) {
	len = SSL_read(pair->ssl, &p->buf[start], bufmax);
	if (pair->proto & proto_close) return -1;
	if (len < 0) {
	    int err;
	    err = SSL_get_error(pair->ssl, len);
	    if (err == SSL_ERROR_NONE
		|| err == SSL_ERROR_WANT_READ
		|| err == SSL_ERROR_WANT_WRITE) {
		if (Debug > 4)
		    message(LOG_DEBUG, "TCP %d: SSL_read interrupted err=%d",
			    sd, err);
		return 0;	/* EINTR */
	    }
	    if (err == SSL_ERROR_SYSCALL) {
		err = ERR_get_error();
		if (err) {
		    message(LOG_ERR,
			    "TCP %d: SSL_read I/O error err=%d, closing",
			    sd, err);
		    message_pair(pair);
		    return -1;	/* error */
		}
	    } else if (err != SSL_ERROR_ZERO_RETURN) {
		message(LOG_ERR, "TCP %d: SSL_read error err=%d, closing",
			sd, err);
		message_pair(pair);
		return -1;	/* error */
	    }
	}
    } else {
#endif
	len = recv(sd, &p->buf[start], bufmax, 0);
	if (pair->proto & proto_close) return -1;
	if (len < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (errno == EINTR) {
		if (Debug > 4)
		    message(LOG_DEBUG, "TCP %d: read interrupted", sd);
		return 0;	/* EINTR */
	    }
	    message(LOG_ERR, "TCP %d: read error err=%d, closing", sd, errno);
	    message_pair(pair);
	    return len;	/* error */
	}
#ifdef USE_SSL
    }
#endif
    if (len == 0) {
	message_time_log(pair);
	if (Debug > 2) message(LOG_DEBUG, "TCP %d: EOF", sd);
	return -2;	/* EOF w/ pair */
    }
    pair->rx += len;
#ifdef ENLARGE
    if (len > pair->bufmax - 10
	&& XferBufMax < pair->bufmax * 2) {
	XferBufMax = pair->bufmax * 2;
	message(LOG_NOTICE, "TCP %d: XferBufMax becomes %d byte",
		sd, XferBufMax);
    }
#endif
    p->len = start + len - p->start;
    if (Debug > 4) {
	SOCKET psd = p->sd;
	if (start > p->start) {
	    message(LOG_DEBUG, "TCP %d: read %d+%d bytes to %d",
		    sd, len, start - p->start, psd);
	} else {
	    message(LOG_DEBUG, "TCP %d: read %d bytes to %d",
		    sd, p->len, psd);
	}
    }
    time(&pair->clock);
    p->clock = pair->clock;
    if (p->proto & proto_base) {
	p->len = baseEncode(&p->buf[p->start], p->len,
			    p->bufmax - p->start);
    } else if (pair->proto & proto_base) {
	p->len = baseDecode(&p->buf[p->start], p->len, p->buf+p->bufmax-1);
	len = *(p->buf+p->bufmax-1);
	if (Debug > 4 && len > 0) {
	    char buf[BUFMAX];
	    for (i=0; i < len; i++)
		sprintf(&buf[i*3], " %02x", p->buf[p->bufmax-2-i]);
	    buf[0] = '(';
	    message(LOG_DEBUG, "TCP %d: save %d bytes \"%s\")", sd, len, buf);
	}
    }
    if ((p->proto & proto_command) != command_health)
	lastReadWrite = pair->clock;
    return p->len;
}

/* http */

#define METHOD_LEN_MAX	10

int commOutput(Pair *pair, fd_set *winp, char *fmt, ...) {
    Pair *p = pair->pair;
    SOCKET psd;
    char *str;
    va_list ap;
    if (p == NULL) return -1;
    psd = p->sd;
    if ((p->proto & (proto_shutdown | proto_close)) || InvalidSocket(psd))
	return -1;
    str = &p->buf[p->start + p->len];
    va_start(ap, fmt);
    vsnprintf(str, BUFMAX - (p->start + p->len), fmt, ap);
    va_end(ap);
    if (p->proto & proto_base)
	p->len += baseEncode(str, strlen(str), BUFMAX - (p->start + p->len));
    else p->len += strlen(str);
    FdSet(psd, winp);		/* need to write */
    return p->len;
}

static char *comm_match(char *buf, char *str) {
    while (*str) {
	if (toupper(*buf++) != *str++) return NULL;	/* unmatch */
    }
    if (*buf) {
	if (!isspace(*buf)) return NULL;
/*	while (isspace(*buf)) buf++;	*/
	if (*buf == ' ') buf++;
    }
    return buf;
}

int doproxy(Pair *pair, fd_set *rinp, char *host, int port) {
    struct sockaddr_in sin;
    short family;
    bzero((char *)&sin, sizeof(sin)); /* clear sin struct */
    sin.sin_port = htons((u_short)port);
    if (!host2addr(host, &sin.sin_addr, &family)) {
	return -1;
    }
    sin.sin_family = family;
    pair->proto &= ~proto_command;
    return reqconn(pair, rinp, &sin);
}

int proxyCONNECT(Pair *pair, fd_set *rinp, fd_set *winp,
		 char *parm, int start) {
    int port = 443;	/* host byte order */
    char *r = parm;
    Pair *p;
    pair->log = message_time(LOG_INFO, "CONNECT %s", parm);
    while (*r) {
	if (isspace(*r)) {
	    *r = '\0';
	    break;
	}
	if (*r == ':') {
	    port = atoi(r+1);
	    *r = '\0';
	}
	r++;
    }
    pair->len += pair->start;
    pair->start = 0;
    p = pair->pair;
    if (p) p->proto |= proto_ohttp_s;	/* remove request header */
    return doproxy(pair, rinp, parm, port);
}

int proxyCommon(Pair *pair, fd_set *rinp, char *parm, int start) {
    int port = 80;
    char *host;
    char *top = &pair->buf[start];
    char *p, *q;
    int i;
    for (i=0; i < METHOD_LEN_MAX; i++) {
	if (parm[i] == ':') break;
    }
    if (strncmp(parm, "http", i) != 0
	|| parm[i+1] != '/' || parm[i+2] != '/') {
	message(LOG_ERR, "Unknown URL format: %s", parm);
	return -1;
    }
    host = &parm[i+3];
    p = host;
    while (*p) {
	if (*p == ':') {
	    port = atoi(p+1);
	    *p++ = '\0';
	    continue;
	}
	if (isspace(*p) || *p == '/') {
	    *p = '\0';
	    break;
	}
	p++;
    }
    i = p - parm;		/* length of 'http://host' */
    p = top;
    while (!isspace(*p)) p++;	/* skip 'GET http://host' */
    while (isspace(*p)) p++;	/* now p points url */
    q = p + i;			/* now q points path */
    if (*q != '/') *--q = '/';
    i = p - top;		/* length of 'GET ' */
    bcopy(top, q-i, i);
    pair->len += (pair->start - (q - top - i));
    pair->start = q - pair->buf - i;
    if (Debug > 1) {
	Pair *r = pair->pair;
	message(LOG_DEBUG, "proxy %d -> http://%s:%d",
		(r ? r->sd : INVALID_SOCKET), host, port);
    }
    return doproxy(pair, rinp, host, port);
}

int proxyGET(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    pair->log = message_time(LOG_INFO, "GET %s", parm);
    return proxyCommon(pair, rinp, parm, start);
}

int proxyPOST(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    pair->log = message_time(LOG_INFO, "POST %s", parm);
    return proxyCommon(pair, rinp, parm, start);
}

int proxyErr(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    message(LOG_ERR, "Unknown method: %s", parm);
    return -1;
}

Comm proxyComm[] = {
    { "CONNECT", proxyCONNECT },
    { "POST", proxyPOST },
    { "GET", proxyGET },
    { NULL, proxyErr },
};

#ifdef USE_POP
int popUSER(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    int ulen, tlen;
    if (Debug) message(LOG_DEBUG, ": USER %s", parm);
    ulen = strlen(parm);
    tlen = strlen(pair->p);
    if (ulen + 1 + tlen + 1 >= BUFMAX) {
	commOutput(pair, winp, "+Err Too long user name\r\n");
	return -1;
    }
    bcopy(pair->p, pair->p + ulen + 1, tlen + 1);
    strcpy(pair->p, parm);
    commOutput(pair, winp, "+OK Password required for %s\r\n", parm);
    pair->proto &= ~state_mask;
    pair->proto |= 1;
    return -2;	/* read more */
}

#define DIGEST_LEN 16

int popPASS(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    MD5_CTX context;
    unsigned char digest[DIGEST_LEN];
    char *str;
    int ulen, tlen, plen, i;
    int state = (pair->proto & state_mask);
    char *p = pair->p;
    pair->p = NULL;
    if (Debug > 5) message(LOG_DEBUG, ": PASS %s", parm);
    if (state < 1) {
	commOutput(pair, winp, "-ERR USER first\r\n");
	return -2;	/* read more */
    }
    ulen = strlen(p);
    str = p + ulen + 1;
    tlen = strlen(str);
    plen = strlen(parm);
    if (ulen + 1 + tlen + plen + 1 >= BUFMAX) {
	commOutput(pair, winp, "+Err Too long password\r\n");
	return -1;
    }
    strcat(str, parm);
    sprintf(pair->buf, "APOP %s ", p);
    ulen = strlen(pair->buf);
    MD5Init(&context);
    MD5Update(&context, str, tlen + plen);
    MD5Final(digest, &context);
    free(p);
    for (i=0; i < DIGEST_LEN; i++) {
	sprintf(pair->buf + ulen + i*2, "%02x", digest[i]);
    }
    pair->log = message_time(LOG_INFO, "POP -> %s", pair->buf);
    strcat(pair->buf, "\r\n");
    pair->start = 0;
    pair->len = strlen(pair->buf);
    return 0;
}

int popAUTH(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    if (Debug) message(LOG_DEBUG, ": AUTH %s", parm);
    commOutput(pair, winp, "-ERR authorization first\r\n");
    return -2;	/* read more */
}

int popCAPA(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    if (Debug) message(LOG_DEBUG, ": CAPA %s", parm);
    commOutput(pair, winp, "-ERR authorization first\r\n");
    return -2;	/* read more */
}

int popAPOP(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    pair->log = message_time(LOG_INFO, "APOP %s", parm);
    pair->len += pair->start - start;
    pair->start = start;
    return 0;
}

int popErr(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    message(LOG_ERR, "Unknown POP command: %s", parm);
    return -1;
}

Comm popComm[] = {
    { "USER", popUSER },
    { "PASS", popPASS },
    { "APOP", popAPOP },
    { "AUTH", popAUTH },
    { "CAPA", popCAPA },
    { NULL, popErr },
};
#endif

int nStones(void) {
    int n = 0;
    Stone *stone;
    for (stone=stones; stone != NULL; stone=stone->next) n++;
    return n;
}

int nPairs(void) {
    int n = 0;
    Pair *pair;
    for (pair=pairs.next; pair != NULL; pair=pair->next) n++;
    return n;
}

int nConns(void) {
    int n = 0;
    Conn *conn;
    for (conn=conns.next; conn != NULL; conn=conn->next) n++;
    return n;
}

int limitCommon(Pair *pair, fd_set *winp, int var, int limit, char *str) {
    if (Debug) message(LOG_DEBUG, ": LIMIT %s %d: %d", str, limit, var);
    if (var < limit) {
	commOutput(pair, winp, "200 %s=%d is less than %d\r\n",
		   str, var, limit);
    } else {
	commOutput(pair, winp, "500 %s=%d is not less than %d\r\n",
		   str, var, limit);
    }
    return -2;	/* read more */
}

int limitPair(Pair *pair, fd_set *rinp, fd_set *winp,
	      char *parm, int start) {
    return limitCommon(pair, winp, nStones(), atoi(parm), "pair");
}

int limitConn(Pair *pair, fd_set *rinp, fd_set *winp,
	      char *parm, int start) {
    return limitCommon(pair, winp, nConns(), atoi(parm), "conn");
}

int limitEstablished(Pair *pair, fd_set *rinp, fd_set *winp,
		     char *parm, int start) {
    time_t now;
    time(&now);
    return limitCommon(pair, winp, (int)(now - lastEstablished),
		       atoi(parm), "established");
}

int limitReadWrite(Pair *pair, fd_set *rinp, fd_set *winp,
		   char *parm, int start) {
    time_t now;
    time(&now);
    return limitCommon(pair, winp, (int)(now - lastReadWrite),
		       atoi(parm), "readwrite");
}

int limitAsync(Pair *pair, fd_set *rinp, fd_set *winp,
		   char *parm, int start) {
    return limitCommon(pair, winp, AsyncCount, atoi(parm), "async");
}

int limitErr(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    if (Debug) message(LOG_ERR, ": Illegal LIMIT %s", parm);
    commOutput(pair, winp, "500 Illegal LIMIT\r\n");
    return -2;	/* read more */
}

Comm limitComm[] = {
    { "PAIR", limitPair },
    { "CONN", limitConn },
    { "ESTABLISHED", limitEstablished },
    { "READWRITE", limitReadWrite },
    { "ASYNC", limitAsync },
    { NULL, limitErr },
};

int healthHELO(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    char str[BUFMAX];
    time_t now;
    time(&now);
    snprintf(str, BUFMAX-1,
	     "stone=%d pair=%d conn=%d established=%d readwrite=%d async=%d",
	     nStones(), nPairs(), nConns(),
	     (int)(now - lastEstablished), (int)(now - lastReadWrite),
	     AsyncCount);
    if (Debug) message(LOG_DEBUG, ": HELO %s: %s", parm, str);
    commOutput(pair, winp, "200 stone:%s debug=%d %s\r\n",
	       VERSION, Debug, str);
    return -2;	/* read more */
}

int healthLIMIT(Pair *pair, fd_set *rinp, fd_set *winp,
		char *parm, int start) {
    Comm *comm = limitComm;
    char *q;
    while (comm->str) {
	if ((q=comm_match(parm, comm->str)) != NULL) break;
	comm++;
    }
    if (!q) return limitErr(pair, rinp, winp, parm, start);
    return (*comm->func)(pair, rinp, winp, q, start);
}

int healthQUIT(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    if (Debug) message(LOG_DEBUG, ": QUIT %s", parm);
    return -1;
}

int healthErr(Pair *pair, fd_set *rinp, fd_set *winp, char *parm, int start) {
    message(LOG_ERR, "Unknown health command: %s", parm);
    return -1;
}

Comm healthComm[] = {
    { "HELO", healthHELO },
    { "LIMIT", healthLIMIT },
    { "QUIT", healthQUIT },
    { NULL, healthErr },
};

int docomm(Pair *pair, fd_set *rinp, fd_set *winp, Comm *comm) {
    char buf[BUFMAX];
    char *p;
    char *q = &pair->buf[pair->start + pair->len];
    int start, i;
    for (p=&pair->buf[pair->start]; p < q; p++) {
	if (*p == '\r' || *p == '\n') break;
    }
    if (p >= q && p < &pair->buf[pair->bufmax]) {
	pair->start += pair->len;
	pair->len = 0;
	return -2;	/* read more */
    }
    for (start=p-pair->buf-1; start >= 0; start--) {
	if (pair->buf[start] == '\r' || pair->buf[start] == '\n') break;
    }
    start++;
    while ((*p == '\r' || *p == '\n') && p < q) p++;
    pair->start = p - pair->buf;
    if (p < q) {
	pair->len = q - p;
    } else {
	pair->len = 0;
    }
    while (comm->str) {
	if ((q=comm_match(&pair->buf[start], comm->str)) != NULL) break;
	comm++;
    }
    if (q == NULL) q = &pair->buf[start];
    for (i=0; q < p && i < BUFMAX-1; i++) {
	if (*q == '\r' || *q == '\n') break;
	buf[i] = *q++;
    }
    buf[i] = '\0';
    return (*comm->func)(pair, rinp, winp, buf, start);
}

int insheader(Pair *pair) {	/* insert header */
    char buf[BUFMAX];
    int len, i;
    len = pair->start + pair->len;
    for (i=pair->start; i < len; i++) {
	if (pair->buf[i] == '\n') break;
    }
    if (i >= len) {
	if (Debug > 3)
	    message(LOG_DEBUG, "TCP %d: insheader needs more", pair->sd);
	return -1;
    }
    i++;
    len -= i;
    if (len > 0) bcopy(&pair->buf[i], buf, len);	/* save rest header */
    i += strnparse(&pair->buf[i], pair->bufmax - i,
		   pair->stone->p, pair->pair);
    pair->buf[i++] = '\r';
    pair->buf[i++] = '\n';
    if (Debug > 5) {
	message(LOG_DEBUG,
		"TCP %d: insheader start=%d, ins=%d, rest=%d, max=%d",
		pair->sd, pair->start, i-pair->start, len, pair->bufmax);
    }
    if (len > 0) bcopy(buf, &pair->buf[i], len);	/* restore */
    pair->len = i - pair->start + len;
    return pair->len;
}

int rmheader(Pair *pair) {	/* remove header */
    char *p;
    char *q = &pair->buf[pair->start+pair->len];
    int state = (pair->proto & state_mask);
    if (Debug > 3) message_buf(pair, pair->len, "rm");
    for (p=&pair->buf[pair->start]; p < q; p++) {
	if (*p == '\r') continue;
	if (*p == '\n') {
	    state++;
	    if (state >= 3) {
		p++;
		break;	/* end of header */
	    }
	} else {
	    state = 1;
	}
    }
    if (state < 3) {
	pair->len = pair->start = 0;
	pair->proto = ((pair->proto & ~state_mask) | state);
	return -2;	/* header will continue... */
    }
    pair->len = q - p;	/* remove header */
    pair->start = p - pair->buf;
    pair->proto &= ~state_mask;
    return pair->len;
}

int first_read(Pair *pair, fd_set *rinp, fd_set *winp) {
    SOCKET sd = pair->sd;
    SOCKET psd;
    Pair *p = pair->pair;
    int len;
    if (p == NULL || (p->proto & (proto_shutdown | proto_close))
	|| InvalidSocket(sd)) return -1;
    psd = p->sd;
    len = p->len;
    pair->proto &= ~proto_first_r;
    if (p->proto & proto_command) {	/* proxy */
	switch(p->proto & proto_command) {
	case command_proxy:
	    len = docomm(p, rinp, winp, proxyComm);
	    break;
#ifdef USE_POP
	case command_pop:
	    if (p->p) len = docomm(p, rinp, winp, popComm);
	    break;
#endif
	case command_health:
	    len = docomm(p, rinp, winp, healthComm);
	    break;
	default:
	    ;
	}
	if (len == -2) {	/* read more */
	    if (Debug > 3) {
		message(LOG_DEBUG, "TCP %d: read more from %d", psd, sd);
	    }
	} else if (len < 0) {
	    doclose(p);
	    doclose(pair);
	    return -1;
	} else {
	    len = p->len;
	}
    }
    if (pair->proto & proto_ohttp) {	/* over http */
	len = rmheader(p);
	if (len >= 0) {
	    if (pair->proto & proto_ohttp_s) {
		commOutput(p, winp, "HTTP/1.0 200 OK\r\n\r\n");
		pair->proto &= ~proto_ohttp_s;
	    }
	}
    }
#ifdef USE_POP
    if ((pair->proto & proto_command) == command_pop) {	/* apop */
	int i;
	char *q;
	for (i=p->start; i < p->start + p->len; i++) {
	    if (p->buf[i] == '<') {	/* time stamp of APOP banner */
		q = pair->p = malloc(BUFMAX);
		if (!q) {
		    message(LOG_ERR, "TCP %d: out of memory", sd);
		    break;
		}
		for (; i < p->start + p->len; i++) {
		    *q++ = p->buf[i];
		    if (p->buf[i] == '>') break;
		}
		*q = '\0';
		break;
	    }
	}
    }
#endif
    if (len <= 0 && !(pair->proto & (proto_eof | proto_close))) {
	if (Debug > 8) {
	    message(LOG_DEBUG, "TCP %d: read more", sd);
	}
	FdSet(sd, rinp);	/* read more */
	if (len < 0) pair->proto |= proto_first_r;
    }
    return len;
}

static void message_select(int pri, char *msg,
			   fd_set *rout, fd_set *wout, fd_set *eout) {
    int i, r, w, e;
    for (i=0; i < FD_SETSIZE; i++) {
	r = FD_ISSET(i, rout);
	w = FD_ISSET(i, wout);
	e = FD_ISSET(i, eout);
	if (r || w || e)
	    message(pri, "%s %d: %c%c%c", msg,
		    i, (r ? 'r' : ' '), (w ? 'w' : ' '), (e ? 'e' : ' '));
    }
}

/* main event loop */

void asyncReadWrite(Pair *pair) {
    fd_set ri, wi, ei;
    fd_set ro, wo, eo;
    struct timeval tv;
    int npairs = 1;
    Pair *p[2];
    Pair *rPair, *wPair;
    SOCKET sd, rsd, wsd;
    int established;
    int again = 0;
    int len;
    int i;
    ASYNC_BEGIN;
    FD_ZERO(&ri);
    FD_ZERO(&wi);
    FD_ZERO(&ei);
    p[0] = pair;
    p[1] = pair->pair;
    if (Debug > 8) message(LOG_DEBUG, "TCP %d, %d: asyncReadWrite ...",
			   (p[0] ? p[0]->sd : INVALID_SOCKET),
			   (p[1] ? p[1]->sd : INVALID_SOCKET));
    if (p[1]) npairs++;
    for (i=0; i < npairs; i++) {
	int isset = 0;
	p[i]->count += REF_UNIT;
	sd = p[i]->sd;
	if ((p[i]->proto & proto_close) || InvalidSocket(sd)) continue;
	if (!(p[i]->proto & proto_eof) && (p[i]->proto & proto_select_r)) {
	    FdSet(sd, &ri);
	    p[i]->proto &= ~proto_select_r;
	    isset = 1;
	}
	if (!(p[i]->proto & proto_shutdown) && (p[i]->proto & proto_select_w)
	    && npairs > 1
	    && (p[i]->proto & proto_connect)
	    && ((p[1-i]->proto & proto_command) == command_health
		|| (p[1-i]->proto & proto_connect))) {
	    FdSet(sd, &wi);	/* never write unless establish */
	    p[i]->proto &= ~proto_select_w;
	    isset = 1;
	}
	if (isset) FdSet(sd, &ei);
    }
    tv.tv_sec = 0;
    tv.tv_usec = TICK_SELECT;
    if (Debug > 10)
	message_select(LOG_DEBUG, "selectReadWrite1", &ri, &wi, &ei);
    while (again
	   || (ro=ri, wo=wi, eo=ei,
	       select(FD_SETSIZE, &ro, &wo, &eo, &tv) > 0)) {
	again = 0;
	for (i=0; i < npairs; i++) {
	    if (!p[i] || (p[i]->proto & proto_close)) continue;
	    sd = p[i]->sd;
	    if (InvalidSocket(sd)) continue;
	    if (FD_ISSET(sd, &eo)) {	/* exception */
		message(LOG_ERR, "TCP %d: exception", sd);
		message_pair(p[i]);
		FD_CLR(sd, &ri);
		FD_CLR(sd, &wi);
		FD_CLR(sd, &ei);
		doclose(p[i]);
		goto leave;
	    } else if (!(p[i]->proto & proto_eof)
		       && FD_ISSET(sd, &ro)) {	/* read */
		rPair = p[i];
		wPair = p[1-i];
		rsd = sd;
		if (wPair) wsd = wPair->sd; else wsd = INVALID_SOCKET;
		FD_CLR(rsd, &ri);
		rPair->count += REF_UNIT;
		len = doread(rPair);
		rPair->count -= REF_UNIT;
		if (len < 0 || (rPair->proto & proto_close) || wPair == NULL) {
		    FD_CLR(rsd, &ri);
		    if (len == -2	/* if EOF w/ pair, */
			&& !(rPair->proto & proto_shutdown)
			/* and not yet shutdowned, */
			&& wPair
			&& !(wPair->proto & (proto_eof | proto_shutdown
					     | proto_close))
			/* and not bi-directional EOF
			   and peer is not yet shutdowned, */
			&& ValidSocket(wsd)) {	/* and pair is valid, */
			rPair->proto |= proto_eof;	/* no more to read */
			if (doshutdown(wPair, 1) < 0) {
			    doclose(rPair);
			    goto leave;
			}
		    } else {
			/* error or already shutdowned
			   or bi-directional EOF */
			if (wPair) doclose(wPair);
			doclose(rPair);
			goto leave;
		    }
		} else {
		    if (len > 0) {
			int first_flag;
			first_flag = (rPair->proto & proto_first_r);
			if (first_flag) len = first_read(rPair, &ri, &wi);
			if (len > 0 && ValidSocket(wsd)
			    && (wPair->proto & proto_connect)
			    && !(wPair->proto & (proto_shutdown | proto_close))
			    && !(rPair->proto & proto_close)) {
			    /* (wPair->proto & proto_eof) may be true */
			    FdSet(wsd, &wi);
			} else {
			    goto leave;
			}
		    } else {	/* EINTR */
			FdSet(rsd, &ri);
		    }
		}
	    } else if (!(p[i]->proto & proto_shutdown)
		       && FD_ISSET(sd, &wo)) {	/* write */
		wPair = p[i];
		rPair = p[1-i];
		wsd = sd;
		if (rPair) rsd = rPair->sd; else rsd = INVALID_SOCKET;
		FD_CLR(wsd, &wi);
		if ((wPair->proto & proto_command) == command_ihead) {
		    if (insheader(wPair) >= 0)	/* insert header */
			wPair->proto &= ~proto_command;
		}
		wPair->count += REF_UNIT;
		len = dowrite(wPair);
		wPair->count -= REF_UNIT;
		if (len < 0 || (wPair->proto & proto_close) || rPair == NULL) {
		    if (rPair && ValidSocket(rsd)) {
			FD_CLR(rsd, &ri);
			doclose(rPair);	/* if error, close */
		    }
		    FD_CLR(wsd, &wi);
		    doclose(wPair);
		    goto leave;
		} else {
		    /* (wPair->proto & proto_eof) may be true */
		    if (wPair->len <= 0) {	/* all written */
			if (wPair->proto & proto_first_w)
			    wPair->proto &= ~proto_first_w;
			if (rPair && ValidSocket(rsd)
			    && (rPair->proto & proto_connect)
			    && !(rPair->proto & (proto_eof | proto_close))
			    && !(wPair->proto & (proto_shutdown | proto_close))
			    ) {
#ifdef USE_SSL
			    if (rPair->ssl && SSL_pending(rPair->ssl)) {
				FdSet(rPair->sd, &ro);
				if (Debug > 4)
				    message(LOG_DEBUG,
					    "TCP %d: SSL_pending, read again",
					    rPair->sd);
				again = 1;
			    }
#endif
			    FdSet(rsd, &ri);
			} else {
			    goto leave;
			}
		    } else {	/* EINTR */
			FdSet(wsd, &wi);
		    }
		}
	    }
	}
	if (Debug > 10)
	    message_select(LOG_DEBUG, "selectReadWrite2", &ri, &wi, &ei);
    }
 leave:
    waitMutex(FdRinMutex);
    waitMutex(FdWinMutex);
    waitMutex(FdEinMutex);
    for (i=0; i < npairs; i++) {
	if (p[i]) {
	    int proto = p[i]->proto;
	    sd = p[i]->sd;
	    if (!(proto & proto_close) && ValidSocket(sd)) {
		int isset = 0;
		if (!(proto & proto_eof) && FD_ISSET(sd, &ri)) {
		    FdSet(sd, &rin);
		    isset = 1;
		}
		if (!(proto & proto_shutdown) && FD_ISSET(sd, &wi)) {
		    FdSet(sd, &win);
		    isset = 1;
		}
		if (isset) FdSet(sd, &ein);
	    }
	    p[i]->count -= REF_UNIT;
	}
    }
    freeMutex(FdEinMutex);
    freeMutex(FdWinMutex);
    freeMutex(FdRinMutex);
    if (Debug > 8) message(LOG_DEBUG, "TCP %d, %d: asyncReadWrite end",
			   (p[0] ? p[0]->sd : INVALID_SOCKET),
			   (p[1] ? p[1]->sd : INVALID_SOCKET));
    ASYNC_END;
}

int scanPairs(fd_set *rop, fd_set *wop, fd_set *eop) {
#ifdef PTHREAD
    pthread_t thread;
    int err;
#endif
    Pair *pair;
    int ret = 1;
    if (Debug > 8) message(LOG_DEBUG, "scanPairs ...");
    for (pair=pairs.next; pair != NULL; pair=pair->next) {
	Pair *p = pair->pair;
	SOCKET sd = pair->sd;
	if (!(pair->proto & proto_close) && ValidSocket(sd)) {
	    time_t clock;
	    int idle = 1;	/* assume no events happen on sd */
	    int isset;
	    waitMutex(FdEinMutex);
	    isset = (FD_ISSET(sd, eop) && FD_ISSET(sd, &ein));
	    if (isset) FD_CLR(sd, &ein);
	    freeMutex(FdEinMutex);
	    if (isset) {
		idle = 0;
		message(LOG_ERR, "TCP %d: exception", sd);
		message_pair(pair);
		doclose(pair);
	    } else {
		waitMutex(FdRinMutex);
		waitMutex(FdWinMutex);
		waitMutex(FdEinMutex);
		isset = ((FD_ISSET(sd, rop) && FD_ISSET(sd, &rin)) ||
			 (FD_ISSET(sd, wop) && FD_ISSET(sd, &win)));
		if (p) {
		    SOCKET psd = p->sd;
		    if (!(p->proto & proto_close) && ValidSocket(psd)) {
			isset |=
			    ((FD_ISSET(sd, rop) && FD_ISSET(sd, &rin)) ||
			     (FD_ISSET(sd, wop) && FD_ISSET(sd, &win)));
		    }
		}
		if (isset) {
		    pair->proto &= ~(proto_select_r | proto_select_w);
		    if (FD_ISSET(sd, &rin)) {
			FD_CLR(sd, &rin);
			pair->proto |= proto_select_r;
		    }
		    if (FD_ISSET(sd, &win)) {
			FD_CLR(sd, &win);
			pair->proto |= proto_select_w;
		    }
		    FD_CLR(sd, &ein);
		    if (p) {
			SOCKET psd = p->sd;
			p->proto &= ~(proto_select_r | proto_select_w);
			if (FD_ISSET(psd, &rin)) {
			    FD_CLR(psd, &rin);
			    p->proto |= proto_select_r;
			}
			if (FD_ISSET(psd, &win)) {
			    FD_CLR(psd, &win);
			    p->proto |= proto_select_w;
			}
			FD_CLR(psd, &ein);
		    }
		}
		freeMutex(FdEinMutex);
		freeMutex(FdWinMutex);
		freeMutex(FdRinMutex);
		if (isset) {
		    idle = 0;
		    ASYNC(asyncReadWrite, pair);
		}
	    }
	    if (idle && pair->timeout > 0
		&& (time(&clock), clock - pair->clock > pair->timeout)) {
		if (pair->count > 0 || Debug > 2) {
		    message(LOG_NOTICE, "TCP %d: idle time exceeds", sd);
		    message_pair(pair);
		    if (pair->count > 0) pair->count -= REF_UNIT;
		}
		doclose(pair);
	    }
	}
    }
    if (Debug > 8) message(LOG_DEBUG, "scanPairs done");
    return ret;
}

/* stone */

#ifdef USE_SSL
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    X509 *err_cert;
    int err, depth;
    long serial = -1;
    SSL *ssl;
    Pair *pair;
    StoneSSL *ss;
    char buf[BUFMAX];
    char *p;
    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);
    ssl = X509_STORE_CTX_get_ex_data
		(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    pair = SSL_get_ex_data(ssl, PairIndex);
    if (!pair) {
	message(LOG_ERR, "SSL callback don't have ex_data, verify fails...");
	return 0;	/* always fail */
    }
    if (pair->proto & proto_source) {
	ss = pair->stone->ssl_server;
    } else {
	ss = pair->stone->ssl_client;
    }
    if (depth == 0) {
	ASN1_INTEGER *n = X509_get_serialNumber(err_cert);
	if (n) serial = ASN1_INTEGER_get(n);
	if (ss->serial == -1 && serial >= 0) {
	    ss->serial = serial;
	} else if (ss->serial >= 0 && serial != ss->serial) {
	    message(LOG_ERR, "SSL callback serial number mismatch %lx != %lx",
		    serial, ss->serial);
	    return 0;	/* fail */
	}
    }
    if (Debug > 3)
	message(LOG_DEBUG, "TCP %d: callback: err=%d, depth=%d, preverify=%d",
		pair->sd, err, depth, preverify_ok);
    p = X509_NAME_oneline(X509_get_subject_name(err_cert), buf, BUFMAX-1);
    if (ss->verbose && p) message(LOG_DEBUG, "[depth%d=%s]", depth, p);
    if (depth > ss->depth) {
	preverify_ok = 0;
	X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_CHAIN_TOO_LONG);
    }
    if (!preverify_ok) return 0;
    if (depth < DEPTH_MAX && ss->re[depth]) {
	regmatch_t pmatch[NMATCH_MAX];
	err = regexec(ss->re[depth], p, (size_t)NMATCH_MAX, pmatch, 0);
	if (Debug > 3) message(LOG_DEBUG, "TCP %d: regexec%d=%d",
			       pair->sd, depth, err);
	if (err) return 0;	/* not match */
	if (!pair->match) {
	    pair->match = malloc(sizeof(char*) * (NMATCH_MAX+1));
	    if (pair->match) {
		int i;
		for (i=0; i <= NMATCH_MAX; i++) pair->match[i] = NULL;
	    }
	}
	if (pair->match) {
	    int i;
	    int j = 1;
	    if (serial >= 0) {
		char str[STRMAX];
		int len;
		snprintf(str, STRMAX-1, "%lx", serial);
		len = strlen(str);
		if (pair->match[0]) free(pair->match[0]);
		pair->match[0] = malloc(len+1);
		if (pair->match[0]) {
		    strncpy(pair->match[0], str, len);
		    pair->match[0][len] = '\0';
		}
	    }
	    for (i=1; i <= NMATCH_MAX; i++) {
		if (pair->match[i]) continue;
		if (pmatch[j].rm_so >= 0) {
		    int len = pmatch[j].rm_eo - pmatch[j].rm_so;
		    pair->match[i] = malloc(len+1);
		    if (pair->match[i]) {
			strncpy(pair->match[i], p + pmatch[j].rm_so, len);
			pair->match[i][len] = '\0';
			if (Debug > 4) message(LOG_DEBUG, "TCP %d: \\%d=%s",
					       pair->sd, i+1, pair->match[i]);
		    }
		    j++;
		}
	    }
	}
    }
    return 1;	/* if re is null, always succeed */
}

StoneSSL *mkStoneSSL(SSLOpts *opts, int isserver) {
    StoneSSL *ss;
    int err;
    int i;
    ss = malloc(sizeof(StoneSSL));
    if (!ss) {
    memerr:
	message(LOG_ERR, "Out of memory.");
	exit(1);
    }
    ss->verbose = opts->verbose;
    if (isserver) {
	ss->ctx = SSL_CTX_new(SSLv23_server_method());
    } else {
	ss->ctx = SSL_CTX_new(SSLv23_client_method());
    }
    if (!ss->ctx) {
	message(LOG_ERR, "SSL_CTX_new error");
	goto error;
    }
    SSL_CTX_set_options(ss->ctx, opts->off);
    SSL_CTX_set_mode(ss->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_verify(ss->ctx, opts->mode, opts->callback);
    SSL_CTX_set_verify_depth(ss->ctx, opts->depth + 1);
    ss->depth = opts->depth;
    ss->serial = opts->serial;
    ss->lbmod = opts->lbmod;
    ss->lbparm = opts->lbparm;
    if ((opts->caFile || opts->caPath)
	&& !SSL_CTX_load_verify_locations(ss->ctx,
					  opts->caFile, opts->caPath)) {
	message(LOG_ERR, "SSL_CTX_load_verify_locations(%s,%s) error",
		opts->caFile, opts->caPath);
	goto error;
    }
    if (opts->keyFile
	&& !SSL_CTX_use_PrivateKey_file
		(ss->ctx, opts->keyFile, X509_FILETYPE_PEM)) {
	message(LOG_ERR, "SSL_CTX_use_PrivateKey_file(%s) error",
		opts->keyFile);
	goto error;
    }
    if (opts->certFile
	&& !SSL_CTX_use_certificate_file(ss->ctx, opts->certFile,
					 X509_FILETYPE_PEM)) {
	message(LOG_ERR, "SSL_CTX_use_certificate_file(%s) error",
		opts->certFile);
	goto error;
    }
    if (opts->cipherList
	&& !SSL_CTX_set_cipher_list(ss->ctx, opts->cipherList)) {
	message(LOG_ERR, "SSL_CTX_set_cipher_list(%s) error",
		opts->cipherList);
	goto error;
    }
    for (i=0; i < DEPTH_MAX; i++) {
	if (i <= opts->depth && opts->regexp[i]) {
	    ss->re[i] = malloc(sizeof(regex_t));
	    if (!ss->re) goto memerr;
	    err = regcomp(ss->re[i], opts->regexp[i], REG_EXTENDED|REG_ICASE);
	    if (err) {
		message(LOG_ERR, "RegEx compiling error %d", err);
		goto error;
	    }
	    if (Debug > 5) {
		message(LOG_DEBUG, "regexp[%d]=%s", i, opts->regexp[i]);
	    }
	} else {
	    ss->re[i] = NULL;
	}
    }
    if (isserver) {
	char str[SSL_MAX_SSL_SESSION_ID_LENGTH+1];
	snprintf(str, SSL_MAX_SSL_SESSION_ID_LENGTH, "%lx",
		 (long)ss->ctx ^ (long)&stones);	/* randomize */
	SSL_CTX_set_session_id_context(ss->ctx, str, strlen(str));
	if (Debug > 4) {
	    message(LOG_DEBUG, "SSL session ID: %s", str);
	}
    }
    return ss;
 error:
    if (opts->verbose)
	message(LOG_INFO, "%s", ERR_error_string(ERR_get_error(), NULL));
    exit(1);
}

void rmStoneSSL(StoneSSL *ss) {
    int i;
    SSL_CTX_free(ss->ctx);
    for (i=0; i < DEPTH_MAX; i++) {
	if (ss->re[i]) {
	    regfree(ss->re[i]);
	    free(ss->re[i]);
	}
    }
    free(ss);
}
#endif

int scanStones(fd_set *rop, fd_set *eop) {
#ifdef PTHREAD
    pthread_t thread;
    int err;
#endif
    Stone *stone;
    for (stone=stones; stone != NULL; stone=stone->next) {
	int isset;
	waitMutex(FdEinMutex);
	isset = (FD_ISSET(stone->sd, eop) && FD_ISSET(stone->sd, &ein));
	if (isset) FD_CLR(stone->sd, &ein);
	freeMutex(FdEinMutex);
	if (isset) {
	    message(LOG_ERR, "stone %d: exception", stone->sd);
	} else {
	    waitMutex(FdRinMutex);
	    isset = (FD_ISSET(stone->sd, rop) && FD_ISSET(stone->sd, &rin));
	    if (isset) FD_CLR(stone->sd, &rin);
	    freeMutex(FdRinMutex);
	    if (isset) {
		if (stone->proto & proto_udp) {
		    ASYNC(asyncUDP, stone);
		} else {
		    ASYNC(asyncAccept, stone);
		}
	    }
	}
    }
    return 1;
}

void rmoldstone(void) {
    Stone *stone, *next;
    stone = oldstones;
    oldstones = NULL;
    for ( ; stone != NULL; stone=next) {
	next = stone->next;
	if (stone->port) {
	    waitMutex(FdRinMutex);
	    waitMutex(FdEinMutex);
	    FD_CLR(stone->sd, &rin);
	    FD_CLR(stone->sd, &ein);
	    freeMutex(FdEinMutex);
	    freeMutex(FdRinMutex);
	    closesocket(stone->sd);
	}
#ifdef USE_SSL
	if (stone->ssl_server) rmStoneSSL(stone->ssl_server);
	if (stone->ssl_client) rmStoneSSL(stone->ssl_client);
#endif
	free(stone);
    }
}

void rmoldconfig(void) {
    int i;
    for (i=0; i < OldConfigArgc; i++) {
	free(OldConfigArgv[i]);
    }
    OldConfigArgc = 0;
    free(OldConfigArgv);
    OldConfigArgv = NULL;
}

void repeater(void) {
    int ret;
    fd_set rout, wout, eout;
    struct timeval tv, *timeout;
    static int spin = 0;
    static int nerrs = 0;
    rout = rin;
    wout = win;
    eout = ein;
    if (conns.next || spin > 0 || AsyncCount > 0) {
	if (AsyncCount == 0 && spin > 0) spin--;
	timeout = &tv;
	timeout->tv_sec = 0;
	timeout->tv_usec = TICK_SELECT;
    } else if (MinInterval > 0) {
	timeout = &tv;
	timeout->tv_sec = MinInterval;
	timeout->tv_usec = 0;
    } else {
	timeout = NULL;		/* block indefinitely */
    }
    if (Debug > 10) {
	message(LOG_DEBUG, "select main(%ld)...",
		(timeout ? timeout->tv_usec : 0));
	message_select(LOG_DEBUG, "select main IN ", &rout, &wout, &eout);
    }
    ret = select(FD_SETSIZE, &rout, &wout, &eout, timeout);
    if (Debug > 10) {
	message(LOG_DEBUG, "select main: %d", ret);
	message_select(LOG_DEBUG, "select main OUT", &rout, &wout, &eout);
    }
    scanClose();
    if (ret > 0) {
	nerrs = 0;
	spin = SPIN_MAX;
	(void)(scanStones(&rout, &eout) > 0 &&
	       scanPairs(&rout, &wout, &eout) > 0 &&
	       scanUDP(&rout, &eout) > 0);
    } else if (ret < 0) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (errno != EINTR) {
	    message(LOG_ERR, "select error err=%d", errno);
	    if (++nerrs >= NERRS_MAX) {
		message(LOG_ERR, "select error %d times, exiting...", nerrs);
		message_select(LOG_INFO, "IN", &rin, &win, &ein);
		message_pairs();
		message_origins();
		message_conns();
		exit(1);
	    }
	}
	usleep(TICK_SELECT);
    }
    scanConns();
    if (oldstones) rmoldstone();
    if (OldConfigArgc) rmoldconfig();
}

int reusestone(Stone *stone) {
    Stone *s;
    if (!oldstones) return 0;
    for (s=oldstones; s != NULL; s=s->next) {
	if (s->port == stone->port && s->proto == stone->proto) {
	    if (Debug > 5)
		message(LOG_DEBUG, "stone %d: reused port %d", s->sd, s->port);
	    stone->sd = s->sd;
	    s->port = 0;
	    return 1;
	}
    }
    return 0;
}

/* make stone */
Stone *mkstone(
    char *dhost,	/* destination hostname */
    int dport,		/* destination port (host byte order) */
    char *host,		/* listening host */
    int port,		/* listening port (host byte order) */
    int nhosts,		/* # of hosts to permit */
    char *hosts[],	/* hosts to permit */
    int proto) {	/* UDP/TCP/SSL */
    Stone *stonep;
    struct sockaddr_in sin;
    char xhost[256], *p;
    short family;
    int allow;
    int i;
    stonep = calloc(1, sizeof(Stone)+sizeof(XHost)*nhosts);
    if (!stonep) {
	message(LOG_ERR, "Out of memory.");
	exit(1);
    }
    stonep->p = NULL;
    stonep->nhosts = nhosts;
    stonep->port = port;
    stonep->timeout = PairTimeOut;
    bzero((char *)&sin, sizeof(sin)); /* clear sin struct */
    sin.sin_family = AF_INET;
    sin.sin_port = htons((u_short)port);/* convert to network byte order */
    if (host) {
	if (!host2addr(host, &sin.sin_addr, &family)) {
	    exit(1);
	}
	sin.sin_family = family;
    }
    if ((proto & proto_command) == command_proxy
	|| (proto & proto_command) == command_health) {
	stonep->nsins = 1;
	stonep->sins = malloc(sizeof(struct sockaddr_in));	/* dummy */
    } else {
	struct sockaddr_in dsin;
	LBSet *lbset;
	if (!host2addr(dhost, &dsin.sin_addr, &family)) {
	    exit(1);
	}
	dsin.sin_family = family;
	dsin.sin_port = htons((u_short)dport);
	lbset = findLBSet(&dsin, proto);
	if (lbset) {
	    stonep->nsins = lbset->nsins;
	    stonep->sins = lbset->sins;
	} else {
	    stonep->nsins = 1;
	    stonep->sins = malloc(sizeof(dsin));
	    if (!stonep->sins) {
		message(LOG_ERR, "Out of memory");
		exit(1);
	    }
	    bcopy(&dsin, stonep->sins, sizeof(dsin));
	}
    }
    stonep->proto = proto;
    if (!reusestone(stonep)) {	/* recycle stone */
	if (proto & proto_udp) {
	    stonep->sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);/* UDP */
	} else {
	    stonep->sd = socket(AF_INET, SOCK_STREAM, 0);	/* TCP */
	    if (ReuseAddr && ValidSocket(stonep->sd)) {
		i = 1;
		setsockopt(stonep->sd, SOL_SOCKET, SO_REUSEADDR,
			   (char*)&i, sizeof(i));
	    }
	}
	if (InvalidSocket(stonep->sd)) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    message(LOG_ERR, "stone %d: Can't get socket err=%d.",
		    stonep->sd, errno);
	    exit(1);
	}
	if (!DryRun) {
	    if (bind(stonep->sd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
#ifdef WINDOWS
		errno = WSAGetLastError();
#endif
		message(LOG_ERR, "stone %d: Can't bind port=%d err=%d.",
			stonep->sd, ntohs(sin.sin_port), errno);
		exit(1);
	    }
#ifndef NO_FORK
	    fcntl(stonep->sd, F_SETFL, O_NONBLOCK);
#endif
	    if (sin.sin_port == 0) {
		i = sizeof(sin);
		getsockname(stonep->sd, (struct sockaddr*)&sin, &i);
	    }
	    if (!(proto & proto_udp)) {	/* TCP */
		if (listen(stonep->sd, BACKLOG_MAX) < 0) {
#ifdef WINDOWS
		    errno = WSAGetLastError();
#endif
		    message(LOG_ERR, "stone %d: Can't listen err=%d.",
			    stonep->sd, errno);
		    exit(1);
		}
	    }
	}	/* !DryRun */
    }
#ifdef USE_SSL
    if (proto & proto_ssl_s) {	/* server side SSL */
	stonep->ssl_server = mkStoneSSL(&ServerOpts, 1);
	if (stonep->ssl_server->lbmod) {
	    if (stonep->ssl_server->lbmod > stonep->nsins) {
		message(LOG_WARNING, "LB set (%d) < lbmod (%d)",
			stonep->nsins, stonep->ssl_server->lbmod);
		stonep->ssl_server->lbmod = stonep->nsins;
	    }
	}
    } else {
	stonep->ssl_server = NULL;
    }
    if (proto & proto_ssl_d) {	/* client side SSL */
	stonep->ssl_client = mkStoneSSL(&ClientOpts, 0);
    } else {
	stonep->ssl_client = NULL;
    }
#endif
    allow = 1;
    for (i=0; i < nhosts; i++) {
	if (!strcmp(hosts[i], "!")) {
	    stonep->xhosts[i].addr.s_addr = (u_long)~0;
	    stonep->xhosts[i].mask.s_addr = 0;
	    allow = !allow;
	    continue;
	}
	strcpy(xhost, hosts[i]);
	p = strchr(xhost, '/');
	if (p != NULL) {
	    int ndigits;
	    *p++ = '\0';
	    ndigits = isdigitaddr(p);
	    if (ndigits == 1) {
		int nbits = atoi(p);
		if (nbits <= 0 || 32 < nbits) {
		    message(LOG_ERR, "Illegal netmask: %s", p);
		    exit(1);
		}
		stonep->xhosts[i].mask.s_addr
		    = htonl((u_long)~0 << (32 - nbits));
	    } else if (!host2addr(p, &stonep->xhosts[i].mask, NULL)) {
		exit(1);
	    }
	} else {
	    stonep->xhosts[i].mask.s_addr = (u_long)~0;
	}
	if (!host2addr(xhost, &stonep->xhosts[i].addr, NULL)) {
	    exit(1);
	}
	if (Debug > 1) {
	    strcpy(xhost, addr2str(&stonep->xhosts[i].addr));
	    if ((proto & proto_command) == command_proxy) {
		message(LOG_DEBUG,
			"stone %d: %s %s (mask %x) to connecting to proxy",
			stonep->sd,
			(allow ? "permit" : "deny"),
			xhost,
			ntohl((unsigned long)stonep->xhosts[i].mask.s_addr));
	    } else if ((proto & proto_command) == command_health) {
		message(LOG_DEBUG,
			"stone %d: %s (mask %x) %s check health",
			stonep->sd,
			xhost,
			ntohl((unsigned long)stonep->xhosts[i].mask.s_addr),
			(allow ? "can" : "can't"));
	    } else {
		message(LOG_DEBUG,
			"stone %d: %s %s (mask %x) to connecting to %s:%s",
			stonep->sd,
			(allow ? "permit" : "deny"),
			xhost,
			ntohl((unsigned long)stonep->xhosts[i].mask.s_addr),
			addr2str(&stonep->sins->sin_addr),
			port2str(stonep->sins->sin_port,
				 stonep->proto, proto_dest));
	    }
	}
    }
    if ((u_long)sin.sin_addr.s_addr) {
	strcpy(xhost, addr2str(&sin.sin_addr));
	strcat(xhost, ":");
    } else {
	xhost[0] = '\0';
    }
    strcpy(xhost + strlen(xhost),
	   port2str(sin.sin_port, stonep->proto, proto_src));
    if ((proto & proto_command) == command_proxy) {
	message(LOG_INFO, "stone %d: proxy <- %s",
		stonep->sd,
		xhost);
    } else if ((proto & proto_command) == command_health) {
	message(LOG_INFO, "stone %d: health <- %s",
		stonep->sd,
		xhost);
    } else {
	message(LOG_INFO, "stone %d: %s:%s <- %s",
		stonep->sd,
		addr2str(&stonep->sins->sin_addr),
		port2str(stonep->sins->sin_port, stonep->proto, proto_dest),
		xhost);
    }
    stonep->backups = NULL;
    if ((proto & proto_command) != command_proxy
	&& (proto & proto_command) != command_health) {
	Backup *bs[LB_MAX];
	int found = 0;
	for (i=0; i < stonep->nsins; i++) {
	    bs[i] = findBackup(&stonep->sins[i], stonep->proto);
	    if (bs[i]) {
		found = 1;
		bs[i]->used = 1;
	    }
	}
	if (found) {
	    stonep->backups = malloc(sizeof(Backup*) * stonep->nsins);
	    if (stonep->backups) {
		for (i=0; i < stonep->nsins; i++) stonep->backups[i] = bs[i];
	    }
	}
    }
    return stonep;
}

/* main */

void help(char *com) {
    message(LOG_INFO, "stone %s  http://www.gcd.org/sengoku/stone/", VERSION);
    message(LOG_INFO, "%s",
	    "Copyright(C)2004 by Hiroaki Sengoku <sengoku@gcd.org>");
#ifdef USE_SSL
    message(LOG_INFO, "%s",
	    "using " OPENSSL_VERSION_TEXT "  http://www.openssl.org/");
#endif
#ifndef NT_SERVICE
    fprintf(stderr,
	    "Usage: %s <opt>... <stone> [-- <stone>]...\n"
	    "opt:  -C <file>         ; configuration file\n"
#ifdef CPP
	    "      -P <command>      ; preprocessor for config. file\n"
	    "      -Q <options>      ; options for preprocessor\n"
#endif
	    "      -N                ; configuration check only\n"
	    "      -d                ; increase debug level\n"
	    "      -p                ; packet dump\n"
	    "      -n                ; numerical address\n"
	    "      -u <max>          ; # of UDP sessions\n"
#ifndef NO_FORK
	    "      -f <n>            ; # of child processes\n"
#endif
#ifndef NO_SYSLOG
	    "      -l                ; use syslog\n"
	    "      -ll               ; run under daemontools\n"
#endif
	    "      -L <file>         ; write log to <file>\n"
	    "      -a <file>         ; write accounting to <file>\n"
	    "      -i <file>         ; write process ID to <file>\n"
	    "      -X <n>            ; size [byte] of Xfer buffer\n"
	    "      -T <n>            ; timeout [sec] of TCP sessions\n"
	    "      -r                ; reuse socket\n"
	    "      -b <n> <master>:<port> <backup>:<port>\n"
	    "                        ; backup host:port for master\n"
	    "      -B <host>:<port>..; load balancing hosts\n"
#ifndef NO_SETUID
	    "      -o <n>            ; set uid to <n>\n"
	    "      -g <n>            ; set gid to <n>\n"
#endif
#ifndef NO_CHROOT
	    "      -t <dir>          ; chroot to <dir>\n"
#endif
#ifdef UNIX_DAEMON
	    "      -D                ; become UNIX Daemon\n"
#endif
	    "      -c <dir>          ; core dump to <dir>\n"
#ifdef USE_SSL
	    "      -q <SSL>          ; SSL client option\n"
	    "      -z <SSL>          ; SSL server option\n"
#endif
	    "stone: <display> [<xhost>...]\n"
	    "       <host>:<port> <sport> [<xhost>...]\n"
	    "       proxy <sport> [<xhost>...]\n"
	    "       <host>:<port#>/http <sport> <Request-Line> [<xhost>...]\n"
	    "       <host>:<port#>/proxy <sport> <header> [<xhost>...]\n"
	    "port:  <port#>[/udp"
#ifdef USE_SSL
	    " | /ssl"
#endif
#ifdef USE_POP
	    " | /apop"
#endif
	    " | /base]\n"
	    "sport: [<host>:]<port#>[/udp"
#ifdef USE_SSL
	    " | /ssl"
#endif
	    " | /http | /base | /ident]\n"
	    "xhost: <host>[/<mask>]\n"
#ifdef USE_SSL
	    "SSL:   default          ; reset to default\n"
	    "       verbose          ; verbose mode\n"
	    "       verify           ; require peer's certificate\n"
	    "       verify,once      ; verify client's certificate only once\n"
	    "       verify,ifany     ; verify client's certificate if any\n"
	    "       verify,none      ; don't require peer's certificate\n"
	    "       uniq             ; check serial # of peer's certificate\n"
	    "       re<n>=<regex>    ; verify depth <n> with <regex>\n"
	    "       depth=<n>        ; set verification depth to <n>\n"
	    "       no_tls1          ; turn off TLSv1\n"
	    "       no_ssl3          ; turn off SSLv3\n"
	    "       no_ssl2          ; turn off SSLv2\n"
	    "       bugs             ; SSL implementation bug workarounds\n"
	    "       serverpref       ; use server's cipher preferences (SSLv2)\n"
	    "       key=<file>       ; key file\n"
	    "       cert=<file>      ; certificate file\n"
	    "       CAfile=<file>    ; certificate file of CA\n"
	    "       CApath=<dir>     ; dir of CAs\n"
	    "       cipher=<ciphers> ; list of ciphers\n"
	    "       lb<n>=<m>        ; load balancing based on CN\n"
#endif
	    , com);
#endif
    exit(1);
}

static void skipcomment(FILE *fp) {
    int c;
    while ((c=getc(fp)) != EOF && c != '\r' && c != '\n')	;
    while ((c=getc(fp)) != EOF && (c == '\r' || c == '\n'))	;
    if (c != EOF) ungetc(c, fp);
}

static int getvar(FILE *fp, char *buf, int bufmax) {
    char var[STRMAX];
    char *val;
    int i = 0;
    int paren = 0;
    int c = getc(fp);
    if (c == EOF) {
	return 0;
    } else if (c == '{') {
	paren = 1;
    } else {
	ungetc(c, fp);
    }
    while ((c=getc(fp)) != EOF && i < STRMAX-1) {
	if (paren && c == '}') {
	    break;
	} else if (isalnum(c) || c == '_') {
	    var[i++] = c;
	} else {
	    ungetc(c, fp);
	    break;
	}
    }
    var[i] = '\0';
    if (*var == '\0') return 0;
    val = getenv(var);
    if (val == NULL) return 0;
    i = strlen(val);
    if (i > bufmax) i = bufmax;
    strncpy(buf, val, i);
    return i;
}

static int gettoken(FILE *fp, char *buf) {
    int i = 0;
    int quote = 0;
    int c;
    while ((c=getc(fp)) != EOF) {
	if (c == '#') {
	    skipcomment(fp);
	    continue;
	}
	if (!isspace(c)) {
	    ungetc(c, fp);
	    break;
	}
    }
    while ((c=getc(fp)) != EOF && i < BUFMAX-1) {
	if (quote != '\'') {
	    if (c == '$') {
		i += getvar(fp, &buf[i], BUFMAX-1-i);
		continue;
	    }
	    if (c == '\\') {	/* escape a char */
		c = getc(fp);
		if (c == EOF) break;
	    }
	}
	if (quote) {
	    if (c == quote) {
		quote = 0;
		continue;
	    }
	} else if (c == '\'' || c == '\"') {
	    quote = c;
	    continue;
	} else if (isspace(c)) {
	    c = getc(fp);
	    if (c != ':' && c != '=') {
		ungetc(c, fp);
		break;
	    }
	} else if (c == '#') {
	    skipcomment(fp);
	    continue;
	}
	buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

FILE *openconfig(void) {
    int pfd[2];
    char host[MAXHOSTNAMELEN];
#ifdef CPP
    if (CppCommand != NULL && *CppCommand != '\0') {
	if (gethostname(host, MAXHOSTNAMELEN-1) < 0) {
	    message(LOG_ERR, "gethostname err=%d", errno);
	    exit(1);
	}
	if (pipe(pfd) < 0) {
	    message(LOG_ERR, "Can't get pipe err=%d", errno);
	    exit(1);
	}
	if (!fork()) {
	    char *argv[BUFMAX/2];
	    int i = 0;
	    char buf[BUFMAX];
	    int len = 0;
	    char *p;
	    if (CppOptions) {
		snprintf(buf, BUFMAX-1, "%s %s", CppCommand, CppOptions);
	    } else {
		strncpy(buf, CppCommand, BUFMAX-1);
	    }
	    argv[i] = "cpp";
	    while (buf[len]) {
		if (isspace(buf[len])) {
		    buf[len++] = '\0';
		    while (buf[len] && isspace(buf[len])) len++;
		    if (buf[len]) argv[++i] = &buf[len];
		    else break;
		}
		len++;
	    }
	    len++;
	    argv[++i] = buf + len;
	    snprintf(argv[i], BUFMAX-len, "-DHOST=%s", host);
	    len += strlen(argv[i]) + 1;
	    argv[++i] = buf + len;
	    for (p=host; *p; p++) if (*p == '.') *p = '_';
	    snprintf(argv[i], BUFMAX-len, "-DHOST_%s", host);
	    len += strlen(argv[i]) + 1;
	    if (getenv("HOME")) {
		argv[++i] = buf + len;
		snprintf(argv[i], BUFMAX-len, "-DHOME=%s", getenv("HOME"));
		len += strlen(argv[i]) + 1;
	    }
	    argv[++i] = ConfigFile;
	    argv[++i] = NULL;
	    close(pfd[0]);
	    close(1);
	    dup(pfd[1]);
	    close(pfd[1]);
	    if (Debug > 9) {
		char str[BUFMAX];
		snprintf(str, BUFMAX, "%s: ", buf);
		for (i=0; argv[i]; i++) {
		    len = strlen(str);
		    snprintf(&str[len], BUFMAX-len, " %s", argv[i]);
		}
		message(LOG_DEBUG, "%s", str);
	    }
	    execv(buf, argv);
	}
	close(pfd[1]);
	return fdopen(pfd[0], "r");
    } else
#endif
	return fopen(ConfigFile, "r");
}

void getconfig(void) {
    FILE *fp;
    int nptr = 0;
    char **new;
    char buf[BUFMAX];
    int len;
    if (ConfigFile == NULL) return;
    ConfigArgc = 0;
    ConfigArgv = NULL;
    fp = openconfig();
    if (fp == NULL) {
	message(LOG_ERR, "Can't open config file err=%d: %s",
		errno, ConfigFile);
	exit(1);
    }
    strcpy(buf, ConfigFile);
    len = strlen(buf);
    do {
	if (Debug > 9) message(LOG_DEBUG, "token: \"%s\"", buf);
	if (ConfigArgc >= nptr) {	/* allocate new ptrs */
	    new = malloc((nptr+BUFMAX)*sizeof(*ConfigArgv));
	    if (new == NULL) {
		message(LOG_ERR, "Out of memory.");
		exit(1);
	    }
	    if (ConfigArgv) {
		bcopy(ConfigArgv, new, nptr*sizeof(*ConfigArgv));
		free(ConfigArgv);
	    }
	    ConfigArgv = new;
	    nptr += BUFMAX;
	}
	ConfigArgv[ConfigArgc] = malloc(len+1);
	bcopy(buf, ConfigArgv[ConfigArgc], len+1);
	ConfigArgc++;
    } while ((len=gettoken(fp, buf)) > 0);
    fclose(fp);
#ifdef CPP
    if (CppCommand != NULL && *CppCommand != '\0') {
	wait(NULL);
    }
#endif
}

int getdist(
    char *p,
    int *portp,	/* host byte order */
    int *protop) {
    char *port_str, *proto_str, *top;
    top = p;
    port_str = proto_str = NULL;
    while (*p) {
	if (*p == ':') {
	    *p++ = '\0';
	    port_str = p;
	} else if (!proto_str && *p == '/') {
	    *p++ = '\0';
	    proto_str = p;
	}
	p++;
    }
    *protop = proto_tcp;	/* default */
    if (proto_str) {
	p = proto_str;
	do {
	    if (!strncmp(p, "tcp", 3)) {
		p += 3;
		*protop &= ~proto_udp;
		*protop |= proto_tcp;
	    } else if (!strncmp(p, "udp", 3)) {
		p += 3;
		*protop &= ~proto_tcp;
		*protop |= proto_udp;
	    } else if (!strncmp(p, "http", 4)) {
		p += 4;
		*protop |= proto_ohttp;
	    } else if (!strncmp(p, "base", 4)) {
		p += 4;
		*protop |= proto_base;
	    } else if (!strncmp(p, "ident", 5)) {
		p += 5;
		*protop |= proto_ident;
	    } else if (!strncmp(p, "proxy", 5)) {
		p += 5;
		*protop &= ~proto_command;
		*protop |= command_ihead;
#ifdef USE_SSL
	    } else if (!strncmp(p, "ssl", 3)) {
		p += 3;
		*protop |= proto_ssl;
#endif
#ifdef USE_POP
	    } else if (!strncmp(p, "apop", 4)) {
		p += 4;
		*protop &= ~proto_command;
		*protop |= command_pop;
#endif
	    } else return -1;	/* error */
	} while ((*p == ',' || *p == '/') && p++);
    }
    if (port_str) {
	*portp = str2port(port_str, *protop);
	if (*portp < 0) {
	    message(LOG_ERR, "Unknown service: %s", port_str);
	    exit(1);
	}
	return 1;
    } else {
	if (!strcmp(top, "proxy")) {
	    *protop &= ~proto_command;
	    *protop |= command_proxy;
	    *portp = 0;
	    return 1;
	}
	if (!strcmp(top, "health")) {
	    *protop &= ~proto_command;
	    *protop |= command_health;
	    *portp = 0;
	    return 1;
	}
	*portp = str2port(top, *protop);
	if (*portp < 0) {
	    message(LOG_ERR, "Unknown service: %s", top);
	    exit(1);
	}
	return 0;	/* no hostname */
    }
}

#ifdef USE_SSL
void sslopts_default(SSLOpts *opts, int isserver) {
    int i;
    opts->verbose = 0;
    opts->mode = SSL_VERIFY_NONE;
    opts->depth = DEPTH_MAX - 1;
    opts->off = 0;
    opts->serial = -2;
    opts->callback = verify_callback;
    if (isserver) {
	char path[BUFMAX];
	snprintf(path, BUFMAX-1, "%s/stone.pem", X509_get_default_cert_dir());
	opts->keyFile = opts->certFile = strdup(path);
    } else {
	opts->keyFile = opts->certFile = NULL;
    }
    opts->caFile = opts->caPath = NULL;
    opts->cipherList = getenv("SSL_CIPHER");
    for (i=0; i < DEPTH_MAX; i++) opts->regexp[i] = NULL;
    opts->lbmod = 0;
    opts->lbparm = 0xFF;
}

int sslopts(int argc, int i, char *argv[], SSLOpts *opts, int isserver) {
    if (!strcmp(argv[i], "default")) {
	sslopts_default(opts, isserver);
    } else if (!strcmp(argv[i], "verbose")) {
	opts->verbose++;
    } else if (!strncmp(argv[i], "verify", 6)
	       && (argv[i][6] == '\0' || argv[i][6] == ',')) {
	if (!strcmp(argv[i]+6, ",none")) {
	    opts->mode = SSL_VERIFY_NONE;
	} else if (isserver) {
	    opts->mode = (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
	    if (argv[i][6] == ',') {
		if (!strcmp(argv[i]+7, "ifany")) {
		    opts->mode = (SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE);
		} else if (!strcmp(argv[i]+7, "once")) {
		    opts->mode |= SSL_VERIFY_CLIENT_ONCE;
		}
	    }
	} else if (argv[i][6] == '\0') {
	    opts->mode = SSL_VERIFY_PEER;
	} else {
	    goto error;
	}
    } else if (!strncmp(argv[i], "re", 2) && isdigit(argv[i][2])
	       && argv[i][3] == '=') {
	int depth = atoi(argv[i]+2);
	if (0 <= depth && depth < DEPTH_MAX) {
	    opts->regexp[depth] = strdup(argv[i]+4);
	} else {
	    goto error;
	}
    } else if (!strncmp(argv[i], "depth=", 6)) {
	opts->depth = atoi(argv[i]+6);
	if (opts->depth >= DEPTH_MAX) opts->depth = DEPTH_MAX - 1;
	else if (opts->depth < 0) opts->depth = 0;
    } else if (!strcmp(argv[i], "bugs")) {
	opts->off |= SSL_OP_ALL;
    } else if (!strcmp(argv[i], "no_tls1")) {
	opts->off |= SSL_OP_NO_TLSv1;
    } else if (!strcmp(argv[i], "no_ssl3")) {
	opts->off |= SSL_OP_NO_SSLv3;
    } else if (!strcmp(argv[i], "no_ssl2")) {
	opts->off |= SSL_OP_NO_SSLv2;
    } else if (!strcmp(argv[i], "serverpref")) {
	opts->off |= SSL_OP_CIPHER_SERVER_PREFERENCE;
    } else if (!strcmp(argv[i], "uniq")) {
	opts->serial = -1;
    } else if (!strncmp(argv[i], "key=", 4)) {
	opts->keyFile = strdup(argv[i]+4);
    } else if (!strncmp(argv[i], "cert=", 5)) {
	opts->certFile = strdup(argv[i]+5);
    } else if (!strncmp(argv[i], "CAfile=", 7)) {
	opts->caFile = strdup(argv[i]+7);
    } else if (!strncmp(argv[i], "CApath=", 7)) {
	opts->caPath = strdup(argv[i]+7);
    } else if (!strncmp(argv[i], "cipher=", 7)) {
	opts->cipherList = strdup(argv[i]+7);
    } else if (!strncmp(argv[i], "lb", 2) && isdigit(argv[i][2])
	       && argv[i][3] == '=') {
	opts->lbparm = argv[i][2] - '0';
	opts->lbmod = atoi(argv[i]+4);
    } else {
    error:
	message(LOG_ERR, "Invalid SSL Option: %s", argv[i]);
	help(argv[0]);
    }
    return i;
}

/* SSL callback */
unsigned long sslthread_id_callback(void) {
    unsigned long ret;
#ifdef WINDOWS
    ret = (unsigned long)GetCurrentThreadId();
#else
#ifdef PTHREAD
    ret = (unsigned long)pthread_self();
#endif
#endif
    if (Debug > 8) message(LOG_DEBUG, "SSL_thread id=%ld", ret);
    return ret;
}

void sslthread_lock_callback(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
	if (Debug > 8)
	    message(LOG_DEBUG, "SSL_lock mode=%x n=%d file=%s line=%d",
		    mode, n, file, line);
#ifdef WINDOWS
	WaitForSingleObject(SSLMutex[n], 500);
#else
#ifdef PTHREAD
	pthread_mutex_lock(&SSLMutex[n]);
#endif
#endif
    } else {
	if (Debug > 8)
	    message(LOG_DEBUG, "SSL_unlock mode=%x n=%d file=%s line=%d",
		    mode, n, file, line);
#ifdef WINDOWS
	ReleaseMutex(SSLMutex[n]);
#else
#ifdef PTHREAD
	pthread_mutex_unlock(&SSLMutex[n]);
#endif
#endif
    }
}

int sslthread_initialize(void) {
    int i;
    NSSLMutexs = CRYPTO_num_locks();
    SSLMutex = malloc(NSSLMutexs * sizeof(*SSLMutex));
    if (!SSLMutex) return -1;
    if (Debug > 1) message(LOG_DEBUG, "SSL thread nlocks=%d", NSSLMutexs);
    for (i=0; i < NSSLMutexs; i++) {
#ifdef WINDOWS
	SSLMutex[i] = CreateMutex(NULL, FALSE, NULL);
	if (!SSLMutex[i]) return -1;
#else
#ifdef PTHREAD
	pthread_mutex_init(&SSLMutex[i], NULL);
#endif
#endif
    }
    CRYPTO_set_id_callback(sslthread_id_callback);
    CRYPTO_set_locking_callback(sslthread_lock_callback);
    return 1;
}
#endif

int dohyphen(char opt, int argc, char *argv[], int argi) {
    switch(opt) {
    case 'd':
	Debug++;
	break;
    case 'p':
	PacketDump = 1;
	break;
#ifndef NO_SYSLOG
    case 'l':
	Syslog++;
	break;
#endif
    case 'L':
	argi++;
	if (DryRun) break;
	if (!strcmp(argv[argi], "-")) {
	    LogFp = stdout;
	} else {
	    if (LogFp && LogFp != stderr) fclose(LogFp);
	    LogFp = fopen(argv[argi], "a");
	    if (LogFp == NULL) {
		LogFp = stderr;
		message(LOG_ERR, "Can't create log file err=%d: %s",
			errno, argv[argi]);
		exit(1);
	    }
	    LogFileName = strdup(argv[argi]);
	}
	setbuf(LogFp, NULL);
	break;
    case 'a':
	argi++;
	if (DryRun) break;
	if (!strcmp(argv[argi], "-")) {
	    AccFp = stdout;
	} else {
	    if (AccFp && AccFp != stdout) fclose(AccFp);
	    AccFp = fopen(argv[argi], "a");
	    if (AccFp == NULL) {
		message(LOG_ERR,
			"Can't create account log file err=%d: %s",
			errno, argv[argi]);
		exit(1);
	    }
	    AccFileName = strdup(argv[argi]);
	}
	setbuf(AccFp, NULL);
	break;
    case 'i':
	PidFile = strdup(argv[++argi]);
	break;
#ifndef NO_CHROOT
    case 't':
	RootDir = strdup(argv[++argi]);
	break;
#endif
    case 'n':
	AddrFlag = 1;
	break;
    case 'u':
	OriginMax = atoi(argv[++argi]);
	break;
    case 'X':
	XferBufMax = atoi(argv[++argi]);
	break;
    case 'T':
	PairTimeOut = atoi(argv[++argi]);
	break;
#ifndef NO_SETUID
    case 'o':
	SetUID = atoi(argv[++argi]);
	break;
    case 'g':
	SetGID = atoi(argv[++argi]);
	break;
#endif
    case 'c':
	CoreDumpDir = strdup(argv[++argi]);
	break;
#ifndef NO_FORK
    case 'f':
	NForks = atoi(argv[++argi]);
	break;
#endif
#ifdef UNIX_DAEMON
    case 'D':
	DaemonMode = 1;
	break;
#endif
    case 'r':
	ReuseAddr = 1;
	break;
    case 'b':
	mkBackup(atoi(argv[argi+1]), argv[argi+2], argv[argi+3]);
	argi += 3;
	break;
    case 'B':
	argi = lbsopts(argc, argi, argv);
	break;
#ifdef USE_SSL
    case 'q':
	if (++argi >= argc) {
	    message(LOG_ERR, "Illegal Option: -q without <SSL>");
	    exit(1);
	}
	argi = sslopts(argc, argi, argv, &ClientOpts, 0);
	break;
    case 'z':
	if (++argi >= argc) {
	    message(LOG_ERR, "Illegal Option: -z without <SSL>");
	    exit(1);
	}
	argi = sslopts(argc, argi, argv, &ServerOpts, 1);
	break;
#endif
#ifdef CPP
    case 'P':
	CppCommand = strdup(argv[++argi]);
	break;
    case 'Q':
	CppOptions = strdup(argv[++argi]);
	break;
#endif
    default:
	return -1;
    }
    return argi;
}

int doopts(int argc, char *argv[]) {
    int i;
    char *p;
    FILE *fp;
    for (i=1; i < argc; i++) {
	p = argv[i];
	if (*p == '-') {
	    p++;
	    while(*p) {
		int ret = dohyphen(*p, argc, argv, i);
		if (ret >= 0) {
		    i = ret;
		} else switch(*p) {
		case '-':	/* end of global options */
		    return i+1;
		case 'N':
		    DryRun = 1;
		    break;
		case 'C':
		    if (!ConfigFile) {
			i++;
			ConfigFile = malloc(strlen(argv[i]) + 1);
			if (ConfigFile == NULL) {
			    message(LOG_ERR, "Out of memory.");
			    exit(1);
			}
			strcpy(ConfigFile, argv[i]);
			break;
		    }	/* drop through */
		default:
		    message(LOG_ERR, "Invalid Option: %s", argv[i]);
		    help(argv[0]);
		}
		p++;
	    }
	} else break;
    }
    return i;
}

void doargs(int argc, int i, char *argv[]) {
    Stone *stone;
    char *host, *shost;
    int port, sport;
    int proto, sproto, dproto;
    char *p;
    int j, k;
    proto = sproto = dproto = proto_tcp;	/* default: TCP */
    if (argc - i < 1) help(argv[0]);
    for (; i < argc; i++) {
	p = argv[i];
	if (*p == '-') {
	    p++;
	    while(*p) {
		int ret = dohyphen(*p, argc, argv, i);
		if (ret >= 0) {
		    i = ret;
		} else {
		    message(LOG_ERR, "Invalid Option: %s", argv[i]);
		    help(argv[0]);
		}
		p++;
	    }
	    continue;
	}
	j = getdist(argv[i], &port, &dproto);
	if (j > 0) {	/* with hostname */
	    host = argv[i++];
	    if (argc <= i) help(argv[0]);
	    j = getdist(argv[i], &sport, &sproto);
	    if (j > 0) {
		shost = argv[i];
	    } else if (j == 0) {
		shost = NULL;
	    } else help(argv[0]);
	} else if (j == 0 && DispHost != NULL) {
	    shost = NULL;	/* without hostname i.e. Display Number */
	    sport = port+XPORT;
	    host = DispHost;
	    port = DispPort;
	    dproto = proto_tcp;
	} else help(argv[0]);
	i++;
	j = 0;
	k = i;
	for (; i < argc; i++, j++) if (!strcmp(argv[i], "--")) break;
	if ((dproto & proto_udp) || (sproto & proto_udp)) {
	    proto &= ~proto_tcp;
	    proto |= proto_udp;
	} else {
	    if (sproto & proto_ohttp) proto |= proto_ohttp_s;
	    if (sproto & proto_ssl) proto |= proto_ssl_s;
	    if (sproto & proto_base) proto |= proto_base_s;
	    if (sproto & proto_ident) proto |= proto_ident;
	    if ((dproto & proto_command) == command_proxy) {
		proto &= ~proto_command;
		proto |= command_proxy;
#ifdef USE_POP
	    } else if ((dproto & proto_command) == command_pop) {
		proto &= ~proto_command;
		proto |= command_pop;
#endif
	    } else if (dproto & proto_ohttp) {
		proto |= proto_ohttp_d;
		goto extra_arg;
	    } else if ((dproto & proto_command) == command_ihead) {
		proto &= ~proto_command;
		proto |= command_ihead;
	      extra_arg:
		p = argv[k++];
		j--;
		if (k > argc || j < 0) help(argv[0]);
	    } else if ((dproto & proto_command) == command_health) {
		proto &= ~proto_command;
		proto |= command_health;
	    }
	    if (dproto & proto_ssl) proto |= proto_ssl_d;
	    if (dproto & proto_base) proto |= proto_base_d;
	}
	stone = mkstone(host, port, shost, sport, j, &argv[k], proto);
	if (proto & proto_ohttp_d) {
	    stone->p = strdup(p);
	} else if ((proto & proto_command) == command_ihead) {
	    stone->p = strdup(p);
	}
	stone->next = stones;
	stones = stone;
	proto = sproto = dproto = proto_tcp;	/* default: TCP */
    }
    for (stone=stones; stone != NULL; stone=stone->next) {
	FdSet(stone->sd, &rin);
	FdSet(stone->sd, &ein);
    }
}

#ifdef FD_SET_BUG
void checkFdSetBug(void) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(0, &set);
    FD_SET(0, &set);
    FD_CLR(0, &set);
    if (FD_ISSET(0, &set)) {
	if (Debug > 0)
	    message(LOG_DEBUG, "FD_SET bug detected");
	FdSetBug = 1;
    }
}
#endif

#ifndef WINDOWS
static void handler(int sig) {
    static unsigned int g = 0;
    static int cnt = 0;
    int i;
    switch(sig) {
    case SIGHUP:
	if (Debug > 4) message(LOG_DEBUG, "SIGHUP.");
#ifndef NO_FORK
	if (NForks) {	/* mother process */
	    if (ConfigFile && !oldstones) {
	        oldstones = stones;
		stones = NULL;
		OldConfigArgc = ConfigArgc;
		OldConfigArgv = ConfigArgv;
		Debug = 0;
		getconfig();	/* reconfigure */
		i = doopts(ConfigArgc, ConfigArgv);
		doargs(ConfigArgc, i, ConfigArgv);
		for (i=0; i < NForks; i++) {
		    kill(Pid[i], SIGHUP);
		    kill(Pid[i], SIGINT);
		}
	    }
	} else {	/* child process */
#endif
	    message_pairs();
	    message_origins();
	    message_conns();
#ifndef NO_FORK
	}
#endif
	if (LogFileName) {
	    fclose(LogFp);
	    LogFp = fopen(LogFileName, "a");
	    if (LogFp == NULL) {
		LogFp = stderr;
		message(LOG_ERR, "Can't re-create log file err=%d: %s",
			errno, LogFileName);
		exit(1);
	    }
	    setbuf(LogFp, NULL);
	}
	if (AccFileName) {
	    fclose(AccFp);
	    AccFp = fopen(AccFileName, "a");
	    if (AccFp == NULL) {
		message(LOG_ERR,
			"Can't re-create account log file err=%d: %s",
			errno, AccFileName);
		exit(1);
	    }
	    setbuf(AccFp, NULL);
	}
	signal(SIGHUP, handler);
	break;
    case SIGTERM:
#ifdef IGN_SIGTERM
	Debug = 0;
	message(LOG_INFO, "SIGTERM. clear Debug level");
	signal(SIGTERM, handler);
	break;
#endif
    case SIGINT:
#ifndef NO_FORK
	if (NForks) {	/* mother process */
	    message(LOG_INFO, "SIGTERM/INT. killing children and exiting...");
	    for (i=0; i < NForks; i++) kill(Pid[i], sig);
	} else
#endif
	    message(LOG_INFO, "SIGTERM/INT. exiting...");  /* child process */
	exit(1);
    case SIGUSR1:
	Debug++;
	message(LOG_INFO, "SIGUSR1. increase Debug level to %d", Debug);
	signal(SIGUSR1, handler);
	break;
    case SIGUSR2:
	if (Debug > 0) Debug--;
	message(LOG_INFO, "SIGUSR2. decrease Debug level to %d", Debug);
	signal(SIGUSR2, handler);
	break;
    case SIGPIPE:
	if (Debug > 0) message(LOG_DEBUG, "SIGPIPE.");
	signal(SIGPIPE, handler);
	break;
    case SIGSEGV:
    case SIGBUS:
    case SIGILL:
    case SIGFPE:
	if (CoreDumpDir) {
	    message(LOG_ERR, "Signal %d, core dumping to %s",
		    sig, CoreDumpDir);
	    if (chdir(CoreDumpDir) < 0) {
		message(LOG_ERR, "Can't chdir to %s err=%d",
			CoreDumpDir, errno);
	    } else {
		abort();
	    }
	} else {
	    message(LOG_ERR, "Signal %d, exiting...");
	}
	exit(1);
	break;
    default:
	message(LOG_INFO, "signal %d. Debug level: %d", sig, Debug);
    }
}
#endif

#ifdef UNIX_DAEMON
void daemonize(void) {
    pid_t pid;
    pid = fork();
    if (pid < 0) {
	message(LOG_ERR, "Can't create daemon err=%d", errno);
	exit(1);
    } 
    if (pid > 0) _exit(0);
    MyPid = getpid();
    if (setsid() < 0)
	message(LOG_WARNING, "Can't create new session err=%d", errno);
    if (chdir("/") < 0)
	message(LOG_WARNING, "Can't change directory to / err=%d", errno);
    umask(0022);
    if (close(0) != 0)
	message(LOG_WARNING, "Can't close stdin err=%d", errno);
    if (close(1) != 0)
	message(LOG_WARNING, "Can't close stdout err=%d", errno);
#ifndef NO_SYSLOG
    if (Syslog > 1) Syslog = 1;
#endif
    if (!LogFileName) LogFp = NULL;
    if (close(2) != 0)
	message(LOG_WARNING, "Can't close stderr err=%d", errno);
}
#endif

void initialize(int argc, char *argv[]) {
    int i, j;
    char display[256], *p;
    int proto;
#ifdef WINDOWS
    WSADATA WSAData;
    if (WSAStartup(MAKEWORD(1, 1), &WSAData)) {
	message(LOG_ERR, "Can't find winsock.");
	exit(1);
    }
    atexit((void(*)(void))WSACleanup);
#endif
    MyPid = getpid();
    LogFp = stderr;
    setbuf(stderr, NULL);
    DispHost = NULL;
    p = getenv("DISPLAY");
    if (p) {
	if (*p == ':') {
	    sprintf(display, "localhost%s", p);
	} else {
	    strcpy(display, p);
	}
	i = 0;
	for (p=display; *p; p++) {
	    if (*p == ':') i = 1;
	    else if (i && *p == '.') {
		*p = '\0';
		break;
	    }
	}
	if (getdist(display, &DispPort, &proto) > 0) {
	    DispHost = display;
	    DispPort += XPORT;
	} else {
	    message(LOG_ERR, "Illegal DISPLAY: %s", p);
	}
    }
#ifdef USE_SSL
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    PairIndex = SSL_get_ex_new_index(0, "Pair index", NULL, NULL, NULL);
    sslopts_default(&ServerOpts, 1);
    sslopts_default(&ClientOpts, 0);
#endif
    i = doopts(argc, argv);
    if (ConfigFile) {
	getconfig();
	j = doopts(ConfigArgc, ConfigArgv);
    }
#ifdef UNIX_DAEMON
    if (DaemonMode) daemonize();
#endif
    if (!DryRun && PidFile) {
	FILE *fp = fopen(PidFile, "w");
	if (fp) {
	    fprintf(fp, "%d\n", MyPid);
	    fclose(fp);
	}
    }
#ifndef NO_SYSLOG
    if (Syslog) {
	sprintf(SyslogName, "stone[%d]", MyPid);
	openlog(SyslogName, 0, LOG_DAEMON);
	if (Syslog > 1) setbuf(stdout, NULL);
    }
#endif
    message(LOG_INFO, "start (%s) [%d]", VERSION, MyPid);
    if (Debug > 0) {
	message(LOG_DEBUG, "Debug level: %d", Debug);
    }
    pairs.next = NULL;
    conns.next = NULL;
    origins.next = NULL;
#ifdef FD_SET_BUG
    checkFdSetBug();
#endif
    FD_ZERO(&rin);
    FD_ZERO(&win);
    FD_ZERO(&ein);
    if (ConfigFile && ConfigArgc > j) {
	if (argc > i) doargs(argc, i, argv);
	doargs(ConfigArgc, j, ConfigArgv);
    } else {
	doargs(argc, i, argv);
    }
    if (!(pkt_buf=malloc(pkt_len_max=PKT_LEN_INI))) {
	message(LOG_ERR, "Out of memory.");
	exit(1);
    }
#ifndef WINDOWS
    signal(SIGHUP, handler);
    signal(SIGTERM, handler);
    signal(SIGINT, handler);
    signal(SIGPIPE, handler);
    signal(SIGUSR1, handler);
    signal(SIGUSR2, handler);
    signal(SIGSEGV, handler);
    signal(SIGBUS, handler);
    signal(SIGILL, handler);
    signal(SIGFPE, handler);
#endif
#ifndef NO_FORK
    if (!DryRun && NForks) {
	Pid = malloc(sizeof(pid_t) * NForks);
	if (!Pid) {
	    message(LOG_ERR, "Out of memory.");
	    exit(1);
	}
	for (i=0; i < NForks; i++) {
	    Pid[i] = fork();
	    if (!Pid[i]) break;
	}
	if (i >= NForks) {	/* the mother process */
	    pid_t id;
	    for (;;) {
		int status;
		id = wait(&status);
		if (id < 0) continue;
		message(LOG_WARNING, "Process died pid=%d, status=%x",
			id, status);
		for (i=0; i < NForks; i++) {
		    if (Pid[i] == id) break;
		}
		if (i < NForks) {
		    id = fork();
		    if (!id) break;	/* respawned child */
		    else Pid[i] = id;
		} else {
		    message(LOG_ERR, "This can't happen pid=%d", id);
		}
	    }
	}
	free(Pid);	/* child process */
	Pid = NULL;
	NForks = 0;
	MyPid = getpid();
#ifndef NO_SYSLOG
	if (Syslog) {
	    closelog();
	    sprintf(SyslogName, "stone[%d]", MyPid);
	    openlog(SyslogName, 0, LOG_DAEMON);
	}
#endif
	message(LOG_INFO, "child start (%s) [%d]", VERSION, MyPid);
    }
#endif
#ifdef PTHREAD
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
#endif
#ifdef WINDOWS
    PairMutex = ConnMutex = OrigMutex = AsyncMutex = NULL;
    if (!(PairMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(ConnMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(OrigMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(AsyncMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(FdRinMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(FdWinMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(FdEinMutex=CreateMutex(NULL, FALSE, NULL))) {
	message(LOG_ERR, "Can't create Mutex err=%d", GetLastError());
    }
#endif
#ifdef OS2
    PairMutex = ConnMutex = OrigMutex = AsyncMutex = NULLHANDLE;
    if ((j=DosCreateMutexSem(NULL, &PairMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &ConnMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &OrigMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &AsyncMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &FdRinMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &FdWinMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &FdEinMutex, 0, FALSE))) {
	message(LOG_ERR, "Can't create Mutex err=%d", j);
    }
#endif
#ifdef USE_SSL
    if (sslthread_initialize() < 0) {
	message(LOG_ERR, "Fail to initialize SSL callback");
    }
#endif
#ifndef NO_CHROOT
    if (RootDir) {
	if (chroot(RootDir) < 0) {
	    message(LOG_WARNING, "Can't change root directory to %s", RootDir);
	}
    }
#endif
#ifndef NO_SETUID
    if (SetUID || SetGID) {
	if (AccFileName) fchown(fileno(AccFp), SetUID, SetGID);
	if (LogFileName) fchown(fileno(LogFp), SetUID, SetGID);
    }
    if (SetGID) if (setgid(SetGID) < 0) {
	message(LOG_WARNING, "Can't set gid err=%d.", errno);
    }
    if (SetUID) if (setuid(SetUID) < 0) {
	message(LOG_WARNING, "Can't set uid err=%d.", errno);
    }
#endif
#ifdef PR_SET_DUMPABLE
    if (CoreDumpDir && (SetUID || SetGID)) {
	if (prctl(PR_SET_DUMPABLE, 1) < 0) {
	    message(LOG_ERR, "prctl err=%d", errno);
	}
    }
#endif
    if (MinInterval > 0) {
	if (Debug > 1) message(LOG_DEBUG, "MinInterval: %d", MinInterval);
    }
    time(&lastEstablished);
    lastReadWrite = lastEstablished;
}

#ifdef NT_SERVICE
/* Main thread - runs until event becomes signalled */
DWORD WINAPI ThreadProc(LPVOID lpParms) {
    HANDLE hStopEvent;
    char *lpArgs[3];
    char *p;
    AddToMessageLog("Starting worker thread...");
    hStopEvent = (HANDLE)lpParms;
    if (NULL == hStopEvent) {
	AddToMessageLog("Invalid event handle.");
	ExitThread(1);
    }
    lpArgs[0] = "stone";
    lpArgs[1] = "-C";
    lpArgs[2] = (char*)malloc(MAX_PATH * 2);
    if (! lpArgs[2]) {
	AddToMessageLog("Can't allocate args buffers.");
	ExitThread(2);
    }
    if (0 == GetModuleFileName(NULL, lpArgs[2], MAX_PATH * 2)) {
	AddToMessageLog("Can't get module filename.");
	ExitThread(3);		
    }
    p = strrchr(lpArgs[2], '.');
    if (NULL == p) strcat(lpArgs[2], ".cfg");
    else strcpy(p, ".cfg");
    initialize(3, lpArgs);
    free(lpArgs[2]);
    do {
	repeater();    	
    } while (WAIT_TIMEOUT == WaitForSingleObject(hStopEvent, 1));
    AddToMessageLog("Exiting worker thread");
    ExitThread(0);
    return 0;
}

long svc_main(HANDLE hStopEvent) {	/* Entry point for the service call */
    long thread_id;
    HANDLE hThread;
    hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ThreadProc,
			   (LPVOID)hStopEvent, 0, &thread_id);
    return hThread != NULL;
}
#else
static void clear_args(int argc, char *argv[]) {
    char *argend = argv[argc-1] + strlen(argv[argc-1]);
    char *p;
    for (p=argv[1]; p < argend; p++) *p = '\0';	/* clear args */
}

int main(int argc, char *argv[]) {
    initialize(argc, argv);
    if (DryRun) return 0;
    clear_args(argc, argv);
    for (;;) repeater();
    return 0;
}
#endif

/*
  For Gnu Emacs.
  Local Variables:
  tab-width: 8
  c-basic-offset: 4
  End:
*/
