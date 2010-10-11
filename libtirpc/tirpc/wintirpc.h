/* Copyright (c) 2010
 * The Regents of the University of Michigan
 * All Rights Reserved
 *
 * Permission is granted to use, copy and redistribute this software
 * for noncommercial education and research purposes, so long as no
 * fee is charged, and so long as the name of the University of Michigan
 * is not used in any advertising or publicity pertaining to the use
 * or distribution of this software without specific, written prior
 * authorization.  Permission to modify or otherwise create derivative
 * works of this software is not granted.
 *
 * This software is provided as is, without representation or warranty
 * of any kind either express or implied, including without limitation
 * the implied warranties of merchantability, fitness for a particular
 * purpose, or noninfringement.  The Regents of the University of
 * Michigan shall not be liable for any damages, including special,
 * indirect, incidental, or consequential damages, with respect to any
 * claim arising out of or in connection with the use of the software,
 * even if it has been or is hereafter advised of the possibility of
 * such damages.
 */

#ifndef _TIRPC_WINTIRPC_H
#define _TIRPC_WINTIRPC_H

/*
 * Eliminate warnings about possibly unsafe uses of snprintf and friends
 * XXX Think about cleaning these up and removing this later XXX
 */
#define _CRT_SECURE_NO_WARNINGS 1


#ifdef _DEBUG
/* use visual studio's debug heap */
# define _CRTDBG_MAP_ALLOC
# include <stdlib.h>
# include <crtdbg.h>
#else
# include <stdlib.h>
#endif

/* Common Windows includes */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <basetsd.h>

#define snprintf _snprintf
//#define vsnprintf _vsnprintf
#define strcasecmp _stricmp
#define strdup _strdup
#define getpid _getpid

#define bcmp memcmp
#define bcopy(d,s,l) memcpy(d,s,l)
#define bzero(d,s) memset(d,0,s)
#define strtok_r strtok_s

#define poll WSAPoll
#define ioctl ioctlsocket

#define __BEGIN_DECLS
#define __END_DECLS
#define __THROW

/*
 * Hash of Windows Socket Handle values
 */
#define WINSOCK_HANDLE_HASH_SIZE	1024
#define WINSOCK_HANDLE_HASH(x) (((x) >> 2) % WINSOCK_HANDLE_HASH_SIZE)

/*
 * Functions imported from BSD
 */
struct timezone 
{
  int  tz_minuteswest; /* minutes W of Greenwich */
  int  tz_dsttime;     /* type of dst correction */
};

extern int gettimeofday(struct timeval *tv, struct timezone *tz);
extern int asprintf(char **str, const char *fmt, ...);

#define SOL_IPV6 IPPROTO_IPV6

#define MAXHOSTNAMELEN 256

struct sockaddr_un {
	int sun_family;
	char sun_path[MAX_PATH];
};
/* Evaluate to actual length of the sockaddr_un structure */
/* XXX Should this return size_t or unsigned int ?? */
#define SUN_LEN(ptr) ((unsigned int)(sizeof(int) + strlen ((ptr)->sun_path)))

/* Debugging function */
void wintirpc_debug(char *fmt, ...);

#endif /* !_TIRPC_WINTIRPC_H */
