/*
 * $Id: nemesis-icmp.h,v 1.1.1.1 2003/10/31 21:29:36 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * 
 * nemesis-icmp.h (ICMP Packet Injector)
 * 
 */

#ifndef __NEMESIS_ICMP_H__
#define __NEMESIS_ICMP_H__

#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#if defined(WIN32)
    #include <pcap.h>
#endif
#if defined(TIME_WITH_SYS_TIME) || defined(WIN32)
    #include <sys/time.h>
    #include <time.h>
#else
    #if defined(HAVE_SYS_TIME_H)
        #include <sys/time.h>
    #elif defined(HAVE_TIME_H)
        #include <time.h>
    #endif
#endif
#if defined(HAVE_NETINET_IN_H)
    #include <netinet/in.h>
#elif defined(WIN32)
    #include <winsock2.h>
#endif
#include <libnet.h>
#include "nemesis.h"

int mode;   /* ICMP injection mode */
int got_origoptions;

int buildicmp(ETHERhdr *, IPhdr *, ICMPhdr *, IPhdr *, FileData *, FileData *, 
        FileData *, char *);

#endif /* __NEMESIS_ICMP_H__ */
