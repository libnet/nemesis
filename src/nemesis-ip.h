/*
 * $Id: nemesis-ip.h,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 * Original version submitted by ocsic <pisco@private.as>
 *
 * nemesis-ip.h (IP Packet Injector)
 *
 */

#ifndef __NEMESIS_IP_H__
#define __NEMESIS_IP_H__

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#if defined(WIN32)
    #include <pcap.h>
#endif
#if defined(HAVE_NETINET_IN_H)
    #include <netinet/in.h>
#elif defined(WIN32)
    #include <winsock2.h>
#endif
#include <libnet.h>
#include "nemesis.h"

int buildip(ETHERhdr *, IPhdr *, FileData *, FileData *, char *);

#endif /* __NEMESIS_IP_H__ */
