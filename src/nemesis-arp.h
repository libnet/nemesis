/*
 * $Id: nemesis-arp.h,v 1.1.1.1 2003/10/31 21:29:36 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeffsnort.org>
 *
 * nemesis-arp.h (ARP Packet Injector)
 *
 */

#ifndef __NEMESIS_ARP_H__
#define __NEMESIS_ARP_H__

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
#if defined(HAVE_NETINET_IP_VAR_H)
    #include <netinet/in.h>
#elif defined(WIN32)
    #include <winsock2.h>
#endif
#include <libnet.h>
#include "nemesis.h"

int buildarp(ETHERhdr *, ARPhdr *, FileData *, char *, int);

#endif /* __NEMESIS_ARP_H__ */
