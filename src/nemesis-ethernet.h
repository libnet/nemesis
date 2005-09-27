/*
 * $Id: nemesis-ethernet.h,v 1.2 2005/09/27 19:46:19 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-ethernet.h (Ethernet Packet Injector)
 *
 */

#ifndef __NEMESIS_ETHERNET_H__
#define __NEMESIS_ETHERNET_H__

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
#if defined(HAVE_NETINET_IN_H)
    #include <netinet/in.h>
#elif defined(WIN32)
    #include <winsock2.h>
#endif
#include <libnet.h>
#include "nemesis.h"

#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q         0x8100  /* IEEE 802.1Q VLAN tagging */
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6          0x86DD  /* IPv6 protocol */
#endif

#ifndef ETHERTYPE_PPOEDISC
#define ETHERTYPE_PPPOEDISC     0x8863  /* PPP Over Ethernet Discovery Stage */
#endif

#ifndef ETHERTYPE_PPOE
#define ETHERTYPE_PPPOE         0x8864  /* PPP Over Ethernet Session Stage */
#endif

int buildether(ETHERhdr *eth, FileData *pd, char *device);

#endif /* __NEMESIS_ETHERNET_H__ */
