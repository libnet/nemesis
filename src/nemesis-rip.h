/*
 * $Id: nemesis-rip.h,v 1.1.1.1.4.1 2005/01/27 20:14:53 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-rip.h (RIP Packet Injector)
 *
 */

#ifndef __NEMESIS_RIP_H__
#define __NEMESIS_RIP_H__

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
#if defined(HAVE_MACHINE_ENDIAN_H)
    #include <machine/endian.h>
#endif
#if defined(HAVE_NETINET_IN_H)
    #include <netinet/in.h>
#elif defined(WIN32)
    #include <winsock2.h>
#endif
#include <libnet.h>
#include "nemesis.h"

int buildrip(ETHERhdr *, IPhdr *, UDPhdr *, RIPhdr *, FileData *,
        FileData *, libnet_t *);

#endif /* __NEMESIS_RIP_H__ */
