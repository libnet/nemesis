/*
 * $Id: nemesis-ospf.h,v 1.1.1.1.4.1 2005/01/27 20:14:53 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * 
 * nemesis-ospf.h (OSPF Packet Injector)
 * 
 */

#ifndef __NEMESIS_OSPF_H__
#define __NEMESIS_OSPF_H__

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
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
#include "nemesis.h"
#include <libnet.h>

extern OSPFhdr      ospfhdr;
extern OSPFHELLOhdr ospfhellohdr;
extern LSAhdr       lsahdr;
extern LSRhdr       lsrhdr;
extern LSUhdr       lsuhdr;
extern ASLSAhdr     aslsahdr;
extern RTRLSAhdr    rtrlsahdr;
extern DBDhdr       dbdhdr;
extern NETLSAhdr    netlsahdr;
extern SUMLSAhdr    sumlsahdr;

int mode; /* OSPF injection mode */

int buildospf(ETHERhdr *, IPhdr *, FileData *, FileData *, libnet_t *, int);

#endif /* __NEMESIS_OSPF_H__ */
