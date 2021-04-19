/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-dns.h (DNS Packet Injector)
 */

#ifndef NEMESIS_DNS_H_
#define NEMESIS_DNS_H_

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
#if defined(HAVE_NETINET_IN_H)
#include <netinet/in.h>
#elif defined(WIN32)
#include <winsock2.h>
#endif
#include "nemesis.h"
#include <libnet.h>

int state; /* default to UDP */

int builddns(ETHERhdr *, IPhdr *, TCPhdr *, UDPhdr *, DNShdr *, struct file *, struct file *, struct file *, libnet_t *);

#endif /* NEMESIS_DNS_H_ */
