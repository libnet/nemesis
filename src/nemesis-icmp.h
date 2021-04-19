/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * 
 * nemesis-icmp.h (ICMP Packet Injector)
 */

#ifndef NEMESIS_ICMP_H_
#define NEMESIS_ICMP_H_

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
#include "nemesis.h"
#include <libnet.h>

int mode; /* ICMP injection mode */
int got_origoptions;

int buildicmp(ETHERhdr *, IPhdr *, ICMPhdr *, IPhdr *, struct file *, struct file *, struct file *, libnet_t *);

#endif /* NEMESIS_ICMP_H_ */
