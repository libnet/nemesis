/*
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 * Original version submitted by ocsic <pisco@private.as>
 *
 * nemesis-ip.h (IP Packet Injector)
 */

#ifndef NEMESIS_IP_H_
#define NEMESIS_IP_H_

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

int buildip(ETHERhdr *, IPhdr *, struct file *, struct file *, libnet_t *);

#endif /* NEMESIS_IP_H_ */
