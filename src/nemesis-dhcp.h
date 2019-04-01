/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * Copyright (C) 2019 Joachim Nilsson <troglobit@gmail.com>
 *
 * nemesis-dhcp.h (DHCP Packet Injector)
 */

#ifndef NEMESIS_DHCP_H_
#define NEMESIS_DHCP_H_

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

int builddhcp(ETHERhdr *, IPhdr *, UDPhdr *, DHCPhdr *, struct file *, struct file *, libnet_t *);

#endif /* NEMESIS_DHCP_H_ */
