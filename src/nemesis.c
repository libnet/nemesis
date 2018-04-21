/*
 * $Id: nemesis.c,v 1.1.1.1.4.1 2005/01/27 20:14:53 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis.c (main)
 */

#include "nemesis.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int optind;

void usage(char *arg)
{
	char *module = "NEMESIS";

	nemesis_maketitle(title, module, version);
	nemesis_printtitle((const char *)title);

	printf("NEMESIS Usage:\n"
	       "  %s [mode] [options]\n"
	       "\n"
	       "NEMESIS modes:\n"
	       "  arp\n"
	       "  dns\n"
	       "  ethernet\n"
	       "  icmp\n"
	       "  igmp\n"
	       "  ip\n"
	       "  ospf\n"
	       "  rip\n"
	       "  tcp\n"
	       "  udp\n"
	       "\n"
	       "NEMESIS options:\n"
	       "  To display options, specify a mode with the option \"help\".\n"
	       "\n", arg);

	exit(1);
}

int main(int argc, char **argv)
{
	char **avtmp, *avval;

	avtmp = argv;
	avval = strrchr(*avtmp, '/');
	if (!avval)
		avval = *avtmp;
	else
		avval++;

	if (!strncmp(avval, "nemesis-arp", 11)) {
		nemesis_arp(argc, argv);
	} else if (argc > 1 && !strncmp(argv[1], "arp", 3)) {
		argv += optind;
		argc -= optind;
		nemesis_arp(argc, argv);
	} else if (!strncmp(avval, "nemesis-dns", 11)) {
		nemesis_dns(argc, argv);
	} else if (argc > 1 && !strncmp(argv[1], "dns", 3)) {
		argv += optind;
		argc -= optind;
		nemesis_dns(argc, argv);
	} else if (!strncmp(avval, "nemesis-ethernet", 16)) {
		nemesis_ethernet(argc, argv);
	} else if (argc > 1 && !strncmp(argv[1], "ethernet", 8)) {
		argv += optind;
		argc -= optind;
		nemesis_ethernet(argc, argv);
	} else if (!strncmp(avval, "nemesis-icmp", 12)) {
		nemesis_icmp(argc, argv);
	} else if (argc > 1 && !strncmp(argv[1], "icmp", 4)) {
		argv += optind;
		argc -= optind;
		nemesis_icmp(argc, argv);
	} else if (!strncmp(avval, "nemesis-igmp", 12)) {
		nemesis_igmp(argc, argv);
	} else if (argc > 1 && !strncmp(argv[1], "igmp", 4)) {
		argv += optind;
		argc -= optind;
		nemesis_igmp(argc, argv);
	} else if (!strncmp(avval, "nemesis-ip", 10)) {
		nemesis_ip(argc, argv);
	} else if (argc > 1 && !strncmp(argv[1], "ip", 2)) {
		argv += optind;
		argc -= optind;
		nemesis_ip(argc, argv);
	} else if (!strncmp(avval, "nemesis-ospf", 12)) {
		nemesis_ospf(argc, argv);
	} else if (argc > 1 && !strncmp(argv[1], "ospf", 4)) {
		argv += optind;
		argc -= optind;
		nemesis_ospf(argc, argv);
	} else if (!strncmp(avval, "nemesis-rip", 11)) {
		nemesis_rip(argc, argv);
	} else if (argc > 1 && !strncmp(argv[1], "rip", 3)) {
		argv += optind;
		argc -= optind;
		nemesis_rip(argc, argv);
	} else if (!strncmp(avval, "nemesis-tcp", 11)) {
		nemesis_tcp(argc, argv);
	} else if (argc > 1 && !strncmp(argv[1], "tcp", 3)) {
		argv += optind;
		argc -= optind;
		nemesis_tcp(argc, argv);
	} else if (!strncmp(avval, "nemesis-udp", 11)) {
		nemesis_udp(argc, argv);
	} else if (argc > 1 && !strncmp(argv[1], "udp", 3)) {
		argv += optind;
		argc -= optind;
		nemesis_udp(argc, argv);
	} else
		usage(argv[0]);

	/* NOTREACHED */
	exit(0);
}
