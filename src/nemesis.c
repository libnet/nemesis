/*
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

static int usage(char *arg)
{
	char *module = "NEMESIS";

	nemesis_maketitle(title, module, version);
	nemesis_printtitle(title);

	printf("NEMESIS Usage:\n"
	       "  %s [mode] [options]\n"
	       "\n"
	       "NEMESIS modes:\n"
	       "  arp\n"
	       "  dns\n"
	       "  dhcp\n"
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
	       "\n",
	       arg);

	return 1;
}

static char *progname(char *arg0)
{
	char *nm;

	nm = strrchr(arg0, '/');
	if (nm)
		nm++;
	else
		nm = arg0;

	return nm;
}

int main(int argc, char **argv)
{
	struct {
		char *name;
		char *link;
		void (*func)(int, char **);
	} mod[] = {
		{ "arp", "nemesis-arp", nemesis_arp },
		{ "dns", "nemesis-dns", nemesis_dns },
		{ "dhcp", "nemesis-dhcp", nemesis_dhcp },
		{ "ethernet", "nemesis-ethernet", nemesis_ethernet },
		{ "icmp", "nemesis-icmp", nemesis_icmp },
		{ "igmp", "nemesis-igmp", nemesis_igmp },
		{ "ip", "nemesis-ip", nemesis_ip },
		{ "ospf", "nemesis-ospf", nemesis_ospf },
		{ "rip", "nemesis-rip", nemesis_rip },
		{ "tcp", "nemesis-tcp", nemesis_tcp },
		{ "udp", "nemesis-udp", nemesis_udp },
		{ NULL, NULL, NULL },
	};
	int i;

	prognm = progname(argv[0]);

	for (i = 0; mod[i].name; i++) {
		if (!strncmp(prognm, mod[i].link, 11))
			mod[i].func(argc, argv);
		else if (argc == 1)
			continue;
		else if (!strncmp(argv[1], mod[i].name, strlen(mod[i].name))) {
			argv += optind;
			argc -= optind;
			mod[i].func(argc, argv);
		}
	}

	return usage(prognm);
}
