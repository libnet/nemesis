/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-igmp.c (IGMP Packet Injector)
 */

#include "nemesis-igmp.h"
#include "nemesis.h"
#if defined(WIN32)
#include <pcap.h>
#endif

static ETHERhdr etherhdr;
static IPhdr    iphdr;
static IGMPhdr  igmphdr;
static struct file pd, ipod;
static int      got_dst, got_group, got_type, got_code;
static uint16_t num_groups;
static char    *payloadfile   = NULL; /* payload file name */
static char    *ipoptionsfile = NULL; /* IP options file name */
static char    *device        = NULL; /* Ethernet device */

#if defined(WIN32)
static char *ifacetmp = NULL;
#endif

static void igmp_cmdline(int, char **);
static int  igmp_exit(int);
static void igmp_initdata(void);
static void igmp_usage(char *);
static void igmp_validatedata(libnet_t *l);
static void igmp_verbose(void);

void nemesis_igmp(int argc, char **argv)
{
	const char *module = "IGMP Packet Injection";
	libnet_t *l;

	nemesis_maketitle(title, module, version);

	if (argc > 1 && !strncmp(argv[1], "help", 4))
		igmp_usage(argv[0]);

	if (nemesis_seedrand() < 0)
		fprintf(stderr, "ERROR: Unable to seed random number generator.\n");

	igmp_initdata();
	igmp_cmdline(argc, argv);

	l = libnet_init(got_link ? LIBNET_LINK_ADV : LIBNET_RAW4, device, errbuf);
	if (!l)
		igmp_exit(1);

	igmp_validatedata(l);
	igmp_verbose();

	if (got_payload) {
#if defined(WIN32)
		if (builddatafromfile(IGMP_LINKBUFFSIZE, &pd, payloadfile, PAYLOADMODE) < 0)
#else
		if (builddatafromfile(((got_link == 1) ? IGMP_LINKBUFFSIZE : IGMP_RAWBUFFSIZE), &pd, payloadfile, PAYLOADMODE) < 0)
#endif
			igmp_exit(1);
	}

	if (got_ipoptions) {
		if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, ipoptionsfile, OPTIONSMODE) < 0)
			igmp_exit(1);
	}

	if (buildigmp(&etherhdr, &iphdr, &igmphdr, &pd, &ipod, l) < 0) {
		puts("\nIGMP Injection Failure");
		igmp_exit(1);
	}

	igmp_exit(0);
}

static void igmp_initdata(void)
{
	/* defaults */
	etherhdr.ether_type = ETHERTYPE_IP;    /* Ethernet type IP */
	memset(etherhdr.ether_shost, 0, 6);    /* Ethernet source address */
	memset(etherhdr.ether_dhost, 0xff, 6); /* Ethernet destination address */

	iphdr.ip_src.s_addr = libnet_get_prand(PRu32); /* IP source address */
	memset(&iphdr.ip_dst.s_addr, 0, 4);            /* IP destination address */
	iphdr.ip_tos = 0;                              /* IP type of service */
	iphdr.ip_id  = libnet_get_prand(PRu16);        /* IP ID */
	iphdr.ip_p   = IPPROTO_IGMP;                   /* IP protocol IGMP */
	iphdr.ip_off = 0;                              /* IP fragmentation offset */
	iphdr.ip_ttl = 1;                              /* IP TTL - set to 1 purposely */

	igmphdr.igmp_type         = 0; /* IGMP type */
	igmphdr.igmp_code         = 0; /* IGMP code */
	igmphdr.igmp_group.s_addr = 0; /* IGMP group IP address */

	pd.file_buf   = NULL;
	pd.file_len   = 0;
	ipod.file_buf = NULL;
	ipod.file_len = 0;
}

static void igmp_validatedata(libnet_t *l)
{
	/*
	 * if a device was specified and the user has not specified a
	 * source hardware address, try to determine the source address
	 * automatically
	 */
	if (got_link) {
		if ((nemesis_check_link(&etherhdr, l)) < 0) {
			fprintf(stderr, "ERROR: Cannot retrieve hardware address of %s.\n", device);
			igmp_exit(1);
		}
	}

	/* Attempt to send valid packets if the user hasn't decided to craft an anomolous packet */
	if (!got_type)
		igmphdr.igmp_type = IGMP_V1_MEMBERSHIP_REPORT;
	if (!got_code)
		igmphdr.igmp_code = 0;
	if (!got_group) {
		if (igmphdr.igmp_type == 0x22) {
			if (!got_dst)
				inet_aton("224.0.0.22", &iphdr.ip_dst);

			if (num_groups)
				igmphdr.igmp_group.s_addr = htonl(num_groups);
		}
	}
}

static void igmp_usage(char *arg)
{
	nemesis_printtitle(title);

	printf("Usage:\n"
	       "  %s [-v (verbose)] [options]\n"
	       "\n", arg);
	printf("General Options:\n"
	       "  -c <COUNT>   Send count number of packets\n"
	       "  -i <WAIT>    Interval to wait between packets\n"
	       "\n");
	printf("IGMP options:\n"
	       "  -p <TYPE>    IGMP protocol type:\n"
	       "                    0x11:  Query, length determines version\n"
	       "                    0x12:  Join, v1\n"
	       "                    0x13:  DVMRP\n"
	       "                    0x14:  PIM, v1\n"
	       "                    0x16:  Join, v2\n"
	       "                    0x17:  Leave, v2\n"
	       "                    0x1e:  Multicast traceroute, response\n"
	       "                    0x1f:  Multicast traceroute\n"
	       "                    0x22:  Membership report, v3 join/leave\n"
	       "                    0x30:  Multicast router advertisement\n"
	       "                    0x31:  Multicast router solicitation\n"
	       "                    0x32:  Multicast router termination\n"
	       "  -r <CODE>    Max resp. code. v1: unused, v2: query response time\n"
	       "  -g <GROUP>   Multicast group for join/leave, or group spec. query\n"
	       "  -n <NUM>     Number of groups in IGMPv3 report (instead of -g)\n"
	       "  -P <FILE>    Raw IGMP payload file\n"
	       "\n");
	printf("IP options:\n"
	       "  -S <ADDR>    Source IP address\n"
	       "  -D <ADDR>    Destination IP address\n"
	       "  -I <ID>      IP ID\n"
	       "  -T <TTL>     IP TTL\n"
	       "  -t <TOS>     IP TOS\n"
	       "  -F <OPT>     IP fragmentation options: -F[D],[M],[R],[offset]\n"
	       "  -O <FILE>    Raw IP options file\n"
	       "\n");
	printf("Data Link Options:\n"
#if defined(WIN32)
	       "  -d <IFNUM>   Network interface number\n"
#else
	       "  -d <IFNAME>  Network interface name\n"
#endif
	       "  -H <MAC>     Source MAC address\n"
	       "  -M <MAC>     Destination MAC address\n");
#if defined(WIN32)
	printf("  -Z           List available network interfaces by number\n");
#endif
	putchar('\n');
	igmp_exit(1);
}

static void igmp_cmdline(int argc, char **argv)
{
	int          opt, i;
	uint32_t     addr_tmp[6];
	char        *igmp_options;

#if defined(WIN32)
	igmp_options = "c:d:D:F:g:H:i:I:M:n:O:p:P:r:S:t:T:vZ?";
#else
	igmp_options = "c:d:D:F:g:H:i:I:M:n:O:p:P:r:S:t:T:v?";
#endif
	while ((opt = getopt(argc, argv, igmp_options)) != -1) {
		switch (opt) {
		case 'c':
			count = atoi(optarg);
			break;

		case 'i':
			interval = xgetusec(optarg);
			break;

		case 'd': /* Ethernet device */
#if defined(WIN32)
			if (nemesis_getdev(atoi(optarg), &device) < 0) {
				fprintf(stderr, "ERROR: Unable to lookup device: '%d'.\n", atoi(optarg));
				igmp_exit(1);
			}
#else
			if (strlen(optarg) < 256) {
				if (device)
					free(device);
				device = strdup(optarg);
				got_link = 1;
			} else {
				fprintf(stderr, "ERROR: device %s > 256 characters.\n", optarg);
				igmp_exit(1);
			}
#endif
			break;

		case 'D': /* destination IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_dst.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid destination IP address: \"%s\".\n", optarg);
				igmp_exit(1);
			}
			got_dst = 1;
			break;

		case 'F': /* IP fragmentation options */
			if (parsefragoptions(&iphdr, optarg) < 0)
				igmp_exit(1);
			break;

		case 'g': /* IGMP group address */
			if ((nemesis_name_resolve(optarg, &igmphdr.igmp_group.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid IGMP group address: \"%s\".\n", optarg);
				igmp_exit(1);
			}
			got_group = 1;
			break;

		case 'H': /* Ethernet source address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_shost[i] = addr_tmp[i];
			break;

		case 'I': /* IP ID */
			iphdr.ip_id = xgetint16(optarg);
			break;

		case 'M': /* Ethernet destination address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_dhost[i] = addr_tmp[i];
			got_dhost = 1;
			break;

		case 'n':
			num_groups = xgetint16(optarg);
			break;

		case 'O': /* IP options file */
			if (strlen(optarg) < 256) {
				if (ipoptionsfile)
					free(ipoptionsfile);
				ipoptionsfile = strdup(optarg);
				got_ipoptions = 1;
			} else {
				fprintf(stderr, "ERROR: IP options file %s > 256 characters.\n", optarg);
				igmp_exit(1);
			}
			break;

		case 'p': /* IGMP type */
			igmphdr.igmp_type = xgetint8(optarg);
			got_type          = 1;
			break;

		case 'P': /* payload file */
			if (strlen(optarg) < 256) {
				if (payloadfile)
					free(payloadfile);
				payloadfile = strdup(optarg);
				got_payload = 1;
			} else {
				fprintf(stderr, "ERROR: payload file %s > 256 characters.\n", optarg);
				igmp_exit(1);
			}
			break;

		case 'r': /* IGMP max resp. code */
			igmphdr.igmp_code = xgetint8(optarg);
			got_code          = 1;
			break;

		case 'S': /* source IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_src.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid source IP address: \"%s\".\n", optarg);
				igmp_exit(1);
			}
			break;

		case 't': /* IP type of service */
			iphdr.ip_tos = xgetint8(optarg);
			break;

		case 'T': /* IP time to live */
			iphdr.ip_ttl = xgetint8(optarg);
			break;

		case 'v':
			verbose++;
			if (verbose == 1)
				nemesis_printtitle(title);
			break;
#if defined(WIN32)
		case 'Z':
			if ((ifacetmp = pcap_lookupdev(errbuf)) == NULL)
				perror(errbuf);

			PrintDeviceList(ifacetmp);
			igmp_exit(1);
#endif
		case '?': /* FALLTHROUTH */
		default:
			igmp_usage(argv[0]);
			break;
		}
	}
	argc -= optind;
	argv += optind;
}

static int igmp_exit(int code)
{
	if (got_payload)
		free(pd.file_buf);

	if (got_ipoptions)
		;
	free(ipod.file_buf);

	if (device != NULL)
		free(device);

	if (ipoptionsfile != NULL)
		free(ipoptionsfile);

	if (payloadfile != NULL)
		free(payloadfile);

#if defined(WIN32)
	if (ifacetmp != NULL)
		free(ifacetmp);
#endif

	exit(code);
}

static void igmp_verbose(void)
{
	if (verbose) {
		if (got_link)
			nemesis_printeth(&etherhdr);

		nemesis_printip(&iphdr);
		printf("         [IGMP Type] %hhu\n", igmphdr.igmp_type);
		printf("         [IGMP Code] %hhu\n", igmphdr.igmp_code);
		printf("[IGMP group address] %s\n", inet_ntoa(igmphdr.igmp_group));
	}
}
