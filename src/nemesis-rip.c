/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-rip.c (RIP Packet Injector)
 */

#include "nemesis-rip.h"
#include "nemesis.h"
#if defined(WIN32)
#include <pcap.h>
#endif

static ETHERhdr etherhdr;
static IPhdr    iphdr;
static UDPhdr   udphdr;
static RIPhdr   riphdr;
static struct file pd, ipod;
static int      got_domain;
static char    *payloadfile   = NULL; /* payload file name */
static char    *ipoptionsfile = NULL; /* IP options file name */
static char    *device        = NULL; /* Ethernet device */

#if defined(WIN32)
static char *ifacetmp = NULL;
#endif

static void rip_cmdline(int, char **);
static int  rip_exit(int);
static void rip_initdata(void);
static void rip_usage(char *);
static void rip_validatedata(void);
static void rip_verbose(void);

void nemesis_rip(int argc, char **argv)
{
	const char *module = "RIP Packet Injection";
	libnet_t *l;

	nemesis_maketitle(title, module, version);

	if (argc > 1 && !strncmp(argv[1], "help", 4))
		rip_usage(argv[0]);

	if (nemesis_seedrand() < 0)
		fprintf(stderr, "ERROR: Unable to seed random number generator.\n");

	rip_initdata();
	rip_cmdline(argc, argv);

	l = libnet_init(got_link ? LIBNET_LINK_ADV : LIBNET_RAW4, device, errbuf);
	if (!l)
		rip_exit(1);
	if (got_link) {
		if ((nemesis_check_link(&etherhdr, l)) < 0) {
			fprintf(stderr, "ERROR: cannot retrieve hardware address of %s.\n", device);
			rip_exit(1);
		}
	}

	rip_validatedata();
	rip_verbose();

	if (got_payload) {
#if defined(WIN32)
		if (builddatafromfile(RIP_LINKBUFFSIZE, &pd, payloadfile, PAYLOADMODE) < 0)
#else
		if (builddatafromfile(((got_link == 1) ? RIP_LINKBUFFSIZE : RIP_RAWBUFFSIZE), &pd, payloadfile, PAYLOADMODE) < 0)
#endif
			rip_exit(1);
	}

	if (got_ipoptions) {
		if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, ipoptionsfile, OPTIONSMODE) < 0)
			rip_exit(1);
	}

	if (buildrip(&etherhdr, &iphdr, &udphdr, &riphdr, &pd, &ipod, l) < 0) {
		puts("\nRIP Injection Failure");
		rip_exit(1);
	}

	rip_exit(0);
}

static void rip_initdata(void)
{
	/* defaults */
	etherhdr.ether_type = ETHERTYPE_IP;    /* Ethernet type IP */
	memset(etherhdr.ether_shost, 0, 6);    /* Ethernet source address */
	memset(etherhdr.ether_dhost, 0xff, 6); /* Ethernet destination address */

	iphdr.ip_src.s_addr = libnet_get_prand(PRu32);
	iphdr.ip_dst.s_addr = inet_addr("224.0.0.9");  /* All RIPv2-aware routers */
	iphdr.ip_tos        = IPTOS_LOWDELAY;          /* IP type of service */
	iphdr.ip_id         = libnet_get_prand(PRu16); /* IP ID */
	iphdr.ip_p          = IPPROTO_UDP;             /* IP protocol UDP */
	iphdr.ip_off        = 0;                       /* IP fragmentation offset */
	iphdr.ip_ttl        = 1;                       /* IP TTL, default 1 because link-local multicast ip_dst */

	udphdr.uh_sport     = 520;                    /* UDP source port */
	udphdr.uh_dport     = 520;                    /* UDP destination port */

	riphdr.rip_cmd      = RIPCMD_REQUEST;          /* RIP command */
	riphdr.rip_ver      = 2;                       /* RIP version */
	riphdr.rip_rd       = 0;                       /* RIP routing domain */
	riphdr.rip_af       = 2;                       /* RIP address family */
	riphdr.rip_rt       = libnet_get_prand(PRu16); /* RIP route tag */
	riphdr.rip_addr     = 0;                       /* RIP address */
	riphdr.rip_mask     = 0;                       /* RIP subnet mask */
	riphdr.rip_next_hop = 0;                       /* RIP next-hop IP address */
	riphdr.rip_metric   = 1;                       /* RIP metric */

	pd.file_buf   = NULL;
	pd.file_len     = 0;
	ipod.file_buf = NULL;
	ipod.file_len   = 0;
}

static void rip_validatedata(void)
{
	uint32_t tmp;

	/* validation tests */
	if (riphdr.rip_ver == 2) {
		/* allow routing domain 0 in RIP2 if specified by the user */
		if (riphdr.rip_rd == 0 && got_domain == 0)
			riphdr.rip_rd = libnet_get_prand(PRu16);
		if (riphdr.rip_mask == 0)
			inet_pton(AF_INET, "255.255.255.0", &riphdr.rip_mask);
	}

	if (iphdr.ip_src.s_addr == 0)
		iphdr.ip_src.s_addr = libnet_get_prand(PRu32);
	if (iphdr.ip_dst.s_addr == 0) {
		switch (riphdr.rip_ver) {
		case 1:
			tmp                 = libnet_get_prand(PRu32);
			iphdr.ip_dst.s_addr = (htonl(tmp) | 0xFF000000);
			break;

		case 2:
			/* The multicast address for RIP2 is RIP2-ROUTERS.MCAST.NET */
			inet_aton("224.0.0.9", &iphdr.ip_dst);
			break;
		default:
			iphdr.ip_dst.s_addr = libnet_get_prand(PRu32);
			break;
		}
	}
}

static void rip_usage(char *arg)
{
	nemesis_printtitle(title);

	printf("RIP usage:\n"
	       "  %s [-v (verbose)] [options]\n"
	       "\n", arg);
	printf("RIP options:\n"
	       "  -c <CMD>     RIP command: 1: request (default), 2: response\n"
	       "  -V <VER>     RIP version: 1 or 2 (default)\n"
	       "  -r <DOMAIN>  RIP routing domain\n"
	       "  -a <AF>      RIP address family\n"
	       "  -R <TAG>     RIP route tag\n"
	       "  -i <ADDR>    RIP route address\n"
	       "  -k <MASK>    RIP network address mask\n"
	       "  -h <ADDR>    RIP next hop address\n"
	       "  -m <METRIC>  RIP metric\n"
	       "  -P <FILE>    Raw RIP payload file\n"
	       "\n");
	printf("UDP options:\n"
	       "  -x <PORT>    Source port, 520 default\n"
	       "  -y <PORT>    Destination port, 520 default\n"
	       "\n");
	printf("IP options\n"
	       "  -S <ADDR>    Source IP address\n"
	       "  -D <ADDR>    Destination IP address, default 224.0.0.9 (v2)\n"
	       "  -I <ID>      IP ID\n"
	       "  -T <TTL>     IP TTL, default: 1\n"
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
	rip_exit(1);
}

static void rip_cmdline(int argc, char **argv)
{
	int          opt, i;
	uint32_t     addr_tmp[6];
	char        *rip_options;

#if defined(WIN32)
	rip_options = "a:c:d:D:F:h:H:i:I:k:m:M:O:P:r:R:S:t:T:V:x:y:vZ?";
#else
	rip_options = "a:c:d:D:F:h:H:i:I:k:m:M:O:P:r:R:S:t:T:V:x:y:v?";
#endif
	while ((opt = getopt(argc, argv, rip_options)) != -1) {
		switch (opt) {
		case 'a': /* RIP address family */
			riphdr.rip_af = xgetint16(optarg);
			break;

		case 'c': /* RIP command */
			riphdr.rip_cmd = xgetint8(optarg);
			break;

		case 'd': /* Ethernet device */
#if defined(WIN32)
			if (nemesis_getdev(atoi(optarg), &device) < 0) {
				fprintf(stderr, "ERROR: Unable to lookup device: '%d'.\n", atoi(optarg));
				rip_exit(1);
			}
#else
			if (strlen(optarg) < 256) {
				if (device)
					free(device);
				device = strdup(optarg);
				got_link = 1;
			} else {
				fprintf(stderr, "ERROR: device %s > 256 characters.\n", optarg);
				rip_exit(1);
			}
#endif
			break;

		case 'D': /* destination IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_dst.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid destination IP address: \"%s\".\n", optarg);
				rip_exit(1);
			}
			break;

		case 'F': /* IP fragmentation options */
			if (parsefragoptions(&iphdr, optarg) < 0)
				rip_exit(1);
			break;

		case 'h': /* RIP next hop address */
			if ((nemesis_name_resolve(optarg, &riphdr.rip_next_hop)) < 0) {
				fprintf(stderr, "ERROR: Invalid next hop IP address: \"%s\".\n", optarg);
				rip_exit(1);
			}
			break;

		case 'H': /* Ethernet source address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_shost[i] = addr_tmp[i];
			break;

		case 'i': /* RIP route address */
			if ((nemesis_name_resolve(optarg, &riphdr.rip_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid destination IP address: \"%s\".\n", optarg);
				rip_exit(1);
			}
			break;

		case 'I': /* IP ID */
			iphdr.ip_id = xgetint16(optarg);
			break;

		case 'k': /* RIP netmask address */
			if ((nemesis_name_resolve(optarg, &riphdr.rip_mask)) < 0) {
				fprintf(stderr, "ERROR: Invalid RIP mask IP address: \"%s\".\n", optarg);
				rip_exit(1);
			}
			break;

		case 'm': /* RIP metric */
			riphdr.rip_metric = xgetint32(optarg);
			break;

		case 'M': /* Ethernet destination address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_dhost[i] = addr_tmp[i];
			break;

		case 'O': /* IP options file */
			if (strlen(optarg) < 256) {
				if (ipoptionsfile)
					free(ipoptionsfile);
				ipoptionsfile = strdup(optarg);
				got_ipoptions = 1;
			} else {
				fprintf(stderr, "ERROR: IP options file %s > 256 characters.\n", optarg);
				rip_exit(1);
			}
			break;

		case 'P': /* payload file */
			if (strlen(optarg) < 256) {
				if (payloadfile)
					free(payloadfile);
				payloadfile = strdup(optarg);
				got_payload = 1;
			} else {
				fprintf(stderr, "ERROR: payload file %s > 256 characters.\n", optarg);
				rip_exit(1);
			}
			break;

		case 'r': /* RIP routing domain */
			riphdr.rip_rd = xgetint16(optarg);
			got_domain    = 1;
			break;

		case 'R': /* RIP route tag */
			riphdr.rip_rt = xgetint16(optarg);
			break;

		case 'S': /* source IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_src.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid source IP address: \"%s\".\n", optarg);
				rip_exit(1);
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

		case 'V': /* RIP version */
			riphdr.rip_ver = xgetint8(optarg);
			break;

		case 'x': /* UDP source port */
			udphdr.uh_sport = xgetint16(optarg);
			break;

		case 'y': /* UDP destination port */
			udphdr.uh_dport = xgetint16(optarg);
			break;
#if defined(WIN32)
		case 'Z':
			if ((ifacetmp = pcap_lookupdev(errbuf)) == NULL)
				perror(errbuf);

			PrintDeviceList(ifacetmp);
			rip_exit(1);
#endif
		case '?': /* FALLTHROUGH */
		default:
			rip_usage(argv[0]);
			break;
		}
	}
	argc -= optind;
	argv += optind;
}

static int rip_exit(int code)
{
	if (got_payload)
		free(pd.file_buf);

	if (got_ipoptions)
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

static void rip_verbose(void)
{
	if (verbose) {
		if (got_link)
			nemesis_printeth(&etherhdr);

		nemesis_printip(&iphdr);
		nemesis_printudp(&udphdr);
		nemesis_printrip(&riphdr);
	}
}
