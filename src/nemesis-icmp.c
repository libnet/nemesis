/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-icmp.c (ICMP Packet Injector)
 */

#include "nemesis-icmp.h"
#include "nemesis.h"
#if defined(WIN32)
#include <pcap.h>
#endif

static ETHERhdr etherhdr;
static IPhdr    iphdr;
static IPhdr    ipunreach;
static ICMPhdr  icmphdr;
static UDPhdr   udphdr;
static struct file pd, ipod, origod;
static int      got_mode, got_type, got_code;
static char    *payloadfile    = NULL; /* payload file name */
static char    *ipoptionsfile  = NULL; /* IP options file name */
static char    *unroptionsfile = NULL; /* ICMP unreach IP options file */
static char    *device         = NULL; /* Ethernet device */

#if defined(WIN32)
static char *ifacetmp = NULL;
#endif

static void icmp_cmdline(int, char **);
static int  icmp_exit(int);
static void icmp_initdata(void);
static void icmp_usage(char *);
static void icmp_validatedata(void);
static void icmp_verbose(void);

void nemesis_icmp(int argc, char **argv)
{
	const char *module = "ICMP Packet Injection";
	libnet_t *l;

	nemesis_maketitle(title, module, version);

	if (argc > 1 && !strncmp(argv[1], "help", 4))
		icmp_usage(argv[0]);

	if (nemesis_seedrand() < 0)
		fprintf(stderr, "ERROR: Unable to seed random number generator.\n");

	icmp_initdata();
	icmp_cmdline(argc, argv);

	l = libnet_init(got_link ? LIBNET_LINK_ADV : LIBNET_RAW4, device, errbuf);
	if (!l)
		icmp_exit(1);

	if (got_link) {
		if ((nemesis_check_link(&etherhdr, l)) < 0) {
			fprintf(stderr, "ERROR: Cannot retrieve hardware address of %s.\n", device);
			icmp_exit(1);
		}
	}

	icmp_validatedata();
	icmp_verbose();

	if (got_payload) {
#if defined(WIN32)
		if (builddatafromfile(ICMP_LINKBUFFSIZE, &pd, payloadfile, PAYLOADMODE) < 0)
#else
		if (builddatafromfile(((got_link == 1) ? ICMP_LINKBUFFSIZE : ICMP_RAWBUFFSIZE),
				      &pd, payloadfile, PAYLOADMODE) < 0)
#endif
			icmp_exit(1);
	}

	if (got_ipoptions) {
		if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, ipoptionsfile, OPTIONSMODE) < 0)
			icmp_exit(1);
	}

	if (got_origoptions) {
		if (builddatafromfile(OPTIONSBUFFSIZE, &origod, unroptionsfile, OPTIONSMODE) < 0)
			icmp_exit(1);
	}

	if (buildicmp(&etherhdr, &iphdr, &icmphdr, &ipunreach, &pd, &ipod, &origod, l) < 0) {
		puts("\nICMP Injection Failure");
		icmp_exit(1);
	}

	icmp_exit(0);
}

static void icmp_initdata(void)
{
	/* defaults */
	etherhdr.ether_type = ETHERTYPE_IP;    /* Ethernet type IP */
	memset(etherhdr.ether_shost, 0, 6);    /* Ethernet source address */
	memset(etherhdr.ether_dhost, 0xff, 6); /* Ethernet destination address */

	iphdr.ip_src.s_addr = libnet_get_prand(PRu32);
	iphdr.ip_dst.s_addr = libnet_get_prand(PRu32);
	iphdr.ip_tos        = 0;                       /* IP type of service (TOS) */
	iphdr.ip_id         = libnet_get_prand(PRu16); /* IP ID */
	iphdr.ip_p          = IPPROTO_ICMP;            /* IP protocol ICMP */
	iphdr.ip_off        = 0;                       /* IP fragmentation offset */
	iphdr.ip_ttl        = 255;                     /* IP TTL */

	ipunreach.ip_src.s_addr = libnet_get_prand(PRu32);
	ipunreach.ip_dst.s_addr = libnet_get_prand(PRu32); /* ICMP unreach IP dst address */
	ipunreach.ip_tos        = 0;                       /* ICMP unreach IP TOS */
	ipunreach.ip_id         = libnet_get_prand(PRu16); /* ICMP unreach IP ID */
	ipunreach.ip_off        = 0;                       /* ICMP unreach IP frag offset */
	ipunreach.ip_ttl        = 255;                     /* ICMP unreach IP TTL */
	ipunreach.ip_p          = 17;                      /* ICMP unreach IP protocol */

	mode                     = ICMP_ECHO;               /* default to ICMP echo */
	icmphdr.icmp_type        = 0;                       /* ICMP type */
	icmphdr.icmp_code        = 0;                       /* ICMP code */
	icmphdr.hun.echo.id      = 0;                       /* ICMP ID */
	icmphdr.hun.echo.seq     = 0;                       /* ICMP sequence number */
	icmphdr.hun.gateway      = libnet_get_prand(PRu32); /* ICMP preferred gateway */
	icmphdr.dun.ts.its_otime = time(NULL);              /* ICMP timestamp req. orig time */
	icmphdr.dun.ts.its_rtime = 0;                       /* ICMP timestamp rea. recv time */
	icmphdr.dun.ts.its_ttime = 0;                       /* ICMP timestamp rep. trans time */
	icmphdr.dun.mask         = 0;                       /* ICMP address mask */

	pd.file_buf     = NULL;
	pd.file_len     = 0;
	ipod.file_buf   = NULL;
	ipod.file_len   = 0;
	origod.file_buf = NULL;
	origod.file_len = 0;
}

static void icmp_validatedata(void)
{
	if (got_mode > 1) {
		fprintf(stderr, "ERROR: ICMP injection mode multiply specified - select only one.\n");
		icmp_exit(1);
	}

	if (got_origoptions && !(mode == ICMP_UNREACH || mode == ICMP_REDIRECT || mode == ICMP_TIMXCEED)) {
		fprintf(stderr, "ERROR: -l is only valid with ICMP redirect, unreach or time exceeded injection.\n");
		icmp_exit(1);
	}

	if (pd.file_len == 0 && (mode == ICMP_UNREACH || mode == ICMP_REDIRECT || mode == ICMP_TIMXCEED)) {
		udphdr.uh_sport = libnet_get_prand(PRu16);
		udphdr.uh_dport = libnet_get_prand(PRu16);
		udphdr.uh_ulen  = htons(20);
		udphdr.uh_sum   = 0;
		if ((pd.file_buf = calloc(8, sizeof(char))) == NULL) {
			perror("ERROR: Unable to allocate ICMP original datagram payload memory");
			icmp_exit(1);
		}
		pd.file_len = 8;
		memcpy(pd.file_buf, &udphdr, pd.file_len);
	}

	/* Attempt to send valid packets if the user hasn't decided to craft an anomolous packet */
	switch (mode) {
	case ICMP_ECHO: /* send an echo request */
		if (!got_type)
			icmphdr.icmp_type = ICMP_ECHO;
		if (!got_code)
			icmphdr.icmp_code = 0;
		break;

	case ICMP_MASKREQ: /* send an address mask request */
		if (!got_type)
			icmphdr.icmp_type = ICMP_MASKREQ;
		if (!got_code)
			icmphdr.icmp_code = 0;
		break;

	case ICMP_UNREACH:
		if (!got_type)
			icmphdr.icmp_type = ICMP_UNREACH;
		if (!got_code)
			icmphdr.icmp_code = ICMP_UNREACH_PORT;
		break;

	case ICMP_TIMXCEED:
		if (!got_type)
			icmphdr.icmp_type = ICMP_TIMXCEED;
		if (!got_code)
			icmphdr.icmp_code = ICMP_TIMXCEED_INTRANS;
		break;

	case ICMP_REDIRECT:
		if (!got_type)
			icmphdr.icmp_type = ICMP_REDIRECT;
		if (!got_code)
			icmphdr.icmp_code = ICMP_REDIRECT_NET;
		break;

	case ICMP_TSTAMP:
		if (!got_type)
			icmphdr.icmp_type = ICMP_TSTAMP;
		if (!got_code)
			icmphdr.icmp_code = 0;
		break;
	}
}

static void icmp_usage(char *arg)
{
	nemesis_printtitle(title);

	printf("Usage:\n"
	       "  %s [-v (verbose)] [options]\n"
	       "\n", arg);
	printf("ICMP options:\n"
	       "  -i <TYPE>    ICMP type\n"
	       "  -c <CODE>    ICMP code\n"
	       "  -s <NUM>     ICMP sequence number\n"
	       "  -m <MASK>    IP network mask for ICMP address mask\n"
	       "  -G <ADDR>    Preferred gateway IP address for ICMP redirect\n"
	       "  -e <ID>      ICMP ID\n"
	       "  -P <FILE>    Raw ICMP payload file\n"
	       "  -q <MODE>    ICMP injection mode:\n"
	       "                    -qE: echo\n"
	       "                    -qM: mask\n"
	       "                    -qU: unreach\n"
	       "                    -qX: time exceeded\n"
	       "                    -qR: redirect\n"
	       "                    -qT: timestamp\n"
	       "\n"
	       " ICMP timestamp options:\n"
	       "  -o <TIME>    Time ICMP timestamp request was sent\n"
	       "  -r <TIME>    Time ICMP timestamp request was received (for reply)\n"
	       "  -a <TIME>    Time ICMP timestamp request reply was transmitted\n"
	       "\n"
	       " ICMP original datagram options:\n"
	       "  -B <ADDR>    Original source IP address\n"
	       "  -b <ADDR>    Original destination IP address\n"
	       "  -p <PROTO>   Original IP protocol\n"
	       "  -f <OFFSET>  Original IP fragmentation offset\n"
	       "  -j <TOS>     Original IP TOS\n"
	       "  -J <TTL>     Original IP TTL\n"
	       "  -l <FILE>    Raw Original IP options file\n"
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
	icmp_exit(1);
}

static void icmp_cmdline(int argc, char **argv)
{
	int          opt, i;
	uint32_t     addr_tmp[6];
	char        *icmp_options;
	char         cmd_mode = 0;

#if defined(WIN32)
	icmp_options = "a:A:b:B:c:d:D:e:f:F:G:H:i:I:j:J:l:m:M:o:O:p:P:q:r:s:S:t:T:vZ?";
#else
	icmp_options = "a:A:b:B:c:d:D:e:f:F:G:H:i:I:j:J:l:m:M:o:O:p:P:q:r:s:S:t:T:v?";
#endif
	while ((opt = getopt(argc, argv, icmp_options)) != -1) {
		switch (opt) {
		case 'a': /* ICMP timestamp reply transmit time (epoch) */
			icmphdr.dun.ts.its_ttime = xgetint32(optarg);
			break;

		case 'A': /* ICMP unreach original IP ID */
			ipunreach.ip_id = xgetint16(optarg);
			break;

		case 'b': /* ICMP unreach original destination IP address */
			if ((nemesis_name_resolve(optarg, &ipunreach.ip_dst.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid destination IP address: \"%s\".\n", optarg);
				icmp_exit(1);
			}
			break;

		case 'B': /* ICMP unreach original source IP address */
			if ((nemesis_name_resolve(optarg, &ipunreach.ip_src.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid source IP address: \"%s\".\n", optarg);
				icmp_exit(1);
			}
			break;

		case 'c': /* ICMP code */
			icmphdr.icmp_code = xgetint8(optarg);
			got_code          = 1;
			break;

		case 'd': /* Ethernet device */
#if defined(WIN32)
			if (nemesis_getdev(atoi(optarg), &device) < 0) {
				fprintf(stderr, "ERROR: Unable to lookup device: '%d'.\n", atoi(optarg));
				icmp_exit(1);
			}
#else
			if (strlen(optarg) < 256) {
				if (device)
					free(device);
				device = strdup(optarg);
				got_link = 1;
			} else {
				fprintf(stderr, "ERROR: device %s > 256 characters.\n", optarg);
				icmp_exit(1);
			}
#endif
			break;

		case 'D': /* destination IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_dst.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid destination IP address: \"%s\".\n", optarg);
				icmp_exit(1);
			}
			break;

		case 'e': /* ICMP ID */
			icmphdr.hun.echo.id = xgetint16(optarg);
			break;

		case 'f': /* ICMP original datagram IP fragmentation offset */
			if (parsefragoptions(&ipunreach, optarg) < 0)
				icmp_exit(1);
			break;

		case 'F': /* IP fragmentation options */
			if (parsefragoptions(&iphdr, optarg) < 0)
				icmp_exit(1);
			break;

		case 'G': /* ICMP redirect preferred gateway IP address */
			if ((nemesis_name_resolve(optarg, &icmphdr.hun.gateway)) < 0) {
				fprintf(stderr, "ERROR: Invalid preferred gateway IP address: %s.\n", optarg);
				icmp_exit(1);
			}
			break;

		case 'H': /* Ethernet source address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_shost[i] = addr_tmp[i];
			break;

		case 'i': /* ICMP type */
			icmphdr.icmp_type = xgetint8(optarg);
			got_type          = 1;
			break;

		case 'I': /* IP ID */
			iphdr.ip_id = xgetint16(optarg);
			break;

		case 'j': /* ICMP original datagram IP type of service */
			ipunreach.ip_tos = xgetint8(optarg);
			break;

		case 'J': /* ICMP original datagram IP time to live */
			ipunreach.ip_ttl = xgetint8(optarg);
			break;

		case 'l': /* ICMP unrechable original IP options file */
			if (strlen(optarg) < 256) {
				if (unroptionsfile)
					free(unroptionsfile);
				unroptionsfile  = strdup(optarg);
				got_origoptions = 1;
			} else {
				fprintf(stderr, "ERROR: ICMP unreach original IP options file %s > 256 characters.\n", optarg);
				icmp_exit(1);
			}
			break;

		case 'm': /* mask for IP address mask messages */
			icmphdr.dun.mask = xgetint32(optarg);
			break;

		case 'M': /* Ethernet destination address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_dhost[i] = addr_tmp[i];
			break;

		case 'o': /* ICMP timestamp originate time (epoch) */
			icmphdr.dun.ts.its_otime = xgetint32(optarg);
			break;

		case 'O': /* IP options file */
			if (strlen(optarg) < 256) {
				if (ipoptionsfile)
					free(ipoptionsfile);
				ipoptionsfile = strdup(optarg);
				got_ipoptions = 1;
			} else {
				fprintf(stderr, "ERROR: IP options file %s > 256 characters.\n", optarg);
				icmp_exit(1);
			}
			break;

		case 'p': /* original IP protocol */
			ipunreach.ip_p = xgetint8(optarg);
			break;

		case 'P': /* payload file */
			if (strlen(optarg) < 256) {
				if (payloadfile)
					free(payloadfile);
				payloadfile = strdup(optarg);
				got_payload = 1;
			} else {
				fprintf(stderr, "ERROR: payload file %s > 256 characters.\n", optarg);
				icmp_exit(1);
			}
			break;

		case 'q': /* ICMP injection mode */
			if (strlen(optarg) == 1) {
				cmd_mode = *optarg;
			} else {
				fprintf(stderr, "ERROR: Invalid ICMP injection mode: %s.\n", optarg);
				icmp_exit(1);
			}
			switch (cmd_mode) {
			case 'E': /* ICMP echo injection */
				mode = ICMP_ECHO;
				got_mode++;
				break;

			case 'M': /* ICMP mask injection */
				mode = ICMP_MASKREQ;
				got_mode++;
				break;

			case 'U': /* ICMP unreach injection */
				mode = ICMP_UNREACH;
				got_mode++;
				break;

			case 'X': /* ICMP time exceeded injection */
				mode = ICMP_TIMXCEED;
				got_mode++;
				break;

			case 'R': /* ICMP redirect injection */
				mode = ICMP_REDIRECT;
				got_mode++;
				break;

			case 'T': /* ICMP timestamp injection */
				mode = ICMP_TSTAMP;
				got_mode++;
				break;

			case '?': /* FALLTHROUGH */
			default:
				fprintf(stderr, "ERROR: Invalid ICMP injection mode: %c.\n", cmd_mode);
				icmp_exit(1);
				/* NOTREACHED */
				break;
			}
			break;

		case 'r': /* ICMP timestamp receive time (epoch) */
			icmphdr.dun.ts.its_rtime = xgetint32(optarg);
			break;

		case 's': /* ICMP sequence number */
			icmphdr.hun.echo.seq = xgetint16(optarg);
			break;

		case 'S': /* source IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_src.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid source IP address: \"%s\".\n", optarg);
				icmp_exit(1);
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
			icmp_exit(1);
#endif
		case '?': /* FALLTHROUGH */
		default:
			icmp_usage(argv[0]);
			break;
		}
	}
	argc -= optind;
	argv += optind;
}

static int icmp_exit(int code)
{
	if (got_payload)
		free(pd.file_buf);

	if (got_ipoptions)
		free(ipod.file_buf);

	if (got_origoptions)
		free(origod.file_buf);

	if (device != NULL)
		free(device);

	if (unroptionsfile != NULL)
		free(unroptionsfile);

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

static void icmp_verbose(void)
{
	if (verbose) {
		if (got_link)
			nemesis_printeth(&etherhdr);

		nemesis_printip(&iphdr);
		nemesis_printicmp(&icmphdr, mode);
	}
}
