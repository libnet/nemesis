/*
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 * Original version submitted by ocsic <pisco@private.as>
 *
 * nemesis-ip.c (IP Packet Injector)
 */

#include "nemesis-ip.h"
#include "nemesis.h"
#if defined(WIN32)
#include <pcap.h>
#endif

static ETHERhdr etherhdr;
static IPhdr    iphdr;
static struct file pd, ipod;
static char    *payloadfile   = NULL; /* payload file name */
static char    *ipoptionsfile = NULL; /* IP options file name */
static char    *device        = NULL; /* Ethernet device */

#if defined(WIN32)
static char    *ifacetmp      = NULL;
#endif

static void ip_cmdline(int, char **);
static int  ip_exit(int);
static void ip_initdata(void);
static void ip_usage(char *);
static void ip_verbose(void);

void nemesis_ip(int argc, char **argv)
{
	const char *module = "IP Packet Injection";
	libnet_t *l;

	nemesis_maketitle(title, module, version);

	if (argc > 1 && !strncmp(argv[1], "help", 4))
		ip_usage(argv[0]);

	if (nemesis_seedrand() < 0)
		fprintf(stderr, "ERROR: Unable to seed random number generator.\n");

	ip_initdata();
	ip_cmdline(argc, argv);

	l = libnet_init(got_link ? LIBNET_LINK_ADV : LIBNET_RAW4, device, errbuf);
	if (!l)
		ip_exit(1);

	if (got_link) {
		if ((nemesis_check_link(&etherhdr, l)) < 0) {
			fprintf(stderr, "ERROR: cannot retrieve hardware address of %s.\n", device);
			ip_exit(1);
		}
	}

	ip_verbose();

	if (got_payload) {
#if defined(WIN32)
		if (builddatafromfile(IP_LINKBUFFSIZE, &pd, payloadfile, PAYLOADMODE) < 0)
#else
		if (builddatafromfile(((got_link == 1) ? IP_LINKBUFFSIZE : IP_RAWBUFFSIZE),
		                      &pd, payloadfile, PAYLOADMODE) < 0)
#endif
			ip_exit(1);
	}

	if (got_ipoptions) {
		if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, ipoptionsfile, OPTIONSMODE) < 0)
			ip_exit(1);
	}

	if (buildip(&etherhdr, &iphdr, &pd, &ipod, l) < 0) {
		puts("\nIP Injection Failure");
		ip_exit(1);
	}

	ip_exit(0);
}

static void ip_initdata(void)
{
	/* defaults */
	etherhdr.ether_type = ETHERTYPE_IP;    /* Ethernet type IP */
	memset(etherhdr.ether_shost, 0, 6);    /* Ethernet source address */
	memset(etherhdr.ether_dhost, 0xff, 6); /* Ethernet destination address */

	iphdr.ip_src.s_addr = libnet_get_prand(PRu32);
	iphdr.ip_dst.s_addr = libnet_get_prand(PRu32);
	iphdr.ip_tos        = 0;                       /* IP type of service */
	iphdr.ip_id         = libnet_get_prand(PRu16); /* IP ID */
	iphdr.ip_off        = 0;                       /* IP fragmentation offset */
	iphdr.ip_ttl        = 255;                     /* IP TTL */
	iphdr.ip_p          = 0;                       /* IP protocol */

	pd.file_buf   = NULL;
	pd.file_len   = 0;
	ipod.file_buf = NULL;
	ipod.file_len = 0;
}

static void ip_usage(char *arg)
{
	nemesis_printtitle(title);

	printf("Usage:\n"
	       "  %s [-v (verbose)] [options]\n\n", arg);
	printf("General Options:\n"
	       "  -c <COUNT>   Send count number of packets\n"
	       "  -i <WAIT>    Interval to wait between packets\n"
	       "\n");
	printf("IP Options:\n"
	       "  -S <ADDR>    Source IP address\n"
	       "  -D <ADDR>    Destination IP address\n"
	       "  -I <ID>      IP ID\n"
	       "  -p <PROTO>   IP protocol number\n"
	       "  -T <TTL>     IP TTL\n"
	       "  -t <TOS>     IP TOS\n"
	       "  -F <OPT>     IP fragmentation options: -F[D],[M],[R],[offset]\n"
	       "  -O <FILE>    Raw IP options file\n"
	       "  -P <FILE>    Raw IP payload file\n"
	       "\n");
	printf("Data Link Options:\n"
#if defined(WIN32)
	       "  -d <IFNUM>   Network interface number>\n"
#else
	       "  -d <IFNAME>  Network interface name\n"
#endif
	       "  -H <MAC>     Source MAC address\n"
	       "  -M <MAC>     Destination MAC address\n");
#if defined(WIN32)
	printf("  -Z           List available network interfaces by number\n");
#endif
	putchar('\n');
	ip_exit(1);
}

static void ip_cmdline(int argc, char **argv)
{
	int          opt, i;
	uint32_t     addr_tmp[6];
	char        *ip_options;

#if defined(WIN32)
	ip_options = "c:d:D:F:H:i:I:M:O:p:P:S:t:T:vZ?";
#else
	ip_options = "c:d:D:F:H:i:I:M:O:p:P:S:t:T:v?";
#endif
	while ((opt = getopt(argc, argv, ip_options)) != -1) {
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
				ip_exit(1);
			}
#else
			if (strlen(optarg) < 256) {
				if (device)
					free(device);
				device = strdup(optarg);
				got_link = 1;
			} else {
				fprintf(stderr, "ERROR: device %s > 256 characters\n", optarg);
				ip_exit(1);
			}
#endif
			break;

		case 'D': /* destination IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_dst.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid destination IP address: \"%s\".\n", optarg);
				ip_exit(1);
			}
			break;

		case 'F': /* IP fragmentation options */
			if (parsefragoptions(&iphdr, optarg) < 0)
				ip_exit(1);
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
			break;

		case 'O': /* IP options file */
			if (strlen(optarg) < 256) {
				if (ipoptionsfile)
					free(ipoptionsfile);
				ipoptionsfile = strdup(optarg);
				got_ipoptions = 1;
			} else {
				fprintf(stderr, "ERROR: IP options file %s > 256 characters.\n", optarg);
				ip_exit(1);
			}
			break;

		case 'p': /* IP protocol */
			iphdr.ip_p = xgetint8(optarg);
			break;

		case 'P': /* payload file */
			if (strlen(optarg) < 256) {
				if (payloadfile)
					free(payloadfile);
				payloadfile = strdup(optarg);
				got_payload = 1;
			} else {
				fprintf(stderr, "ERROR: payload file %s > 256 characters\n", optarg);
				ip_exit(1);
			}
			break;

		case 'S': /* source IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_src.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid source IP address: \"%s\".\n", optarg);
				ip_exit(1);
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
			ip_exit(1);
#endif
		case '?': /* FALLTHROUGH */
		default:
			ip_usage(argv[0]);
			break;
		}
	}
	argc -= optind;
	argv += optind;
}

static int ip_exit(int code)
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

static void ip_verbose(void)
{
	if (verbose) {
		if (got_link)
			nemesis_printeth(&etherhdr);

		nemesis_printip(&iphdr);
	}
}
