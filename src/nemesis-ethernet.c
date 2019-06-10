/*
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-ethernet.c (Ethernet Packet Injector)
 */

#include "nemesis-ethernet.h"
#include "nemesis.h"
#if defined(WIN32)
#include <pcap.h>
#endif

static ETHERhdr etherhdr;
static struct file pd;
static char    *payloadfile = NULL; /* payload file name */
static char    *device      = NULL; /* Ethernet device */

#if defined(WIN32)
static char *ifacetmp = NULL;
#endif

static void ethernet_cmdline(int, char **);
static int  ethernet_exit(int);
static void ethernet_initdata(void);
static void ethernet_usage(char *);
static void ethernet_verbose(void);

void nemesis_ethernet(int argc, char **argv)
{
	const char *module = "Ethernet Packet Injection";
	libnet_t *l;

	nemesis_maketitle(title, module, version);

	if (argc > 1 && !strncmp(argv[1], "help", 4))
		ethernet_usage(argv[0]);

	ethernet_initdata();
	ethernet_cmdline(argc, argv);

	l = libnet_init(LIBNET_LINK_ADV, device, errbuf);
	if (!l)
		ethernet_exit(1);

	if ((nemesis_check_link(&etherhdr, l)) < 0) {
		fprintf(stderr, "ERROR: Cannot retrieve hardware address of %s.\n", device);
		ethernet_exit(1);
	}

	ethernet_verbose();

	if (got_payload) {
		if (builddatafromfile(ETHERBUFFSIZE, &pd, payloadfile, PAYLOADMODE) < 0)
			ethernet_exit(1);
	}

	if (buildether(&etherhdr, &pd, l) < 0) {
		puts("\nEthernet Injection Failure");
		ethernet_exit(1);
	}

	ethernet_exit(0);
}

static void ethernet_initdata(void)
{
	/* defaults */
	etherhdr.ether_type = ETHERTYPE_IP;    /* Ethernet type IP */
	memset(etherhdr.ether_shost, 0, 6);    /* Ethernet source address */
	memset(etherhdr.ether_dhost, 0xff, 6); /* Ethernet destination address */

	pd.file_buf = NULL;
	pd.file_len = 0;
}

static void ethernet_usage(char *arg)
{
	nemesis_printtitle(title);

	printf("Ethernet Usage:\n"
	       "  %s [-v (verbose)] [options]\n"
	       "\n", arg);
	printf("General Options:\n"
	       "  -c <COUNT>   Send count number of packets\n"
	       "  -i <WAIT>    Interval to wait between packets\n"
	       "\n");
	printf("Ethernet Options:\n"
#if defined(WIN32)
	       "  -d <IFNUM>   Network interface number\n"
#else
	       "  -d <IFNAME>  Network interface name\n"
#endif
	       "  -H <MAC>     Source MAC address\n"
	       "  -M <MAC>     Destination MAC address\n"
	       "  -P <FILE>    Raw Ethernet payload file\n"
	       "  -T <TYPE>    Ethernet frame type, defaults to IP (0x0800)\n");
#if defined(WIN32)
	printf("  -Z           List available network interfaces by number\n");
#endif
	putchar('\n');
	ethernet_exit(1);
}

static void ethernet_cmdline(int argc, char **argv)
{
	int          opt, i;
	uint32_t     addr_tmp[6];
	char        *ethernet_options;

#if defined(WIN32)
	ethernet_options = "c:d:H:i:M:P:T:vZ?";
#else
	ethernet_options = "c:d:H:i:M:P:T:v?";
#endif
	while ((opt = getopt(argc, argv, ethernet_options)) != -1) {
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
				ethernet_exit(1);
			}
#else
			if (strlen(optarg) < 256) {
				if (device)
					free(device);
				device = strdup(optarg);
			} else {
				fprintf(stderr, "ERROR: device %s > 256 characters.\n", optarg);
				ethernet_exit(1);
			}
#endif
			break;

		case 'H': /* Ethernet source address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_shost[i] = addr_tmp[i];
			break;

		case 'M': /* Ethernet destination address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_dhost[i] = addr_tmp[i];
			break;

		case 'P': /* payload file */
			if (strlen(optarg) < 256) {
				if (payloadfile)
					free(payloadfile);
				payloadfile = strdup(optarg);
				got_payload = 1;
			} else {
				fprintf(stderr, "ERROR: payload file %s > 256 characters.\n", optarg);
				ethernet_exit(1);
			}
			break;

		case 'T':
			etherhdr.ether_type = xgetint16(optarg);
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
			ethernet_exit(1);
#endif
		case '?': /* FALLTHROUGH */
		default:
			ethernet_usage(argv[0]);
			break;
		}
	}
	argc -= optind;
	argv += optind;
}

static int ethernet_exit(int code)
{
	if (got_payload)
		free(pd.file_buf);

	if (device != NULL)
		free(device);

	if (payloadfile != NULL)
		free(payloadfile);

#if defined(WIN32)
	if (ifacetmp != NULL)
		free(ifacetmp);
#endif

	exit(code);
}

static void ethernet_verbose(void)
{
	if (verbose)
		nemesis_printeth(&etherhdr);
}
