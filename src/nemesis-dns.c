/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-dns.c (DNS Packet Injector)
 */

#include "nemesis-dns.h"
#include "nemesis.h"
#if defined(WIN32)
#include <pcap.h>
#endif

static ETHERhdr etherhdr;
static IPhdr    iphdr;
static TCPhdr   tcphdr;
static UDPhdr   udphdr;
static DNShdr   dnshdr;
static struct file pd, ipod, tcpod;
static char    *payloadfile    = NULL; /* payload file name */
static char    *ipoptionsfile  = NULL; /* IP options file name */
static char    *tcpoptionsfile = NULL; /* TCP options file name */
static char    *device         = NULL; /* Ethernet device */

#if defined(WIN32)
static char *ifacetmp = NULL;
#endif

static void dns_cmdline(int, char **);
static int  dns_exit(int);
static void dns_initdata(void);
static void dns_usage(char *);
static void dns_validatedata(void);
static void dns_verbose(void);

void nemesis_dns(int argc, char **argv)
{
	const char *module = "DNS Packet Injection";
	libnet_t *l;

	nemesis_maketitle(title, module, version);

	if (argc > 1 && !strncmp(argv[1], "help", 4))
		dns_usage(argv[0]);

	if (nemesis_seedrand() < 0)
		fprintf(stderr, "ERROR: Unable to seed random number generator.\n");

	dns_initdata();
	dns_cmdline(argc, argv);

	l = libnet_init(got_link ? LIBNET_LINK_ADV : LIBNET_RAW4, device, errbuf);
	if (!l)
		dns_exit(1);

	if (got_link) {
		if ((nemesis_check_link(&etherhdr, l)) < 0) {
			fprintf(stderr, "ERROR: cannot retrieve hardware address of %s.\n", device);
			dns_exit(1);
		}
	}

	dns_validatedata();
	dns_verbose();

	if (got_payload) {
		if (state) {
#if defined(WIN32)
			if (builddatafromfile(DNSTCP_LINKBUFFSIZE, &pd, payloadfile, PAYLOADMODE) < 0)
#else
			if (builddatafromfile(((got_link == 1) ? DNSTCP_LINKBUFFSIZE : DNSTCP_RAWBUFFSIZE), &pd,
			                      payloadfile, PAYLOADMODE) < 0)
#endif
				dns_exit(1);
		} else {
#if defined(WIN32)
			if (builddatafromfile(DNSUDP_LINKBUFFSIZE, &pd, payloadfile, PAYLOADMODE) < 0)
#else
			if (builddatafromfile(((got_link == 1) ? DNSUDP_LINKBUFFSIZE : DNSUDP_RAWBUFFSIZE),
			                      &pd, payloadfile, PAYLOADMODE) < 0)
#endif
				dns_exit(1);
		}
	}

	if (got_ipoptions) {
		if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, ipoptionsfile, OPTIONSMODE) < 0)
			dns_exit(1);
	}

	if (state && got_tcpoptions) {
		if (builddatafromfile(OPTIONSBUFFSIZE, &tcpod, tcpoptionsfile, OPTIONSMODE) < 0)
			dns_exit(1);
	}

	if (builddns(&etherhdr, &iphdr, &tcphdr, &udphdr, &dnshdr, &pd, &ipod, &tcpod, l) < 0) {
		puts("\nDNS Injection Failure");
		dns_exit(1);
	}

	dns_exit(0);
}

static void dns_initdata(void)
{
	/* defaults */
	etherhdr.ether_type = ETHERTYPE_IP;    /* Ethernet type IP */
	memset(etherhdr.ether_shost, 0, 6);    /* Ethernet source address */
	memset(etherhdr.ether_dhost, 0xff, 6); /* Ethernet destination address */

	iphdr.ip_src.s_addr = libnet_get_prand(PRu32);
	iphdr.ip_dst.s_addr = libnet_get_prand(PRu32);
	iphdr.ip_tos        = IPTOS_LOWDELAY;          /* IP type of service */
	iphdr.ip_id         = libnet_get_prand(PRu16); /* IP ID */
	iphdr.ip_p          = IPPROTO_UDP;
	iphdr.ip_off        = 0;   /* IP fragmentation offset */
	iphdr.ip_ttl        = 255; /* IP TTL */

	tcphdr.th_sport = libnet_get_prand(PRu16); /* TCP source port */
	tcphdr.th_dport = 53;                      /* TCP destination port */
	tcphdr.th_seq   = libnet_get_prand(PRu32); /* randomize sequence number */
	tcphdr.th_ack   = libnet_get_prand(PRu32); /* randomize ack number */
	tcphdr.th_flags = 0;                       /* TCP flags */
	tcphdr.th_win   = 4096;                    /* TCP window size */
	tcphdr.th_urp   = libnet_get_prand(PRu16);

	udphdr.uh_sport = libnet_get_prand(PRu16); /* UDP source port */
	udphdr.uh_dport = 53;                      /* UDP destination port */

	dnshdr.id          = libnet_get_prand(PRu16); /* DNS packet ID */
	dnshdr.flags       = libnet_get_prand(PRu16); /* DNS flags */
	dnshdr.num_q       = libnet_get_prand(PRu16); /* Number of questions */
	dnshdr.num_answ_rr = libnet_get_prand(PRu16); /* Number of answer resource records */
	dnshdr.num_auth_rr = libnet_get_prand(PRu16); /* Number of authority resource records */
	dnshdr.num_addi_rr = libnet_get_prand(PRu16);

	pd.file_buf    = NULL;
	pd.file_len    = 0;
	ipod.file_buf  = NULL;
	ipod.file_len  = 0;
	tcpod.file_buf = NULL;
	tcpod.file_len = 0;
}

static void dns_validatedata(void)
{
	if (state && tcphdr.th_flags == 0)
		tcphdr.th_flags |= TH_SYN;
}

static void dns_usage(char *arg)
{
	nemesis_printtitle(title);

	printf("DNS usage:\n"
	       "  %s [-v (verbose)] [options]\n"
	       "\n", arg);
	printf("DNS options:\n"
	       "  -i <ID>      DNS ID\n"
	       "  -g <FLAGS>   DNS flags\n"
	       "  -q <NUM>     Number of Questions\n"
	       "  -b <NUM>     Number of Answer     RRs (resource records)\n"
	       "  -A <NUM>     Number of Authority  RRs\n"
	       "  -r <NUM>     Number of Additional RRs\n"
	       "  -P <FILE>    Raw DNS payload file\n"
	       "  -k           TCP transport, default UDP\n"
	       "\n");
	printf("TCP options (with -k):\n"
	       "  -x <PORT>    Source port\n"
	       "  -y <PORT>    Destination port\n"
	       "  -f <FLAG>    TCP flags:\n"
	       "                   -fS (SYN), -fA (ACK), -fR (RST), -fP (PSH)\n"
	       "                   -fF (FIN), -fU (URG), -fE (ECE), -fC (CWR)\n"
	       "  -w <SIZE>    Window size, bytes\n"
	       "  -s <NUM>     SEQ number\n"
	       "  -a <NUM>     ACK number\n"
	       "  -u <OFFSET>  Urgent pointer offset, remember -fU\n"
	       "  -o <FILE>    Raw TCP options file\n"
	       "\n");
	printf("UDP options (without -k):\n"
	       "  -x <PORT>    Source port\n"
	       "  -y <PORT>    Destination port\n"
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
	dns_exit(1);
}

static void dns_cmdline(int argc, char **argv)
{
	int          opt, i, flag;
	uint32_t     addr_tmp[6];
	char        *dns_options;
	char        *p, c;

#if defined(WIN32)
	dns_options = "a:A:b:d:D:f:F:g:H:i:I:M:o:O:P:q:r:s:S:t:T:u:w:x:y:kvZ?";
#else
	dns_options = "a:A:b:d:D:f:F:g:H:i:I:M:o:O:P:q:r:s:S:t:T:u:w:x:y:kv?";
#endif
	while ((opt = getopt(argc, argv, dns_options)) != -1) {
		switch (opt) {
		case 'a': /* ACK window */
			tcphdr.th_ack = xgetint32(optarg);
			break;

		case 'A': /* number of authoritative resource records */
			dnshdr.num_auth_rr = xgetint16(optarg);
			break;

		case 'b': /* number of answers */
			dnshdr.num_answ_rr = xgetint16(optarg);
			break;

		case 'd': /* Ethernet device */
#if defined(WIN32)
			if (nemesis_getdev(atoi(optarg), &device) < 0) {
				fprintf(stderr, "ERROR: Unable to lookup device: '%d'.\n", atoi(optarg));
				dns_exit(1);
			}
#else
			if (strlen(optarg) < 256) {
				if (device)
					free(device);
				device = strdup(optarg);
				got_link = 1;
			} else {
				fprintf(stderr, "ERROR: device %s > 256 characters.\n", optarg);
				dns_exit(1);
			}
#endif
			break;

		case 'D': /* destination IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_dst.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid destination IP address: \"%s\".\n", optarg);
				dns_exit(1);
			}
			break;

		case 'f': /* TCP flags */
			p = optarg;
			while (*p != '\0') {
				c    = *p;
				flag = strchr(validtcpflags, c) - validtcpflags;
				if (flag < 0 || flag > 7) {
					printf("ERROR: Invalid TCP flag: %c.\n", c);
					dns_exit(1);
				} else {
					tcphdr.th_flags |= 1 << flag;
					p++;
				}
			}
			break;

		case 'F': /* IP fragmentation options */
			if (parsefragoptions(&iphdr, optarg) < 0)
				dns_exit(1);
			break;

		case 'g': /* DNS flags */
			dnshdr.flags = xgetint16(optarg);
			break;

		case 'H': /* Ethernet source address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_shost[i] = addr_tmp[i];
			break;

		case 'i': /* DNS ID */
			dnshdr.id = xgetint16(optarg);
			break;

		case 'I': /* IP ID */
			iphdr.ip_id = xgetint16(optarg);
			break;

		case 'k': /* use TCP */
			iphdr.ip_tos = 0;
			iphdr.ip_p   = IPPROTO_TCP;
			state        = 1;
			break;

		case 'M': /* Ethernet destination address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_dhost[i] = addr_tmp[i];
			break;

		case 'o': /* TCP options file */
			if (strlen(optarg) < 256) {
				if (tcpoptionsfile)
					free(tcpoptionsfile);
				tcpoptionsfile = strdup(optarg);
				got_tcpoptions = 1;
			} else {
				fprintf(stderr, "ERROR: TCP options file %s > 256 characters.\n", optarg);
				dns_exit(1);
			}
			break;

		case 'O': /* IP options file */
			if (strlen(optarg) < 256) {
				if (ipoptionsfile)
					free(ipoptionsfile);
				ipoptionsfile = strdup(optarg);
				got_ipoptions = 1;
			} else {
				fprintf(stderr, "ERROR: IP options file %s > 256 characters.\n", optarg);
				dns_exit(1);
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
				dns_exit(1);
			}
			break;

		case 'q': /* number of questions */
			dnshdr.num_q = xgetint16(optarg);
			break;

		case 'r': /* number of additional resource records */
			dnshdr.num_addi_rr = xgetint16(optarg);
			break;

		case 's': /* TCP sequence number */
			tcphdr.th_seq = xgetint32(optarg);
			break;

		case 'S': /* source IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_src.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid source IP address: \"%s\".\n", optarg);
				dns_exit(1);
			}
			break;

		case 't': /* IP type of service */
			iphdr.ip_tos = xgetint8(optarg);
			break;

		case 'T': /* IP time to live */
			iphdr.ip_ttl = xgetint8(optarg);
			break;

		case 'u': /* TCP urgent pointer */
			tcphdr.th_urp = xgetint16(optarg);
			break;

		case 'v':
			verbose++;
			if (verbose == 1)
				nemesis_printtitle(title);
			break;

		case 'w': /* TCP window size */
			tcphdr.th_win = xgetint16(optarg);
			break;


		case 'x': /* TCP/UDP source port */
			tcphdr.th_sport = xgetint16(optarg);
			udphdr.uh_sport = xgetint16(optarg);
			break;

		case 'y': /* TCP/UDP destination port */
			tcphdr.th_dport = xgetint16(optarg);
			udphdr.uh_dport = xgetint16(optarg);
			break;
#if defined(WIN32)
		case 'Z':
			if ((ifacetmp = pcap_lookupdev(errbuf)) == NULL)
				perror(errbuf);

			PrintDeviceList(ifacetmp);
			dns_exit(1); /* FALLTHROUGH */
#endif
		case '?': /* FALLTHROUGH */
		default:
			dns_usage(argv[0]);
			break;
		}
	}
	argc -= optind;
	argv += optind;
}

static int dns_exit(int code)
{
	if (got_payload)
		free(pd.file_buf);

	if (got_ipoptions)
		free(ipod.file_buf);

	if (got_tcpoptions)
		free(tcpod.file_buf);

	if (device != NULL)
		free(device);

	if (tcpoptionsfile != NULL)
		free(tcpoptionsfile);

	if (ipoptionsfile != NULL)
		free(ipoptionsfile);

	if (payloadfile != NULL)
		;
	free(payloadfile);

#if defined(WIN32)
	if (ifacetmp != NULL)
		free(ifacetmp);
#endif

	exit(code);
}

static void dns_verbose(void)
{
	if (verbose) {
		if (got_link)
			nemesis_printeth(&etherhdr);

		nemesis_printip(&iphdr);

		if (state)
			nemesis_printtcp(&tcphdr);
		else
			nemesis_printudp(&udphdr);

		printf("   [DNS # Questions] %hu\n", dnshdr.num_q);
		printf("  [DNS # Answer RRs] %hu\n", dnshdr.num_answ_rr);
		printf("    [DNS # Auth RRs] %hu\n", dnshdr.num_auth_rr);
		printf("  [DNS # Addtnl RRs] %hu\n\n", dnshdr.num_addi_rr);
	}
}
