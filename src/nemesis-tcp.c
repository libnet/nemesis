/*
 * $Id: nemesis-tcp.c,v 1.3 2005/09/27 19:46:19 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-tcp.c (TCP Packet Injector)
 *
 */

#include "nemesis-tcp.h"
#include "nemesis.h"
#if defined(WIN32)
    #include <pcap.h>
#endif

static ETHERhdr etherhdr;
static IPhdr iphdr;
static TCPhdr tcphdr;
static FileData pd, ipod, tcpod;
static int got_payload;
static char *payloadfile = NULL;       /* payload file name */
static char *ipoptionsfile = NULL;     /* IP options file name */
static char *tcpoptionsfile = NULL;    /* IP options file name */
static char *device = NULL;            /* Ethernet device */
#if defined(WIN32)
    static char *ifacetmp = NULL;
#endif

static void tcp_cmdline(int argc, char **argv);
static int tcp_exit(int code);
static void tcp_initdata(void);
static void tcp_usage(char *arg);
static void tcp_validatedata(void);
static void tcp_verbose(void);

void 
nemesis_tcp(int argc, char **argv)
{
	const char *module = "TCP Packet Injection";

	nemesis_maketitle(title, module, version);

	if (argc > 1 && !strncmp(argv[1], "help", 4))
		tcp_usage(argv[0]);

	if (nemesis_seedrand() < 0)
		fprintf(stderr, "ERROR: Unable to seed random number "
		    "generator.\n");

	tcp_initdata();
	tcp_cmdline(argc, argv);    
	tcp_validatedata();
	tcp_verbose();

	if (got_payload) {
#if defined(WIN32)
		if (builddatafromfile(TCP_LINKBUFFSIZE, &pd, 
		    (const char *)payloadfile, 
		    (const uint32_t)PAYLOADMODE) < 0) {
#else
		if (builddatafromfile(((got_link == 1) ? TCP_LINKBUFFSIZE :
		    TCP_RAWBUFFSIZE), &pd, (const char *)payloadfile, 
                    (const uint32_t)PAYLOADMODE) < 0) {
#endif
			tcp_exit(1);
		}
	}

	if (got_ipoptions) {
		if (builddatafromfile(OPTIONSBUFFSIZE, &ipod,
		    (const char *)ipoptionsfile, 
		    (const uint32_t)OPTIONSMODE) < 0) {
			tcp_exit(1);
		}
	}

	if (got_tcpoptions) {
		if (builddatafromfile(OPTIONSBUFFSIZE, &tcpod, 
		    (const char *)tcpoptionsfile, 
		    (const uint32_t)OPTIONSMODE) < 0) {
			tcp_exit(1);
		}
	}

	if (buildtcp(&etherhdr, &iphdr, &tcphdr, &pd, &ipod, &tcpod, 
	    device) < 0) {
		puts("\nTCP Injection Failure");
		tcp_exit(1);
	} else {
		puts("\nTCP Packet Injected");
		tcp_exit(0);
	}
}

static void
tcp_initdata(void)
{
	/* defaults */
	etherhdr.ether_type = ETHERTYPE_IP;	/* Ethernet type IP */
	memset(etherhdr.ether_shost, 0, 6);	/* Ethernet src address */
	memset(etherhdr.ether_dhost, 0xff, 6);	/* Ethernet dst address */
	memset(&iphdr.ip_src.s_addr, 0, 4);	/* IP source address */
	memset(&iphdr.ip_dst.s_addr, 0, 4);	/* IP destination address */
	iphdr.ip_tos = 0;			/* IP type of service */
	iphdr.ip_id = (uint16_t)libnet_get_prand(PRu16);	/* IP ID */
	iphdr.ip_p = IPPROTO_TCP;		/* IP protocol TCP */
	iphdr.ip_off = 0;			/* IP fragmentation offset */
	iphdr.ip_ttl = 255;			/* IP TTL */
	tcphdr.th_sport = (uint16_t)libnet_get_prand(PRu16);
						/* TCP source port */
	tcphdr.th_dport = (uint16_t)libnet_get_prand(PRu16);
						/* TCP destination port */
	tcphdr.th_seq = (uint32_t)libnet_get_prand(PRu32);
						/* randomize sequence number */
	tcphdr.th_ack = (uint32_t)libnet_get_prand(PRu32);
						/* randomize ack number */
	tcphdr.th_flags |= TH_SYN;		/* TCP flags */
	tcphdr.th_win = 4096;			/* TCP window size */
	pd.file_mem = NULL;
	pd.file_s = 0;
	ipod.file_mem = NULL;
	ipod.file_s = 0;
	tcpod.file_mem = NULL;
	tcpod.file_s = 0;
	return;
}

static void
tcp_validatedata(void)
{
	struct sockaddr_in sin;

	/* validation tests */
	if (iphdr.ip_src.s_addr == 0)
		iphdr.ip_src.s_addr = (uint32_t)libnet_get_prand(PRu32);
	if (iphdr.ip_dst.s_addr == 0)
		iphdr.ip_dst.s_addr = (uint32_t)libnet_get_prand(PRu32);

	/* 
	 * If the user has supplied a source hardware addess but not a device
	 * try to select a device automatically.
	 */
	if (memcmp(etherhdr.ether_shost, zero, 6) && !got_link && !device) {
		if (libnet_select_device(&sin, &device, (char *)&errbuf) < 0) {
			fprintf(stderr, "ERROR: Device not specified and "
			    "unable to automatically select a device.\n");
			tcp_exit(1);
		} else {
#ifdef DEBUG
			printf("DEBUG: automatically selected device: "
			    "       %s\n", device);
#endif
			got_link = 1;
		}
	}

	/* 
	 * If a device was specified and the user has not specified a source 
	 * hardware address, try to determine the source address
	 * automatically.
	 */
	if (got_link) {
		if ((nemesis_check_link(&etherhdr, device)) < 0) {
			fprintf(stderr, "ERROR: cannot retrieve hardware "
			    "address of %s.\n", device);
			tcp_exit(1);
		}
	}
	return;
}

static void
tcp_usage(char *arg)
{
	nemesis_printtitle((const char *)title);

	printf("TCP usage:\n  %s [-v (verbose)] [options]\n\n", arg);
	printf("TCP options: \n"
	    "  -x <Source port>\n"
	    "  -y <Destination port>\n"
	    "  -f <TCP flags>\n"
	    "     -fS (SYN), -fA (ACK), -fR (RST), -fP (PSH), -fF (FIN),"
	    " -fU (URG)\n"
	    "     -fE (ECE), -fC (CWR)\n"
	    "  -w <Window size>\n"
	    "  -s <SEQ number>\n"
	    "  -a <ACK number>\n"
	    "  -u <Urgent pointer offset>\n"
	    "  -o <TCP options file>\n"
	    "  -P <Payload file>\n\n");
	printf("IP options: \n"
	    "  -S <Source IP address>\n"
	    "  -D <Destination IP address>\n"
	    "  -I <IP ID>\n"
	    "  -T <IP TTL>\n"
	    "  -t <IP TOS>\n"
	    "  -F <IP fragmentation options>\n"
	    "     -F[D],[M],[R],[offset]\n"
	    "  -O <IP options file>\n\n");
	printf("Data Link Options: \n"
#if defined(WIN32)
	    "  -d <Ethernet device number>\n"
#else
	    "  -d <Ethernet device name>\n"
#endif
	    "  -H <Source MAC address>\n"
	    "  -M <Destination MAC address>\n");
#if defined(WIN32)
	printf("  -Z (List available network interfaces by number)\n");
#endif
	putchar('\n');
	tcp_exit(1);
}

static void
tcp_cmdline(int argc, char **argv)
{
	int opt, i;
	uint32_t addr_tmp[6];
	char *tcp_options;
	extern char *optarg;
	extern int optind;

#if defined(ENABLE_PCAPOUTPUT)
  #if defined(WIN32)
	tcp_options = "a:d:D:f:F:H:I:M:o:O:P:s:S:t:T:u:w:x:y:vWZ?";
  #else
	tcp_options = "a:d:D:f:F:H:I:M:o:O:P:s:S:t:T:u:w:x:y:vW?";
  #endif
#else
  #if defined(WIN32)
	tcp_options = "a:d:D:f:F:H:I:M:o:O:P:s:S:t:T:u:w:x:y:vZ?";
  #else
	tcp_options = "a:d:D:f:F:H:I:M:o:O:P:s:S:t:T:u:w:x:y:v?";
  #endif
#endif

	while ((opt = getopt(argc, argv, tcp_options)) != -1) {
		switch (opt) {
		case 'a':	/* ACK window */
			if (getint32(optarg, &tcphdr.th_ack) < 0)
				tcp_usage(argv[0]);
			break;
		case 'd':	/* Ethernet device */
#if defined(WIN32)
			if (nemesis_getdev(atoi(optarg), &device) < 0) {
				fprintf(stderr, "ERROR: Unable to lookup "
				    "device: '%d'.\n", atoi(optarg));
				tcp_usage(argv[0]);
			}
#else
			if (strlen(optarg) < 256) {
				device = strdup(optarg);
				got_link = 1;
			} else {
				fprintf(stderr, "ERROR: device %s > 256 "
				    "characters.\n", optarg);
				tcp_usage(argv[0]);
			}
#endif
			break;
		case 'D':	/* destination IP address */
			if ((nemesis_name_resolve(optarg, 
			    (uint32_t *)&iphdr.ip_dst.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid destination "
				    "IP address: " "\"%s\".\n", optarg);
				tcp_usage(argv[0]);
			}
			break;
		case 'f':	/* TCP flags */
			if (parsetcpflags(optarg, &tcphdr) < 0)
				tcp_usage(argv[0]);
			break;
		case 'F':	/* IP fragmentation options */
			if (parsefragoptions(optarg, &iphdr) < 0)
				tcp_usage(argv[0]);
			break;
		case 'H':	/* Ethernet source address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", 
			    &addr_tmp[0], &addr_tmp[1], &addr_tmp[2], 
			    &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_shost[i] = (uint8_t)addr_tmp[i];
			break;
		case 'I':	/* IP ID */
			if (getint16(optarg, &iphdr.ip_id) < 0)
				tcp_usage(argv[0]);
			break;
		case 'M':	/* Ethernet destination address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", 
			    &addr_tmp[0], &addr_tmp[1], &addr_tmp[2], 
			    &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_dhost[i] = (uint8_t)addr_tmp[i]; 
			break;
		case 'o':	/* TCP options file */
			if (strlen(optarg) < 256) {
				tcpoptionsfile = strdup(optarg);
				got_tcpoptions = 1;
			} else {
				fprintf(stderr, "ERROR: TCP options file %s > "
				    "256 characters.\n", optarg);
				tcp_usage(argv[0]);
			}
			break;
		case 'O':	/* IP options file */
			if (strlen(optarg) < 256) {
				ipoptionsfile = strdup(optarg);
				got_ipoptions = 1;
			} else {
				fprintf(stderr, "ERROR: IP options file %s > "
				    "256 characters.\n", optarg);
				tcp_usage(argv[0]);
			}
			break;
		case 'P':	/* payload file */
			if (strlen(optarg) < 256) {
				payloadfile = strdup(optarg);
				got_payload = 1;
			} else {
				fprintf(stderr, "ERROR: payload file %s > 256 "
				    "characters.\n", optarg);
				tcp_usage(argv[0]);
			}
			break;
		case 's':	/* TCP sequence number */
			if (getint32(optarg, &tcphdr.th_seq) < 0)
				tcp_usage(argv[0]);
			break;
		case 'S':	/* source IP address */
			if ((nemesis_name_resolve(optarg, 
			    (uint32_t *)&iphdr.ip_src.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid source IP "
				    "address: \"%s\".\n", optarg);
				tcp_usage(argv[0]);
			}
			break;
		case 't':	/* IP type of service */
			if (getint8(optarg, &iphdr.ip_tos) < 0)
				tcp_usage(argv[0]);
			break;
		case 'T':	/* IP time to live */
			if (getint8(optarg, &iphdr.ip_ttl) < 0)
				tcp_usage(argv[0]);
			break;
		case 'u':	/* TCP urgent pointer */
			if (getint16(optarg, &tcphdr.th_urp) < 0)
				tcp_usage(argv[0]);
			break;
		case 'v':
			if (++verbose >= 1)
				nemesis_printtitle((const char *)title);
			break;
		case 'w':	/* TCP window size */
			if (getint16(optarg, &tcphdr.th_win) < 0)
				tcp_usage(argv[0]);
			break;
		case 'x':	/* TCP source port */
			if (getint16(optarg, &tcphdr.th_sport) < 0)
				tcp_usage(argv[0]);
			break;
		case 'y':	/* TCP destination port */
			if (getint16(optarg, &tcphdr.th_dport) < 0)
				tcp_usage(argv[0]);
			break;
#if defined(WIN32)
		case 'Z':
			if ((ifacetmp = pcap_lookupdev(errbuf)) == NULL)
				perror(errbuf);
			else
				PrintDeviceList(ifacetmp);

			tcp_exit(1);
			/* NOTREACHED */
			break;
#endif
		case '?':	/* FALLTHROUGH */
		default:
			tcp_usage(argv[0]);
			break;
			}
		}
	argc -= optind;
	argv += optind;
	return;
}

static int
tcp_exit(int code)
{
	if (got_payload)
		free(pd.file_mem);

	if (got_ipoptions)
		free(ipod.file_mem);

	if (got_tcpoptions)
		free(tcpod.file_mem);

	if (device != NULL)
		free(device);

	if (tcpoptionsfile != NULL)
		free(tcpoptionsfile);

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

static void
tcp_verbose(void)
{
	if (verbose) {
		if (got_link)
			nemesis_printeth(&etherhdr);

		nemesis_printip(&iphdr);
		nemesis_printtcp(&tcphdr);
	}
	return;
}
