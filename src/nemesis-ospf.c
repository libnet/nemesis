/*
 * $Id: nemesis-ospf.c,v 1.1.1.1.4.1 2005/01/27 20:14:53 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-ospf.c (OSPF Packet Injector)
 *
 */

#include "nemesis-ospf.h"
#include "nemesis.h"
#if defined(WIN32)
#include <pcap.h>
#endif

static ETHERhdr etherhdr;
static IPhdr    iphdr;
static struct file pd, ipod;
static int      got_mode      = 0;
static int      got_type      = 0;
static char    *payloadfile   = NULL; /* payload file name */
static char    *ipoptionsfile = NULL; /* IP options file name */
static char    *device        = NULL; /* Ethernet device */

#if defined(WIN32)
char *ifacetmp;
#endif

OSPFhdr      ospfhdr;
OSPFHELLOhdr ospfhellohdr;
LSAhdr       lsahdr;
LSRhdr       lsrhdr;
LSUhdr       lsuhdr;
ASLSAhdr     aslsahdr;
RTRLSAhdr    rtrlsahdr;
DBDhdr       dbdhdr;
NETLSAhdr    netlsahdr;
SUMLSAhdr    sumlsahdr;

static void ospf_cmdline(int, char **);
static int  ospf_exit(int);
static void ospf_initdata(void);
static void ospf_usage(char *);
static void ospf_validatedata(void);
static void ospf_verbose(void);

void nemesis_ospf(int argc, char **argv)
{
	const char *module = "OSPF Packet Injection";
	libnet_t *l;

	nemesis_maketitle(title, module, version);

	if (argc > 1 && !strncmp(argv[1], "help", 4))
		ospf_usage(argv[0]);

	if (nemesis_seedrand() < 0)
		fprintf(stderr, "ERROR: Unable to seed random number generator.\n");
	ospf_initdata();
	ospf_cmdline(argc, argv);
	l = libnet_init(got_link ? LIBNET_LINK_ADV : LIBNET_RAW4, device, errbuf);
	if (!l)
		ospf_exit(1);
	if (got_link) {
		if ((nemesis_check_link(&etherhdr, l)) < 0) {
			fprintf(stderr, "ERROR: Cannot retrieve hardware address of "
			                "%s.\n",
			        device);
			ospf_exit(1);
		}
	}

	ospf_validatedata();
	ospf_verbose();

	if (got_payload) {
#if defined(WIN32)
		if (builddatafromfile(TCP_LINKBUFFSIZE, &pd, payloadfile, PAYLOADMODE) < 0)
#else
		if (builddatafromfile(((got_link == 1) ? TCP_LINKBUFFSIZE : TCP_RAWBUFFSIZE), &pd, payloadfile, PAYLOADMODE) < 0)
#endif
			ospf_exit(1);
	}

	if (got_ipoptions) {
		if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, ipoptionsfile, OPTIONSMODE) < 0)
			ospf_exit(1);
	}
	if (buildospf(&etherhdr, &iphdr, &pd, &ipod, l, got_type) < 0) {
		puts("\nOSPF Injection Failure");
		ospf_exit(1);
	}

	ospf_exit(0);
}

static void ospf_initdata(void)
{
	/* defaults */
	etherhdr.ether_type = ETHERTYPE_IP;    /* Ethernet type IP */
	memset(etherhdr.ether_shost, 0, 6);    /* Ethernet source address */
	memset(etherhdr.ether_dhost, 0xff, 6); /* Ethernet destination address */

	iphdr.ip_src.s_addr = libnet_get_prand(PRu32);
	iphdr.ip_dst.s_addr = libnet_get_prand(PRu32);
	iphdr.ip_tos        = IPTOS_LOWDELAY;          /* IP type of service */
	iphdr.ip_id         = libnet_get_prand(PRu16); /* IP ID */
	iphdr.ip_off        = 0;                       /* IP fragmentation offset */
	iphdr.ip_ttl        = 255;                     /* IP TTL */
	iphdr.ip_p          = IPPROTO_OSPF;
	pd.file_buf         = NULL;
	pd.file_len           = 0;
	ipod.file_buf       = NULL;
	ipod.file_len         = 0;

	/* OSPF initialization */
	ospfhdr.ospf_v              = 2;
	ospfhdr.ospf_type           = LIBNET_OSPF_HELLO;
	ospfhdr.ospf_len            = LIBNET_OSPF_H;
	ospfhdr.ospf_sum            = 0;
	ospfhdr.ospf_auth_type      = LIBNET_OSPF_AUTH_NULL;
	ospfhdr.ospf_rtr_id.s_addr  = libnet_get_prand(PRu32);
	ospfhdr.ospf_area_id.s_addr = 0;

	ospfhellohdr.hello_nmask.s_addr    = libnet_get_prand(PRu32);
	ospfhellohdr.hello_intrvl          = libnet_get_prand(PRu16);
	ospfhellohdr.hello_opts            = libnet_get_prand(PR8);   /* Options for HELLO packets (look above) */
	ospfhellohdr.hello_rtr_pri         = libnet_get_prand(PR8);   /* router's priority (if 0, can't be backup) */
	ospfhellohdr.hello_dead_intvl      = libnet_get_prand(PRu32); /* # of secs a router is silent till deemed down */
	ospfhellohdr.hello_des_rtr.s_addr  = libnet_get_prand(PRu32); /* Designated router on the network */
	ospfhellohdr.hello_bkup_rtr.s_addr = libnet_get_prand(PRu32); /* Backup router */
	ospfhellohdr.hello_nbr.s_addr      = libnet_get_prand(PRu32);

	lsahdr.lsa_age        = libnet_get_prand(PRu16); /* time in seconds since the LSA was originated */
	lsahdr.lsa_opts       = libnet_get_prand(PR8);   /* look above for OPTS_* */
	lsahdr.lsa_type       = libnet_get_prand(PR8);   /* look below for LS_TYPE_* */
	lsahdr.lsa_id         = libnet_get_prand(PRu32); /* link State ID */
	lsahdr.lsa_adv.s_addr = libnet_get_prand(PRu32); /* router ID of Advertising router */
	lsahdr.lsa_seq        = libnet_get_prand(PRu32); /* LSA sequence number to detect old/bad ones */
	lsahdr.lsa_sum        = libnet_get_prand(PRu16); /* "Fletcher Checksum" of all fields minus age */
	lsahdr.lsa_len        = libnet_get_prand(PRu16);

	lsrhdr.lsr_type         = libnet_get_prand(PRu32); /* type of LS being requested */
	lsrhdr.lsr_lsid         = libnet_get_prand(PRu32); /* link state ID */
	lsrhdr.lsr_adrtr.s_addr = libnet_get_prand(PRu32);

	lsuhdr.lsu_num = libnet_get_prand(PRu32);

	aslsahdr.as_nmask.s_addr    = libnet_get_prand(PRu32); /* Netmask for advertised destination */
	aslsahdr.as_metric          = LIBNET_AS_E_BIT_ON;      /* May have to set E bit in first 8bits */
	aslsahdr.as_fwd_addr.s_addr = libnet_get_prand(PRu32); /* Forwarding address */
	aslsahdr.as_rte_tag         = libnet_get_prand(PRu16);

	rtrlsahdr.rtr_flags     = libnet_get_prand(PRu16); /* set to help describe packet */
	rtrlsahdr.rtr_num       = libnet_get_prand(PRu16); /* number of links within that packet */
	rtrlsahdr.rtr_link_id   = libnet_get_prand(PRu32); /* describes link_data (look below) */
	rtrlsahdr.rtr_link_data = libnet_get_prand(PRu32); /* Depending on link_id, info is here */
	rtrlsahdr.rtr_type      = libnet_get_prand(PR8);   /* Description of router link */
	rtrlsahdr.rtr_tos_num   = libnet_get_prand(PR8);   /* number of different TOS metrics for this link */
	rtrlsahdr.rtr_metric    = libnet_get_prand(PRu16); /* the "cost" of using this link */

	dbdhdr.dbd_mtu_len = libnet_get_prand(PRu16); /* max length of IP dgram that this 'if' can use */
	dbdhdr.dbd_opts    = libnet_get_prand(PR8);   /* DBD packet options (from above) */
	dbdhdr.dbd_type    = libnet_get_prand(PR8);   /* type of exchange occurring */
	dbdhdr.dbd_seq     = libnet_get_prand(PRu32);

	netlsahdr.net_nmask.s_addr = libnet_get_prand(PRu32); /* Netmask for that network */
	netlsahdr.net_rtr_id       = libnet_get_prand(PRu32);

	sumlsahdr.sum_nmask.s_addr = libnet_get_prand(PRu32); /* Netmask of destination IP address */
	sumlsahdr.sum_metric       = libnet_get_prand(PRu32); /* Same as in rtr_lsa (&0xfff to use last 24bit */
	sumlsahdr.sum_tos_metric   = libnet_get_prand(PRu32);
}

static void ospf_validatedata(void)
{
	if (got_mode > 1) {
		fprintf(stderr, "ERROR: OSPF injection mode multiply specified - select only one.\n");
		ospf_exit(1);
	}
}

static void ospf_usage(char *arg)
{
	nemesis_printtitle(title);

	printf("OSPF usage:\n  %s [-v (verbose)] [options]\n\n", arg);
	printf("OSPF Packet Types: \n"
	       "  -p <OSPF Protocol>\n"
	       "     -pH HELLO, -pN LSA NET, -pR LSA Router, -pE LSA AS_EXTERNAL, -pS LSA_SUM -pD DBD, -pL LSR, -pU LSU\n");
	printf("OSPF HELLO options: \n"
	       "  -N <Neighbor Router Address>\n"
	       "  -i <Dead Router Interval>\n"
	       "  -l <OSPF Interval>\n");
	printf("OSPF DBD options: \n"
	       "  -z <MAX DGRAM Length>\n"
	       "  -x <Exchange Type>\n");
	printf("OSPF LSU options: \n"
	       "  -B <num of LSAs to bcast>\n");
	printf("OSPF LSR related options: \n"
	       "  -L <router id>\n"
	       "  -G <LSA age>\n");
	printf("OSPF LSA_RTR options: \n"
	       "  -u <LSA_RTR num>\n"
	       "  -y <LSA_RTR router type>\n"
	       "  -j <LSA_RTR link ID>\n"
	       "  -q <LSA_RTR rtr_metric>\n"
	       "  -w <LSA_RTR TOS number>\n"
	       "  -k <LSA_RTR link data>\n");
	printf("OSPF LSA_AS_EXT options: \n"
	       "  -f <LSA_AS_EXT forward address>\n"
	       "  -g <LSA_AS_EXT tag>\n");
	printf("OSPF LSA_NET options: \n"
	       "  -e <LSA_NET netmask>\n"
	       "  -h <LSA_NET RTR_ID>\n");
	printf("OSPF LSA_SUM options: \n"
	       "  -b <LSA_SUM netmask> \n"
	       "  -c <LSA_SUM metric>\n"
	       "  -Q <LSA_SUM TOS metric>\n");
	printf("OSPF options: \n"
	       "  -R <OSPF source router ID (IP address)>\n"
	       "  -A <OSPF Area id>\n"
	       "  -a <OSPF authorization type>\n"
	       "  -m <OSPF Metric>\n"
	       "  -s <Sequence Number>\n"
	       "  -r <Advertising Router Address>\n"
	       "  -n <OSPF Netmask>\n"
	       "  -o <OSPF Options>\n"
	       "  -P <Payload file>\n\n");
	printf("IP Options\n"
	       "  -S <Source IP address>\n"
	       "  -D <Destination IP address>\n"
	       "  -I <IP ID>\n"
	       "  -t <IP/OSPF tos>\n"
	       "  -T <IP TTL>\n"
	       "  -F <IP fragmentation options>\n"
	       "     -F[D],[M],[R],[offset]\n"
	       "  -O <IP options file>\n\n");
	printf("Data Link Options: \n"
#if defined(WIN32)
	       "  -d <Ethernet device number>\n"
#else
	       "  -d <Ethernet device name>\n"
#endif
	       "  -H <Source MAC Address>\n"
	       "  -M <Destination MAC Address>\n");
#if defined(WIN32)
	printf("  -Z (List available network interfaces by number)\n");
#endif
	putchar('\n');
	ospf_exit(1);
}

static uint32_t ip2int(char *arg)
{
	struct in_addr ia;

	if (!inet_aton(arg, &ia))
		return 0;

	return ntohl(ia.s_addr);
}

static void ospf_cmdline(int argc, char **argv)
{
	int          opt, i;
	uint32_t     addr_tmp[6];
	char        *ospf_options;
	char         cmd_mode = 0;
	extern char *optarg;
	extern int   optind;

#if defined(WIN32)
	ospf_options = "a:A:B:b:c:d:D:f:F:g:G:H:i:k:I:l:L:m:M:n:N:o:O:p:P:r:R:s:S:t:T:u:x:y:z:vZ?";
#else
	ospf_options = "a:A:B:b:c:d:D:f:F:g:G:H:i:k:I:l:L:m:M:n:N:o:O:p:P:r:R:s:S:t:T:u:x:y:z:v?";
#endif
	while ((opt = getopt(argc, argv, ospf_options)) != -1) {
		switch (opt) {
		case 'a': /* OSPF authorization type */
			ospfhdr.ospf_auth_type = xgetint16(optarg);
			break;
		case 'A': /* OSPF area ID */
			ospfhdr.ospf_area_id.s_addr = ip2int(optarg);
			break;
		case 'B': /* OSPF # of broadcasted link state advertisements */
			if (got_type != 3) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			lsuhdr.lsu_num = xgetint32(optarg);
			break;
		case 'd': /* Ethernet device */
#if defined(WIN32)
			if (nemesis_getdev(atoi(optarg), &device) < 0) {
				fprintf(stderr, "ERROR: Unable to lookup device: '%d'.\n", atoi(optarg));
				ospf_exit(1);
			}
#else
			if (strlen(optarg) < 256) {
				if (device)
					free(device);
				device = strdup(optarg);
				got_link = 1;
			} else {
				fprintf(stderr, "ERROR: device %s > 256 characters.\n", optarg);
				ospf_exit(1);
			}
#endif
			break;
		case 'D': /* destination IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_dst.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid destination IP address: \"%s\".\n", optarg);
				ospf_exit(1);
			}
			break;
		case 'f': /* external AS LSA forwarding IP address */
			if (got_type != 5) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			if ((nemesis_name_resolve(optarg, &aslsahdr.as_fwd_addr.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid external LSA forwarding IP address: \"%s\".\n", optarg);
				ospf_exit(1);
			}
			break;
		case 'F': /* IP fragmentation options */
			if (parsefragoptions(&iphdr, optarg) < 0)
				ospf_exit(1);
			break;
		case 'g': /* OSPF external route tag */
			if (got_type != 5) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			aslsahdr.as_rte_tag = xgetint32(optarg);
			break;
		case 'G': /* OSPF link state acknowledgment age in seconds */
			lsahdr.lsa_age = xgetint16(optarg);
			break;
		case 'H': /* Ethernet source address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_shost[i] = addr_tmp[i];
			break;
		case 'i': /* OSPF HELLO link state countdown timer in seconds */
			if (got_type != 0) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			ospfhellohdr.hello_dead_intvl = xgetint32(optarg);
			break;
		case 'I': /* IP ID */
			iphdr.ip_id = xgetint16(optarg);
			break;
		case 'k': /* OSPF link state acknowledgment link data */
			if (got_type != 6) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			rtrlsahdr.rtr_link_data = xgetint32(optarg);
			break;
		case 'l': /* OSPF HELLO las packet interval in seconds */
			if (got_type != 0) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			ospfhellohdr.hello_intrvl = xgetint16(optarg);
			break;
		case 'L': /* OSPF link state request ID, or LSA ID */
			lsrhdr.lsr_lsid = ip2int(optarg);
			if (!lsrhdr.lsr_lsid) {
				fprintf(stderr, "ERROR: Invalid Link State ID (LSA ID): \"%s\".\n", optarg);
				ospf_exit(1);
			}
			lsahdr.lsa_id = lsrhdr.lsr_lsid;
			break;
		case 'm': /* OSPF link state acknowledgment link metric */
			if (got_type != 6) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			rtrlsahdr.rtr_metric = xgetint16(optarg);
			break;
		case 'M': /* Ethernet destination address */
			memset(addr_tmp, 0, sizeof(addr_tmp));
			sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
			       &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4], &addr_tmp[5]);
			for (i = 0; i < 6; i++)
				etherhdr.ether_dhost[i] = addr_tmp[i];
			break;
		case 'n': /* OSPF multi-purpose netmask placement */
			if (got_type != 0) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			if ((nemesis_name_resolve(optarg, &ospfhellohdr.hello_nmask.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid netmask IP address: \"%s\".\n", optarg);
				ospf_exit(1);
			} else {
				memcpy(&ospfhellohdr.hello_nmask.s_addr, &netlsahdr.net_nmask.s_addr, sizeof(u_int));
				memcpy(&ospfhellohdr.hello_nmask.s_addr, &sumlsahdr.sum_nmask.s_addr, sizeof(u_int));
				memcpy(&ospfhellohdr.hello_nmask.s_addr, &aslsahdr.as_nmask.s_addr, sizeof(u_int));
			}
			break;
		case 'N': /* OSPF HELLO neighbor router */
			if (got_type != 0) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			if ((nemesis_name_resolve(optarg, &ospfhellohdr.hello_nbr.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid OSPF HELLO neighbor IP address: \"%s\".\n", optarg);
				ospf_exit(1);
			}
			break;
		case 'o': /* OSPF multi purpose options */
			ospfhellohdr.hello_opts = xgetint8(optarg);
			lsahdr.lsa_opts         = xgetint8(optarg);
			dbdhdr.dbd_opts         = xgetint8(optarg);
			break;
		case 'O': /* IP options file */
			if (strlen(optarg) < 256) {
				if (ipoptionsfile)
					free(ipoptionsfile);
				ipoptionsfile = strdup(optarg);
				got_ipoptions = 1;
			} else {
				fprintf(stderr, "ERROR: IP options file %s > 256 characters.\n", optarg);
				ospf_exit(1);
			}
			break;
		case 'p': /* OSPF injection mode */
			if (strlen(optarg) == 1) {
				cmd_mode = *optarg;
			} else {
				fprintf(stderr, "ERROR: Invalide OSPF injection mode: %s.\n", optarg);
				ospf_exit(1);
			}
			switch (cmd_mode) {
			case 'N': /* OSPF link state advertisement NET */
				ospfhdr.ospf_type = LIBNET_OSPF_LSA;
				lsahdr.lsa_type   = LIBNET_LS_TYPE_NET;
				got_mode++;
				got_type = 4;
				break;
			case 'E': /* OSPF link state advertisement AS_EXTERNAL */
				ospfhdr.ospf_type = LIBNET_OSPF_LSA;
				lsahdr.lsa_type   = LIBNET_LS_TYPE_ASEXT;
				got_mode++;
				got_type = 5;
				break;
			case 'R': /* OSPF link state advertisement ROUTER */
				ospfhdr.ospf_type = LIBNET_OSPF_LSA;
				lsahdr.lsa_type   = LIBNET_LS_TYPE_RTR;
				got_mode++;
				got_type = 6;
				break;
			case 'S': /* OSPF link state advertisement Summary */
				ospfhdr.ospf_type = LIBNET_OSPF_LSA;
				got_mode++;
				got_type = 7;
				break;
			case 'D': /* OSPF database description */
				ospfhdr.ospf_type = LIBNET_OSPF_DBD;
				got_mode++;
				got_type = 1;
				break;
			case 'H': /* OSPF Hello */
				ospfhdr.ospf_type = LIBNET_OSPF_HELLO;
				got_mode++;
				got_type = 0;
				break;
			case 'L': /* OSPF link state request */
				ospfhdr.ospf_type = LIBNET_OSPF_LSR;
				got_mode++;
				got_type = 2;
				break;
			case 'U': /* OSPF link state update */
				ospfhdr.ospf_type = LIBNET_OSPF_LSU;
				lsahdr.lsa_type   = LIBNET_LS_TYPE_IP; /* XXX: How about ASBR? */
				got_mode++;
				got_type = 3;
				break;
			case '?': /* FALLTHROUGH */
			default:
				fprintf(stderr, "ERROR: Invalid OSPF injection mode: %c.\n", cmd_mode);
				ospf_exit(1);
				/* NOTREACHED */
				break;
			}
			break;
		case 'P': /* payload file */
			if (strlen(optarg) < 256) {
				if (payloadfile)
					free(payloadfile);
				payloadfile = strdup(optarg);
				got_payload = 1;
			} else {
				fprintf(stderr, "ERROR: payload file %s > 256 characters.\n", payloadfile);
				ospf_exit(1);
			}
			break;
		case 'r': /* OSPF advertising router ID */
			if ((nemesis_name_resolve(optarg, &lsahdr.lsa_adv.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid OSPF advertising router ID (IP address): \"%s\".\n", optarg);
				ospf_exit(1);
			}
			break;
		case 'R': /* OSPF source router ID */
			if ((nemesis_name_resolve(optarg, &ospfhdr.ospf_rtr_id.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid OSPF source router ID (IP address): \"%s\".\n", optarg);
				ospf_exit(1);
			}
			break;
		case 's': /* OSPF DBD sequence number */
			if (got_type != 1) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			dbdhdr.dbd_seq = xgetint32(optarg);
			break;
		case 'S': /* source IP address */
			if ((nemesis_name_resolve(optarg, &iphdr.ip_src.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid source IP address: \"%s\".\n", optarg);
				ospf_exit(1);
			}
			break;
		case 't': /* IP type of service */
			iphdr.ip_tos = xgetint8(optarg);
			break;
		case 'T': /* IP time to live */
			iphdr.ip_ttl = xgetint8(optarg);
			break;
		case 'u': /* OSPF number of links in link state header */
			if (got_type != 6) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			rtrlsahdr.rtr_num = xgetint16(optarg);
			break;
		case 'v':
			verbose++;
			if (verbose == 1)
				nemesis_printtitle(title);
			break;
		case 'x': /* OSPF DBD exchange type */
			if (got_type != 1) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			dbdhdr.dbd_type = xgetint8(optarg);
			break;
		case 'y': /* OSPF description of router link */
			if (got_type != 6) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			rtrlsahdr.rtr_type = xgetint8(optarg);
			break;
		case 'z': /* OSPF DBD interface MTU size */
			if (got_type != 1) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			dbdhdr.dbd_mtu_len = xgetint16(optarg);
			break;

		case 'e': /* LSA_NET netmask */
			if (got_type != 4) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			if ((nemesis_name_resolve(optarg, &netlsahdr.net_nmask.s_addr)) < 0) {
				fprintf(stderr, "ERROR: Invalid netmask: \"%s\".\n", optarg);
				ospf_exit(1);
			}
			break;
		case 'b': /* LSA_SUM or LSU Summary-LSA netmask */
			if (got_type != 7 && got_type != 3) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			sumlsahdr.sum_nmask.s_addr = ip2int(optarg);
			if (!sumlsahdr.sum_nmask.s_addr) {
				fprintf(stderr, "ERROR: Invalid netmask: \"%s\".\n", optarg);
				ospf_exit(1);
			}
			break;
		case 'h': /* LSA_NET RTR ID */
			if (got_type != 4) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			netlsahdr.net_rtr_id = xgetint32(optarg);
			break;
		case 'c': /* LSA_SUM or LSU Summary-LSA metric */
			if (got_type != 7 && got_type != 3) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			sumlsahdr.sum_metric = xgetint32(optarg);
			break;
		case 'Q': /* LSA_SUM TOS metric */
			if (got_type != 7) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			sumlsahdr.sum_tos_metric = xgetint32(optarg);
			break;
		case 'j': /* LSA_RTR link ID */
			if (got_type != 6) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			rtrlsahdr.rtr_link_id = xgetint32(optarg);
			break;
		case 'q': /* LSA_RTR metric */
			if (got_type != 6) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			rtrlsahdr.rtr_metric = xgetint16(optarg);
			break;
		case 'w': /* LSA_RTR TOS number */
			if (got_type != 6) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			rtrlsahdr.rtr_tos_num = xgetint8(optarg);
			break;
		case '?': /* FALLTHROUGH */
		default:
			ospf_usage(argv[0]);
			break;
		}
	}
	argc -= optind;
	argv += optind;
}

static int ospf_exit(int code)
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

static void ospf_verbose(void)
{
	if (verbose) {
		if (got_link)
			nemesis_printeth(&etherhdr);

		nemesis_printip(&iphdr);

		nemesis_printospf(&ospfhdr);

		if (mode == 1) {
		} else if (mode == 2) {
		} else if (mode == 3) {
		}
	}
}
