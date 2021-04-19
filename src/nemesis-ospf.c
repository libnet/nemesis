/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-ospf.c (OSPF Packet Injector)
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
static char *ifacetmp = NULL;
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
	iphdr.ip_dst.s_addr = inet_addr("224.0.0.5");  /* All OSPF routers */
	iphdr.ip_tos        = IPTOS_LOWDELAY;          /* IP type of service */
	iphdr.ip_id         = libnet_get_prand(PRu16); /* IP ID */
	iphdr.ip_off        = 0;                       /* IP fragmentation offset */
	iphdr.ip_ttl        = 1;                       /* IP TTL, default 1 because link-local multicast ip_dst */
	iphdr.ip_p          = IPPROTO_OSPF;
	pd.file_buf         = NULL;
	pd.file_len         = 0;
	ipod.file_buf       = NULL;
	ipod.file_len       = 0;

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
	ospfhellohdr.hello_opts            = libnet_get_prand(PR8) & 0xEF; /* Skip LLS bit */
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
	lsrhdr.lsr_adrtr.s_addr = libnet_get_prand(PRu32); /* router ID of Advertising router */

	lsuhdr.lsu_num = 1;

	aslsahdr.as_nmask.s_addr    = libnet_get_prand(PRu32); /* Netmask for advertised destination */
	aslsahdr.as_metric          = LIBNET_AS_E_BIT_ON;      /* May have to set E bit in first 8bits */
	aslsahdr.as_fwd_addr.s_addr = libnet_get_prand(PRu32); /* Forwarding address */
	aslsahdr.as_rte_tag         = libnet_get_prand(PRu16);

	rtrlsahdr.rtr_flags     = libnet_get_prand(PRu16); /* set to help describe packet */
	rtrlsahdr.rtr_num       = 1;                       /* number of links in LSA */
	rtrlsahdr.rtr_link_id   = libnet_get_prand(PRu32); /* describes link_data (look below) */
	rtrlsahdr.rtr_link_data = libnet_get_prand(PRu32); /* Depending on link_id, info is here */
	rtrlsahdr.rtr_type      = 1;
	rtrlsahdr.rtr_tos_num   = 0;
	rtrlsahdr.rtr_metric    = libnet_get_prand(PRu16); /* the "cost" of using this link */

	dbdhdr.dbd_mtu_len = libnet_get_prand(PRu16); /* max length of IP dgram that this 'if' can use */
	dbdhdr.dbd_opts    = libnet_get_prand(PR8);   /* DBD packet options (from above) */
	dbdhdr.dbd_type    = libnet_get_prand(PR8);   /* type of exchange occurring */
	dbdhdr.dbd_seq     = libnet_get_prand(PRu32);

	netlsahdr.net_nmask.s_addr = libnet_get_prand(PRu32); /* Netmask for that network */
	netlsahdr.net_rtr_id       = libnet_get_prand(PRu32);

	sumlsahdr.sum_nmask.s_addr = libnet_get_prand(PRu32); /* Netmask of destination IP address */
	sumlsahdr.sum_metric       = libnet_get_prand(PRu32) & 0x0fff;
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

	printf("Usage:\n"
	       "  %s [-v (verbose)] [options]\n"
	       "\n", arg);
	printf("OSPF packet types:\n"
	       "  -p <TYPE>    OSPF packet type:\n"
	       "               -pH: HELLO\n"
	       "               -pD: Database Descriptor (DBD)\n"
	       "               -pR: Link State Request (LSR)\n"
	       "                    -pRN: request Network LSA\n"
	       "                    -pRR: request Router LSA\n"
	       "                    -pRE: request AS-External LSA\n"
	       "                    -pRS: request Network Summary LSA\n"
	       "               -pU: Link State Update (LSU)\n"
	       "                    -pUN: LSU with Network LSA\n"
	       "                    -pUR: LSU with Router LSA\n"
	       "                    -pUE: LSU with AS-External LSA\n"
	       "                    -pUS: LSU with Network Summary LSA\n"
	       "               -pA: Link State Acknowledge (LSAck)\n"
	       "                    -pAN: LSAck of Network LSA\n"
	       "                    -pAR: LSAck of Router LSA\n"
	       "                    -pAE: LSAck of AS-External LSA\n"
	       "                    -pAS: LSAck of Network Summary LSA\n"
	       "\n");
	printf("OSPF HELLO options:\n"
	       "  -N <ADDR>    Neighbor Router Address\n"
	       "  -i <SEC>     Dead Router Interval, seconds\n"
	       "  -l <SEC>     OSPF Hello Interval, seconds\n"
	       "\n");
	printf("OSPF DBD options:\n"
	       "  -z <LEN>     MAX DGRAM Length\n"
	       "  -x <TYPE>    Exchange Type\n"
	       "\n");
	printf("OSPF LSU options:\n"
	       "  -B <NUM>     Number of LSAs\n"
	       "  -P <FILE>    RAW payload file with LSAs, -pU mode\n"
	       "\n");
	printf("OSPF Router LSA options:\n"
	       "  -L <ADDR>    Link State ID: Originating Router ID (IP address)\n"
	       "  -u <NUM>     Number of links, default: 1\n"
	       "  -j <ADDR>    Link ID\n"
	       "  -k <DATA>    Link data\n"
	       "  -y <TYPE>    Link type, default: 1\n"
	       "  -w <TOS>     Link TOS number, default: 0\n"
	       "  -m <METRIC>  Link TOS (0) metric (2 bytes)\n"
	       "\n");
	printf("OSPF AS-External LSA options:\n"
	       "  -f <ADDR>    Forward address\n"
	       "  -g <TAG>     External route tag\n"
	       "\n");
	printf("OSPF Network LSA options:\n"
	       "  -L <ADDR>    Link State ID: Designated Router (IP address)\n"
	       "  -n <MASK>    Netmask\n"
	       "  -h <ADDR>    Attached Router (IP address)\n"
	       "\n");
	printf("OSPF Summary LSA options:\n"
	       "  -L <ADDR>    Link State ID: Network route to summarize\n"
	       "  -n <MASK>    Netmask of route\n"
	       "  -c <NUM>     Cost of this route (4 bytes)\n"
	       "\n");
	printf("OSPF LSR and LSU/LSA options (generic):\n"
	       "  -G <SEC>     LSA age\n"
	       "  -L <ADDR>    Link State ID\n"
	       "  -r <ADDR>    Advertising Router Address\n"
	       "  -s <NUM>     Sequence Number\n"
	       "  -n <MASK>    Multi-purpose netmask\n"
	       "\n");
	printf("OSPF options:\n"
	       "  -R <ADDR>    OSPF source router ID\n"
	       "  -A <ADDR>    OSPF Area ID, e.g. 0.0.0.1\n"
	       "  -a <TYPE>    OSPF authorization type\n"
	       "  -o <OPT>     Generic OSPF Options, for HELLO, LSA or DBD, 1 byte\n"
	       "  -P <FILE>    Raw OSPF payload file\n"
	       "\n");
	printf("IP options\n"
	       "  -S <ADDR>    Source IP address\n"
	       "  -D <ADDR>    Destination IP address, default 224.0.0.5, but\n"
	       "               can be 224.0.0.6 or a unicast address as well\n"
	       "  -I <ID>      IP ID\n"
	       "  -T <TTL>     IP TTL, default: 1\n"
	       "  -t <TOS>     IP/OSPF TOS\n"
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

#if defined(WIN32)
	ospf_options = "a:A:B:c:d:D:f:F:g:G:h:H:i:I:j:k:l:L:m:M:n:N:o:O:p:P:r:R:s:S:t:T:u:vw:x:y:z:Z?";
#else
	ospf_options = "a:A:B:c:d:D:f:F:g:G:h:H:i:I:j:k:l:L:m:M:n:N:o:O:p:P:r:R:s:S:t:T:u:vw:x:y:z:?";
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


		case 'c': /* LSA_SUM or LSU Summary-LSA metric */
			if (got_type != 7 && got_type != 3) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			sumlsahdr.sum_metric = xgetint32(optarg);
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


		case 'h': /* LSA_NET RTR ID */
			if (got_type != 4) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			netlsahdr.net_rtr_id = ip2int(optarg);
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


		case 'j':
			rtrlsahdr.rtr_link_id = ip2int(optarg);
			break;


		case 'k': /* OSPF link state acknowledgment link data */
			rtrlsahdr.rtr_link_data = ip2int(optarg);
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
			netlsahdr.net_nmask.s_addr = sumlsahdr.sum_nmask.s_addr =
				aslsahdr.as_nmask.s_addr = ospfhellohdr.hello_nmask.s_addr = ip2int(optarg);
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
			if (strlen(optarg) >= 1) {
				cmd_mode = optarg[0];
				if (strlen(optarg) > 1) {
					optarg[0] = optarg[1];
					optarg[1] = 0;
				}
			} else {
				fprintf(stderr, "ERROR: Invalid OSPF injection mode: %s.\n", optarg);
				ospf_exit(1);
			}

			switch (cmd_mode) {
			case 'A': /* OSPF Link State Acknowledge */
				ospfhdr.ospf_type = LIBNET_OSPF_LSA;
				got_mode++;
				got_type = 8;

				/* Possible to create RAW LS Ack with -pA */
				cmd_mode = optarg[0];
				if (!cmd_mode)
					break;

				/* Predefined LS Ack types */
				switch (cmd_mode) {
				case 'E': /* OSPF link state advertisement AS_EXTERNAL */
					lsahdr.lsa_type = LIBNET_LS_TYPE_ASEXT;
					break;


				case 'N': /* OSPF link state advertisement NET */
					lsahdr.lsa_type = LIBNET_LS_TYPE_NET;
					break;


				case 'R': /* OSPF link state advertisement ROUTER */
					lsahdr.lsa_type = LIBNET_LS_TYPE_RTR;
					break;


				case 'S': /* OSPF link state advertisement Summary */
					lsahdr.lsa_type = LIBNET_LS_TYPE_IP; /* XXX: How about ASBR? */
					break;

				default:
					fprintf(stderr, "ERROR: Unsupported LS Ack type.\n");
					ospf_exit(1);
					/* NOTREACHED */
					break;
				}
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


			case 'R': /* OSPF link state request */
				ospfhdr.ospf_type = LIBNET_OSPF_LSR;
				got_mode++;
				got_type = 2;

				/* Predefined LS Requst types */
				cmd_mode = optarg[0];
				switch (cmd_mode) {
				case 'E':
					lsrhdr.lsr_type = 5;
					break;


				case 'N':
					lsrhdr.lsr_type = 2;
					break;


				case 'R':
					lsrhdr.lsr_type = 1;
					break;


				case 'S':
					lsrhdr.lsr_type = 3;
					break;

				default:
					fprintf(stderr, "ERROR: Unsupported LS Request type.\n");
					ospf_exit(1);
					/* NOTREACHED */
					break;
				}
				break;


			case 'U': /* OSPF link state update */
				ospfhdr.ospf_type = LIBNET_OSPF_LSU;
				lsahdr.lsa_type   = LIBNET_LS_TYPE_IP; /* XXX: How about ASBR? */
				got_mode++;
				got_type = 3;

				/* Possible to create RAW LS Update with -pU */
				cmd_mode = optarg[0];
				if (!cmd_mode)
					break;

				/* Predefined LS Update types */
				switch (cmd_mode) {
				case 'E': /* OSPF link state advertisement AS_EXTERNAL */
					lsahdr.lsa_type = LIBNET_LS_TYPE_ASEXT;
					got_type = 5;
					break;


				case 'N': /* OSPF link state advertisement NET */
					lsahdr.lsa_type = LIBNET_LS_TYPE_NET;
					got_type = 4;
					break;


				case 'R': /* OSPF link state advertisement ROUTER */
					lsahdr.lsa_type = LIBNET_LS_TYPE_RTR;
					got_type = 6;
					break;


				case 'S': /* OSPF link state advertisement Summary */
					lsahdr.lsa_type = LIBNET_LS_TYPE_IP; /* XXX: How about ASBR? */
					got_type = 7;
					break;

				default:
					fprintf(stderr, "ERROR: Unsupported LS Update type.\n");
					ospf_exit(1);
					/* NOTREACHED */
					break;
				}
				break;


			case '?': /* FALLTHROUGH */
			default:
				fprintf(stderr, "ERROR: OSPF injection mode -p%c not found.\n", cmd_mode);
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
			lsahdr.lsa_adv.s_addr = ip2int(optarg);
			if (!lsahdr.lsa_adv.s_addr) {
				fprintf(stderr, "ERROR: Invalid OSPF advertising router ID (IP address): \"%s\".\n", optarg);
				ospf_exit(1);
			}
			lsrhdr.lsr_adrtr.s_addr = lsahdr.lsa_adv.s_addr;
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


		case 'w': /* LSA_RTR TOS number */
			if (got_type != 6) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			rtrlsahdr.rtr_tos_num = xgetint8(optarg);
			break;


		case 'x': /* OSPF DBD exchange type */
			if (got_type != 1) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			dbdhdr.dbd_type = xgetint8(optarg);
			break;


		case 'y': /* OSPF description of router link */
			rtrlsahdr.rtr_type = xgetint8(optarg);
			break;


		case 'z': /* OSPF DBD interface MTU size */
			if (got_type != 1) {
				fprintf(stderr, "error type of packet parameter\n");
				ospf_exit(1);
			}
			dbdhdr.dbd_mtu_len = xgetint16(optarg);
			break;

#if defined(WIN32)
		case 'Z':
			if ((ifacetmp = pcap_lookupdev(errbuf)) == NULL)
				perror(errbuf);

			PrintDeviceList(ifacetmp);
			ospf_exit(1);
#endif

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
