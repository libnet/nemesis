/*
 * $Id: nemesis-ospf.c,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
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
static IPhdr iphdr;
static OSPFhdr ospfhdr;
static OSPFHELLOhdr ospfhellohdr;
static LSAhdr lsahdr;
static LSRhdr lsrhdr;
static LSUhdr lsuhdr;
static ASLSAhdr aslsahdr;
static RTRLSAhdr rtrlsahdr;
static DBDhdr dbdhdr;
static NETLSAhdr netlsahdr;
static SUMLSAhdr sumlsahdr;
static FileData pd, ipod;
static int got_payload;
static int got_mode;
static char *payloadfile = NULL;       /* payload file name */
static char *ipoptionsfile = NULL;     /* IP options file name */
static char *device = NULL;            /* Ethernet device */
#if defined(WIN32)
    char *ifacetmp;
#endif

static void ospf_cmdline(int, char **);
static int ospf_exit(int);
static void ospf_initdata(void);
static void ospf_usage(char *);
static void ospf_validatedata(void);
static void ospf_verbose(void);

void nemesis_ospf(int argc, char **argv)
{
    const char *module = "OSPF Packet Injection";

    fprintf(stderr, "Sorry, OSPF is currently non-functional.\n");
    ospf_exit(1);

    nemesis_maketitle(title, module, version);

    if (argc > 1 && !strncmp(argv[1], "help", 4))
            ospf_usage(argv[0]);

    if (nemesis_seedrand() < 0)
        fprintf(stderr, "ERROR: Unable to seed random number generator.\n");

    ospf_initdata();
    ospf_cmdline(argc, argv);
    ospf_validatedata();
    ospf_verbose();

    if (got_payload)
    {
#if defined(WIN32)
        if (builddatafromfile(TCP_LINKBUFFSIZE, &pd, (const char *)payloadfile, 
                (const u_int32_t)PAYLOADMODE) < 0)
#else
        if (builddatafromfile(((got_link == 1) ? TCP_LINKBUFFSIZE :
                TCP_RAWBUFFSIZE), &pd, (const char *)payloadfile, 
                (const u_int32_t)PAYLOADMODE) < 0)
#endif
            ospf_exit(1);
    }

    if (got_ipoptions)
    {
        if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, 
                (const char *)ipoptionsfile, (const u_int32_t)OPTIONSMODE) < 0)
            ospf_exit(1);
    }

    if (buildospf(&etherhdr, &iphdr, &pd, &ipod, device) < 0)
    {
        puts("\nOSPF Injection Failure");
        ospf_exit(1);
    }
    else
    {
        puts("\nOSPF Packet Injected");
        ospf_exit(0);
    }
}

static void ospf_initdata(void)
{
    /* defaults */
    etherhdr.ether_type = ETHERTYPE_IP;     /* Ethernet type IP */
    memset(etherhdr.ether_shost, 0, 6);     /* Ethernet source address */
    memset(etherhdr.ether_dhost, 0xff, 6);  /* Ethernet destination address */
    memset(&iphdr.ip_src.s_addr, 0, 4);     /* IP source address */
    memset(&iphdr.ip_dst.s_addr, 0, 4);     /* IP destination address */
    iphdr.ip_tos = IPTOS_LOWDELAY;          /* IP type of service */
    iphdr.ip_id = (u_int16_t)libnet_get_prand(PRu16);   /* IP ID */
    iphdr.ip_off = 0;                       /* IP fragmentation offset */
    iphdr.ip_ttl = 255;                     /* IP TTL */
    pd.file_mem = NULL;
    pd.file_s = 0;
    ipod.file_mem = NULL;
    ipod.file_s = 0;

    return;
}
    
static void ospf_validatedata(void)
{
    struct sockaddr_in sin;

    /* validation tests */
    if (iphdr.ip_src.s_addr == 0)
        iphdr.ip_src.s_addr = (u_int32_t)libnet_get_prand(PRu32);
    if (iphdr.ip_dst.s_addr == 0)
        iphdr.ip_dst.s_addr = (u_int32_t)libnet_get_prand(PRu32);

    /* if the user has supplied a source hardware addess but not a device
     * try to select a device automatically
     */
    if (memcmp(etherhdr.ether_shost, zero, 6) && !got_link && !device)
    {
        if (libnet_select_device(&sin, &device, (char *)&errbuf) < 0)
        {
            fprintf(stderr, "ERROR: Device not specified and unable to "
                    "automatically select a device.\n");
            ospf_exit(1);
        }
        else
        {
#ifdef DEBUG
            printf("DEBUG: automatically selected device: "
                    "       %s\n", device);
#endif
            got_link = 1;
        }
    }

    /* if a device was specified and the user has not specified a source 
     * hardware address, try to determine the source address automatically
     */
    if (got_link)
    {
        if ((nemesis_check_link(&etherhdr, device)) < 0)
        {
            fprintf(stderr, "ERROR: cannot retrieve hardware address of %s.\n",
                    device);
            ospf_exit(1);
        }
    }

    if (got_mode > 1)
    {
        fprintf(stderr, "ERROR: OSPF injection mode multiply specified - "
                "select only one.\n");
        ospf_exit(1);
    }
}


static void ospf_usage(char *arg)
{
    nemesis_printtitle((const char *)title);

    printf("OSPF usage:\n  %s [-v (verbose)] [options]\n\n", arg);
    printf("OSPF Packet Types: \n"
           "  -p <OSPF Protocol>\n"
           "     -pH HELLO, -pa LSA, -pD DBD, -pL LSR, -pU LSU\n");
    printf("OSPF HELLO options: \n"
           "  -N <Neighbor Router Address>\n"
           "  -i <Dead Router Interval>\n"
           "  -l <OSPF Interval>\n");
    printf("OSPF DBD options: \n"
           "  -z <MAX DGRAM Length>\n"
           "  -x <Exchange Type>\n");
    printf("OSPF LSU options: \n"
           "  -B <num of LSAs to bcast>\n");
    printf("OSPF LSA related options: \n"
           "  -L <router id>\n"
           "  -G <LSA age>\n");
    printf("OSPF LSA_RTR options: \n"
           "  -u <LSA_RTR num>\n"
           "  -y <LSA_RTR router type>\n"
           "  -k <LSA_RTR router data>\n");
    printf("OSPF LSA_AS_EXT options: \n"
           "  -f <LSA_AS_EXT forward address>\n"
           "  -g <LSA_AS_EXT tag>\n");
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

static void ospf_cmdline(int argc, char **argv)
{
    int opt, i;
    u_int32_t addr_tmp[6];
    char *ospf_options;
    char cmd_mode = 0;
    extern char *optarg;
    extern int optind;

#if defined(ENABLE_PCAPOUTPUT)
  #if defined(WIN32)
    ospf_options = "a:A:B:d:D:f:F:g:G:H:i:k:I:l:L:m:M:n:N:o:O:p:P:r:R:s:S:t:T:u:x:y:z:vWZ?";
  #else
    ospf_options = "a:A:B:d:D:f:F:g:G:H:i:k:I:l:L:m:M:n:N:o:O:p:P:r:R:s:S:t:T:u:x:y:z:vW?";
  #endif
#else
  #if defined(WIN32)
    ospf_options = "a:A:B:d:D:f:F:g:G:H:i:k:I:l:L:m:M:n:N:o:O:p:P:r:R:s:S:t:T:u:x:y:z:vZ?";
  #else
    ospf_options = "a:A:B:d:D:f:F:g:G:H:i:k:I:l:L:m:M:n:N:o:O:p:P:r:R:s:S:t:T:u:x:y:z:v?";
  #endif
#endif

    while ((opt = getopt(argc, argv, ospf_options)) != -1)
    {
        switch (opt)
        {
            case 'a':   /* OSPF authorization type */
                ospfhdr.ospf_auth_type = (u_int16_t)htons(xgetint16(optarg));
                break;
            case 'A':   /* OSPF area ID */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&ospfhdr.ospf_area_id.s_addr)) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid OSPF area ID IP address: "
                            "\"%s\".\n", optarg);
                    ospf_exit(1);
                }
                break;
            case 'B':   /* OSPF # of broadcasted link state advertisements */
                lsuhdr.lsu_num = (u_int32_t)htonl(xgetint32(optarg));
                break;
            case 'd':   /* Ethernet device */
#if defined(WIN32)
                if (nemesis_getdev(atoi(optarg), &device) < 0)
                {
                    fprintf(stderr, "ERROR: Unable to lookup device: '%d'.\n", 
                            atoi(optarg));
                    ospf_exit(1);
                }
#else
                if (strlen(optarg) < 256)
                {
                    device = strdup(optarg);
                    got_link = 1;
                }
                else
                {
                    fprintf(stderr, "ERROR: device %s > 256 characters.\n", 
                            optarg);
                    ospf_exit(1);
                }
#endif
                break;
            case 'D':   /* destination IP address */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&iphdr.ip_dst.s_addr)) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid destination IP address: "
                            "\"%s\".\n", optarg);
                    ospf_exit(1);
                }
                break;
            case 'f':   /* external AS LSA forwarding IP address */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&aslsahdr.as_fwd_addr.s_addr)) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid external LSA forwarding IP "
                            "address: \"%s\".\n", optarg);
                    ospf_exit(1);
                }
                break;
            case 'F':   /* IP fragmentation options */
                if (parsefragoptions(&iphdr, optarg) < 0)
                    ospf_exit(1);
                break;
            case 'g':   /* OSPF external route tag */
                aslsahdr.as_rte_tag = (u_int32_t)htonl(xgetint32(optarg));
                break;
            case 'G':   /* OSPF link state acknowledgment age in seconds */
                lsahdr.lsa_age = (u_int16_t)htons(xgetint16(optarg));
                break;
            case 'H':   /* Ethernet source address */
                memset(addr_tmp, 0, sizeof(addr_tmp));
                sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                        &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                        &addr_tmp[5]);
                for (i = 0; i < 6; i++)
                    etherhdr.ether_shost[i] = (u_int8_t)addr_tmp[i];
                break;
            case 'i':   /* OSPF HELLO link state countdown timer in seconds */
                ospfhellohdr.hello_dead_intvl = (u_int16_t)htonl(xgetint32(optarg));
                break;
            case 'I':   /* IP ID */
                iphdr.ip_id = xgetint16(optarg);
                break;
            case 'k':   /* OSPF link state acknowledgment link data */
                rtrlsahdr.rtr_link_data = (u_int32_t)htonl(xgetint32(optarg));
                break;
            case 'l':   /* OSPF HELLO las packet interval in seconds */
                ospfhellohdr.hello_intrvl = (u_int16_t)htons(xgetint16(optarg));
                break;
            case 'L':   /* OSPF link state request ID */
                lsrhdr.lsr_lsid = (u_int32_t)htonl(xgetint32(optarg));
                break;
            case 'm':   /* OSPF link state acknowledgment link metric */
                rtrlsahdr.rtr_metric = (u_int16_t)htons(xgetint16(optarg));
                break;
            case 'M':   /* Ethernet destination address */
                memset(addr_tmp, 0, sizeof(addr_tmp));
                sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                        &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                        &addr_tmp[5]);
                for (i = 0; i < 6; i++)
                    etherhdr.ether_dhost[i] = (u_int8_t)addr_tmp[i]; 
                break;
            case 'n':   /* OSPF multi-purpose netmask placement */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&ospfhellohdr.hello_nmask.s_addr)) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid netmask IP address: \"%s\""
                            ".\n", optarg);
                    ospf_exit(1);
                }
                else
                {
                    memcpy(&ospfhellohdr.hello_nmask.s_addr, 
                            &netlsahdr.net_nmask.s_addr, sizeof(u_int));
                    memcpy(&ospfhellohdr.hello_nmask.s_addr, 
                            &sumlsahdr.sum_nmask.s_addr, sizeof(u_int));
                    memcpy(&ospfhellohdr.hello_nmask.s_addr, 
                            &aslsahdr.as_nmask.s_addr, sizeof(u_int));
                }
                break;
            case 'N':   /* OSPF HELLO neighbor router */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&ospfhellohdr.hello_nbr.s_addr)) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid OSPF HELLO neighbor "
                            "IP address: \"%s\".\n", optarg);
                    ospf_exit(1);
                }
                break;
            case 'o':   /* OSPF multi purpose options */
                ospfhellohdr.hello_opts = xgetint8(optarg);
                lsahdr.lsa_opts = xgetint8(optarg);
                dbdhdr.dbd_opts = xgetint8(optarg);
                break;
            case 'O':   /* IP options file */
                if (strlen(optarg) < 256)
                {
                    ipoptionsfile = strdup(optarg);
                    got_ipoptions = 1;
                }
                else
                {
                    fprintf(stderr, "ERROR: IP options file %s > 256 "
                            "characters.\n", optarg);
                    ospf_exit(1);
                }
                break;
            case 'p':   /* OSPF injection mode */
                if (strlen(optarg) == 1)
                {
                    cmd_mode = *optarg;
                }
                else
                {
                    fprintf(stderr, "ERROR: Invalide OSPF injection mode: "
                            "%s.\n", optarg);
                    ospf_exit(1);
                }
                switch (cmd_mode)
                {
                    case 'A':   /* OSPF link state advertisement */
                        ospfhdr.ospf_type = LIBNET_OSPF_LSA;
                        got_mode++;
                        break;
                    case 'D':   /* OSPF database description */
                        ospfhdr.ospf_type = LIBNET_OSPF_DBD;
                        got_mode++;
                        break;
                    case 'H':   /* OSPF Hello */
                        ospfhdr.ospf_type = LIBNET_OSPF_HELLO;
                        got_mode++;
                        break;
                    case 'L':   /* OSPF link state request */
                        ospfhdr.ospf_type = LIBNET_OSPF_LSR;
                        got_mode++;
                        break;
                    case 'U':   /* OSPF link state update */
                        ospfhdr.ospf_type = LIBNET_OSPF_LSU;
                        got_mode++;
                        break;
                    case '?':   /* FALLTHROUGH */
                    default:
                        fprintf(stderr, "ERROR: Invalid OSPF injection "
                                "mode: %c.\n", cmd_mode);
                        ospf_exit(1);
                        /* NOTREACHED */
                        break;
                }
                break;
            case 'P':   /* payload file */
                if (strlen(optarg) < 256)
                {
                    payloadfile = strdup(optarg);
                    got_payload = 1;
                }
                else
                {
                    fprintf(stderr, "ERROR: payload file %s > 256 "
                            "characters.\n", payloadfile);
                    ospf_exit(1);
                }
                break;
            case 'r':   /* OSPF advertising router ID */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&lsahdr.lsa_adv.s_addr)) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid OSPF advertising router ID "
                            "(IP address): \"%s\".\n", optarg);
                    ospf_exit(1);
                }
                break;
            case 'R':   /* OSPF source router ID */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&ospfhdr.ospf_rtr_id.s_addr)) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid OSPF source router ID (IP "
                            "address): \"%s\".\n", optarg);
                    ospf_exit(1);
                }
                break;
            case 's':   /* OSPF DBD sequence number */
                dbdhdr.dbd_seq = (u_int32_t)htonl(xgetint32(optarg));
                break;
            case 'S':   /* source IP address */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&iphdr.ip_src.s_addr)) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid source IP address: \"%s\"."
                            "\n", optarg);
                    ospf_exit(1);
                }
                break;
            case 't':   /* IP type of service */
                iphdr.ip_tos = xgetint8(optarg);
                break;
            case 'T':   /* IP time to live */
                iphdr.ip_ttl = xgetint8(optarg);
                break;
            case 'u':   /* OSPF number of links in link state header */
                rtrlsahdr.rtr_num = (u_int16_t)htons(xgetint16(optarg));
                break;
            case 'v':
                verbose++;
                if (verbose == 1)
                    nemesis_printtitle((const char *)title);
                break;
            case 'x':   /* OSPF DBD exchange type */
                dbdhdr.dbd_type = xgetint8(optarg);
                break;
            case 'y':   /* OSPF description of router link */
                rtrlsahdr.rtr_type = xgetint8(optarg);
                break;
            case 'z':   /* OSPF DBD interface MTU size */
                dbdhdr.dbd_mtu_len = (u_int16_t)htons(xgetint16(optarg));
                break;
            case '?':   /* FALLTHROUGH */
            default:
                ospf_usage(argv[0]);
                break;
        }
    }
    argc -= optind;
    argv += optind;
    return;
}

static int ospf_exit(int code)
{
    if (got_payload)
        free(pd.file_mem);

    if (got_ipoptions)
        free(ipod.file_mem);

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
    if (verbose)
    {
        if (got_link)
            nemesis_printeth(&etherhdr);

        nemesis_printip(&iphdr);

        nemesis_printospf(&ospfhdr);

        printf("[OSPF Options] 0x%x\n", ooptions);
        printf("[Priority] %d\n", priority);
        printf("[Advertising Router ID] 0x%ld\n", addrid);
        printf("[Advertising Area ID] 0x%ld\n", addaid);

        if (mode == 1)
        {
            printf("[Dead router interval] %d\n", dead_int);
        }
        else if (mode == 2)
        {
            printf("[Netmask] %ld\n", mask);
            printf("[Sequence Number] %d\n", seqnum);
            printf("[Router Advertisement Age] %d\n", ospf_age);
            printf("[Link State ID] %d\n", rtrid);
        }
        else if (mode == 3)
        {
            printf("[Link State ID]	%d\n", rtrid);
        }
    }
    return;
}
