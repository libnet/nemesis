/*
 * $Id: nemesis-udp.c,v 1.1.1.1 2003/10/31 21:29:38 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-udp.c (UDP Packet Injector)
 *
 */

#include "nemesis-udp.h"
#include "nemesis.h"
#if defined(WIN32)
    #include <pcap.h>
#endif

static ETHERhdr etherhdr;
static IPhdr iphdr;
static UDPhdr udphdr;
static FileData pd, ipod;
static int got_payload;
static char *payloadfile = NULL;   /* payload file name */
static char *ipoptionsfile = NULL; /* IP options file name */
static char *device = NULL;        /* Ethernet device */
#if defined(WIN32)
    static char *ifacetmp = NULL;
#endif

static void udp_cmdline(int, char **);
static int udp_exit(int);
static void udp_initdata(void);
static void udp_usage(char *);
static void udp_validatedata(void);
static void udp_verbose(void);

void nemesis_udp(int argc, char **argv)
{
    const char *module = "UDP Packet Injection";
    
    nemesis_maketitle(title, module, version);

    if (argc > 1 && !strncmp(argv[1], "help", 4))
        udp_usage(argv[0]);

    if (nemesis_seedrand() < 0)
        fprintf(stderr, "ERROR: Unable to seed random number generator.\n");

    udp_initdata();
    udp_cmdline(argc, argv);    
    udp_validatedata();
    udp_verbose();

    if (got_payload)
    {
#if defined(WIN32)
        if (builddatafromfile(UDP_LINKBUFFSIZE, &pd, 
                (const char *)payloadfile, (const u_int32_t)PAYLOADMODE) < 0)
#else
        if (builddatafromfile(((got_link == 1) ? UDP_LINKBUFFSIZE :
                UDP_RAWBUFFSIZE), &pd, 
                (const char *)payloadfile, (const u_int32_t)PAYLOADMODE) < 0)
#endif
            udp_exit(1);
    }

    if (got_ipoptions)
    {
        if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, 
                (const char *)ipoptionsfile, (const u_int32_t)OPTIONSMODE) < 0)
            udp_exit(1);
    }

    if (buildudp(&etherhdr, &iphdr, &udphdr, &pd, &ipod, device) < 0)
    {
        puts("\nUDP Injection Failure");
        udp_exit(1);
    }
    else
    {
        puts("\nUDP Packet Injected");
        udp_exit(0);
    }
}

static void udp_initdata(void)
{
    /* defaults */
    etherhdr.ether_type = ETHERTYPE_IP;     /* Ethernet type IP */
    memset(etherhdr.ether_shost, 0, 6);     /* Ethernet source address */
    memset(etherhdr.ether_dhost, 0xff, 6);  /* Ethernet destination address */
    memset(&iphdr.ip_src.s_addr, 0, 4);     /* IP source address */
    memset(&iphdr.ip_dst.s_addr, 0, 4);     /* IP destination address */
    iphdr.ip_tos = 0;                       /* IP type of service */
    iphdr.ip_id = (u_int16_t)libnet_get_prand(PRu16);   /* IP ID */
    iphdr.ip_p = IPPROTO_UDP;               /* IP protocol TCP */
    iphdr.ip_off = 0;                       /* IP fragmentation offset */
    iphdr.ip_ttl = 255;                     /* IP TTL */
    udphdr.uh_sport = (u_int16_t)libnet_get_prand(PRu16);
                                            /* UDP source port */
    udphdr.uh_dport = 33435;                /* UDP destination port */
    pd.file_mem = NULL;
    pd.file_s = 0;
    ipod.file_mem = NULL;
    ipod.file_s = 0;
    return;
}

static void udp_validatedata(void)
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
            udp_exit(1);
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
            udp_exit(1);
        }
    }
    return;
}

static void udp_usage(char *arg)
{
    nemesis_printtitle((const char *)title);

    printf("UDP usage:\n  %s [-v (verbose)] [options]\n\n", arg);
    printf("UDP options: \n"
           "  -x <Source port>\n"
           "  -y <Destination port>\n"
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
    udp_exit(1);
}

static void udp_cmdline(int argc, char **argv)
{
    int opt, i;
    u_int32_t addr_tmp[6];
    char *udp_options;
    extern char *optarg;
    extern int optind;

#if defined(ENABLE_PCAPOUTPUT)
  #if defined(WIN32)
    udp_options = "d:D:F:H:I:M:O:P:S:t:T:x:y:vWZ?";
  #else
    udp_options = "d:D:F:H:I:M:O:P:S:t:T:x:y:vW?";
  #endif
#else
  #if defined(WIN32)
    udp_options = "d:D:F:H:I:M:O:P:S:t:T:x:y:vZ?";
  #else
    udp_options = "d:D:F:H:I:M:O:P:S:t:T:x:y:v?";
  #endif
#endif

    while ((opt = getopt(argc, argv, udp_options)) != -1)
    {
        switch (opt)
        {
            case 'd':   /* Ethernet device */
#if defined(WIN32)
                if (nemesis_getdev(atoi(optarg), &device) < 0)
                {
                    fprintf(stderr, "ERROR: Unable to lookup device: '%d'.\n", 
                            atoi(optarg));
                    udp_exit(1);
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
                    udp_exit(1);
                }
#endif
                break;
            case 'D':   /* destination IP address */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&iphdr.ip_dst.s_addr)) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid destination IP address: "
                            "\"%s\".\n", optarg);
                    udp_exit(1);
                }
                break;
            case 'F':   /* IP fragmentation options */
                if (parsefragoptions(&iphdr, optarg) < 0)
                    udp_exit(1);
                break;
            case 'H':    /* Ethernet source address */
                memset(addr_tmp, 0, sizeof(addr_tmp));
                sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                        &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                        &addr_tmp[5]);
                for (i = 0; i < 6; i++)
                    etherhdr.ether_shost[i] = (u_int8_t)addr_tmp[i];
                break;
            case 'I':   /* IP ID */
                iphdr.ip_id = xgetint16(optarg);
                break;
            case 'M':    /* Ethernet destination address */
                memset(addr_tmp, 0, sizeof(addr_tmp));
                sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                        &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                        &addr_tmp[5]);
                for (i = 0; i < 6; i++)
                    etherhdr.ether_dhost[i] = (u_int8_t)addr_tmp[i];
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
                    udp_exit(1);
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
                            "characters.\n", optarg);
                    udp_exit(1);
                }
                break;
            case 'S':    /* source IP address */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&iphdr.ip_src.s_addr)) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid source IP address: \"%s\"."
                            "\n", optarg);
                    udp_exit(1);
                }
                break;
            case 't':   /* IP type of service */
                iphdr.ip_tos = xgetint8(optarg);
                break;
            case 'T':   /* IP time to live */
                iphdr.ip_ttl = xgetint8(optarg);
                break;
            case 'v':
                verbose++;
                if (verbose == 1)
                    nemesis_printtitle((const char *)title);
                break;
            case 'x':    /* UDP source port */
                udphdr.uh_sport = xgetint16(optarg);
                break;
            case 'y':   /* UDP destination port */
                udphdr.uh_dport = xgetint16(optarg);
                break;
#if defined(WIN32)
            case 'Z':
                if ((ifacetmp = pcap_lookupdev(errbuf)) == NULL)
                    perror(errbuf);

                PrintDeviceList(ifacetmp);
                udp_exit(1);
#endif
            case '?':   /* FALLTHROUGH */
            default:                    
                udp_usage(argv[0]);
                break;
        }
    }
    argc -= optind;
    argv += optind;
    return;
}

static int udp_exit(int code)
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

static void udp_verbose(void)
{
    if (verbose)
    {
        if (got_link)
            nemesis_printeth(&etherhdr);

        nemesis_printip(&iphdr);
        nemesis_printudp(&udphdr);
    }
    return;
}
