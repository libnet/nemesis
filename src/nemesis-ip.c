/*
 * $Id: nemesis-ip.c,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 * Original version submitted by ocsic <pisco@private.as>
 *
 * nemesis-ip.c (IP Packet Injector)
 *
 */

#include "nemesis-ip.h"
#include "nemesis.h"
#if defined(WIN32)
    #include <pcap.h>
#endif

static ETHERhdr etherhdr;
static IPhdr iphdr;
static FileData pd, ipod;
static int got_payload;
static char *payloadfile = NULL;       /* payload file name */
static char *ipoptionsfile = NULL;     /* IP options file name */  
static char *device = NULL;            /* Ethernet device */
#if defined(WIN32)
    static char *ifacetmp = NULL;
#endif

static void ip_cmdline(int, char **);
static int ip_exit(int);
static void ip_initdata(void);
static void ip_usage(char *);
static void ip_validatedata(void);
static void ip_verbose(void);

void nemesis_ip(int argc, char **argv)
{
    const char *module = "IP Packet Injection";

    nemesis_maketitle(title, module, version);
  
    if (argc > 1 && !strncmp(argv[1], "help", 4))
        ip_usage(argv[0]);

    if (nemesis_seedrand() < 0)
        fprintf(stderr, "ERROR: Unable to seed random number generator.\n");
  
    ip_initdata();
    ip_cmdline(argc, argv);    
    ip_validatedata(); 
    ip_verbose();

    if (got_payload)
    {
#if defined(WIN32)
        if (builddatafromfile(IP_LINKBUFFSIZE, &pd, (const char *)payloadfile, 
                (const u_int32_t)PAYLOADMODE) < 0)
#else
        if (builddatafromfile(((got_link == 1) ? IP_LINKBUFFSIZE :
                IP_RAWBUFFSIZE), &pd, (const char *)payloadfile, 
                (const u_int32_t)PAYLOADMODE) < 0)
#endif
            ip_exit(1);
    }

    if (got_ipoptions)
    {
        if (builddatafromfile(OPTIONSBUFFSIZE, &ipod, 
                (const char *)ipoptionsfile, (const u_int32_t)OPTIONSMODE) < 0)
            ip_exit(1);
    }

    if (buildip(&etherhdr, &iphdr, &pd, &ipod, device) < 0)
    {
        puts("\nIP Injection Failure");
        ip_exit(1);
    }
    else
    {
        puts("\nIP Packet Injected");
        ip_exit(0);
    }
}

static void ip_initdata(void)
{
    /* defaults */
    etherhdr.ether_type = ETHERTYPE_IP;     /* Ethernet type IP */
    memset(etherhdr.ether_shost, 0, 6);     /* Ethernet source address */
    memset(etherhdr.ether_dhost, 0xff, 6);  /* Ethernet destination address */
    memset(&iphdr.ip_src.s_addr, 0, 4);     /* IP source address */
    memset(&iphdr.ip_dst.s_addr, 0, 4);     /* IP destination address */
    iphdr.ip_tos = 0;                       /* IP type of service */
    iphdr.ip_id = (u_int16_t)libnet_get_prand(PRu16);   /* IP ID */
    iphdr.ip_off = 0;                       /* IP fragmentation offset */
    iphdr.ip_ttl = 255;                     /* IP TTL */
    iphdr.ip_p = 0;                         /* IP protocol */
    pd.file_mem = NULL;
    pd.file_s = 0;
    ipod.file_mem = NULL;
    ipod.file_s = 0;
    return;
}

static void ip_validatedata(void)
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
            printf("ERROR: Device not specified and unable to automatically "
                    "select a device.\n");
            ip_exit(1);
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
            fprintf(stderr, "ERROR: cannot retrieve hardware address of "
                    "%s.\n", device);
            ip_exit(1);
        }

    }
    return;
}

static void ip_usage(char *arg)
{
    nemesis_printtitle((const char *)title);
  
    printf("IP Usage:\n  %s [-v (verbose)] [options]\n\n", arg);
    printf("IP Options: \n"
           "  -S <Source IP address>\n"
           "  -D <Destination IP address>\n"
           "  -I <IP ID>\n"
           "  -p <IP protocol number>\n"
           "  -T <IP TTL>\n"
           "  -t <IP TOS>\n"
           "  -F <IP fragmentation options>\n"
           "     -F[D],[M],[R],[offset]\n"
           "  -O <IP options file>\n"
           "  -P <Payload file>\n\n");
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
    ip_exit(1);
}

static void ip_cmdline(int argc, char **argv)
{
    int opt, i;
    u_int32_t addr_tmp[6];
    char *ip_options;
    extern char *optarg;
    extern int optind;

#if defined(ENABLE_PCAPOUTPUT)
  #if defined(WIN32)
    ip_options = "d:D:F:H:I:M:O:p:P:S:t:T:vWZ?";
  #else
    ip_options = "d:D:F:H:I:M:O:p:P:S:t:T:vW?";
  #endif
#else
  #if defined(WIN32)
    ip_options = "d:D:F:H:I:M:O:p:P:S:t:T:vZ?";
  #else
    ip_options = "d:D:F:H:I:M:O:p:P:S:t:T:v?";
  #endif
#endif

    while ((opt = getopt(argc, argv, ip_options)) != -1)
    {
        switch (opt)
        {
            case 'd':    /* Ethernet device */
#if defined(WIN32)
                if (nemesis_getdev(atoi(optarg), &device) < 0)
                {
                    fprintf(stderr, "ERROR: Unable to lookup device: '%d'.\n", 
                            atoi(optarg));
                    ip_exit(1);
                }
#else
                if (strlen(optarg) < 256)
                {
                    device = strdup(optarg);
                    got_link = 1;
                }
                else
                {
                    fprintf(stderr, "ERROR: device %s > 256 characters\n",
                            optarg);
                    ip_exit(1);
                }
#endif
                break;
            case 'D':    /* destination IP address */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&iphdr.ip_dst.s_addr )) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid destination IP address: "
                            "\"%s\".\n", optarg);
                    ip_exit(1);
                }
                break;
            case 'F':    /* IP fragmentation options */
                if (parsefragoptions(&iphdr, optarg) < 0)
                    ip_exit(1);
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
                    ip_exit(1);
                }
                break;
            case 'p':   /* IP protocol */
                iphdr.ip_p = xgetint8(optarg);
                break;
            case 'P':   /* payload file */
                if (strlen(optarg) < 256)
                {
                    payloadfile = strdup(optarg);
                    got_payload = 1;
                }
                else
                {
                    fprintf(stderr, "ERROR: payload file %s > 256 characters\n",
                            optarg);
                    ip_exit(1);
                }
                break;
            case 'S':    /* source IP address */
                if ((nemesis_name_resolve(optarg, 
                        (u_int32_t *)&iphdr.ip_src.s_addr )) < 0)
                {
                    fprintf(stderr, "ERROR: Invalid source IP address: \"%s\"."
                            "\n", optarg);
                    ip_exit(1);
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
#if defined(WIN32)
            case 'Z':
                if ((ifacetmp = pcap_lookupdev(errbuf)) == NULL)
                    perror(errbuf);

                PrintDeviceList(ifacetmp);
                ip_exit(1);
#endif
            case '?':    /* FALLTHROUGH */
            default:
                ip_usage(argv[0]);
                break;
        }    
    }
    argc -= optind;
    argv += optind;
    return;
}

static int ip_exit(int code)
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

static void ip_verbose(void)
{
    if (verbose)
    {
        if (got_link)
            nemesis_printeth(&etherhdr);

        nemesis_printip(&iphdr);
    }
    return;
}
