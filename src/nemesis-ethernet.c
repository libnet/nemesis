/*
 * $Id: nemesis-ethernet.c,v 1.1.1.1 2003/10/31 21:29:36 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-ethernet.c (Ethernet Packet Injector)
 *
 */

#include "nemesis-ethernet.h"
#include "nemesis.h"
#if defined(WIN32)
    #include <pcap.h>
#endif

static ETHERhdr etherhdr;
static FileData pd;
static int got_payload;
static char *payloadfile = NULL;        /* payload file name */
static char *device = NULL;            /* Ethernet device */
#if defined(WIN32)
    static char *ifacetmp = NULL;
#endif

static void ethernet_cmdline(int, char **);
static int ethernet_exit(int);
static void ethernet_initdata(void);
static void ethernet_usage(char *);
static void ethernet_validatedata(void);
static void ethernet_verbose(void);

void nemesis_ethernet(int argc, char **argv)
{
    const char *module = "Ethernet Packet Injection";

    nemesis_maketitle(title, module, version);
  
    if (argc > 1 && !strncmp(argv[1], "help", 4))
        ethernet_usage(argv[0]);

    ethernet_initdata();
    ethernet_cmdline(argc, argv);    
    ethernet_validatedata();
    ethernet_verbose();

    if (got_payload)
    {
        if (builddatafromfile(ETHERBUFFSIZE, &pd, (const char *)payloadfile, 
                (const u_int32_t)PAYLOADMODE) < 0)
            ethernet_exit(1);
    }

    if (buildether(&etherhdr, &pd, device) < 0)
    {
        puts("\nEthernet Injection Failure");
        ethernet_exit(1);
    }
    else
    {
        puts("\nEthernet Packet Injected");
        ethernet_exit(0);
    }
}

static void ethernet_initdata(void)
{
    /* defaults */
    etherhdr.ether_type = ETHERTYPE_IP;     /* Ethernet type IP */
    memset(etherhdr.ether_shost, 0, 6);     /* Ethernet source address */
    memset(etherhdr.ether_dhost, 0xff, 6);  /* Ethernet destination address */
    pd.file_mem = NULL;
    pd.file_s = 0;
    return;
}

static void ethernet_validatedata(void)
{
    struct sockaddr_in sin;

    /* validation tests */
    if (device == NULL)
    { 
        if (libnet_select_device(&sin, &device, (char *)&errbuf) < 0)
        {
            fprintf(stderr, "ERROR: Device not specified and unable to "
                    "automatically select a device.\n");
            ethernet_exit(1);
        }
        else
        {
#ifdef DEBUG
            printf("DEBUG: automatically selected device: "
                    "       %s\n", device);
#endif
        }
    }

    /* Determine if there's a source hardware address set */
    if ((nemesis_check_link(&etherhdr, device)) < 0)
    {
        fprintf(stderr, "ERROR: Cannot retrieve hardware address of %s.\n", 
                device);
        ethernet_exit(1);
    } 
    return;
}

static void ethernet_usage(char *arg)
{
    nemesis_printtitle((const char *)title);
  
    printf("Ethernet Usage:\n  %s [-v (verbose)] [options]\n\n", arg);
    printf("Ethernet Options: \n"
#if defined(WIN32)
           "  -d <Ethernet device number>\n"
#else
           "  -d <Ethernet device name>\n"
#endif
           "  -H <Source MAC address>\n"
           "  -M <Destination MAC address>\n"
           "  -P <Payload file>\n"
           "  -T <Ethernet frame type (defaults to IP)>\n");
#if defined(WIN32)
    printf("  -Z (List available network interfaces by number)\n");
#endif
    putchar('\n');
    ethernet_exit(1);
}

static void ethernet_cmdline(int argc, char **argv)
{
    int opt, i;
    u_int32_t addr_tmp[6];
    char *ethernet_options;
    extern char *optarg;
    extern int optind;

#if defined(ENABLE_PCAPOUTPUT)
  #if defined(WIN32)
    ethernet_options = "d:H:M:P:T:vWZ?";
  #else
    ethernet_options = "d:H:M:P:T:vW?";
  #endif
#else
  #if defined(WIN32)
    ethernet_options = "d:H:M:P:T:vZ?";
  #else
    ethernet_options = "d:H:M:P:T:v?";
  #endif
#endif

    while ((opt = getopt(argc, argv, ethernet_options)) != -1)
    {
        switch (opt)
        {
            case 'd':   /* Ethernet device */
#if defined(WIN32)
                if (nemesis_getdev(atoi(optarg), &device) < 0)
                {
                    fprintf(stderr, "ERROR: Unable to lookup device: '%d'.\n", 
                            atoi(optarg));
                    ethernet_exit(1);
                }
#else
                if (strlen(optarg) < 256)
                    device = strdup(optarg);
                else
                {
                    fprintf(stderr, "ERROR: device %s > 256 characters.\n",
                            optarg);
                    ethernet_exit(1);
                }
#endif
                break;
            case 'H':    /* Ethernet source address */
                memset(addr_tmp, 0, sizeof(addr_tmp));
                sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                        &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                        &addr_tmp[5]);
                for (i = 0; i < 6; i++)
                    etherhdr.ether_shost[i] = (u_int8_t)addr_tmp[i];
                break;
            case 'M':    /* Ethernet destination address */
                memset(addr_tmp, 0, sizeof(addr_tmp));
                sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &addr_tmp[0],
                        &addr_tmp[1], &addr_tmp[2], &addr_tmp[3], &addr_tmp[4],
                        &addr_tmp[5]);
                for (i = 0; i < 6; i++)
                    etherhdr.ether_dhost[i] = (u_int8_t)addr_tmp[i];
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
                    ethernet_exit(1);
                }
                break;
            case 'T':
                etherhdr.ether_type = xgetint16(optarg);
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
                ethernet_exit(1);
#endif
            case '?':    /* FALLTHROUGH */
            default:
                ethernet_usage(argv[0]);
                break;
        }    
    }
    argc -= optind;
    argv += optind;
    return;
}

static int ethernet_exit(int code)
{
    if (got_payload)
        free(pd.file_mem);

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
    return;
}
