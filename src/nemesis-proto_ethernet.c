/*
 * $Id: nemesis-proto_ethernet.c,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_ethernet.c (Ethernet Packet Generator)
 *
 */

#include "nemesis-ethernet.h"
#include "nemesis.h"

int buildether(ETHERhdr *eth, FileData *pd, char *device)
{
    int n;
    u_int32_t eth_packetlen;
    static u_int8_t *pkt;
    char *ethertype;
    struct libnet_link_int *l2 = NULL;

    /* sanity checks */
    if (pd->file_mem == NULL)
        pd->file_s = 0;

    eth_packetlen = LIBNET_ETH_H + pd->file_s;

    if ((l2 = libnet_open_link_interface(device, errbuf)) == NULL)
    {
        nemesis_device_failure(INJECTION_LINK, (const char *)device);
        return -1;
    }

    if (libnet_init_packet(eth_packetlen, &pkt) == -1)
    {
        fprintf(stderr, "ERROR: Unable to allocate packet memory.\n");
        exit(1);
    }

    libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, eth->ether_type,
            pd->file_mem, pd->file_s, pkt);

    n = libnet_write_link_layer(l2, device, pkt, eth_packetlen);
#ifdef DEBUG
    printf("DEBUG: eth_packetlen is %u.\n", eth_packetlen);
#endif
    if (verbose == 2)
        nemesis_hexdump(pkt, eth_packetlen, HEX_ASCII_DECODE);
    if (verbose == 3)
        nemesis_hexdump(pkt, eth_packetlen, HEX_RAW_DECODE);

    switch(eth->ether_type)
    {
        case ETHERTYPE_PUP:
            ethertype = "PUP";
            break;
        case ETHERTYPE_IP:
            ethertype = "IP";
            break;
        case ETHERTYPE_ARP:
            ethertype = "ARP";
            break;
        case ETHERTYPE_REVARP:
            ethertype = "REVARP";
            break;
        case ETHERTYPE_8021Q:
            ethertype = "802.1q";
            break;
        case ETHERTYPE_IPV6:
            ethertype = "IPV6";
            break;
        case ETHERTYPE_PPPOEDISC:
            ethertype = "PPOEDISC";
            break;
        case ETHERTYPE_PPPOE:
            ethertype = "PPOE";
            break;
        default:
            ethertype = NULL;
            break;
    }
   
    if (verbose)
    {
        if (ethertype != NULL)
            printf("Wrote %d byte Ethernet type %s packet through linktype "
                    "%s.\n", n, ethertype, 
                    nemesis_lookup_linktype(l2->linktype));
        else
            printf("Wrote %d byte Ethernet type %hu packet through linktype "
                    "%s.\n", n, eth->ether_type, 
                    nemesis_lookup_linktype(l2->linktype));
    }
    libnet_destroy_packet(&pkt);
    if (l2 != NULL)
        libnet_close_link_interface(l2);
    return (n);
}
