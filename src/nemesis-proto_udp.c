/*
 * $Id: nemesis-proto_udp.c,v 1.1.1.1.4.1 2005/01/27 20:14:53 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_udp.c (UDP Packet Generator)
 *
 */

#include "nemesis-udp.h"
#include "nemesis.h"

int buildudp(ETHERhdr *eth, IPhdr *ip, UDPhdr *udp, FileData *pd, 
        FileData *ipod, libnet_t *l)
{
    int n;
    u_int32_t udp_packetlen = 0, udp_meta_packetlen = 0;
    static u_int8_t *pkt;
    u_int8_t link_offset = 0;
    
#if !defined(WIN32)
    int sockbuff = IP_MAXPACKET;
#endif

    if (pd->file_mem == NULL)
        pd->file_s = 0;
    if (ipod->file_mem == NULL)
        ipod->file_s = 0;

    if (got_link)   /* data link layer transport */
    {
        link_offset = LIBNET_ETH_H;
    }

    udp_packetlen = link_offset + LIBNET_IPV4_H + LIBNET_UDP_H + pd->file_s + ipod->file_s;
    udp_meta_packetlen = udp_packetlen - link_offset;

#ifdef DEBUG
    printf("DEBUG: UDP packet length %u.\n", udp_packetlen);
    printf("DEBUG:  IP options size  %u.\n", ipod->file_s);
    printf("DEBUG: UDP payload size  %u.\n", pd->file_s);
#endif

    (void)libnet_build_udp(udp->uh_sport, 
                           udp->uh_dport, 
                           pd->file_s + LIBNET_UDP_H,
                           0,
                           pd->file_mem, 
                           pd->file_s, 
                           l,
                           0);

    if (got_ipoptions)
    {
        if ((libnet_build_ipv4_options(ipod->file_mem, ipod->file_s, l, 0)) == -1)
        {
            fprintf(stderr, "ERROR: Unable to add IP options, discarding them.\n");
        }
    }

    (void)libnet_build_ipv4(udp_meta_packetlen, 
                            ip->ip_tos, 
                            ip->ip_id, 
                            ip->ip_off, 
                            ip->ip_ttl, 
                            ip->ip_p, 
                            0,
                            ip->ip_src.s_addr, 
                            ip->ip_dst.s_addr,
                            NULL, 
                            0, 
                            l,
                            0);

    if (got_link)
        (void)libnet_build_ethernet(eth->ether_dhost, eth->ether_shost,ETHERTYPE_IP,NULL,0, l,0);

    (void)libnet_pblock_coalesce(l, &pkt, &udp_packetlen);
    n = libnet_write(l);

    if (verbose == 2)
        nemesis_hexdump(pkt, udp_packetlen, HEX_ASCII_DECODE);
    if (verbose == 3)
        nemesis_hexdump(pkt, udp_packetlen, HEX_RAW_DECODE);

    if (n != udp_packetlen)
    {
        fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote "
                "%d bytes.\n", n);
    }
    else
    {
        if (verbose)
        {
            if (got_link)
                printf("Wrote %d byte UDP packet through linktype %s.\n", n, 
                        nemesis_lookup_linktype(l->link_type));
            else
                printf("Wrote %d byte UDP packet.\n", n);
        }
    }
    libnet_destroy(l);
    return n;
}
