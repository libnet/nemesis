/*
 * $Id: nemesis-proto_igmp.c,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_igmp.c (IGMP Packet Generator)
 *
 */

#include "nemesis-igmp.h"
#include "nemesis.h"

int buildigmp(ETHERhdr *eth, IPhdr *ip, IGMPhdr *igmp, FileData *pd,
        FileData *ipod, char *device)
{
    int n;
    u_int32_t igmp_packetlen = 0, igmp_meta_packetlen = 0;
    static int sockfd = -1;
    static u_int8_t *pkt;
    struct libnet_link_int *l2 = NULL;
    u_int8_t link_offset = 0;
#if !defined(WIN32)
    int sockbuff = IP_MAXPACKET;
#endif

    if (pd->file_mem == NULL)
        pd->file_s = 0;
    if (ipod->file_mem == NULL)
        ipod->file_s = 0;

    if (got_link)    /* data link layer transport */
    {
        if ((l2 = libnet_open_link_interface(device, errbuf)) == NULL)
        {
            nemesis_device_failure(INJECTION_LINK, (const char *)device);
            return -1;
        }
        link_offset = LIBNET_ETH_H;
    }
    else
    {
        if ((sockfd = libnet_open_raw_sock(IPPROTO_RAW)) < 0)
        {
            nemesis_device_failure(INJECTION_RAW, (const char *)NULL);
            return -1;
        }
#if !defined(WIN32)
        if ((setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const void *)&sockbuff, 
                sizeof(sockbuff))) < 0)
        {
            fprintf(stderr, "ERROR: setsockopt() failed.\n");
            return -1;
        }
#endif
    }

    igmp_packetlen = link_offset + LIBNET_IP_H + LIBNET_IGMP_H + 
            pd->file_s + ipod->file_s;

    igmp_meta_packetlen = igmp_packetlen - (link_offset + LIBNET_IP_H);

#ifdef DEBUG
    printf("DEBUG: IGMP packet length %u.\n", igmp_packetlen);
    printf("DEBUG: IP   options size  %u.\n", ipod->file_s);
    printf("DEBUG: IGMP payload size  %u.\n", pd->file_s);
#endif

    if (libnet_init_packet(igmp_packetlen, &pkt) == -1)
    {
        fprintf(stderr, "ERROR: Unable to allocate packet memory.\n");
        return -1;
    }

    if (got_link)
        libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, ETHERTYPE_IP, 
                NULL, 0, pkt);

    libnet_build_ip(igmp_meta_packetlen, ip->ip_tos, ip->ip_id, ip->ip_off, 
            ip->ip_ttl, ip->ip_p, ip->ip_src.s_addr, ip->ip_dst.s_addr, 
            NULL, 0, pkt + link_offset);

    libnet_build_igmp(igmp->igmp_type, igmp->igmp_code, 
                igmp->igmp_group.s_addr, pd->file_mem, pd->file_s, pkt + 
                link_offset + LIBNET_IP_H);

    if (got_ipoptions)
    {
        if ((libnet_insert_ipo((struct ipoption *)ipod->file_mem, 
                ipod->file_s, pkt + link_offset)) == -1)
        {
            fprintf(stderr, "ERROR: Unable to add IP options, discarding "
                    "them.\n");
        }
    }

    if (got_link)
        libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H + 
                ipod->file_s);

    libnet_do_checksum(pkt + link_offset, IPPROTO_IGMP, LIBNET_IGMP_H + 
            pd->file_s + ipod->file_s);

    if (got_link)
        n = libnet_write_link_layer(l2, device, pkt, igmp_packetlen);
    else
        n = libnet_write_ip(sockfd, pkt, igmp_packetlen);

    if (verbose == 2)
        nemesis_hexdump(pkt, igmp_packetlen, HEX_ASCII_DECODE);
    if (verbose == 3)
        nemesis_hexdump(pkt, igmp_packetlen, HEX_RAW_DECODE);

    if (n != igmp_packetlen)
    {
        fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote "
                "%d bytes.\n", n);
    }
    else
    {
        if (verbose)
        {
            if (got_link)
                printf("Wrote %d byte IGMP packet through linktype %s.\n", 
                        n, nemesis_lookup_linktype(l2->linktype));
            else
                printf("Wrote %d byte IGMP packet.\n", n);
        } 
    }
    libnet_destroy_packet(&pkt);
    if (got_link)
        libnet_close_link_interface(l2);
    else
        libnet_close_raw_sock(sockfd);
    return n;
}
