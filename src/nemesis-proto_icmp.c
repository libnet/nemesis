/*
 * $Id: nemesis-proto_icmp.c,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_icmp.c (ICMP Packet Generator)
 *
 */

#include "nemesis-icmp.h"
#include "nemesis.h"

int buildicmp(ETHERhdr *eth, IPhdr *ip, ICMPhdr *icmp, IPhdr *ipunreach, 
        FileData *pd, FileData *ipod, FileData *origod, char *device)
{
    int n;
    u_int32_t icmp_packetlen = 0, icmp_meta_packetlen = 0;
    static u_int8_t *pkt;
    static int sockfd = -1;
    struct libnet_link_int *l2 = NULL;
    u_int8_t link_offset = 0;
#if !defined(WIN32)
    int sockbuff = IP_MAXPACKET;
#endif

    if (pd->file_mem == NULL)
        pd->file_s = 0;
    if (ipod->file_mem == NULL)
        ipod->file_s = 0;
    if (origod->file_mem == NULL)
        origod->file_s = 0;

    if (got_link)   /* data link layer transport */
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

    /* determine exactly how much memory to allocate based upon the ICMP mode */
    icmp_packetlen = link_offset + LIBNET_IP_H + pd->file_s + 
            ipod->file_s;

    switch (mode)
    {
        case ICMP_ECHO:
            icmp_packetlen += LIBNET_ICMP_ECHO_H; 
            break;
        case ICMP_UNREACH:
        case ICMP_REDIRECT:
        case ICMP_TIMXCEED:
            icmp_packetlen += LIBNET_ICMP_ECHO_H + LIBNET_IP_H + 
                    origod->file_s;
            break;
        case ICMP_TSTAMP:
            icmp_packetlen += LIBNET_ICMP_TS_H;
            break;
        case ICMP_MASKREQ:
            icmp_packetlen += LIBNET_ICMP_MASK_H;
            break;
    }

    icmp_meta_packetlen = icmp_packetlen - (link_offset + LIBNET_IP_H);

#ifdef DEBUG
    printf("DEBUG: ICMP packet length %u.\n", icmp_packetlen);
    printf("DEBUG: IP   options size  %u.\n", ipod->file_s);
    printf("DEBUG: ICMP original IP options size %u.\n", origod->file_s);
    printf("DEBUG: ICMP payload size  %u.\n", pd->file_s);
#endif

    if (libnet_init_packet(icmp_packetlen, &pkt) == -1)
    {
        fprintf(stderr, "ERROR: Unable to allocate packet memory.\n");
        return -1;
    }

    if (got_link)
        libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, ETHERTYPE_IP, 
                NULL, 0, pkt);

    libnet_build_ip(icmp_meta_packetlen, ip->ip_tos, ip->ip_id, ip->ip_off, 
            ip->ip_ttl, ip->ip_p, ip->ip_src.s_addr, ip->ip_dst.s_addr, 
            NULL, 0, pkt + link_offset);

    switch (mode)
    {
        case ICMP_ECHO:
            libnet_build_icmp_echo(icmp->icmp_type, icmp->icmp_code, 
                    icmp->hun.echo.id, icmp->hun.echo.seq, pd->file_mem, 
                    pd->file_s, pkt + link_offset + LIBNET_IP_H);
            break;
        case ICMP_MASKREQ:
            libnet_build_icmp_mask(icmp->icmp_type, icmp->icmp_code, 
                    icmp->hun.echo.id, icmp->hun.echo.seq, icmp->dun.mask,
                    pd->file_mem, pd->file_s, pkt + link_offset + 
                    LIBNET_IP_H);
            break;
        case ICMP_TSTAMP:
            libnet_build_icmp_timestamp(icmp->icmp_type, icmp->icmp_code, 
                    icmp->hun.echo.id, icmp->hun.echo.seq, 
                    icmp->dun.ts.its_otime, icmp->dun.ts.its_rtime,
                    icmp->dun.ts.its_ttime, pd->file_mem, pd->file_s, 
                    pkt + link_offset + LIBNET_IP_H);
            break;
            /* Behind the scenes, the packet builder functions for unreach,
             * and time exceeded are the same.  Therefore, the unreach function 
             * is used to build both packet types.
             */
        case ICMP_UNREACH:
        case ICMP_TIMXCEED:
            libnet_build_icmp_unreach(icmp->icmp_type, icmp->icmp_code, 0,
                    ipunreach->ip_tos, ipunreach->ip_id, ipunreach->ip_off,
                    ipunreach->ip_ttl, ipunreach->ip_p, 
                    ipunreach->ip_src.s_addr, ipunreach->ip_dst.s_addr,
                    pd->file_mem, pd->file_s, pkt + link_offset + 
                    LIBNET_IP_H);
            break;
        case ICMP_REDIRECT:
            libnet_build_icmp_redirect(icmp->icmp_type, icmp->icmp_code, 
                    ntohl(icmp->hun.gateway), 0, ipunreach->ip_tos, 
                    ipunreach->ip_id, ipunreach->ip_off, ipunreach->ip_ttl,
                    ipunreach->ip_p, ipunreach->ip_src.s_addr, 
                    ipunreach->ip_dst.s_addr, pd->file_mem, pd->file_s, 
                    pkt + link_offset + LIBNET_IP_H);
            break;
    }

    if (mode == ICMP_UNREACH || mode == ICMP_TIMXCEED || mode == ICMP_REDIRECT)
    {
        if (got_origoptions)
        {
            if ((libnet_insert_ipo((struct ipoption *)origod->file_mem,
                    origod->file_s, pkt + link_offset + LIBNET_IP_H + 
                    LIBNET_ICMP_UNREACH_H + ipod->file_s)) == -1)
            {
                fprintf(stderr, "ERROR: Unable to add original IP options, "
                        "discarding them.\n");
            }
        }
    }

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

    switch (mode)
    {
        case ICMP_ECHO:
            libnet_do_checksum(pkt + link_offset, IPPROTO_ICMP, 
                    LIBNET_ICMP_ECHO_H + pd->file_s + ipod->file_s);
            break;
        case ICMP_MASKREQ:
            libnet_do_checksum(pkt + link_offset, IPPROTO_ICMP, 
                    LIBNET_ICMP_MASK_H + pd->file_s + ipod->file_s);
            break;
        case ICMP_TSTAMP:
            libnet_do_checksum(pkt + link_offset, IPPROTO_ICMP, 
                    LIBNET_ICMP_TS_H + pd->file_s + ipod->file_s);
            break;
        case ICMP_UNREACH:
        case ICMP_TIMXCEED:
            libnet_do_checksum(pkt + link_offset, IPPROTO_ICMP, 
                    LIBNET_ICMP_UNREACH_H + pd->file_s + ipod->file_s + 
                    origod->file_s);
            break;
        case ICMP_REDIRECT:
            libnet_do_checksum(pkt + link_offset, IPPROTO_ICMP, 
                    LIBNET_ICMP_REDIRECT_H + pd->file_s + ipod->file_s + 
                    origod->file_s);
            break;
    }

    if (got_link)
        n = libnet_write_link_layer(l2, device, pkt, icmp_packetlen);
    else
        n = libnet_write_ip(sockfd, pkt, icmp_packetlen);

    if (verbose == 2)
        nemesis_hexdump(pkt, icmp_packetlen, HEX_ASCII_DECODE);
    if (verbose == 3)
        nemesis_hexdump(pkt, icmp_packetlen, HEX_RAW_DECODE);

    if (n != icmp_packetlen)
    {
        fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote "
                "%d bytes.\n", n);
    }
    else
    {
        if (verbose)
        {
            if (got_link)
                printf("Wrote %d byte ICMP packet through linktype %s.\n", 
                        n, nemesis_lookup_linktype(l2->linktype));
            else
                printf("Wrote %d byte ICMP packet.\n", n);
        } 
    }
    libnet_destroy_packet(&pkt);
    if (got_link)
        libnet_close_link_interface(l2);
    else
        libnet_close_raw_sock(sockfd);
    return n;
}
