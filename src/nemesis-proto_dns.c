/*
 * $Id: nemesis-proto_dns.c,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_dns.c (DNS Packet Generator)
 *
 */

#include "nemesis-dns.h"
#include "nemesis.h"

int builddns(ETHERhdr *eth, IPhdr *ip, TCPhdr *tcp, UDPhdr *udp, DNShdr *dns, 
        FileData *pd, FileData *ipod, FileData *tcpod, char *device) 
{
    int n;
    u_int32_t dns_packetlen = 0, dns_meta_packetlen = 0;
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
    if (tcpod->file_mem == NULL)
        tcpod->file_s = 0;

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

    dns_packetlen = link_offset + LIBNET_IP_H + LIBNET_DNS_H + pd->file_s + 
            ipod->file_s;

    if (state == 0)    /* UDP */
        dns_packetlen += LIBNET_UDP_H;
    else    /* TCP */
        dns_packetlen += LIBNET_TCP_H + tcpod->file_s;

    dns_meta_packetlen = dns_packetlen - (link_offset + LIBNET_IP_H);

#ifdef DEBUG
    printf("DEBUG: DNS packet length %u.\n", dns_packetlen);
    printf("DEBUG: IP  options size  %u.\n", ipod->file_s);
    printf("DEBUG: TCP options size  %u.\n", tcpod->file_s);
    printf("DEBUG: DNS payload size  %u.\n", pd->file_s);
#endif

    if (libnet_init_packet(dns_packetlen, &pkt) == -1)
    {
        fprintf(stderr, "ERROR: Unable to allocate packet memory.\n");
        return -1;
    }

    if (got_link)
        libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, 
                ETHERTYPE_IP, NULL, 0, pkt);

    libnet_build_ip(dns_meta_packetlen, ip->ip_tos, ip->ip_id, 
            ip->ip_off, ip->ip_ttl, ip->ip_p, ip->ip_src.s_addr, 
            ip->ip_dst.s_addr, NULL, 0, pkt + link_offset);

    if (state == 0)
    {
        libnet_build_udp(udp->uh_sport, udp->uh_dport, NULL, 0, 
                pkt + link_offset + LIBNET_IP_H);
    }
    else
    {
        libnet_build_tcp(tcp->th_sport, tcp->th_dport, tcp->th_seq, 
                tcp->th_ack, tcp->th_flags, tcp->th_win, tcp->th_urp, 
                NULL, 0, pkt + link_offset + LIBNET_IP_H);
    }

    libnet_build_dns(dns->id, dns->flags, dns->num_q, dns->num_answ_rr, 
            dns->num_auth_rr, dns->num_addi_rr, pd->file_mem, 
            pd->file_s, pkt + link_offset + LIBNET_IP_H + ((state == 0) ? 
            LIBNET_UDP_H : LIBNET_TCP_H));

    if (got_ipoptions)
    {
        if ((libnet_insert_ipo((struct ipoption *)ipod->file_mem, 
                ipod->file_s, pkt + link_offset)) == -1)
        {
            fprintf(stderr, "ERROR: Unable to add IP options, discarding "
                    "them.\n");
        }
    }

    if (state == 1)
    {
        if (got_tcpoptions)
        {
            if ((libnet_insert_tcpo((struct tcpoption *)tcpod->file_mem, 
                    tcpod->file_s, pkt + link_offset)) == -1)
            {
                fprintf(stderr, "ERROR: Unable to add TCP options, discarding "
                        "them.\n");
            }
        }
    }

    if (got_link)
        libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H +
                ipod->file_s);

    libnet_do_checksum(pkt + link_offset, ((state == 0) ? IPPROTO_UDP : 
            IPPROTO_TCP), ((state == 0) ?  LIBNET_UDP_H : LIBNET_TCP_H) + 
            LIBNET_DNS_H + pd->file_s + ipod->file_s + 
            ((state == 0) ? 0: tcpod->file_s));

    if (got_link)
        n = libnet_write_link_layer(l2, device, pkt, dns_packetlen);
    else
        n = libnet_write_ip(sockfd, pkt, dns_packetlen);

    if (verbose == 2)
        nemesis_hexdump(pkt, dns_packetlen, HEX_ASCII_DECODE);
    if (verbose == 3)
        nemesis_hexdump(pkt, dns_packetlen, HEX_RAW_DECODE);

    if (n != dns_packetlen)
    {
        fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote %d "
                "bytes.\n", n);
    }
    else
    {
        if (verbose)
        {
            if (got_link)
            {
                printf("Wrote %d byte DNS (%s) packet through "
                        "linktype %s.\n", n, ((state == 0) ? "UDP" : "TCP"), 
                        nemesis_lookup_linktype(l2->linktype));
            }
            else
            {
                printf("Wrote %d byte DNS (%s) packet\n", n,
                        ((state == 1) ? "UDP" : "TCP"));
            }
        }
    }
    libnet_destroy_packet(&pkt);
    if (got_link)
        libnet_close_link_interface(l2);
    else
        libnet_close_raw_sock(sockfd);
    return n;
}
