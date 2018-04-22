/*
 * $Id: nemesis-proto_dns.c,v 1.1.1.1.4.1 2005/01/27 20:14:53 jnathan Exp $
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
             FileData *pd, FileData *ipod, FileData *tcpod, libnet_t *l)
{
	int             n;
	uint32_t        dns_packetlen = 0, dns_meta_packetlen = 0;
	static uint8_t *pkt;
	uint8_t         link_offset = 0;

	if (pd->file_mem == NULL)
		pd->file_s = 0;
	if (ipod->file_mem == NULL)
		ipod->file_s = 0;
	if (tcpod->file_mem == NULL)
		tcpod->file_s = 0;

	if (got_link) { /* data link layer transport */
		link_offset = LIBNET_ETH_H;
	}

	dns_packetlen = link_offset + LIBNET_IPV4_H + pd->file_s + ipod->file_s;

	if (state == 0) /* UDP */
		dns_packetlen += LIBNET_UDP_H + LIBNET_UDP_DNSV4_H;
	else /* TCP */
		dns_packetlen += LIBNET_TCP_H + tcpod->file_s + LIBNET_TCP_DNSV4_H;

	dns_meta_packetlen = dns_packetlen - link_offset;

#ifdef DEBUG
	printf("DEBUG: DNS packet length %u.\n", dns_packetlen);
	printf("DEBUG: IP  options size  %u.\n", ipod->file_s);
	printf("DEBUG: TCP options size  %u.\n", tcpod->file_s);
	printf("DEBUG: DNS payload size  %u.\n", pd->file_s);
#endif

	// build dns header
	(void)libnet_build_dnsv4(((state == 0) ? LIBNET_UDP_DNSV4_H : LIBNET_TCP_DNSV4_H) + pd->file_s,
	                         dns->id,
	                         dns->flags,
	                         dns->num_q, dns->num_answ_rr, dns->num_auth_rr, dns->num_addi_rr, pd->file_mem, pd->file_s, l, 0);

	if (state == 0)    // build UDP
	{
		(void)libnet_build_udp(udp->uh_sport,
		                       udp->uh_dport, LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + pd->file_s, 0, NULL, 0, l, 0);

	} else    // BUILD TCP
	{
		if (got_tcpoptions) {
			if (libnet_build_tcp_options(tcpod->file_mem, tcpod->file_s, l, 0) == -1)
				fprintf(stderr, "ERROR: Unable to add TCP options, discarding them.\n");
		}

		(void)libnet_build_tcp(tcp->th_sport,
		                       tcp->th_dport,
		                       tcp->th_seq,
		                       tcp->th_ack,
		                       tcp->th_flags,
		                       tcp->th_win, 0, tcp->th_urp, LIBNET_TCP_H + LIBNET_TCP_DNSV4_H + pd->file_s, NULL, 0, l, 0);
	}

	if (got_ipoptions) {
		if (libnet_build_ipv4_options(ipod->file_mem, ipod->file_s, l, 0) == -1) {
			fprintf(stderr, "ERROR: Unable to add IP options, discarding them.\n");
		}
	}

	(void)libnet_build_ipv4(dns_meta_packetlen,
	                        ip->ip_tos,
	                        ip->ip_id,
	                        ip->ip_off, ip->ip_ttl, ip->ip_p, 0, ip->ip_src.s_addr, ip->ip_dst.s_addr, NULL, 0, l, 0);

	if (got_link)
		(void)libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, eth->ether_type, NULL, 0, l, 0);

	(void)libnet_pblock_coalesce(l, &pkt, &dns_packetlen);
	n = libnet_write(l);

	if (verbose == 2)
		nemesis_hexdump(pkt, dns_packetlen, HEX_ASCII_DECODE);
	if (verbose == 3)
		nemesis_hexdump(pkt, dns_packetlen, HEX_RAW_DECODE);

	if (n != (int)dns_packetlen) {
		fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote %d "
		                "bytes.\n",
		        n);
	} else {
		if (verbose) {
			if (got_link) {
				printf("Wrote %d byte DNS (%s) packet through linktype %s.\n", n, ((state == 0) ? "UDP" : "TCP"),
				       nemesis_lookup_linktype(l->link_type));
			} else {
				printf("Wrote %d byte DNS (%s) packet\n", n, ((state == 1) ? "UDP" : "TCP"));
			}
		}
	}
	libnet_destroy(l);
	return n;
}
