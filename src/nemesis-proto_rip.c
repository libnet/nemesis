/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_rip.c (RIP Packet Generator)
 */

#include "nemesis-rip.h"
#include "nemesis.h"

int buildrip(ETHERhdr *eth, IPhdr *ip, UDPhdr *udp, RIPhdr *rip, struct file *pd, struct file *ipod, libnet_t *l)
{
	int             n;
	uint32_t        rip_packetlen = 0, rip_meta_packetlen = 0;
	static uint8_t *pkt;
	uint8_t         link_offset = 0;

	if (pd->file_buf == NULL)
		pd->file_len = 0;
	if (ipod->file_buf == NULL)
		ipod->file_len = 0;

	if (got_link) /* data link layer transport */
		link_offset = LIBNET_ETH_H;

	rip_packetlen      = link_offset + LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_RIP_H + pd->file_len + ipod->file_len;
	rip_meta_packetlen = rip_packetlen - link_offset;

#ifdef DEBUG
	printf("DEBUG: RIP packet length %u.\n", rip_packetlen);
	printf("DEBUG:  IP options size  %zd.\n", ipod->file_len);
	printf("DEBUG: RIP payload size  %zd.\n", pd->file_len);
#endif

	(void)libnet_build_rip(rip->rip_cmd,
	                       rip->rip_ver,
	                       rip->rip_rd,
	                       rip->rip_af,
	                       rip->rip_rt,
	                       rip->rip_addr,
	                       rip->rip_mask,
	                       rip->rip_next_hop,
	                       rip->rip_metric,
	                       pd->file_buf,
	                       pd->file_len,
	                       l,
	                       0);
	(void)libnet_build_udp(udp->uh_sport,
	                       udp->uh_dport,
	                       LIBNET_UDP_H + pd->file_len + LIBNET_RIP_H,
	                       0,
	                       NULL,
	                       0,
	                       l,
	                       0);

	if (got_ipoptions) {
		if (libnet_build_ipv4_options(ipod->file_buf, ipod->file_len, l, 0) == -1) {
			fprintf(stderr, "ERROR: Unable to add IP options, discarding them.\n");
		}
	}

	libnet_build_ipv4(rip_meta_packetlen,
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
		libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, ETHERTYPE_IP, NULL, 0, l, 0);

	libnet_pblock_coalesce(l, &pkt, &rip_packetlen);
	n = libnet_write(l);

	if (verbose == 2)
		nemesis_hexdump(pkt, rip_packetlen, HEX_ASCII_DECODE);
	if (verbose == 3)
		nemesis_hexdump(pkt, rip_packetlen, HEX_RAW_DECODE);

	if (n != (int)rip_packetlen) {
		fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote "
		                "%d bytes.\n",
		        n);
	} else {
		if (verbose) {
			if (got_link)
				printf("Wrote %d byte RIP packet through linktype %s.\n", n, nemesis_lookup_linktype(l->link_type));
			else
				printf("Wrote %d byte RIP packet.\n", n);
		}
	}
	libnet_destroy(l);
	return n;
}
