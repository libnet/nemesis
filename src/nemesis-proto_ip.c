/*
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 * Original version submitted by ocsic <pisco@private.as>
 *
 * nemesis-proto_ip.c (IP Packet Generator)
 */

#include "nemesis-ip.h"
#include "nemesis.h"

int buildip(ETHERhdr *eth, IPhdr *ip, struct file *pd, struct file *ipod, libnet_t *l)
{
	int             n;
	uint32_t        ip_packetlen = 0, ip_meta_packetlen = 0;
	static uint8_t *pkt;
	uint8_t         link_offset = 0;

	if (pd->file_buf == NULL)
		pd->file_len = 0;
	if (ipod->file_buf == NULL)
		ipod->file_len = 0;

	if (got_link) /* data link layer transport */
		link_offset = LIBNET_ETH_H;

	ip_packetlen      = link_offset + LIBNET_IPV4_H + pd->file_len + ipod->file_len;
	ip_meta_packetlen = ip_packetlen - link_offset;

#ifdef DEBUG
	printf("DEBUG: IP packet length %u.\n", ip_packetlen);
	printf("DEBUG: IP options size  %u.\n", ipod->file_len);
	printf("DEBUG: IP payload size  %u.\n", pd->file_len);
#endif

	if (got_ipoptions) {
		if ((libnet_build_ipv4_options(ipod->file_buf, ipod->file_len, l, 0)) == -1)
			fprintf(stderr, "ERROR: Unable to add IP options, discarding them.\n");
	}
	libnet_build_ipv4(ip_meta_packetlen,
			  ip->ip_tos,
			  ip->ip_id,
			  ip->ip_off,
			  ip->ip_ttl,
			  ip->ip_p,
			  0,
			  ip->ip_src.s_addr,
			  ip->ip_dst.s_addr,
			  pd->file_buf,
			  pd->file_len,
			  l,
			  0);

	if (got_link)
		libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, ETHERTYPE_IP, NULL, 0, l, 0);

	libnet_pblock_coalesce(l, &pkt, &ip_packetlen);
	n = libnet_write(l);

	if (verbose == 2)
		nemesis_hexdump(pkt, ip_packetlen, HEX_ASCII_DECODE);
	if (verbose == 3)
		nemesis_hexdump(pkt, ip_packetlen, HEX_RAW_DECODE);

	if (n != (int)ip_packetlen) {
		fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote %d bytes.\n", n);
	} else {
		if (verbose) {
			if (got_link)
				printf("Wrote %d byte IP packet through linktype %s.\n",
				       n, nemesis_lookup_linktype(l->link_type));
			else
				printf("Wrote %d byte IP packet\n", n);
		}
	}
	libnet_destroy(l);
	return n;
}
