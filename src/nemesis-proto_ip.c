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
	uint32_t len = 0, ip_len = 0, link_offset = 0;
	int      n;

	if (pd->file_buf == NULL)
		pd->file_len = 0;
	if (ipod->file_buf == NULL)
		ipod->file_len = 0;

	if (got_link) /* data link layer transport */
		link_offset = LIBNET_ETH_H;

	len    = link_offset + LIBNET_IPV4_H + pd->file_len + ipod->file_len;
	ip_len = len - link_offset;

#ifdef DEBUG
	printf("DEBUG: IP packet length %u.\n", len);
	printf("DEBUG: IP options size  %zd.\n", ipod->file_len);
	printf("DEBUG: IP payload size  %zd.\n", pd->file_len);
#endif

	if (got_ipoptions) {
		if ((libnet_build_ipv4_options(ipod->file_buf, ipod->file_len, l, 0)) == -1)
			fprintf(stderr, "ERROR: Unable to add IP options, discarding them.\n");
	}
	libnet_build_ipv4(ip_len,
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

	n = nemesis_send_frame(l, &len);
	if (n != (int)len) {
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
