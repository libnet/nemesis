/*
 * THE NEMESIS PROJECT
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 *
 * nemesis-proto_arp.c (ARP Packet Generator)
 */

#include "nemesis-arp.h"
#include "nemesis.h"

int buildarp(ETHERhdr *eth, ARPhdr *arp, struct file *pd, libnet_t *l)
{
	uint32_t len;
	int      n = 0;

	/* validation tests */
	if (pd->file_buf == NULL)
		pd->file_len = 0;

	len = LIBNET_ARP_H + LIBNET_ETH_H + pd->file_len;

#ifdef DEBUG
	printf("DEBUG: ARP packet length %u.\n", len);
	printf("DEBUG: ARP payload size  %zd.\n", pd->file_len);
#endif

	// build arp header for packets
	libnet_build_arp(arp->ar_hrd,
	                 arp->ar_pro,
	                 arp->ar_hln,
	                 arp->ar_pln,
	                 arp->ar_op,
	                 arp->ar_sha,
	                 arp->ar_spa,
	                 arp->ar_tha,
	                 arp->ar_tpa,
	                 pd->file_buf,
	                 pd->file_len,
	                 l,
	                 0);

	libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, eth->ether_type, NULL, 0, l, 0);

	n = nemesis_send_frame(l, &len);
	if (n != (int)len) {
		fprintf(stderr, "ERROR: Incomplete packet injection.  Only "
			"wrote %d bytes.\n", n);
	} else {
		if (verbose) {
			printf("Wrote %d byte %s packet through linktype %s.\n", n,
			       (eth->ether_type == ETHERTYPE_ARP ? "ARP" : "RARP"),
			       nemesis_lookup_linktype(l->link_type));
		}
	}

	libnet_destroy(l);

	return (n);
}
