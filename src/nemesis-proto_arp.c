/*
 * $Id: nemesis-proto_arp.c,v 1.1.1.1.4.1 2005/01/27 20:14:53 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 *
 * nemesis-proto_arp.c (ARP Packet Generator)
 *
 */

#include "nemesis-arp.h"
#include "nemesis.h"

int buildarp(ETHERhdr *eth, ARPhdr *arp, FileData *pd, libnet_t *l)
{
	int      n = 0;
	uint32_t arp_packetlen;
	uint8_t *pkt;

	/* validation tests */
	if (pd->file_mem == NULL)
		pd->file_s = 0;

	arp_packetlen = LIBNET_ARP_H + LIBNET_ETH_H + pd->file_s;

#ifdef DEBUG
	printf("DEBUG: ARP packet length %u.\n", arp_packetlen);
	printf("DEBUG: ARP payload size  %u.\n", pd->file_s);
#endif

	// build arp header for packets
	libnet_build_arp(arp->ar_hrd,
	                 arp->ar_pro,
	                 arp->ar_hln,
	                 arp->ar_pln,
	                 arp->ar_op,
	                 ar_sha,
	                 ar_spa,
	                 ar_tha,
	                 ar_tpa,
	                 pd->file_mem,
	                 pd->file_s,
	                 l,
	                 0);

	libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, eth->ether_type, NULL, 0, l, 0);
	libnet_pblock_coalesce(l, &pkt, &arp_packetlen);

	n = libnet_write(l);

	if (verbose == 2)
		nemesis_hexdump(pkt, arp_packetlen, HEX_ASCII_DECODE);
	if (verbose == 3)
		nemesis_hexdump(pkt, arp_packetlen, HEX_RAW_DECODE);

	if (n != (int)arp_packetlen) {
		fprintf(stderr, "ERROR: Incomplete packet injection.  Only "
		                "wrote %d bytes.\n",
		        n);
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
