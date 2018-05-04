/*
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_ethernet.c (Ethernet Packet Generator)
 */

#include "nemesis-ethernet.h"
#include "nemesis.h"

int buildether(ETHERhdr *eth, struct file *pd, libnet_t *l)
{
	static uint8_t *pkt;
	uint32_t        eth_packetlen;
	char           *ethertype;
	int             n;

	/* sanity checks */
	if (pd->file_buf == NULL)
		pd->file_len = 0;

	eth_packetlen = LIBNET_ETH_H + pd->file_len;

	libnet_build_ethernet(eth->ether_dhost,
	                      eth->ether_shost,
	                      eth->ether_type,
	                      pd->file_buf,
	                      pd->file_len,
	                      l,
	                      0);

	n = libnet_write(l);

#ifdef DEBUG
	printf("DEBUG: eth_packetlen is %u.\n", eth_packetlen);
#endif
	libnet_pblock_coalesce(l, &pkt, &eth_packetlen);
	if (verbose == 2)
		nemesis_hexdump(pkt, eth_packetlen, HEX_ASCII_DECODE);
	if (verbose == 3)
		nemesis_hexdump(pkt, eth_packetlen, HEX_RAW_DECODE);

	switch (eth->ether_type) {
	case ETHERTYPE_PUP:
		ethertype = "PUP";
		break;

	case ETHERTYPE_IP:
		ethertype = "IP";
		break;

	case ETHERTYPE_ARP:
		ethertype = "ARP";
		break;

	case ETHERTYPE_REVARP:
		ethertype = "REVARP";
		break;

	case ETHERTYPE_8021Q:
		ethertype = "802.1q";
		break;

	case ETHERTYPE_IPV6:
		ethertype = "IPV6";
		break;

	case ETHERTYPE_PPPOEDISC:
		ethertype = "PPOEDISC";
		break;

	case ETHERTYPE_PPPOE:
		ethertype = "PPOE";
		break;
	default:
		ethertype = NULL;
		break;
	}

	if (verbose) {
		if (ethertype != NULL)
			printf("Wrote %d byte Ethernet type %s packet through linktype "
			       "%s.\n",
			       n, ethertype, nemesis_lookup_linktype(l->link_type));
		else
			printf("Wrote %d byte Ethernet type %hu packet through linktype "
			       "%s.\n",
			       n, eth->ether_type, nemesis_lookup_linktype(l->link_type));
	}
	libnet_destroy(l);
	return (n);
}
