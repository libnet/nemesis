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
	uint32_t  len;
	char     *ethertype;
	int       n;

	/* sanity checks */
	if (pd->file_buf == NULL)
		pd->file_len = 0;

	len = LIBNET_ETH_H + pd->file_len;

	libnet_build_ethernet(eth->ether_dhost,
	                      eth->ether_shost,
	                      eth->ether_type,
	                      pd->file_buf,
	                      pd->file_len,
	                      l,
	                      0);

	n = nemesis_send_frame(l, &len);

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

	return n;
}
