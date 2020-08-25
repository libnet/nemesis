/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_igmp.c (IGMP Packet Generator)
 */

#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include "nemesis-igmp.h"
#include "nemesis.h"

int buildigmp(ETHERhdr *eth, IPhdr *ip, IGMPhdr *igmp, struct file *pd,
	      struct file *ipod, libnet_t *l)
{
	uint32_t igmp_len, len;
	uint8_t  link_offset = 0;
	int      n;

	if (pd->file_buf == NULL)
		pd->file_len = 0;
	if (ipod->file_buf == NULL)
		ipod->file_len = 0;

	if (got_link)
		link_offset = LIBNET_ETH_H;

	len      = link_offset + LIBNET_IPV4_H + LIBNET_IGMP_H + pd->file_len + ipod->file_len;
	igmp_len = len - (link_offset + LIBNET_IPV4_H);

#ifdef DEBUG
	printf("DEBUG: IGMP packet length %u.\n", len);
	printf("DEBUG: IP   options size  %zd.\n", ipod->file_len);
	printf("DEBUG: IGMP payload size  %zd.\n", pd->file_len);
#endif

	libnet_build_igmp(igmp->igmp_type,
			  igmp->igmp_code,
			  0,
			  igmp->igmp_group.s_addr,
			  pd->file_buf,
			  pd->file_len,
			  l, 0);

	if (got_ipoptions) {
		if ((libnet_build_ipv4_options(ipod->file_buf, ipod->file_len, l, 0)) == -1)
			fprintf(stderr, "ERROR: Unable to add IP options, discarding them.\n");
	}

	libnet_build_ipv4(igmp_len + LIBNET_IPV4_H,
			  ip->ip_tos,
			  ip->ip_id,
			  ip->ip_off,
			  ip->ip_ttl,
			  ip->ip_p,
			  0,
			  ip->ip_src.s_addr,
			  ip->ip_dst.s_addr,
			  NULL, 0, l, 0);

	if (got_link) {
		if (!got_dhost) {
			char daddr[4];

			inet_ntop(AF_INET, &ip->ip_dst, daddr, sizeof(daddr));
			ETHER_MAP_IP_MULTICAST(daddr, eth->ether_dhost);
		}

		libnet_build_ethernet(eth->ether_dhost,
				      eth->ether_shost,
				      ETHERTYPE_IP,
				      NULL, 0, l, 0);
	}

	n = nemesis_send_frame(l, &len);
	if (n != (int)len) {
		fprintf(stderr, "ERROR: Incomplete packet injection. Only wrote %d bytes.\n", n);
	} else {
		if (verbose) {
			if (got_link)
				printf("Wrote %d byte IGMP packet through linktype %s.\n",
				       n, nemesis_lookup_linktype(l->link_type));
			else
				printf("Wrote %d byte IGMP packet.\n", n);
		}
	}
	libnet_destroy(l);
	return n;
}
