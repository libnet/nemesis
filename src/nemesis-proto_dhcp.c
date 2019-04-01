/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * Copyright (C) 2019 Joachim Nilsson <troglobit@gmail.com>
 *
 * nemesis-proto_dhcp.c (DHCP Packet Generator)
 */

#include "nemesis-dhcp.h"
#include "nemesis.h"

int builddhcp(ETHERhdr *eth, IPhdr *ip, UDPhdr *udp, DHCPhdr *dhcp,
             struct file *pd, struct file *ipod, libnet_t *l)
{
	static uint8_t *pkt;
	uint32_t        dhcp_meta_packetlen = 0;
	uint32_t        dhcp_packetlen = 0;
	uint8_t         link_offset = 0;
	int             n;

	if (pd->file_buf == NULL)
		pd->file_len = 0;
	if (ipod->file_buf == NULL)
		ipod->file_len = 0;

	if (got_link)		/* data link layer transport */
		link_offset = LIBNET_ETH_H;

	dhcp_packetlen = link_offset + LIBNET_IPV4_H + pd->file_len + ipod->file_len;
	dhcp_packetlen += LIBNET_UDP_H + LIBNET_DHCPV4_H;

	dhcp_meta_packetlen = dhcp_packetlen - link_offset;

#ifdef DEBUG
	printf("DEBUG: DHCP packet length %u.\n", dhcp_packetlen);
	printf("DEBUG: IP  options size  %zd.\n", ipod->file_len);
	printf("DEBUG: DHCP payload size  %zd.\n", pd->file_len);
#endif

	libnet_build_dhcpv4(dhcp->dhcp_opcode,
			    dhcp->dhcp_htype,
			    dhcp->dhcp_hlen,
			    dhcp->dhcp_hopcount,
			    dhcp->dhcp_xid,
			    dhcp->dhcp_secs,
			    dhcp->dhcp_flags,
			    dhcp->dhcp_cip,
			    dhcp->dhcp_yip,
			    dhcp->dhcp_sip,
			    dhcp->dhcp_gip,
			    dhcp->dhcp_chaddr,
			    dhcp->dhcp_sname,
			    NULL,
			    pd->file_buf, pd->file_len, l, 0);

	libnet_build_udp(udp->uh_sport,
			 udp->uh_dport,
			 LIBNET_UDP_H + LIBNET_DHCPV4_H + pd->file_len,
			 0, NULL, 0, l, 0);

	if (got_ipoptions) {
		if (libnet_build_ipv4_options(ipod->file_buf, ipod->file_len, l, 0) == -1)
			fprintf(stderr, "ERROR: Unable to add IP options, discarding them.\n");
	}

	libnet_build_ipv4(dhcp_meta_packetlen,
			  ip->ip_tos,
			  ip->ip_id,
			  ip->ip_off,
			  ip->ip_ttl,
			  ip->ip_p,
			  0,
			  ip->ip_src.s_addr,
			  ip->ip_dst.s_addr,
			  NULL, 0, l, 0);

	if (got_link)
		libnet_build_ethernet(eth->ether_dhost,
				      eth->ether_shost,
				      eth->ether_type,
				      NULL, 0, l, 0);

	libnet_pblock_coalesce(l, &pkt, &dhcp_packetlen);
	n = libnet_write(l);

	if (verbose == 2)
		nemesis_hexdump(pkt, dhcp_packetlen, HEX_ASCII_DECODE);
	if (verbose == 3)
		nemesis_hexdump(pkt, dhcp_packetlen, HEX_RAW_DECODE);

	if (n != (int)dhcp_packetlen) {
		fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote %d bytes.\n", n);
	} else {
		if (verbose) {
			if (got_link)
				printf("Wrote %d byte DHCP packet through linktype %s.\n",
				       n, nemesis_lookup_linktype(l->link_type));
			else
				printf("Wrote %d byte DHCP packet\n", n);
		}
	}
	libnet_destroy(l);

	return n;
}
