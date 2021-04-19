/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_icmp.c (ICMP Packet Generator)
 */

#include "nemesis-icmp.h"
#include "nemesis.h"

int buildicmp(ETHERhdr *eth, IPhdr *ip, ICMPhdr *icmp, IPhdr *ipunreach,
	      struct file *pd, struct file *ipod, struct file *origod,
              libnet_t *l)
{
	static uint8_t *pkt;
	uint32_t        icmp_packetlen = 0;
	uint32_t        icmp_meta_packetlen = 0;
	uint8_t         link_offset = 0;
	int             n;

	if (pd->file_buf == NULL)
		pd->file_len = 0;
	if (ipod->file_buf == NULL)
		ipod->file_len = 0;
	if (origod->file_buf == NULL)
		origod->file_len = 0;

	if (got_link)
		link_offset = LIBNET_ETH_H;

	icmp_packetlen = link_offset + LIBNET_IPV4_H + pd->file_len + ipod->file_len;

	switch (mode) {
	case ICMP_ECHO:
		icmp_packetlen += LIBNET_ICMPV4_ECHO_H;
		break;

	case ICMP_UNREACH:
	case ICMP_REDIRECT:
	case ICMP_TIMXCEED:
		icmp_packetlen += LIBNET_ICMPV4_ECHO_H + LIBNET_IPV4_H + origod->file_len;
		break;

	case ICMP_TSTAMP:
		icmp_packetlen += LIBNET_ICMPV4_TS_H;
		break;

	case ICMP_MASKREQ:
		icmp_packetlen += LIBNET_ICMPV4_MASK_H;
		break;
	}

	icmp_meta_packetlen = icmp_packetlen - link_offset;

#ifdef DEBUG
	printf("DEBUG: ICMP packet length %u.\n", icmp_packetlen);
	printf("DEBUG: IP   options size  %zd.\n", ipod->file_len);
	printf("DEBUG: ICMP original IP options size %zd.\n", origod->file_len);
	printf("DEBUG: ICMP payload size  %zd.\n", pd->file_len);
#endif

	switch (mode) {
	case ICMP_ECHO:
		libnet_build_icmpv4_echo(icmp->icmp_type,
					 icmp->icmp_code,
					 0,
		                         icmp->hun.echo.id,
					 icmp->hun.echo.seq,
					 pd->file_buf,
					 pd->file_len,
					 l, 0);
		break;

	case ICMP_MASKREQ:
		libnet_build_icmpv4_mask(icmp->icmp_type,
					 icmp->icmp_code,
					 0,
		                         icmp->hun.echo.id,
					 icmp->hun.echo.seq,
					 icmp->dun.mask,
					 pd->file_buf,
					 pd->file_len,
					 l, 0);
		break;

	case ICMP_TSTAMP:
		libnet_build_icmpv4_timestamp(icmp->icmp_type,
					      icmp->icmp_code,
					      0,
		                              icmp->hun.echo.id,
					      icmp->hun.echo.seq,
		                              icmp->dun.ts.its_otime,
					      icmp->dun.ts.its_rtime,
		                              icmp->dun.ts.its_ttime,
					      pd->file_buf,
					      pd->file_len,
					      l, 0);
		break;
		/*
		 * Behind the scenes, the packet builder functions for unreach,
		 * and time exceeded are the same.  Therefore, the unreach function
		 * is used to build both packet types.
		 */
	case ICMP_UNREACH:
	case ICMP_TIMXCEED:
		libnet_build_icmpv4_unreach(icmp->icmp_type,
					    icmp->icmp_code,
					    0,
					    pd->file_buf,
					    pd->file_len,
					    l, 0);
		break;

	case ICMP_REDIRECT:
		libnet_build_icmpv4_redirect(icmp->icmp_type,
					     icmp->icmp_code,
					     0,
		                             icmp->hun.gateway,
					     pd->file_buf,
					     pd->file_len,
					     l, 0);
		break;
	}

	if ((mode == ICMP_UNREACH || mode == ICMP_TIMXCEED || mode == ICMP_REDIRECT) && got_origoptions) {
		if (libnet_build_ipv4_options(origod->file_buf, origod->file_len, l, 0) == -1)
			fprintf(stderr, "ERROR: Unable to add original IP options, discarding them.\n");
	}

	if (got_ipoptions) {
		if ((libnet_build_ipv4_options(ipod->file_buf, ipod->file_len, l, 0)) == -1)
			fprintf(stderr, "ERROR: Unable to add IP options, discarding them.\n");
	}

	libnet_build_ipv4(icmp_meta_packetlen,
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
				      ETHERTYPE_IP,
				      NULL, 0, l, 0);

	libnet_pblock_coalesce(l, &pkt, &icmp_packetlen);
	n = libnet_write(l);

	if (verbose == 2)
		nemesis_hexdump(pkt, icmp_packetlen, HEX_ASCII_DECODE);
	if (verbose == 3)
		nemesis_hexdump(pkt, icmp_packetlen, HEX_RAW_DECODE);

	if (n != (int)icmp_packetlen) {
		fprintf(stderr, "ERROR: Incomplete packet injection. Only wrote %d bytes.\n", n);
	} else {
		if (verbose) {
			if (got_link)
				printf("Wrote %d byte ICMP packet through linktype %s.\n",
				       n, nemesis_lookup_linktype(l->link_type));
			else
				printf("Wrote %d byte ICMP packet.\n", n);
		}
	}
	libnet_destroy(l);
	return n;
}
