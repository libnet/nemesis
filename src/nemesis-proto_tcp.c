/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_tcp.c (TCP Packet Generator)
 */

#include "nemesis-tcp.h"
#include "nemesis.h"

int buildtcp(ETHERhdr *eth, IPhdr *ip, TCPhdr *tcp, struct file *pd,
             struct file *ipod, struct file *tcpod, libnet_t *l)
{
	uint32_t len = 0, tcp_len = 0, link_offset = 0;
	int      n;

	if (pd->file_buf == NULL)
		pd->file_len = 0;
	if (ipod->file_buf == NULL)
		ipod->file_len = 0;
	if (tcpod->file_buf == NULL)
		tcpod->file_len = 0;

	if (got_link) { /* data link layer transport */
		link_offset = LIBNET_ETH_H;
	}

	len     = link_offset + LIBNET_IPV4_H + LIBNET_TCP_H + pd->file_len + ipod->file_len + tcpod->file_len;
	tcp_len = len - link_offset;

#ifdef DEBUG
	printf("DEBUG: TCP packet length %u.\n", len);
	printf("DEBUG: IP  options size  %zd.\n", ipod->file_len);
	printf("DEBUG: TCP options size  %zd.\n", tcpod->file_len);
	printf("DEBUG: TCP payload size  %zd.\n", pd->file_len);
#endif

	if (got_tcpoptions) {
		if ((libnet_build_tcp_options(tcpod->file_buf, tcpod->file_len, l, 0)) == -1) {
			fprintf(stderr, "ERROR: Unable to add TCP options, discarding them.\n");
		}
	}

	libnet_build_tcp(tcp->th_sport,
	                 tcp->th_dport,
	                 tcp->th_seq,
	                 tcp->th_ack,
	                 tcp->th_flags,
	                 tcp->th_win,
	                 0, tcp->th_urp,
	                 LIBNET_TCP_H + pd->file_len + tcpod->file_len,
	                 pd->file_buf,
	                 pd->file_len,
	                 l,
	                 0);
	if (got_ipoptions) {
		if ((libnet_build_ipv4_options(ipod->file_buf, ipod->file_len, l, 0)) == -1) {
			fprintf(stderr, "ERROR: Unable to add IP options, discarding them.\n");
		}
	}

	libnet_build_ipv4(tcp_len,
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

	n = nemesis_send_frame(l, &len);
	if (n != (int)len) {
		fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote %d bytes.\n", n);
	} else {
		if (verbose) {
			if (got_link)
				printf("Wrote %d byte TCP packet through linktype %s.\n", n, nemesis_lookup_linktype(l->link_type));
			else
				printf("Wrote %d byte TCP packet.\n", n);
		}
	}
	libnet_destroy(l);
	return n;
}
