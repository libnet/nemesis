/*
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_ospf.c (OSPF Packet Generator)
 */

#include "nemesis-ospf.h"
#include "nemesis.h"

u_char auth[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

static void build_hello(struct file *pd, libnet_t *l)
{
	libnet_pblock_t *p;

// XXX: Change to libnet_build_ospfv2_hello_neighbor() when rolled out in Debian
// XXX: See upstream libnet issue https://github.com/sam-github/libnet/issues/69
	libnet_build_ospfv2_hello(ospfhellohdr.hello_nmask.s_addr,    /* netmask */
	                          ospfhellohdr.hello_intrvl,          /* interval */
	                          ospfhellohdr.hello_opts,            /* options */
	                          ospfhellohdr.hello_rtr_pri,         /* priority */
	                          ospfhellohdr.hello_dead_intvl,      /* dead int */
	                          ospfhellohdr.hello_des_rtr.s_addr,  /* router */
	                          ospfhellohdr.hello_bkup_rtr.s_addr, /* router */
//				  ospfhellohdr.hello_nbr.s_addr,      /* neighbor */
	                          pd->file_buf,                       /* payload */
	                          pd->file_len,                         /* payload size */
	                          l,                                  /* libnet handle */
	                          0);                                 /* libnet id */

	/* Workaround for missing neighbor address bug in libnet1, issue #69 (above) */
	p = l->protocol_blocks;
	if (p) {
		struct libnet_ospf_hello_hdr *hello = (struct libnet_ospf_hello_hdr *)p->buf;

		hello->hello_nbr = ospfhellohdr.hello_nbr;
	}

	/* authentication data */
	libnet_build_data(auth,               /* auth data */
	                  LIBNET_OSPF_AUTH_H, /* payload size */
	                  l,                  /* libnet handle */
	                  0);                 /* libnet id */

	libnet_build_ospfv2(LIBNET_OSPF_HELLO_H + pd->file_len +
			    LIBNET_OSPF_AUTH_H,                   /* OSPF packet length */
	                    ospfhdr.ospf_type,                    /* OSPF packet type */
	                    ospfhdr.ospf_rtr_id.s_addr,           /* router id */
	                    ospfhdr.ospf_area_id.s_addr,          /* area id */
	                    0,                                    /* checksum */
	                    LIBNET_OSPF_AUTH_NULL,                /* auth type */
			    NULL, 0, l, 0);
}

static void build_dbd(struct file *pd, libnet_t *l)
{
	libnet_build_ospfv2_dbd(dbdhdr.dbd_mtu_len,
				dbdhdr.dbd_opts, /* DBD packet options (from above) */
				dbdhdr.dbd_type, /* type of exchange occurring */
				dbdhdr.dbd_seq, pd->file_buf, pd->file_len, l, 0);

	/* authentication data */
	libnet_build_data(auth,               /* auth data */
			  LIBNET_OSPF_AUTH_H, /* payload size */
			  l,                  /* libnet handle */
			  0);                 /* libnet id */

	libnet_build_ospfv2(LIBNET_OSPF_DBD_H + pd->file_len +
			    LIBNET_OSPF_AUTH_H,                 /* OSPF packet length */
			    ospfhdr.ospf_type,                  /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,         /* router id */
			    ospfhdr.ospf_area_id.s_addr,        /* area id */
			    0,                                  /* checksum */
			    LIBNET_OSPF_AUTH_NULL,              /* auth type */
			    NULL, 0, l, 0);
}

static void build_lsr(struct file *pd, libnet_t *l)
{
	libnet_build_ospfv2_lsr(lsrhdr.lsr_type,
				lsrhdr.lsr_lsid,
				lsrhdr.lsr_adrtr.s_addr,
				pd->file_buf,
				pd->file_len,
				l, 0);

	/* authentication data */
	libnet_build_data(auth, LIBNET_OSPF_AUTH_H, l, 0);

	libnet_build_ospfv2(LIBNET_OSPF_LSR_H + pd->file_len +
			    LIBNET_OSPF_AUTH_H,                 /* OSPF packet length */
			    ospfhdr.ospf_type,                  /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,         /* router id */
			    ospfhdr.ospf_area_id.s_addr,        /* area id */
			    0,                                  /* checksum */
			    LIBNET_OSPF_AUTH_NULL,              /* auth type */
			    NULL, 0, l, 0);
}

static void build_lsu(struct file *pd, libnet_t *l)
{
	libnet_build_ospfv2_lsu(lsuhdr.lsu_num, pd->file_buf, pd->file_len, l, 0);

	/* authentication data */
	libnet_build_data(auth, LIBNET_OSPF_AUTH_H, l, 0);

	libnet_build_ospfv2(LIBNET_OSPF_LSU_H + pd->file_len +
			    LIBNET_OSPF_AUTH_H,	                /* OSPF packet length */
			    ospfhdr.ospf_type,                  /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,         /* router id */
			    ospfhdr.ospf_area_id.s_addr,        /* area id */
			    0,                                  /* checksum */
			    LIBNET_OSPF_AUTH_NULL,              /* auth type */
			    NULL, 0, l, 0);
}

static void build_lsartr(struct file *pd, libnet_t *l)
{
	libnet_build_ospfv2_lsa_rtr(rtrlsahdr.rtr_flags,
				    rtrlsahdr.rtr_num,
				    rtrlsahdr.rtr_link_id,
				    rtrlsahdr.rtr_link_data,
				    rtrlsahdr.rtr_type,
				    rtrlsahdr.rtr_tos_num,
				    rtrlsahdr.rtr_metric,
				    pd->file_buf, pd->file_len, l, 0);

	libnet_build_ospfv2_lsa(lsahdr.lsa_age,
		lsahdr.lsa_opts,
		lsahdr.lsa_type,
		lsahdr.lsa_id,
		lsahdr.lsa_adv.s_addr,
		lsahdr.lsa_seq,
		lsahdr.lsa_sum,
		LIBNET_OSPF_LSA_H +
		LIBNET_OSPF_LS_RTR_H,
		NULL, 0, l, 0);

	libnet_build_ospfv2_lsu(lsuhdr.lsu_num, NULL, 0, l, 0);

	/* authentication data */
	libnet_build_data(auth, LIBNET_OSPF_AUTH_H, l, 0);

	libnet_build_ospfv2(LIBNET_OSPF_LS_RTR_H + pd->file_len +
		LIBNET_OSPF_LSA_H + (LIBNET_OSPF_LSU_H - 4) +
			    LIBNET_OSPF_AUTH_H,                     /* OSPF packet length */
			    ospfhdr.ospf_type,                      /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,             /* router id */
			    ospfhdr.ospf_area_id.s_addr,            /* area id */
			    0,                                      /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                  /* auth type */
			    NULL, 0, l, 0);
}

static void build_lsanet(struct file *pd, libnet_t *l)
{
	libnet_build_ospfv2_lsa_net(netlsahdr.net_nmask.s_addr,
				    netlsahdr.net_rtr_id,
				    pd->file_buf,
				    pd->file_len,
				    l,
				    0);

	libnet_build_ospfv2_lsa(lsahdr.lsa_age,
				lsahdr.lsa_opts,
				lsahdr.lsa_type,
				lsahdr.lsa_id,
				lsahdr.lsa_adv.s_addr,
				lsahdr.lsa_seq,
				lsahdr.lsa_sum,
				LIBNET_OSPF_LSA_H +
				LIBNET_OSPF_LS_NET_H,
				NULL, 0, l, 0);

	libnet_build_ospfv2_lsu(lsuhdr.lsu_num, NULL, 0, l, 0);

	/* authentication data */
	libnet_build_data(auth, LIBNET_OSPF_AUTH_H, l, 0);

	libnet_build_ospfv2(LIBNET_OSPF_LS_NET_H + pd->file_len +
			    LIBNET_OSPF_LSA_H + (LIBNET_OSPF_LSU_H - 4) +
			    LIBNET_OSPF_AUTH_H, /* OSPF packet length */
			    ospfhdr.ospf_type,                      /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,             /* router id */
			    ospfhdr.ospf_area_id.s_addr,            /* area id */
			    0,                                      /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                  /* auth type */
			    NULL, 0, l, 0);
}

static void build_lsasum(struct file *pd, libnet_t *l)
{
	/*
	 * XXX: Workaround for old style struct libnet_sum_lsa_hdr in libnet1
	 *      The TOS and TOS-metric fields (4 bytes) are optional, only for
	 *      compat with RFC1583.
	 *
	 * So we use libnet_build_ospfv2_lsa_net() to create the Summary-LSA.
	 */
	libnet_build_ospfv2_lsa_net(sumlsahdr.sum_nmask.s_addr,
				    sumlsahdr.sum_metric,
				    pd->file_buf, pd->file_len, l, 0);

	libnet_build_ospfv2_lsa(lsahdr.lsa_age,
				lsahdr.lsa_opts,
				lsahdr.lsa_type,
				lsahdr.lsa_id,
				lsahdr.lsa_adv.s_addr,
				lsahdr.lsa_seq,
				lsahdr.lsa_sum,
				LIBNET_OSPF_LSA_H +
				LIBNET_OSPF_LS_NET_H,
				pd->file_buf, pd->file_len, l, 0);

	/* Number of LSAs included, this function (and Nemesi) defaults to 1 */
	libnet_build_ospfv2_lsu(lsuhdr.lsu_num, NULL, 0, l, 0);

	/* authentication data */
	libnet_build_data(auth, LIBNET_OSPF_AUTH_H, l, 0);

	libnet_build_ospfv2(LIBNET_OSPF_LS_NET_H + pd->file_len +
			    LIBNET_OSPF_LSA_H + LIBNET_OSPF_LSU_H +
			    LIBNET_OSPF_AUTH_H,	                   /* OSPF packet length */
			    ospfhdr.ospf_type,                     /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,            /* router id */
			    ospfhdr.ospf_area_id.s_addr,           /* area id */
			    0,                                     /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                 /* auth type */
			    NULL, 0, l, 0);
}

/*
 * Build LS Acknowledge for Summary-LSA (IP Network)
 */
static void build_lsack(struct file *pd, libnet_t *l)
{
	size_t acklen = 8;

	if (LIBNET_LS_TYPE_ASEXT == lsahdr.lsa_type)
		acklen = 16;

	libnet_build_ospfv2_lsa(lsahdr.lsa_age,
				lsahdr.lsa_opts,
				lsahdr.lsa_type,
				lsahdr.lsa_id,
				lsahdr.lsa_adv.s_addr,
				lsahdr.lsa_seq,
				lsahdr.lsa_sum,
				LIBNET_OSPF_LSA_H + acklen,
				pd->file_buf, pd->file_len, l, 0);

	/* authentication data */
	libnet_build_data(auth, LIBNET_OSPF_AUTH_H, l, 0);

	libnet_build_ospfv2(LIBNET_OSPF_LSA_H + pd->file_len +
			    LIBNET_OSPF_AUTH_H,	                   /* OSPF packet length */
			    ospfhdr.ospf_type,                     /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,            /* router id */
			    ospfhdr.ospf_area_id.s_addr,           /* area id */
			    0,                                     /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                 /* auth type */
			    NULL, 0, l, 0);
}

static void build_lsaas(struct file *pd, libnet_t *l)
{
	libnet_build_ospfv2_lsa_as(aslsahdr.as_nmask.s_addr,
				   aslsahdr.as_metric,
				   aslsahdr.as_fwd_addr.s_addr,
				   aslsahdr.as_rte_tag,
				   pd->file_buf, pd->file_len, l, 0);

	libnet_build_ospfv2_lsa(lsahdr.lsa_age,
				lsahdr.lsa_opts,
				lsahdr.lsa_type,
				lsahdr.lsa_id,
				lsahdr.lsa_adv.s_addr,
				lsahdr.lsa_seq,
				lsahdr.lsa_sum,
				LIBNET_OSPF_LSA_H +
				LIBNET_OSPF_LS_AS_EXT_H,
				NULL, 0, l, 0);

	libnet_build_ospfv2_lsu(lsuhdr.lsu_num, NULL, 0, l, 0);

	/* authentication data */
	libnet_build_data(auth, LIBNET_OSPF_AUTH_H, l, 0);

	libnet_build_ospfv2(LIBNET_OSPF_LS_AS_EXT_H + pd->file_len +
			    LIBNET_OSPF_LSA_H + (LIBNET_OSPF_LSU_H - 4) +
			    LIBNET_OSPF_AUTH_H,                      /* OSPF packet length */
			    ospfhdr.ospf_type,                       /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,              /* router id */
			    ospfhdr.ospf_area_id.s_addr,             /* area id */
			    0,                                       /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                   /* auth type */
			    NULL, 0, l, 0);
}

int buildospf(ETHERhdr *eth, IPhdr *ip, struct file *pd, struct file *ipod, libnet_t *l, int got_type)
{
	int             n;
	uint32_t        ospf_packetlen = 0, ospf_meta_packetlen = 0;
	static uint8_t *pkt;
	uint8_t         link_offset = 0;

	if (pd->file_buf == NULL)
		pd->file_len = 0;
	if (ipod->file_buf == NULL)
		ipod->file_len = 0;

	if (got_link) /* data link layer transport */
		link_offset = LIBNET_ETH_H;

	ospf_packetlen = link_offset + LIBNET_IPV4_H + LIBNET_OSPF_H + LIBNET_OSPF_AUTH_H + pd->file_len + ipod->file_len;

	switch (got_type) {
	case 0: /* hello */
		ospf_packetlen += LIBNET_OSPF_HELLO_H;
		build_hello(pd, l);
		break;

	case 1: /* dbd */
		ospf_packetlen += LIBNET_OSPF_DBD_H;
		build_dbd(pd, l);
		break;

	case 2: /* lsr */
		ospf_packetlen += LIBNET_OSPF_LSR_H;
		build_lsr(pd, l);
		break;

	case 3: /* lsu */
		ospf_packetlen += LIBNET_OSPF_LSU_H;
		build_lsu(pd, l);
		break;

	case 4: /* lsu: lsa net */
		ospf_packetlen += LIBNET_OSPF_LSA_H + LIBNET_OSPF_LS_NET_H;
		build_lsanet(pd, l);
		break;

	case 5: /* lsu: lsa as_e */
		ospf_packetlen += LIBNET_OSPF_LSA_H + LIBNET_OSPF_LS_AS_EXT_H;
		build_lsaas(pd, l);
		break;

	case 6: /* lsu: lsa router */
		ospf_packetlen += LIBNET_OSPF_LSA_H + LIBNET_OSPF_LS_RTR_H;
		build_lsartr(pd, l);
		break;

	case 7: /* lsu: lsa sum */
		ospf_packetlen += LIBNET_OSPF_LSA_H + LIBNET_OSPF_LS_SUM_H;
		build_lsasum(pd, l);
		break;

	case 8: /* lsack */
		ospf_packetlen += LIBNET_OSPF_LSA_H;
		build_lsack(pd, l);
		break;
	}

	ospf_meta_packetlen = ospf_packetlen - link_offset;

#ifdef DEBUG
	printf("DEBUG: OSPF packet length %u.\n", ospf_packetlen);
	printf("DEBUG: IP   options size  %zd.\n", ipod->file_len);
	printf("DEBUG: OSPF payload size  %zd.\n", pd->file_len);
#endif

	libnet_build_ipv4(ospf_meta_packetlen,
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

	libnet_pblock_coalesce(l, &pkt, &ospf_packetlen);
	n = libnet_write(l);

	if (verbose == 2)
		nemesis_hexdump(pkt, ospf_packetlen, HEX_ASCII_DECODE);
	if (verbose == 3)
		nemesis_hexdump(pkt, ospf_packetlen, HEX_RAW_DECODE);

	if (n != (int)ospf_packetlen) {
		fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote %d bytes.\n", n);
	} else {
		if (verbose) {
			if (got_link)
				printf("Wrote %d byte OSPF packet through linktype %s.\n",
				       n, nemesis_lookup_linktype(l->link_type));
			else
				printf("Wrote %d byte OSPF packet.\n", n);
		}
	}

	libnet_destroy(l);
	return n;
}
