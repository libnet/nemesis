/*
 * $Id: nemesis-proto_ospf.c,v 1.1.1.1.4.1 2005/01/27 20:14:53 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_ospf.c (OSPF Packet Generator)
 *
 */

#include "nemesis-ospf.h"
#include "nemesis.h"

u_char auth[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

int build_hello(FileData *pd, libnet_t *l)
{
	libnet_build_ospfv2_hello(ospfhellohdr.hello_nmask.s_addr,    /* netmask */
	                          ospfhellohdr.hello_intrvl,          /* interval */
	                          ospfhellohdr.hello_opts,            /* options */
	                          ospfhellohdr.hello_rtr_pri,         /* priority */
	                          ospfhellohdr.hello_dead_intvl,      /* dead int */
	                          ospfhellohdr.hello_des_rtr.s_addr,  /* router */
	                          ospfhellohdr.hello_bkup_rtr.s_addr, /* router */
//				  ospfhellohdr.hello_nbr.s_addr,      /* neighbor */
	                          pd->file_mem,                       /* payload */
	                          pd->file_s,                         /* payload size */
	                          l,                                  /* libnet handle */
	                          0);                                 /* libnet id */

	/* authentication data */
	libnet_build_data(auth,               /* auth data */
	                  LIBNET_OSPF_AUTH_H, /* payload size */
	                  l,                  /* libnet handle */
	                  0);                 /* libnet id */

	libnet_build_ospfv2(LIBNET_OSPF_HELLO_H + LIBNET_OSPF_AUTH_H + pd->file_s, /* OSPF packet length */
	                    LIBNET_OSPF_HELLO,                                     /* OSPF packet type */
	                    ospfhdr.ospf_rtr_id.s_addr,                            /* router id */
	                    ospfhdr.ospf_area_id.s_addr,                           /* area id */
	                    0,                                                     /* checksum */
	                    LIBNET_OSPF_AUTH_NULL,                                 /* auth type */
	                    NULL,                                                  /* payload */
	                    0,                                                     /* payload size */
	                    l,                                                     /* libnet handle */
	                    0);                                                    /* libnet id */
}

int build_dbd(FileData *pd, libnet_t *l)
{
	libnet_build_ospfv2_dbd(dbdhdr.dbd_mtu_len,
				dbdhdr.dbd_opts, /* DBD packet options (from above) */
				dbdhdr.dbd_type, /* type of exchange occurring */
				dbdhdr.dbd_seq, pd->file_mem, pd->file_s, l, 0);

	/* authentication data */
	libnet_build_data(auth,               /* auth data */
			  LIBNET_OSPF_AUTH_H, /* payload size */
			  l,                  /* libnet handle */
			  0);                 /* libnet id */

	libnet_build_ospfv2(LIBNET_OSPF_HELLO_H + LIBNET_OSPF_AUTH_H + pd->file_s, /* OSPF packet length */
			    LIBNET_OSPF_HELLO,                                     /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,                            /* router id */
			    ospfhdr.ospf_area_id.s_addr,                           /* area id */
			    0,                                                     /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                                 /* auth type */
			    NULL,                                                  /* payload */
			    0,                                                     /* payload size */
			    l,                                                     /* libnet handle */
			    0);                                                    /* libnet id */
}

int build_lsr(FileData *pd, libnet_t *l)
{
	libnet_build_ospfv2_lsr(lsrhdr.lsr_type, lsrhdr.lsr_lsid, lsrhdr.lsr_adrtr.s_addr, pd->file_mem, pd->file_s, l, 0);

	/* authentication data */
	libnet_build_data(auth,               /* auth data */
			  LIBNET_OSPF_AUTH_H, /* payload size */
			  l,                  /* libnet handle */
			  0);                 /* libnet id */

	libnet_build_ospfv2(LIBNET_OSPF_HELLO_H + LIBNET_OSPF_AUTH_H + pd->file_s, /* OSPF packet length */
			    LIBNET_OSPF_HELLO,                                     /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,                            /* router id */
			    ospfhdr.ospf_area_id.s_addr,                           /* area id */
			    0,                                                     /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                                 /* auth type */
			    NULL,                                                  /* payload */
			    0,                                                     /* payload size */
			    l,                                                     /* libnet handle */
			    0);                                                    /* libnet id */
}

int build_lsu(FileData *pd, libnet_t *l)
{
	libnet_build_ospfv2_lsu(lsuhdr.lsu_num, pd->file_mem, pd->file_s, l, 0);

	/* authentication data */
	libnet_build_data(auth,               /* auth data */
			  LIBNET_OSPF_AUTH_H, /* payload size */
			  l,                  /* libnet handle */
			  0);                 /* libnet id */

	libnet_build_ospfv2(LIBNET_OSPF_HELLO_H + LIBNET_OSPF_AUTH_H + pd->file_s, /* OSPF packet length */
			    LIBNET_OSPF_HELLO,                                     /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,                            /* router id */
			    ospfhdr.ospf_area_id.s_addr,                           /* area id */
			    0,                                                     /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                                 /* auth type */
			    NULL,                                                  /* payload */
			    0,                                                     /* payload size */
			    l,                                                     /* libnet handle */
			    0);                                                    /* libnet id */
}

int build_lsartr(FileData *pd, libnet_t *l)
{
	libnet_build_ospfv2_lsa_rtr(rtrlsahdr.rtr_flags,
				    rtrlsahdr.rtr_num,
				    rtrlsahdr.rtr_link_id,
				    rtrlsahdr.rtr_link_data,
				    rtrlsahdr.rtr_type,
				    rtrlsahdr.rtr_tos_num,
				    rtrlsahdr.rtr_metric,
				    pd->file_mem,
				    pd->file_s,
				    l,
				    0);

	libnet_build_ospfv2_lsa(lsahdr.lsa_age,
				lsahdr.lsa_opts,
				lsahdr.lsa_type,
				lsahdr.lsa_id,
				lsahdr.lsa_adv.s_addr,
				lsahdr.lsa_seq,
				lsahdr.lsa_sum,
				lsahdr.lsa_len,
				NULL,
				0,
				l,
				0);

	/* authentication data */
	libnet_build_data(auth,               /* auth data */
			  LIBNET_OSPF_AUTH_H, /* payload size */
			  l,                  /* libnet handle */
			  0);                 /* libnet id */

	libnet_build_ospfv2(LIBNET_OSPF_HELLO_H + LIBNET_OSPF_AUTH_H + pd->file_s, /* OSPF packet length */
			    LIBNET_OSPF_HELLO,                                     /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,                            /* router id */
			    ospfhdr.ospf_area_id.s_addr,                           /* area id */
			    0,                                                     /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                                 /* auth type */
			    NULL,                                                  /* payload */
			    0,                                                     /* payload size */
			    l,                                                     /* libnet handle */
			    0);                                                    /* libnet id */
}

int build_lsanet(FileData *pd, libnet_t *l)
{
	libnet_build_ospfv2_lsa_net(netlsahdr.net_nmask.s_addr,
				    netlsahdr.net_rtr_id,
				    pd->file_mem,
				    pd->file_s,
				    l,
				    0);

	libnet_build_ospfv2_lsa(lsahdr.lsa_age,
				lsahdr.lsa_opts,
				lsahdr.lsa_type,
				lsahdr.lsa_id,
				lsahdr.lsa_adv.s_addr,
				lsahdr.lsa_seq,
				lsahdr.lsa_sum,
				lsahdr.lsa_len,
				NULL,
				0,
				l,
				0);

	/* authentication data */
	libnet_build_data(auth,               /* auth data */
			  LIBNET_OSPF_AUTH_H, /* payload size */
			  l,                  /* libnet handle */
			  0);                 /* libnet id */

	libnet_build_ospfv2(LIBNET_OSPF_HELLO_H + LIBNET_OSPF_AUTH_H + pd->file_s, /* OSPF packet length */
			    LIBNET_OSPF_HELLO,                                     /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,                            /* router id */
			    ospfhdr.ospf_area_id.s_addr,                           /* area id */
			    0,                                                     /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                                 /* auth type */
			    NULL,                                                  /* payload */
			    0,                                                     /* payload size */
			    l,                                                     /* libnet handle */
			    0);                                                    /* libnet id */
}

int build_lsasum(FileData *pd, libnet_t *l)
{
	libnet_build_ospfv2_lsa_sum(sumlsahdr.sum_nmask.s_addr,
				    sumlsahdr.sum_metric,
				    sumlsahdr.sum_tos_metric,
				    pd->file_mem,
				    pd->file_s,
				    l,
				    0);

	libnet_build_ospfv2_lsa(lsahdr.lsa_age,
				lsahdr.lsa_opts,
				lsahdr.lsa_type,
				lsahdr.lsa_id,
				lsahdr.lsa_adv.s_addr,
				lsahdr.lsa_seq,
				lsahdr.lsa_sum,
				lsahdr.lsa_len,
				NULL,
				0,
				l,
				0);

	/* authentication data */
	libnet_build_data(auth,               /* auth data */
			  LIBNET_OSPF_AUTH_H, /* payload size */
			  l,                  /* libnet handle */
			  0);                 /* libnet id */

	libnet_build_ospfv2(LIBNET_OSPF_HELLO_H + LIBNET_OSPF_AUTH_H + pd->file_s, /* OSPF packet length */
			    LIBNET_OSPF_HELLO,                                     /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,                            /* router id */
			    ospfhdr.ospf_area_id.s_addr,                           /* area id */
			    0,                                                     /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                                 /* auth type */
			    NULL,                                                  /* payload */
			    0,                                                     /* payload size */
			    l,                                                     /* libnet handle */
			    0);                                                    /* libnet id */
}

int build_lsaas(FileData *pd, libnet_t *l)
{
	libnet_build_ospfv2_lsa_as(aslsahdr.as_nmask.s_addr,
				   aslsahdr.as_metric,
				   aslsahdr.as_fwd_addr.s_addr,
				   aslsahdr.as_rte_tag,
				   pd->file_mem,
				   pd->file_s,
				   l,
				   0);

	libnet_build_ospfv2_lsa(lsahdr.lsa_age,
				lsahdr.lsa_opts,
				lsahdr.lsa_type,
				lsahdr.lsa_id,
				lsahdr.lsa_adv.s_addr,
				lsahdr.lsa_seq,
				lsahdr.lsa_sum,
				lsahdr.lsa_len,
				NULL,
				0,
				l,
				0);

	/* authentication data */
	libnet_build_data(auth,               /* auth data */
			  LIBNET_OSPF_AUTH_H, /* payload size */
			  l,                  /* libnet handle */
			  0);                 /* libnet id */

	libnet_build_ospfv2(LIBNET_OSPF_HELLO_H + LIBNET_OSPF_AUTH_H + pd->file_s, /* OSPF packet length */
			    LIBNET_OSPF_HELLO,                                     /* OSPF packet type */
			    ospfhdr.ospf_rtr_id.s_addr,                            /* router id */
			    ospfhdr.ospf_area_id.s_addr,                           /* area id */
			    0,                                                     /* checksum */
			    LIBNET_OSPF_AUTH_NULL,                                 /* auth type */
			    NULL,                                                  /* payload */
			    0,                                                     /* payload size */
			    l,                                                     /* libnet handle */
			    0);                                                    /* libnet id */
}

int buildospf(ETHERhdr *eth, IPhdr *ip, FileData *pd, FileData *ipod, libnet_t *l, int got_type)
{
	int              n;
	u_int32_t        ospf_packetlen = 0, ospf_meta_packetlen = 0;
	static u_int8_t *pkt;
	u_int8_t         link_offset = 0;

	if (pd->file_mem == NULL)
		pd->file_s = 0;
	if (ipod->file_mem == NULL)
		ipod->file_s = 0;

	if (got_link) /* data link layer transport */
		link_offset = LIBNET_ETH_H;

	ospf_packetlen = link_offset + LIBNET_IPV4_H + LIBNET_OSPF_H + LIBNET_OSPF_AUTH_H + pd->file_s + ipod->file_s;

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
	case 4: /* lsa net */
		ospf_packetlen += LIBNET_OSPF_LSA_H + LIBNET_OSPF_LS_NET_H;
		build_lsanet(pd, l);
		break;
	case 5: /* lsa as_e */
		ospf_packetlen += LIBNET_OSPF_LSA_H + LIBNET_OSPF_LS_AS_EXT_H;
		build_lsaas(pd, l);
		break;
	case 6: /* lsa router */
		ospf_packetlen += LIBNET_OSPF_LSA_H + LIBNET_OSPF_LS_RTR_H;
		build_lsartr(pd, l);
		break;
	case 7: /* lsa sum */
		ospf_packetlen += LIBNET_OSPF_LSA_H + LIBNET_OSPF_LS_SUM_H;
		build_lsasum(pd, l);
		break;
	}

	ospf_meta_packetlen = ospf_packetlen - link_offset;

#ifdef DEBUG
	printf("DEBUG: OSPF packet length %u.\n", ospf_packetlen);
	printf("DEBUG: IP   options size  %u.\n", ipod->file_s);
	printf("DEBUG: OSPF payload size  %u.\n", pd->file_s);
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
	printf("mark1\n");
	n = libnet_write(l);
	printf("mark2\n");

	if (verbose == 2)
		nemesis_hexdump(pkt, ospf_packetlen, HEX_ASCII_DECODE);
	if (verbose == 3)
		nemesis_hexdump(pkt, ospf_packetlen, HEX_RAW_DECODE);

	if (n != ospf_packetlen) {
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
