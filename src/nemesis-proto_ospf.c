/*
 * $Id: nemesis-proto_ospf.c,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
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

int buildospf(ETHERhdr *eth, IPhdr *ip, FileData *pd, FileData *ipod,
        char *device)
{
    int n;
    u_int32_t ospf_packetlen = 0, ospf_meta_packetlen = 0;
    static u_int8_t *pkt;
    static int sockfd = -1;
    struct libnet_link_int *l2 = NULL;
    u_int8_t link_offset = 0;
#if !defined(WIN32)
    int sockbuff = IP_MAXPACKET;
#endif

    if (pd->file_mem == NULL)
        pd->file_s = 0;
    if (ipod->file_mem == NULL)
        ipod->file_s = 0;

    if (got_link)   /* data link layer transport */
    {
        if ((l2 = libnet_open_link_interface(device, errbuf)) == NULL)
        {
            nemesis_device_failure(INJECTION_LINK, (const char *)device);
            return -1;
        }
        link_offset = LIBNET_ETH_H;
    }
    else
    {
        if ((sockfd = libnet_open_raw_sock(IPPROTO_RAW)) < 0)
        {
            nemesis_device_failure(INJECTION_RAW, (const char *)NULL);
            return -1;
        }
#if !defined(WIN32)
        if ((setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const void *)&sockbuff, 
                sizeof(sockbuff))) < 0)
        {
            fprintf(stderr, "ERROR: setsockopt() failed.\n");
            return -1;
        }
#endif
    }

    ospf_packetlen = link_offset + LIBNET_IP_H + LIBNET_OSPF_H + pd->file_s +
            ipod->file_s;

    ospf_meta_packetlen = ospf_packetlen - (link_offset + LIBNET_IP_H);

#ifdef DEBUG
    printf("DEBUG: OSPF packet length %u.\n", ospf_packetlen);
    printf("DEBUG: IP   options size  %u.\n", ipod->file_s);
    printf("DEBUG: OSPF payload size  %u.\n", pd->file_s);
#endif

    if (libnet_init_packet(ospf_packetlen, &pkt) == -1)
    {
        fprintf(stderr, "ERROR: Unable to allocate packet memory.\n");
        return -1;
    }

    if (got_link)
        libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, ETHERTYPE_IP, 
                NULL, 0, pkt);

        libnet_build_ip(ospf_meta_packetlen, ip->ip_tos, ip->ip_id, ip->ip_off, 
            ip->ip_ttl, ip->ip_p, ip->ip_src.s_addr, ip->ip_dst.s_addr, 
            NULL, 0, pkt + ((got_link == 1) ? LIBNET_ETH_H : 0));

    if (got_link)
        n = libnet_write_link_layer(l2, device, pkt, ospf_packetlen);
    else
        n = libnet_write_ip(sockfd, pkt, ospf_packetlen);

    if (verbose == 2)
        nemesis_hexdump(pkt, ospf_packetlen, HEX_ASCII_DECODE);
    if (verbose == 3)
        nemesis_hexdump(pkt, ospf_packetlen, HEX_RAW_DECODE);

    if (n != ospf_packetlen)
    {
        fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote "
                "%d bytes.\n", n);
    }
    else
    {
        if (verbose)
        {
            if (got_link)
                printf("Wrote %d byte OSPF packet through linktype %s.\n", 
                        n, nemesis_lookup_linktype(l2->linktype));
            else
                printf("Wrote %d byte OSPF packet.\n", n);
        } 
    }

    libnet_destroy_packet(&pkt);
    if (got_link)
        libnet_close_link_interface(l2);
    else
        libnet_close_raw_sock(sockfd);
    return n;
}
#if 0
int build_hello()
{				/* OSPF Hello */

      if (libnet_init_packet(LIBNET_OSPF_H + LIBNET_AUTH_H +
			     LIBNET_HELLO_H + LIBNET_IP_H + LIBNET_ETH_H
			     + payload_s + option_s, &pkt) == -1) {
	 printf("libnet_init_packet memory error\n");
	 exit(1);
      }
      libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP,
			    NULL, 0, pkt);

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_HELLO_H,
		      tos, id, frag, ttl, IPPROTO_OSPF, source, dest, NULL, 0, pkt + 
              LIBNET_ETH_H);

      libnet_build_ospf(LIBNET_HELLO_H + LIBNET_AUTH_H,
      /* size of packet */
			LIBNET_OSPF_HELLO,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL,	0, pkt + LIBNET_IP_H + LIBNET_ETH_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_IP_H +
			  LIBNET_ETH_H, auth);

      libnet_build_ospf_hello(mask,	/* OSPF netmask */
			      interval,	/* secs since last pkt sent */
			      ooptions,	/* OSPF options */
			      priority,	/* OSPF priority */
			      dead_int,	/* Time til router is deemed down */
			      source,	/* designated router */
			      source,	/* backup router */
			      neighbor,	/* address of neigbor router */
			      payload,	/* OSPF payload pointer */
			      payload_s,	/* OSPF payload size */
			    pkt + LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H
			      + LIBNET_AUTH_H);
      /* pkt hdr mem */

      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H);
      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_OSPF, LIBNET_OSPF_H +
		  LIBNET_HELLO_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

      n = libnet_write_link_layer(l, device, pkt, LIBNET_ETH_H +
	      LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_HELLO_H + LIBNET_AUTH_H +
				  payload_s + option_s);

      if (n != LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_HELLO_H +
	  LIBNET_AUTH_H + payload_s + option_s) {
	 fprintf(stderr, "Incomplete data transmission.  Only wrote %d bytes\n", n);
		 } else {
	 if (verbose)
	    printf("Wrote %d byte OSPF packet through linktype %d\n", n,
		   l->linktype);
      }
   }
    /* end of data link layer */ 
   else {

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_HELLO_H,	/* size of packet */
		      tos, id, frag, ttl, IPPROTO_OSPF, source, dest,	NULL,
		      0, pkt);	

      libnet_build_ospf(LIBNET_HELLO_H + LIBNET_AUTH_H,	/* size of packet */
			LIBNET_OSPF_HELLO,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_IP_H, auth);

      libnet_build_ospf_hello(mask,	/* OSPF netmask */
			      interval,	/* secs since last pkt sent */
			      ooptions,	/* OSPF options */
			      priority,	/* OSPF priority */
			      dead_int,	/* Time til router is deemed down */
			      source,	/* designated router */
			      source,	/* backup router */
			      neighbor,	/* address of neigbor router */
			      payload,	/* OSPF payload pointer */
			      payload_s,	/* OSPF payload size */
			 pkt + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H);	/* pkt hdr mem */

      libnet_do_checksum(pkt, IPPROTO_OSPF, LIBNET_OSPF_H + LIBNET_HELLO_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

      c = libnet_write_ip(sockfd, pkt, LIBNET_OSPF_H + LIBNET_HELLO_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

      if (c < LIBNET_OSPF_H + LIBNET_HELLO_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s) {
      }
   }				/* end of ip layer */
}

int build_dbd()
{				/* Database Description */
      if (libnet_init_packet(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_DBD_H
		  + LIBNET_IP_H + LIBNET_ETH_H + payload_s + option_s, &pkt)
	  == -1) {
	 printf("libnet_init_packet memory error\n");
	 exit(1);
      }
      libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP,
			    NULL, 0, pkt);

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_DBD_H, 
		      tos, id, frag, ttl, IPPROTO_OSPF, source, dest, NULL,
		      0, pkt + LIBNET_ETH_H);

      libnet_build_ospf(LIBNET_DBD_H + LIBNET_AUTH_H,	/* size of packet */
			LIBNET_OSPF_DBD,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H + LIBNET_ETH_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_IP_H + LIBNET_ETH_H,
			  auth);

      libnet_build_ospf_dbd(mtusize,	/* max dgram length */
			    ooptions,	/* OSPF options */
			    exchange,	/* exchange type */
			    seqnum,	/* DBD sequence number */
			    payload,	/* DBD payload pointer */
			    payload_s,	/* DBD payload size */
			    pkt + LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H
			    + LIBNET_AUTH_H);
      /* packet header memory */

      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H);
      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_OSPF, LIBNET_OSPF_H +
		    LIBNET_DBD_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

      n = libnet_write_link_layer(l, device, pkt, LIBNET_ETH_H +
		LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_DBD_H + LIBNET_AUTH_H +
				  payload_s + option_s);

      if (n != LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_DBD_H +
	  LIBNET_AUTH_H + payload_s + option_s) {
	 fprintf(stderr, "Incomplete data transmission.  Only wrote %d bytes\n", n);
		 } else {
	 if (verbose)
	    printf("Wrote %d byte OSPF packet through linktype %d\n", n,
		   l->linktype);
      }
   }
    /* end of data link layer */ 
   else {

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_DBD_H,	/* size of packet */
		      tos, id, frag, ttl, IPPROTO_OSPF, source,	dest,
		      NULL,	0, pkt);

      libnet_build_ospf(LIBNET_DBD_H + LIBNET_AUTH_H,	/* size of packet */
			LIBNET_OSPF_DBD,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + IP_H);

      auth[0] = 0;
      auth[1] = 0;
      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_IP_H, auth);

      libnet_build_ospf_dbd(mtusize,	/* max dgram length */
			    ooptions,	/* OSPF options */
			    exchange,	/* exchange type */
			    seqnum,	/* DBD sequence number */
			    payload,	/* DBD payload pointer */
			    payload_s,	/* DBD payload size */
			 pkt + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H);	/* packet header memory */

      libnet_do_checksum(pkt, IPPROTO_OSPF, LIBNET_OSPF_H + LIBNET_DBD_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

      c = libnet_write_ip(sockfd, pkt, LIBNET_OSPF_H + LIBNET_DBD_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

      if (c < LIBNET_OSPF_H + LIBNET_DBD_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s) {
      } else {
      }
   }				/* end of ip layer */
}

int build_lsr()
{				/* Link State Request */
      if (libnet_init_packet(LIBNET_OSPF_H + LIBNET_AUTH_H +
			     LIBNET_LSR_H + LIBNET_IP_H + LIBNET_ETH_H
			     + payload_s + option_s, &pkt) == -1) {
	 printf("libnet_init_packet memory error\n");
	 exit(1);
      }
      libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP, NULL, 0, pkt);

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSR_H,
      /* size of p acket */
		      tos, id, frag, ttl, IPPROTO_OSPF,	source,
		      dest, NULL, 0, pkt + LIBNET_ETH_H);

      libnet_build_ospf(LIBNET_HELLO_H + LIBNET_AUTH_H,
      /* size of packet */
			LIBNET_OSPF_HELLO,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H + LIBNET_ETH_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_IP_H +
			  LIBNET_ETH_H, auth);

      libnet_build_ospf_lsr(LIBNET_LS_TYPE_RTR, rtrid, router, payload,
			    payload_s, pkt + LIBNET_ETH_H + LIBNET_IP_H + 
                            LIBNET_OSPF_H + LIBNET_AUTH_H);

      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H);
      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_OSPF, LIBNET_OSPF_H +
		    LIBNET_LSR_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

      n = libnet_write_link_layer(l, device, pkt, LIBNET_ETH_H +
		LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_LSR_H + LIBNET_AUTH_H +
				  payload_s + option_s);

      if (n != LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_HELLO_H +
	  LIBNET_AUTH_H + payload_s + option_s) {
	 fprintf(stderr, "Incomplete data transmission.  Only wrote %d bytes\n", n);
		 } else {
	 if (verbose)
	    printf("Wrote %d byte OSPF packet through linktype %d\n", n,
		   l->linktype);
      }
   }
    /* end of data link layer */ 
   else {			/* ip layer */
      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSR_H,	
		      tos, id, frag, ttl, IPPROTO_OSPF,	source,	dest, NULL,	
		      0, pkt);

      auth[0] = 0;
      auth[1] = 0;

      libnet_build_ospf(LIBNET_AUTH_H + LIBNET_LSR_H,	/* size of packet */
			LIBNET_OSPF_LSR,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H);

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_IP_H, auth);

      libnet_build_ospf_lsr(LIBNET_LS_TYPE_RTR, rtrid, router, payload,
			    payload_s, pkt + LIBNET_IP_H + LIBNET_OSPF_H + 
                            LIBNET_AUTH_H);

      libnet_do_checksum(pkt, IPPROTO_OSPF, LIBNET_IP_H + LIBNET_OSPF_H +
			 LIBNET_AUTH_H + LIBNET_LSR_H + payload_s);

      c = libnet_write_ip(sockfd, pkt, LIBNET_IP_H + LIBNET_OSPF_H +
			  LIBNET_AUTH_H + LIBNET_LSR_H + payload_s +
			  option_s);

      if (c < LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSR_H +
	  payload_s + option_s) {
   }				/* end of ip layer */
}

int build_lsu()
{				/* Link State Update */
      if (libnet_init_packet(LIBNET_OSPF_H + LIBNET_AUTH_H +
			     LIBNET_HELLO_H + LIBNET_IP_H + LIBNET_ETH_H
			     + payload_s + option_s, &pkt) == -1) {
	 printf("libnet_init_packet memory error\n");
	 exit(1);
      }
      libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP, NULL,
			    0, pkt);

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSU_H, tos, id, 
              frag, ttl, IPPROTO_OSPF, source, dest, NULL, 0, pkt + 
              LIBNET_ETH_H);

      libnet_build_ospf(LIBNET_LSU_H + LIBNET_AUTH_H,	/* size of packet */
			LIBNET_OSPF_LSU,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H + LIBNET_ETH_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_IP_H
			  + LIBNET_ETH_H, auth);

      libnet_build_ospf_lsu(bcastnum,	/* num of LSAs to bcast */
			    payload,	/* DBD payload pointer */
			    payload_s,	/* DBD payload size */
			 pkt + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H);
      /* packet header memory */

      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_OSPF, LIBNET_OSPF_H +
		    LIBNET_LSU_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

      n = libnet_write_link_layer(l, device, pkt, LIBNET_ETH_H +
		LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_LSU_H + LIBNET_AUTH_H +
				  payload_s + option_s);

      if (n != LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_LSU_H +
	  LIBNET_AUTH_H + payload_s + option_s) {
	 fprintf(stderr, "Incomplete data transmission.  Only wrote %d bytes\n", n);
      } else {
	 if (verbose)
	    printf("Wrote %d byte OSPF packet through linktype %d\n", n,
		   l->linktype);
      }
   }
    /* end of data link layer */ 
   else {

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSU_H,
      /* size of packet */
		      tos, id, frag, ttl, IPPROTO_OSPF, source, dest,
		      NULL,	0,	pkt);

      libnet_build_ospf(LIBNET_LSU_H + LIBNET_AUTH_H,	/* size of packet */
			LIBNET_OSPF_LSU,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_IP_H, auth);

      libnet_build_ospf_lsu(bcastnum,	/* num of LSAs to bcast */
			    payload,	/* DBD payload pointer */
			    payload_s,	/* DBD payload size */
			 pkt + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H);
      /* packet header memory */

      libnet_do_checksum(pkt, IPPROTO_OSPF, LIBNET_OSPF_H + LIBNET_LSU_H +
			 LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

      c = libnet_write_ip(sockfd, pkt, LIBNET_OSPF_H + LIBNET_LSU_H +
			  LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

      if (c < LIBNET_OSPF_H + LIBNET_LSU_H + LIBNET_IP_H + LIBNET_AUTH_H
	  + payload_s) {
      }
   }				/* end of ip layer */
}

int build_lsartr()
{				/* Router Links Advertisement */
      if (libnet_init_packet(LIBNET_OSPF_H + LIBNET_AUTH_H +
	       LIBNET_LSA_H + LIBNET_LS_RTR_LEN + LIBNET_IP_H + LIBNET_ETH_H
			     + payload_s + option_s, &pkt) == -1) {
	 printf("libnet_init_packet memory error\n");
	 exit(1);
      }
      libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP, NULL,
			    0, pkt);

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H +
		      LIBNET_LS_RTR_LEN, tos, id, frag,	ttl, IPPROTO_OSPF,	
		      source, dest,	NULL, 0, pkt + LIBNET_ETH_H);

      libnet_build_ospf(LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_RTR_LEN,
      /* size of packet */
			LIBNET_OSPF_LSA,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H + LIBNET_ETH_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_ETH_H + LIBNET_IP_H,
			  auth);

      libnet_build_ospf_lsa(ospf_age, ooptions, LIBNET_LS_TYPE_RTR, rtrid,
			    router, seqnum, LIBNET_LS_RTR_LEN, NULL,
			    0, pkt + LIBNET_ETH_H + LIBNET_AUTH_H + 
                            LIBNET_OSPF_H + LIBNET_IP_H);

      libnet_build_ospf_lsa_rtr(rtr_flags, num, rtrid, rtrdata, rtrtype, tos, 
                                metric, payload, payload_s, pkt + 
                                LIBNET_ETH_H + LIBNET_LSA_H + LIBNET_AUTH_H +
				LIBNET_OSPF_H + LIBNET_IP_H);

      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H);

      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_OSPF, LIBNET_IP_H
	+ LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_RTR_LEN);

      libnet_do_checksum(pkt + LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H +
	   LIBNET_AUTH_H, IPPROTO_OSPF_LSA, LIBNET_LS_RTR_LEN + LIBNET_LSA_H
			 + payload_s);

      n = libnet_write_link_layer(l, device, pkt, LIBNET_ETH_H +
		LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_LSA_H + LIBNET_AUTH_H +
				  LIBNET_LS_RTR_LEN + payload_s + option_s);

      if (n != LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_LSA_H +
	  LIBNET_AUTH_H + LIBNET_LS_RTR_LEN + payload_s + option_s) {
	 fprintf(stderr, "Incomplete data transmission.  Only wrote %d bytes\n", n);
		 } else {
	 if (verbose)
	    printf("Wrote %d byte OSPF packet through linktype %d\n", n,
		   l->linktype);
      }
   }
    /* end of data link layer */ 
   else {

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H +
		      LIBNET_LS_RTR_LEN, tos, id, frag,	ttl, IPPROTO_OSPF,	
		      source, dest,	NULL, 0, pkt);

      libnet_build_ospf(LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_RTR_LEN,
      /* size of packet */
			LIBNET_OSPF_LSA,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_IP_H, auth);

      libnet_build_ospf_lsa(ospf_age, ooptions, LIBNET_LS_TYPE_RTR, rtrid,
			    router, seqnum, LIBNET_LS_RTR_LEN, NULL,
			    0, pkt + LIBNET_AUTH_H + LIBNET_OSPF_H + 
                            LIBNET_IP_H);

      libnet_build_ospf_lsa_rtr(rtr_flags, num, rtrid, rtrdata, rtrtype,
				tos, metric, payload, payload_s,
				pkt + LIBNET_LSA_H + LIBNET_AUTH_H +
				LIBNET_OSPF_H + LIBNET_IP_H);

      libnet_do_checksum(pkt, IPPROTO_OSPF, LIBNET_IP_H + LIBNET_OSPF_H +
			 LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_RTR_LEN);

      libnet_do_checksum(pkt + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H,
	    IPPROTO_OSPF_LSA, LIBNET_LS_RTR_LEN + LIBNET_LSA_H + payload_s);


      c = libnet_write_ip(sockfd, pkt, LIBNET_IP_H + LIBNET_OSPF_H +
			  LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_RTR_LEN +
			  payload_s + option_s);

      if (c < LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H +
	  LIBNET_LS_RTR_LEN + payload_s + option_s) {
   }
}

int build_lsanet()
{				/* Network Links Advertisement */
      if (libnet_init_packet(LIBNET_OSPF_H + LIBNET_AUTH_H +
	       LIBNET_LSA_H + LIBNET_LS_NET_LEN + LIBNET_IP_H + LIBNET_ETH_H
			     + payload_s + option_s, &pkt) == -1) {
	 printf("libnet_init_packet memory error\n");
	 exit(1);
      }
      libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP, NULL, 0, pkt);

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H +
		      LIBNET_LS_NET_LEN, tos, id, frag,	ttl, IPPROTO_OSPF,	
		      source, dest,	NULL, 0, pkt + LIBNET_ETH_H);

      libnet_build_ospf(LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_NET_LEN,
      /* size of packet */
			LIBNET_OSPF_LSA,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H + LIBNET_ETH_H);	

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_ETH_H + LIBNET_IP_H,
			  auth);

      libnet_build_ospf_lsa(ospf_age, ooptions, LIBNET_LS_TYPE_NET, rtrid,
			    router, seqnum, LIBNET_LS_NET_LEN, NULL,
			    0, pkt + LIBNET_ETH_H + LIBNET_AUTH_H + 
                            LIBNET_OSPF_H + LIBNET_IP_H);

      libnet_build_ospf_lsa_net(mask, rtrid, payload, payload_s,
			 pkt + LIBNET_ETH_H + LIBNET_LSA_H + LIBNET_AUTH_H +
				LIBNET_OSPF_H + LIBNET_IP_H);

      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H);

      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_OSPF,
		  LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H
			 + LIBNET_LS_NET_LEN);

      libnet_do_checksum(pkt + LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H
		      + LIBNET_AUTH_H, IPPROTO_OSPF_LSA, LIBNET_LS_NET_LEN +
			 LIBNET_LSA_H + payload_s);

      n = libnet_write_link_layer(l, device, pkt, LIBNET_ETH_H +
		LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_LSA_H + LIBNET_AUTH_H +
				  LIBNET_LS_NET_LEN + payload_s + option_s);


      if (n != LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_LSA_H +
	  LIBNET_AUTH_H + LIBNET_LS_NET_LEN + payload_s + option_s) {
	 fprintf(stderr, "Incomplete data transmission.  Only wrote %d bytes\n", n);
		 } else {
	 if (verbose)
	    printf("Wrote %d byte OSPF packet through linktype %d\n", n,
		   l->linktype);
      }
   }
    /* end of data link layer */ 
   else {
      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H +
		      LIBNET_LS_NET_LEN, tos, id, frag,	ttl, IPPROTO_OSPF,
		      source, dest,	NULL, 0, pkt);

      libnet_build_ospf(LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_NET_LEN,
      /* size of packet */
			LIBNET_OSPF_LSA,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_IP_H, auth);

      libnet_build_ospf_lsa(ospf_age, ooptions, LIBNET_LS_TYPE_NET, rtrid,
			    router, seqnum, LIBNET_LS_NET_LEN,
			    NULL, 0, pkt + LIBNET_AUTH_H + LIBNET_OSPF_H + 
                            LIBNET_IP_H);

      libnet_build_ospf_lsa_net(mask, rtrid, payload, payload_s,
				pkt + LIBNET_LSA_H + LIBNET_AUTH_H +
				LIBNET_OSPF_H + LIBNET_IP_H);

      libnet_do_checksum(pkt, IPPROTO_OSPF, LIBNET_IP_H + LIBNET_OSPF_H +
			 LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_RTR_LEN);

      libnet_do_checksum(pkt + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H,
	    IPPROTO_OSPF_LSA, LIBNET_LS_RTR_LEN + LIBNET_LSA_H + payload_s);

      c = libnet_write_ip(sockfd, pkt, LIBNET_IP_H + LIBNET_OSPF_H +
			  LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_NET_LEN +
			  payload_s + option_s);

      if (c < LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H +
	  LIBNET_LS_NET_LEN + payload_s + option_s) {
   }
}

int build_lsasum_ip()
{				/* Summary Links Advertisement */
      if (libnet_init_packet(LIBNET_OSPF_H + LIBNET_AUTH_H +
	       LIBNET_LSA_H + LIBNET_LS_SUM_LEN + LIBNET_IP_H + LIBNET_ETH_H
			     + payload_s + option_s, &pkt) == -1) {
	 printf("libnet_init_packet memory error\n");
	 exit(1);
      }
      libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP, NULL,
			    0, pkt);

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H +
		      LIBNET_LS_SUM_LEN, tos, id, frag,	ttl, IPPROTO_OSPF,
		      source, dest, NULL, 0, pkt + LIBNET_ETH_H);

      libnet_build_ospf(LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_SUM_LEN,
      /* size of packet */
			LIBNET_OSPF_LSA,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H + LIBNET_ETH_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_ETH_H + LIBNET_OSPF_H + LIBNET_IP_H,
			  auth);

      libnet_build_ospf_lsa(ospf_age, ooptions, LIBNET_LS_TYPE_IP, rtrid,
			    router, seqnum, LIBNET_LS_SUM_LEN,
			    NULL, 0, pkt + LIBNET_ETH_H + LIBNET_AUTH_H + 
                            LIBNET_OSPF_H + LIBNET_IP_H);

      libnet_build_ospf_lsa_sum(mask, metric, tos, payload,
				payload_s, pkt + LIBNET_ETH_H + LIBNET_LSA_H + 
                                LIBNET_AUTH_H + LIBNET_OSPF_H + LIBNET_IP_H);

      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H);

      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_OSPF, LIBNET_IP_H +
	  LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_SUM_LEN);

      libnet_do_checksum(pkt + LIBNET_ETH_H + LIBNET_IP_H +
			 LIBNET_OSPF_H + LIBNET_AUTH_H, IPPROTO_OSPF_LSA,
			 LIBNET_LS_SUM_LEN + LIBNET_LSA_H + payload_s);

      n = libnet_write_link_layer(l, device, pkt, LIBNET_ETH_H +
		LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_LSA_H + LIBNET_AUTH_H +
				  LIBNET_LS_SUM_LEN + payload_s + option_s);

      if (n != LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_LSA_H +
	  LIBNET_AUTH_H + LIBNET_LS_SUM_LEN + payload_s + option_s) {
	 fprintf(stderr, "Incomplete data transmission.  Only wrote %d bytes \n", n);
      } else {
	 if (verbose)
	    printf("Wrote %d byte OSPF packet through linktype %d\n", n,
		   l->linktype);
      }
   }
    /* end of data link layer */ 
   else {

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H +
		      LIBNET_LS_SUM_LEN, tos, id, frag,	ttl, IPPROTO_OSPF,	
		      source, dest,	NULL, 0, pkt);

      libnet_build_ospf(LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_SUM_LEN,
      /* size of packet */
			LIBNET_OSPF_LSA,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_IP_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_OSPF_H + LIBNET_IP_H, auth);

      libnet_build_ospf_lsa(ospf_age, ooptions, LIBNET_LS_TYPE_IP, rtrid,
			    router, seqnum, LIBNET_LS_SUM_LEN, NULL,
			    0, pkt + LIBNET_AUTH_H + LIBNET_OSPF_H + 
                            LIBNET_IP_H);

      libnet_build_ospf_lsa_sum(mask, metric, tos, payload, payload_s,
				pkt + LIBNET_LSA_H + LIBNET_AUTH_H +
				LIBNET_OSPF_H + LIBNET_IP_H);

      libnet_do_checksum(pkt, IPPROTO_OSPF, LIBNET_IP_H +
	  LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_SUM_LEN);

      libnet_do_checksum(pkt + LIBNET_IP_H +
			 LIBNET_OSPF_H + LIBNET_AUTH_H, IPPROTO_OSPF_LSA,
			 LIBNET_LS_SUM_LEN + LIBNET_LSA_H + payload_s);

      c = libnet_write_ip(sockfd, pkt, LIBNET_IP_H + LIBNET_OSPF_H +
			  LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_SUM_LEN +
			  payload_s + option_s);

      if (c < LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H +
	  LIBNET_LS_SUM_LEN + payload_s + option_s) {
      }
   }
}

int build_lsaas()
{				/* Summary Links Advertisement */
      if (libnet_init_packet(LIBNET_OSPF_H + LIBNET_AUTH_H +
	    LIBNET_LSA_H + LIBNET_LS_AS_EXT_LEN + LIBNET_IP_H + LIBNET_ETH_H
			     + payload_s + option_s, &pkt) == -1) {
	 printf("libnet_init_packet memory error\n");
	 exit(1);
      }
      libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP, NULL,
			    0, pkt);

      libnet_build_ip(LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H +
		      LIBNET_LS_AS_EXT_LEN,	tos, id, frag, ttl, IPPROTO_OSPF,
		      source, dest,	NULL, 0, pkt + LIBNET_ETH_H);


      libnet_build_ospf(LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_AS_EXT_LEN,
      /* size of packet */
			LIBNET_OSPF_LSA,	/* OSPF type */
			addrid,	/* router ID */
			addaid,	/* area ID */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL, 0, pkt + LIBNET_ETH_H + LIBNET_IP_H);

      auth[0] = 0;
      auth[1] = 0;

      LIBNET_OSPF_AUTHCPY(pkt + LIBNET_ETH_H + LIBNET_OSPF_H + LIBNET_IP_H,
			  auth);

      libnet_build_ospf_lsa(ospf_age, ooptions, LIBNET_LS_TYPE_ASEXT, rtrid,
			    router, seqnum, LIBNET_LS_AS_EXT_LEN,
			    NULL, 0, pkt + LIBNET_ETH_H + LIBNET_AUTH_H + LIBNET_OSPF_H +
			    LIBNET_IP_H);

      libnet_build_ospf_lsa_as(mask, metric, as_fwd, as_tag, payload,
			       payload_s, pkt + LIBNET_ETH_H + LIBNET_LSA_H + 
                   LIBNET_AUTH_H + LIBNET_OSPF_H + LIBNET_IP_H);

      libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H);

      libnet_do_checksum(pkt, IPPROTO_OSPF, LIBNET_IP_H + LIBNET_OSPF_H +
		       LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_AS_EXT_LEN);

      libnet_do_checksum(pkt + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H,
	 IPPROTO_OSPF_LSA, LIBNET_LS_AS_EXT_LEN + LIBNET_LSA_H + payload_s);

      n = libnet_write_link_layer(l, device, pkt, LIBNET_ETH_H +
		LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_LSA_H + LIBNET_AUTH_H +
			       LIBNET_LS_AS_EXT_LEN + payload_s + option_s);

      if (n != LIBNET_ETH_H + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_LSA_H +
	  LIBNET_AUTH_H + LIBNET_LS_AS_EXT_LEN + payload_s + option_s) {
	 fprintf(stderr, "Incomplete data transmission.  Only wrote %d bytes \n", n);
      } else {
	 if (verbose)
	    printf("Wrote %d byte OSPF packet through linktype %d\n", n,
		   l->linktype);
      }
   }
#endif
