/*
 * $Id: nemesis-ospf.h,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * 
 * nemesis-ospf.h (OSPF Packet Injector)
 * 
 */

#ifndef __NEMESIS_OSPF_H__
#define __NEMESIS_OSPF_H__

#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#if defined(WIN32)
    #include <pcap.h>
#endif
#if defined(HAVE_MACHINE_ENDIAN_H)
    #include <machine/endian.h>
#endif
#if defined(HAVE_NETINET_IN_H)
    #include <netinet/in.h>
#elif defined(WIN32)
    #include <winsock2.h>
#endif
#include <libnet.h>
#include "nemesis.h"

u_short id,            /* IP id */
        frag,          /* frag shit */
        mtusize,       /* Max dgram length (DBD) */
        num,           /* LSA_RTR num */
        interval,      /* secs since last pkt sent */
        rtr_flags,     /* LSA_RTR flags */
        metric,        /* OSPF metric */
        ospf_age;      /* OSPF advertisement age */

u_long source,         /* source address */
       dest,           /* destination address */
       neighbor,       /* neighbor router */
       as_fwd,         /* AS_EXT forward address */
       addrid,         /* advertising router id */
       addaid,         /* advertising area id */
       router,         /* advertising router */
       auth[2],        /* authentication type */
       mask;           /* subnet mask (icmp_mask) */

u_char priority,       /* OSPF priority */
       exchange,       /* DBD exchange type */
       rtrtype,        /* LSA_RTR type */
       ooptions;       /* OSPF options */

u_int dead_int,        /* dead router interval in secs */
      as_tag,          /* AS_EXT tag */
      seqnum,          /* seqnum for LSA */
      bcastnum,        /* num of LSAs to bcast (LSU) */
      rtrdata,         /* LSA_RTR router data */
      rtrid;           /* router id for LSA */

int mode;   /* OSPF injection mode */

int buildospf(ETHERhdr *, IPhdr *, FileData *, FileData *, char *);

#endif /* __NEMESIS_OSPF_H__ */
