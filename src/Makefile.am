## $Id: Makefile.am,v 1.1.1.1 2003/10/31 21:29:36 jnathan Exp $

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = nemesis

nemesis_SOURCES = nemesis-arp.c nemesis-arp.h \
nemesis-dns.c nemesis-dns.h \
nemesis-ethernet.c nemesis-ethernet.h \
nemesis-fileio.c nemesis-functions.c \
nemesis-icmp.c nemesis-icmp.h \
nemesis-igmp.c nemesis-igmp.h \
nemesis-ip.c nemesis-ip.h \
nemesis-ospf.c nemesis-ospf.h \
nemesis-printout.c \
nemesis-proto_arp.c \
nemesis-proto_dns.c \
nemesis-proto_ethernet.c \
nemesis-proto_icmp.c \
nemesis-proto_igmp.c \
nemesis-proto_ip.c \
nemesis-proto_ospf.c \
nemesis-proto_rip.c \
nemesis-proto_tcp.c \
nemesis-proto_udp.c \
nemesis-rip.c nemesis-rip.h \
nemesis-tcp.c nemesis-tcp.h \
nemesis-udp.c nemesis-udp.h \
nemesis.c nemesis.h \
W32_fzs.c
 
INCLUDES = @INCLUDES@
nemesis_LDADD = @LIBOBJS@
