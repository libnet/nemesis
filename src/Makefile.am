AUTOMAKE_OPTIONS = foreign subdir-objects
DISTCLEANFILES   = *~

AM_CFLAGS        = -W -Wall -Wextra -Wno-unused-parameter -Wno-empty-body
AM_CFLAGS       += -std=gnu99
AM_CPPFLAGS      = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD

bin_PROGRAMS     = nemesis
nemesis_SOURCES  = nemesis-arp.c      nemesis-arp.h       nemesis-proto_arp.c		\
		   nemesis-dns.c      nemesis-dns.h       nemesis-proto_dns.c		\
		   nemesis-dhcp.c     nemesis-dhcp.h      nemesis-proto_dhcp.c		\
		   nemesis-ethernet.c nemesis-ethernet.h  nemesis-proto_ethernet.c	\
		   nemesis-icmp.c     nemesis-icmp.h      nemesis-proto_icmp.c		\
		   nemesis-igmp.c     nemesis-igmp.h      nemesis-proto_igmp.c		\
		   nemesis-ip.c       nemesis-ip.h        nemesis-proto_ip.c		\
		   nemesis-tcp.c      nemesis-tcp.h       nemesis-proto_tcp.c		\
		   nemesis-udp.c      nemesis-udp.h       nemesis-proto_udp.c		\
		   nemesis-ospf.c     nemesis-ospf.h      nemesis-proto_ospf.c		\
		   nemesis-rip.c      nemesis-rip.h       nemesis-proto_rip.c		\
		   nemesis-fileio.c   nemesis-functions.c nemesis-printout.c		\
		   nemesis.c          nemesis.h						\
		   W32_fzs.c
nemesis_LDADD    = $(LIBS) $(LIBOBJS)
