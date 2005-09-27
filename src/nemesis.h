/*
 * $Id: nemesis.h,v 1.4 2005/09/27 19:46:19 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis.h
 *
 */

#ifndef __NEMESIS_H__
#define __NEMESIS_H__

#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <stdint.h>
#include <libnet.h>

#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY 0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT 0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY 0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST 0x02
#endif
#ifndef TH_ECE
#define TH_ECE 0x40
#endif
#ifndef TH_CWR
#define TH_CWR 0x80
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

#define getint32(s, d) getint((s), (void *)(d), 32)
#define getint16(s, d) getint((s), (void *)(d), 16)
#define getint8(s, d) getint((s), (void *)(d), 8)

#define STPUTC(c) putchar(c);
#define STPUTS(s) { const char *p; p = s; while(*p) STPUTC(*(p++)); }

#define ARPBUFFSIZE 1472

#define DNSTCP_RAWBUFFSIZE 65403    /* plan for IP and TCP options */
#define DNSTCP_LINKBUFFSIZE 1368    /* link-layer version of above */
#define DNSUDP_RAWBUFFSIZE 65455    /* plan for IP options */
#define DNSUDP_LINKBUFFSIZE 1420    /* link-layer version of above */

#define ETHERBUFFSIZE 1500          /* max frame size */

#define ICMP_RAWBUFFSIZE 65399      /* plan for IP options & max ICMP header 
                                       len */
#define ICMP_LINKBUFFSIZE 1364      /* link-layer version of above */

#define IGMP_RAWBUFFSIZE 65467      /* plan for IP options */
#define IGMP_LINKBUFFSIZE 1432      /* link-layer version of above */

#define IP_RAWBUFFSIZE 65475        /* plan for IP options */
#define IP_LINKBUFFSIZE 1440        /* link-layer version of above */

#define RIP_RAWBUFFSIZE 65451       /* plan for IP options & max RIP header 
                                       len */
#define RIP_LINKBUFFSIZE 1416       /* link-layer version of above */

#define TCP_RAWBUFFSIZE 65415       /* plan for IP and TCP options */
#define TCP_LINKBUFFSIZE 1380       /* link-layer version of above */

#define UDP_RAWBUFFSIZE 65467       /* plan for IP options */
#define UDP_LINKBUFFSIZE 1432       /* link-layer version of above */

#define BUILD 26                /* build number, update for each build */
#define FP_MAX_ARGS 4           /* number of IP fragment parsing tokens */
#define ERRBUFFSIZE 256
#define TITLEBUFFSIZE 81
#define WINERRBUFFSIZE 1024

#define HEX_ASCII_DECODE 0x02
#define HEX_RAW_DECODE 0x04

#define INJECTION_RAW 0x02
#define INJECTION_LINK 0x04

#define PAYLOADMODE 0
#define OPTIONSMODE 1
#define OPTIONSBUFFSIZE 40

typedef struct libnet_arp_hdr ARPhdr;
typedef struct libnet_as_lsa_hdr ASLSAhdr;
typedef struct libnet_auth_hdr AUTHhdr;
typedef struct libnet_dbd_hdr DBDhdr;
typedef struct libnet_dns_hdr DNShdr;
typedef struct libnet_ethernet_hdr ETHERhdr;
typedef struct libnet_icmp_hdr ICMPhdr;
typedef struct libnet_igmp_hdr IGMPhdr;
typedef struct libnet_ip_hdr IPhdr;
typedef struct libnet_lsa_hdr LSAhdr;
typedef struct libnet_lsr_hdr LSRhdr;
typedef struct libnet_lsu_hdr LSUhdr;
typedef struct libnet_ospf_hdr OSPFhdr;
typedef struct libnet_ospf_hello_hdr OSPFHELLOhdr;
typedef struct libnet_net_lsa_hdr NETLSAhdr;
typedef struct libnet_rip_hdr RIPhdr;
typedef struct libnet_rtr_lsa_hdr RTRLSAhdr;
typedef struct libnet_sum_lsa_hdr SUMLSAhdr;
typedef struct libnet_tcp_hdr TCPhdr;
typedef struct libnet_udp_hdr UDPhdr;
typedef struct libnet_vrrp_hdr VRRPhdr;

extern char zero[ETHER_ADDR_LEN];
extern char one[ETHER_ADDR_LEN];
extern char title[TITLEBUFFSIZE];
extern char errbuf[ERRBUFFSIZE];
extern char *pcap_outfile;
extern char *validtcpflags;
extern const char *version;
extern int verbose;
extern int got_link;
extern int got_ipoptions;
extern int got_tcpoptions;

typedef struct _FileData
{
    int32_t file_s;         /* file size */
    uint8_t *file_mem;     /* pointer to file memory */
} FileData;

/* support functions */
int getint(const char *str, void *data, int size);
//int gmt2local(time_t);
int nemesis_name_resolve(char *hostname, uint32_t *address);
int nemesis_check_link(ETHERhdr *eth, char *device);
int nemesis_getdev(int devnum, char **device);
char *nemesis_lookup_linktype(int linktype);
int nemesis_seedrand(void);
int parsefragoptions(char *str, IPhdr *iph);
int parsetcpflags(char *str, TCPhdr *tcp);

#if defined(WIN32) || !defined(HAVE_INET_ATON)
    int inet_aton(const char *cp, struct in_addr *addr);
#endif
#if defined(WIN32) || !defined(HAVE_GETOPT)
    int getopt(int nargc, char * const *nargv, const char *ostr);
#endif
#if defined(WIN32) || !defined(HAVE_STRLCAT)
    size_t strlcat(char *dst, const char *src, size_t size);
#endif
#if defined(WIN32) || !defined(HAVE_STRLCPY)
    size_t strlcpy(char *dst, const char *src, size_t size);
#endif
#if defined(WIN32) || !defined(HAVE_STRSEP)
    char *strsep(register char **stringp, const char *delim);
#endif
#if defined(WIN32)
    void PrintDeviceList(const char *device);
    void *GetAdapterFromList(void *device, int index);
    int nemesis_getdev(int devnum, char **device);
#endif

/* file I/O functions */
int builddatafromfile(const size_t buffsize, FileData *memory, 
        const char *file, const uint32_t mode);

/* printout functions */
void nemesis_hexdump(char *buf, uint32_t len, int mode);
void nemesis_device_failure(int mode, const char *device);
void nemesis_maketitle(char *title, const char *module, const char *version);
void nemesis_printeth(ETHERhdr *eth);
void nemesis_printarp(ARPhdr *arp);
void nemesis_printip(IPhdr *ip);
void nemesis_printtcp(TCPhdr *tcp);
void nemesis_printudp(UDPhdr *udp);
void nemesis_printicmp(ICMPhdr *icmp, int mode);
void nemesis_printrip(RIPhdr *rip);
void nemesis_printospf(OSPFhdr *ospf);
void nemesis_printtitle(const char *title);
void nemesis_usage(char *arg);

/* injection functions */
void nemesis_arp(int argc, char **argv);
void nemesis_dns(int argc, char **argv);
void nemesis_ethernet(int argc, char **argv);
void nemesis_icmp(int argc, char **argv);
void nemesis_igmp(int argc, char **argv);
void nemesis_ip(int argc, char **argv);
void nemesis_ospf(int argc, char **argv);
void nemesis_rip(int argc, char **argv);
void nemesis_tcp(int argc, char **argv);
void nemesis_udp(int argc, char **argv);

#endif /* __NEMESIS_H__ */
