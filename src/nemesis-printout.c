/*
 * $Id: nemesis-printout.c,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-functions.c (nemesis utility functions)
 *
 */

#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(WIN32)
    #include <pcap.h>
#endif
#include <unistd.h>
#if defined(HAVE_LIMITS_H) || defined(WIN32)
    #include <limits.h>
#endif
#if defined(HAVE_ERRNO_H) || defined(WIN32)
    #include <errno.h>
#endif
#if defined(HAVE_NETINET_IN_H)
    #include <netinet/in.h>
#elif defined(WIN32)
    #include <winsock2.h>
    #include <process.h>
#endif
#include <libnet.h>
#include "nemesis.h"


/**
 * Dumps a packet payload in hex format
 *
 * @param buf pointer to allocated payload memory
 * @param len length of buffer to print in hex format
 *
 * @notes Contributed by Dragos Ruiu <dr@kyx.net>.  A very nice piece of code.
 *
 * @return void function
 */
void nemesis_hexdump(char *buf, u_int32_t len, int mode)
{
    int c, linemod;
    char *p, *l, *dump, *predump, *postdump, dumpbuf[40];

    l = &(buf[len - 1]);
    dump = dumpbuf;
    putchar('\n');

    switch (mode)
    {
        case HEX_RAW_DECODE:
            linemod = 26;
            predump = "   ";
            postdump = "";
            break;
        case HEX_ASCII_DECODE:  /* FALLTHROUGH */
        default:
            linemod = 16;
            predump = "   ";
            postdump = "  ";
            break;
    }

    STPUTS("[Hexdump]\n");
    for (p = buf; p <= l; p++)
    {
        *(dump++) = (isprint((int)*p) ? *p : '.');
        putchar((c = (*p & 0xF0) >> 4) < 10 ? c + '0' : c + '7');
        putchar((c = *p & 0x0F) < 10 ? c + '0' : c + '7');

        if (!(((p - buf) + 1) % linemod) || (p == l))
        {
            /* pad the last line */
            if (p == l)
            {
                while (((((p++) - buf) + 1) % linemod))
                {
                    STPUTS(predump);
                }
            }
            *dump = 0;
            STPUTS(postdump);
            if (mode == HEX_ASCII_DECODE)
                puts(dumpbuf);
            else
                putchar('\n');
            dump = dumpbuf;
        }
        else
            putchar(' ');
    }
    putchar('\n');
}


/**
 * Print the source and destination within the supplied ETHERhdr struct in 
 * ASCII form.
 *
 * @param eth pointer to an ETHERhdr struct
 *
 * @return void function
 */
void nemesis_printeth(ETHERhdr *eth)
{
    char *ethertype = "Unknown";

    switch (eth->ether_type)
    {
        case ETHERTYPE_PUP:
            ethertype = "PUP";
            break;
        case ETHERTYPE_IP:
            ethertype = "IP";
            break;
        case ETHERTYPE_ARP:
            ethertype = "ARP";
            break;
        case ETHERTYPE_REVARP:
            ethertype = "RARP";
            break;
        case ETHERTYPE_VLAN:
            ethertype = "802.1q";
            break;
        case ETHERTYPE_IPV6:
            ethertype = "IPv6";
            break;
        case 34915:
            ethertype = "PPOE discovery";
            break;
        case 34916:
            ethertype = "PPOE session";
            break;
        default:
            break;
    }

    printf("               [MAC] %02X:%02X:%02X:%02X:%02X:%02X > "
            "%02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_shost[0], 
            eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], 
            eth->ether_shost[4], eth->ether_shost[5], eth->ether_dhost[0],
            eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3],
            eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("     [Ethernet type] %s (%#.4x)\n\n", ethertype, eth->ether_type); 
    return;
}


/**
 * Verbosely print portions of the ARP header in ASCII form.
 *
 * @param arp pointer to an ARPhdr struct
 *
 * @return void function
 */
void nemesis_printarp(ARPhdr *arp)
{
    char *src = NULL, *dst = NULL;
    char *opcode = "Unknown";

    switch (arp->ar_op)
    {
        case ARPOP_REQUEST:
            opcode = "Request";
            break;
        case ARPOP_REPLY:
            opcode = "Reply";
            break;
        case ARPOP_REVREQUEST:
            opcode = "Reverse request";
            break;
        case ARPOP_REVREPLY:
            opcode = "Reverse reply";
            break;
    }

    src = strdup(inet_ntoa(*(struct in_addr *)&arp->ar_spa));
    dst = strdup(inet_ntoa(*(struct in_addr *)&arp->ar_tpa));

    printf("  [Protocol addr:IP] %s > %s\n", src, dst);
    printf(" [Hardware addr:MAC] %02x:%02x:%02x:%02x:%02x:%02x > " 
            "%02X:%02X:%02X:%02X:%02X:%02X\n", arp->ar_sha[0], arp->ar_sha[1], 
            arp->ar_sha[2], arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5], 
            arp->ar_tha[0], arp->ar_tha[1], arp->ar_tha[2], arp->ar_tha[3], 
            arp->ar_tha[4], arp->ar_tha[5]);

    printf("        [ARP opcode] %s\n", opcode);
    printf("  [ARP hardware fmt] %s (%hu)\n", "Ethernet", arp->ar_hrd);
    printf("  [ARP proto format] %s (%#.4x)\n", "IP", arp->ar_pro);
    printf("  [ARP protocol len] %d\n", arp->ar_hln);
    printf("  [ARP hardware len] %d\n\n", arp->ar_pln);

    if (src != NULL)
        free(src);
    if (dst != NULL)
        free(dst);

    return;
}


/**
 * Verbosely print portions of the IP header in ASCII form.
 *
 * @param ip pointer to an IPhdr struct
 *
 * @return void function
 */
void nemesis_printip(IPhdr *ip)
{
    char *protoname = "Unknown";
    char *src = NULL, *dst = NULL;

    src = strdup(inet_ntoa(ip->ip_src));
    dst = strdup(inet_ntoa(ip->ip_dst));

    printf("                [IP] %s > %s\n", src, dst);
    printf("             [IP ID] %hu\n", ip->ip_id);

    switch(ip->ip_p)
    {
        case 0:
            protoname = "IP";
            break;
        case 1:
            protoname = "ICMP";
            break;
        case 2:
            protoname = "IGMP";
            break;
        case 3:
            protoname = "GGP";
            break;
        case 4:
            protoname = "IP-ENCAP";
            break;
        case 5:
            protoname = "ST";
            break;
        case 6:
            protoname = "TCP";
            break;
        case 7:
            protoname = "UCL";
            break;
        case 8:
            protoname = "EGP";
            break;
        case 9:
            protoname = "IGP";
            break;
        case 10:
            protoname = "BBN-RCC-MON";
            break;
        case 11:
            protoname = "NVP-II";
            break;
        case 12:
            protoname = "PUP";
            break;
        case 13:
            protoname = "ARGUS";
            break;
        case 14:
            protoname = "EMCON";
            break;
        case 15:
            protoname = "XNET";
            break;
        case 16:
            protoname = "CHAOS";
            break;
        case 17:
            protoname = "UDP";
            break;
        case 18:
            protoname = "MUX";
            break;
        case 19:
            protoname = "DCN-MEAS";
            break;
        case 20:
            protoname = "HMP";
            break;
        case 21:
            protoname = "PRM";
            break;
        case 22:
            protoname = "XNS-IDP";
            break;
        case 23:
            protoname = "TRUNK-1";
            break;
        case 24:
            protoname = "TRUNK-2";
            break;
        case 25:
            protoname = "LEAF-1";
            break;
        case 26:
            protoname = "LEAF-2";
            break;
        case 27:
            protoname = "RDP";
            break;
        case 28:
            protoname = "IRTP";
            break;
        case 29:
            protoname = "ISO-TP4";
            break;
        case 30:
            protoname = "NETBLT";
            break;
        case 31:
            protoname = "MFE-NSP";
            break;
        case 32:
            protoname = "MERIT-INP";
            break;
        case 33:
            protoname = "SEP";
            break;
        case 34:
            protoname = "3PC";
            break;
        case 35:
            protoname = "IDPR";
            break;
        case 36:
            protoname = "XTP";
            break;
        case 37:
            protoname = "DDP";
            break;
        case 38:
            protoname = "IDPR-CMTP";
            break;
        case 39:
            protoname = "IDPR-CMTP";
            break;
        case 40:
            protoname = "IL";
            break;
        case 41:
            protoname = "IPv6";
            break;
        case 42:
            protoname = "SDRP";
            break;
        case 43:
            protoname = "SIP-SR";
            break;
        case 44:
            protoname = "SIP-FRAG";
            break;
        case 45:
            protoname = "IDRP";
            break;
        case 46:
            protoname = "RSVP";
            break;
        case 47:
            protoname = "GRE";
            break;
        case 48:
            protoname = "MHRP";
            break;
        case 49:
            protoname = "BNA";
            break;
        case 50:
            protoname = "IPSEC-ESP";
            break;
        case 51:
            protoname = "IPSEC-AH";
            break;
        case 52:
            protoname = "I-NLSP";
            break;
        case 53:
            protoname = "SWIPE";
            break;
        case 54:
            protoname = "NHRP";
            break;
        case 55:
            protoname = "MOBILEIP";
            break;
        case 57:
            protoname = "SKIP";
            break;
        case 58:
            protoname = "IPv6-ICMP";
            break;
        case 59:
            protoname = "IPv6-NoNxt";
            break;
        case 60:
            protoname = "IPv6-Opts";
            break;
        case 61:
            protoname = "any";
            break;
        case 62:
            protoname = "CFTP";
            break;
        case 63:
            protoname = "any";
            break;
        case 64:
            protoname = "SAT-EXPAK";
            break;
        case 65:
            protoname = "KRYPTOLAN";
            break;
        case 66:
            protoname = "RVD";
            break;
        case 67:
            protoname = "IPPC";
            break;
        case 68:
            protoname = "any";
            break;
        case 69:
            protoname = "SAT-MON";
            break;
        case 70:
            protoname = "VISA";
            break;
        case 71:
            protoname = "IPCV";
            break;
        case 72:
            protoname = "CPNX";
            break;
        case 73:
            protoname = "CPHB";
            break;
        case 74:
            protoname = "WSN";
            break;
        case 75:
            protoname = "PVP";
            break;
        case 76:
            protoname = "BR-SAT-MON";
            break;
        case 77:
            protoname = "SUN-ND";
            break;
        case 78:
            protoname = "WB-MON";
            break;
        case 79:
            protoname = "WB-EXPAK";
            break;
        case 80:
            protoname = "ISO-IP";
            break;
        case 81:
            protoname = "VMTP";
            break;
        case 82:
            protoname = "SECURE-VMTP";
            break;
        case 83:
            protoname = "VINES";
            break;
        case 84:
            protoname = "TTP";
            break;
        case 85:
            protoname = "NSFNET-IGP";
            break;
        case 86:
            protoname = "DGP";
            break;
        case 87:
            protoname = "TCF";
            break;
        case 88:
            protoname = "IGRP";
            break;
        case 89:
            protoname = "OSPFIGP";
            break;
        case 90:
            protoname = "Sprite-RPC";
            break;
        case 91:
            protoname = "LARP";
            break;
        case 92:
            protoname = "MTP";
            break;
        case 93:
            protoname = "AX.25";
            break;
        case 94:
            protoname = "IPIP";
            break;
        case 95:
            protoname = "MICP";
            break;
        case 96:
            protoname = "SCC-SP";
            break;
        case 97:
            protoname = "ETHERIP";
            break;
        case 98:
            protoname = "ENCAP";
            break;
        case 99:
            protoname = "any";
            break;
        case 100:
            protoname = "GMTP";
            break;
        case 103:
            protoname = "PIM";
            break;
        case 108:
            protoname = "IPComp";
            break;
        case 112:
            protoname = "VRRP";
            break;
        case 255:
            protoname = "Reserved";
            break;
    }
    printf("          [IP Proto] %s (%hu)\n", protoname, ip->ip_p);
    printf("            [IP TTL] %u\n", ip->ip_ttl);
    printf("            [IP TOS] 0x%.2x\n", ip->ip_tos);
    printf("    [IP Frag offset] 0x%.4x\n", ip->ip_off & IP_OFFMASK);
    STPUTS("     [IP Frag flags] ");
    if ((ip->ip_off & IP_RF) >> 15)
        STPUTS("RESERVED ");
    if ((ip->ip_off & IP_DF) >> 14)
        STPUTS("DF ");
    if ((ip->ip_off & IP_MF) >> 13)
        STPUTS("MF ");

    putchar('\n');

    if (src != NULL)
        free(src);
    if (dst != NULL)
        free(dst);

    return;
}


/**
 * Verbosely print portions of the TCP header in ASCII form.
 *
 * @param tcp TCPhdr struct
 *
 * @return void function
 */
void nemesis_printtcp(TCPhdr *tcp)
{
        printf("         [TCP Ports] %hu > %hu\n", tcp->th_sport, 
                tcp->th_dport);
        STPUTS("         [TCP Flags] ");
        if (tcp->th_flags & TH_SYN)
            STPUTS("SYN ");
        if (tcp->th_flags & TH_ACK)
            STPUTS("ACK ");
        if (tcp->th_flags & TH_RST)
            STPUTS("RST ");
        if (tcp->th_flags & TH_PUSH)
            STPUTS("PSH ");
        if (tcp->th_flags & TH_URG)
            STPUTS("URG ");
        if (tcp->th_flags & TH_FIN)
            STPUTS("FIN ");
        if (tcp->th_flags & TH_ECE)
            STPUTS("ECE ");
        if (tcp->th_flags & TH_CWR)
            STPUTS("CWR ");

        putchar('\n');
        printf("[TCP Urgent Pointer] %u\n", tcp->th_urp);
        printf("   [TCP Window Size] %u\n", tcp->th_win);
        if (tcp->th_flags & TH_ACK)
            printf("    [TCP Ack number] %lu\n", tcp->th_ack);
        if (tcp->th_flags & TH_SYN)
            printf("    [TCP Seq number] %lu\n", tcp->th_seq);

        putchar('\n');
        return;
}


/**
 * Verbosely print portions of the UDP header in ASCII form.
 *
 * @param udp UDPhdr struct
 *
 * @return void function
 */
void nemesis_printudp(UDPhdr *udp)
{
    printf("         [UDP Ports] %hu > %hu\n\n", udp->uh_sport, udp->uh_dport);
    return;
}


/**
 * Verbosely print portions of the ICMP header in ASCII form.
 *
 * @param icmp ICMPhdr struct
 * @param mode ICMP injection mode
 *
 * @return void function
 */
void nemesis_printicmp(ICMPhdr *icmp, int mode)
{
    char *icmptype = "Unknown";
    char *icmpcode = "Unknown";
    char *mask = NULL, *gateway = NULL;

    mask = strdup(inet_ntoa(*(struct in_addr *)&icmp->dun.mask));
    gateway = strdup(inet_ntoa(*(struct in_addr *)&icmp->hun.gateway));

    switch (icmp->icmp_type)
    {
        case 0:
            icmptype = "Echo Reply";
            if (icmp->icmp_code == 0)
                icmpcode = "Echo Reply";
            break;
        case 3:
            icmptype = "Destination Unreachable";
            switch (icmp->icmp_code)
            {
                case 0:
                    icmpcode = "Network Unreachable";
                    break;
                case 1:
                    icmpcode =  "Host Unreachable";
                    break;
                case 2:
                    icmpcode = "Protocol Unreachable";
                    break;
                case 3:
                    icmpcode = "Port Unreachable";
                    break;
                case 4:
                    icmpcode = "Fragmentation Needed";
                    break;
                case 5:
                    icmpcode = "Source Route Failed";
                    break;
                case 6:
                    icmpcode = "Destination Network Unknown";
                    break;
                case 7:
                    icmpcode = "Destination Host Unknown";
                    break;
                case 8:
                    icmpcode = "Source Host Isolated (obsolete)";
                    break;
                case 9:
                    icmpcode = "Destination Network Administratively "
                            "Prohibited";
                    break;
                case 10:
                    icmpcode = "Destination Host Administratively "
                            "Prohibited";
                    break;
                case 11:
                    icmpcode = "Network Unreachable For TOS";
                    break;
                case 12:
                    icmpcode = "Host Unreachable For TOS";
                    break;
                case 13: 
                    icmpcode = "Communication Administratively Prohibited "
                            "By Filtering";
                    break;
                case 14:
                    icmpcode = "Host Precedence Violation";
                    break;
                case 15:
                    icmpcode = "Precedence Cutoff In Effect";
                    break;
                default:
                    break;
                }
            break;
        case 4:
            icmptype = "Source Quench";
            if (icmp->icmp_code == 0)
                icmpcode = "Source Quench";
            break;
        case 5:
            icmptype = "Redirect";
            switch (icmp->icmp_code)
            {
                case 0:
                    icmpcode = "Redirect For Network";
                    break;
                case 1:
                    icmpcode = "Redirect For Host";
                    break;
                case 2:
                    icmpcode = "Redirect For TOS and Network";
                    break;
                case 3:
                    icmpcode = "Redirect For TOS and Host";
                    break;
                default:
                    break;
            }
            break;
        case 8:
            icmptype = "Echo Request";
            if (icmp->icmp_code == 0)
                icmpcode = "Echo Request";
            break;
        case 9:
            icmptype = "Router Advertisement";
            if (icmp->icmp_code == 0)
                icmpcode = "Router Advertisement";
            break;
        case 10:
            icmptype = "Router Solicitation";
            if (icmp->icmp_code == 0)
                icmpcode = "Router Solicitation";
            break;
        case 11:
            icmptype = "Time Exceeded";
            switch (icmp->icmp_code)
            {
                case 0:
                    icmpcode = "TTL = 0 During Transmit";
                    break;
                case 1:
                    icmpcode = "TTL = 0 During Reassembly";
                    break;
                default:
                    break;
            }
            break;
        case 12:
            icmptype = "Parameter Problem";
            switch (icmp->icmp_code)
            {
                case 0:
                    icmpcode = "IP Header Bad (catchall error)";
                    break;
                case 1:
                    icmpcode = "Required Option Missing";
                    break;
                default:
                    break;
            }
        case 13:
            icmptype = "Timestamp Request";
            if (icmp->icmp_code == 0)
                icmpcode = "Timestamp Request";
            break;
        case 14:
            icmpcode = "Timestamp Reply";
            if (icmp->icmp_code == 0)
                icmpcode = "Timestamp Reply";
            break;
        case 15:
            icmptype = "Information Request";
            if (icmp->icmp_code == 0)
                icmpcode = "Information Request";
            break;
        case 16:
            icmptype = "Information Reply";
            if (icmp->icmp_code == 0)
                icmpcode = "Information Reply";
            break;
        case 17:
            icmptype = "Address Mask Request";
            if (icmp->icmp_code == 0)
                icmpcode = "Address Mask Request";
            break;
        case 18:
            icmptype = "Address Mask Reply";
            if (icmp->icmp_code == 0)
                icmptype = "Address Mask Reply";
            break;
        default:
            icmptype = "Unknown";
            break;
    }
    printf("         [ICMP Type] %s\n", icmptype);
    printf("         [ICMP Code] %s\n", icmpcode);

    if (mode == ICMP_ECHO || mode == ICMP_MASKREQ || mode == ICMP_TSTAMP)
    {
        printf("           [ICMP ID] %hu\n", icmp->hun.echo.id);
        printf("   [ICMP Seq number] %hu\n", icmp->hun.echo.seq);
    }
    if (mode == ICMP_MASKREQ)
        printf(" [ICMP Address Mask] %s\n", mask);
    if (mode == ICMP_REDIRECT)
        printf(" [ICMP Pref Gateway] %s\n", gateway);

    putchar('\n');

    if (mask != NULL)
        free(mask);
    if (gateway != NULL)
        free(gateway);

    return;
}


/**
 * Verbosely print portions of the RIP header in ASCII form.
 *
 * @param rip pointer to a RIPhdr struct
 *
 * @return void function
 *
 */
void nemesis_printrip(RIPhdr *rip)
{
    char *cmd = "Unknown";
    char *family = "Unknown";
    char *addr = NULL, *mask = NULL, *hop = NULL;

    addr = strdup(inet_ntoa(*(struct in_addr *)&rip->addr));
    mask = strdup(inet_ntoa(*(struct in_addr *)&rip->mask));
    hop = strdup(inet_ntoa(*(struct in_addr *)&rip->next_hop));

    switch(rip->cmd)
    {
        case RIPCMD_REQUEST:
            cmd = "Request";
            break;
        case RIPCMD_RESPONSE:
            cmd = "Response";
            break;
        case RIPCMD_TRACEON:
            cmd = "Tracing on (obsolete)";
            break;
        case RIPCMD_TRACEOFF:
            cmd = "Tracing off (obsolete)";
            break;
        case RIPCMD_POLL:
            cmd = "Poll";
            break;
        case RIPCMD_POLLENTRY:
            cmd = "Poll entry";
            break;
        case RIPCMD_MAX:
            cmd = "Max";
            break;
        default:
            break;
    }
    printf("       [RIP Command] %s (%hu)\n", cmd, (u_int16_t)rip->cmd);
    printf("       [RIP Version] %hu\n", (u_int16_t)rip->ver);
    printf("[RIP Routing domain] %hu\n", (u_int16_t)rip->rd);
    if (rip->af == 2)
        family = "IP";

    printf("[RIP Address family] %s (%hu)\n", family, (u_int16_t)rip->af);
    printf("     [RIP Route tag] %hu\n", (u_int16_t)rip->rt);
    printf("       [RIP Address] %s\n", addr);
    printf("  [RIP Network mask] %s\n", mask);
    printf("      [RIP Next hop] %s\n", hop);
    printf("        [RIP Metric] %u\n", (u_int32_t)rip->metric);

    putchar('\n');

    if (addr != NULL)
        free(addr);
    if (mask != NULL)
        free(mask);
    if (hop != NULL)
        free(hop);

    return;
}


/**
 * Verbosely print portions of the OSPF header in ASCII form.
 *
 * @param opsf OSPfhdr struct
 *
 * @return void function
 */
void nemesis_printospf(OSPFhdr *ospf)
{
    char *type = "";
    char *auth_type = "Unknown";
    char *rtr_id = NULL, *area_id = NULL;

    rtr_id = strdup(inet_ntoa(*(struct in_addr *)&ospf->ospf_rtr_id.s_addr));
    area_id = strdup(inet_ntoa(*(struct in_addr *)&ospf->ospf_area_id.s_addr));

    switch(ospf->ospf_type)
    {
        case LIBNET_OSPF_HELLO:
            type = "Hello";
            break;
        case LIBNET_OSPF_DBD:
            type = "Database Description";
            break;
        case LIBNET_OSPF_LSR:
            type = "Link State Request";
            break;
        case LIBNET_OSPF_LSU:
            type = "Link State Update";
            break;
        case LIBNET_OSPF_LSA:
            type = "Link State Acknowledgement";
            break;
    }

    switch(ntohs(ospf->ospf_auth_type))
    {
        case LIBNET_OSPF_AUTH_NULL:
            auth_type = "None";
            break;
        case LIBNET_OSPF_AUTH_SIMPLE:
            auth_type = "Simple password";
            break;
        case LIBNET_OSPF_AUTH_MD5:
            auth_type = "MD5";
            break;
    }

    printf("         [OSPF Type] %s\n", type);
    printf("[OSPF src router ID] %s\n", rtr_id);
    printf("      [OSPF area ID] %s\n", area_id);
    printf("    [OSPF auth type] %s\n", auth_type);

    putchar('\n');

    if (type != NULL)
        free(type);
    if (rtr_id != NULL)
        free(rtr_id);
    if (area_id != NULL)
        free(area_id);
    if (auth_type != NULL)
        free(auth_type);

    return;
}


/**
 * Build the title string for each nemesis protocol builder.
 *
 * @param title the buffer containing the concatenated title
 * @param module the name of the protocol builder module
 * @param version release version
 *
 * @return void function
 */
void nemesis_maketitle(char *title, const char *module, const char *version)
{
    char tmptitle[TITLEBUFFSIZE], buildnum[13];


    strlcpy(tmptitle, module, sizeof(tmptitle));
    /* strlcat(char *dst, const char *src, size_t size) automatically uses 
     * size - strlen(dst) - 1 for size argument
     */
    strlcat(tmptitle, version, sizeof(tmptitle));
    snprintf(buildnum, sizeof(buildnum), " (Build %d)", BUILD);
    strlcat(tmptitle, buildnum, sizeof(tmptitle));

    memcpy(title, tmptitle, sizeof(tmptitle));
}


/**
 * Print the title string for each nemesis protocol builder.
 *
 * @param title the buffer containing the concatenated title
 *
 * @return void function
 */
void nemesis_printtitle(const char *title)
{
    putchar('\n');
    puts(title);
    putchar('\n');

    return;
}


/**
 * Print an error when an Ethernet device can't be opened for link-layer 
 * injection.
 *
 * @param errmsg the buffer containing the error message
 *
 * @return void function
 */
void nemesis_device_failure(int mode, const char *device)
{
    if (mode == INJECTION_RAW)
        fprintf(stderr, "ERROR: Unable to open raw socket for packet "
                "injection: %s.\n", errbuf);
    else if (mode == INJECTION_LINK && device != NULL && errbuf != NULL)
        fprintf(stderr, "ERROR: Unable to open layer 2 device '%s' for packet "
                "injection: %s.\n", device, errbuf);

#if !defined(WIN32)
    fprintf(stderr, "You may need root privileges to use nemesis.\n");
#else
    fprintf(stderr, "You may need Administrator privileges to use nemesis.\n");
#endif

    return;
}
