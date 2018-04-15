N E M E S I S  -  TCP/IP Packet Injection
=========================================

The Nemesis Project is designed to be a command line based, portable
human IP stack for UNIX-like and Windows systems.  The suite is broken
down by protocol, and should allow for useful scripting of injected
packets from simple shell scripts.


Key Features
------------

* ARP/RARP, DNS, ETHERNET, ICMP, IGMP, IP, OSPF, RIP, TCP and UDP
  protocol support
* Layer 2 or Layer 3 injection on UNIX-like systems
* Layer 2 injection (only) on Windows systems
* Packet payload from file
* IP and TCP options from file
* Tested on OpenBSD, Linux, Solaris, Mac OS X and Windows 2000

Each supported protocol uses its own protocol "injector" which is
accompanied by a man page explaining its functionality.

Consult the ChangeLog for release details, and the documentation for
each protocol injector for in-depth descriptions of the available
functionality.


Examples
--------

* Inject malformed ICMP redirect

        sudo nemesis icmp -S 10.10.10.3 -D 10.10.10.1 -G 10.10.10.3 -i 5

* IGMP v2 join for group 239.186.39.5

        sudo nemesis igmp -v -p 22 -S 192.168.1.20 -i 239.186.39.5 -D 239.186.39.5

* IGMP v2 query, max resp. time 10 sec, with Router Alert IP option

        echo -ne '\x94\x04\x00\x00' >RA
        sudo nemesis igmp -v -p 0x11 -c 100 -D 224.0.0.1 -O RA

  or

        echo -ne '\x94\x04\x00\x00' | sudo nemesis igmp -v -p 0x11 -c 100 -D 224.0.0.1 -O -

* IGMP v3 query, with Router Alert IP option

        echo -ne '\x03\x64\x00\x00' > v3
        sudo ./src/nemesis igmp -p 0x11 -c 100 -i 0.0.0.0 -P v3 -D 224.0.0.1 -O RA

* Random TCP packet

        sudo nemesis tcp

* DoS and DDoS testing

        sudo nemesis tcp -v -S 192.168.1.1 -D 192.168.2.2 -fSA -y 22 -P foo
        sudo nemesis udp -v -S 10.11.12.13 -D 10.1.1.2 -x 11111 -y 53 -P bindpkt
        sudo nemesis icmp redirect -S 10.10.10.3 -D 10.10.10.1 -G 10.10.10.3 -qR
        sudo nemesis arp -v -d ne0 -H 0:1:2:3:4:5 -S 10.11.30.5 -D 10.10.15.1


Origin & References
--------------------

Nemesis was created by Mark Grimes in 1999, in 2001 Jeff Nathan took
over maintainership.  In 2018, after more than a decade of inactivity,
Joachim Nilsson stepped in, converted from CVS to GIT and merged the
stale libnet-1.1 upgrade branch from 2005.

Thanks to everyone that has reported bugs and especially those that have
provided patches.
