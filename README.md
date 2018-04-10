N E M E S I S  -  TCP/IP Packet Injection
=========================================

The Nemesis Project is designed to be a command line based, portable
human IP stack for UNIX-like and Windows systems.  The suite is broken
down by protocol, and should allow for useful scripting of injected
packets from simple shell scripts.

Key Features
------------

* ARP/RARP, DNS, ETHERNET, ICMP, IGMP, IP, OSPF*, RIP, TCP and UDP
  protocol support
* Layer 2 or Layer 3 injection on UNIX-like systems
* Layer 2 injection (only) on Windows systems
* Packet payload from file
* IP and TCP options from file
* Tested on OpenBSD, Linux, Solaris, Mac OS X and Windows 2000

*OSPF is currently non-functional.

Each supported protocol uses its own protocol "injector" which is
accompanied by a man page explaining its functionality.

Consult the ChangeLog for release details, and the documentation for
each protocol injector for in-depth descriptions of the available
functionality.


Origin & References
--------------------

Nemesis was created by Mark Grimes in 1999, in 2001 Jeff Nathan took
over maintainership.  In 2018, after more than a decade of inactivity,
Joachim Nilsson stepped in, converted from CVS to GIT and merged the
old libnet-1.1 branch from 2005.

Thanks to everyone that has reported bugs and especially those that have
provided patches.
