Change Log
==========

All notable changes to the project are documented in this file.

- Versions prior to v1.4, by Jeff Nathan <email:jeff at snort dot org>
- Versions prior to 1.31, by Mark Grimes <email:mark at stateful dot net>


[v1.4][] - 2004-10-07
---------------------

New and improved nemesis: nemesis-ethernet and nemesis-ip.

### Changes

- License change, from 2-clause BSD to 3-clause
- Windows support (link-layer injection only)
- Useful man pages
- Single binary
- Improved cross-platform support via GNU autotools
- Easier to use
  - Nemesis will attempt to fill in as many details as possible
	in a packet, thus requiring fewer or even no command line switches
  - Each protocol builder attempts to build a proper packet by default
- Organized code base
  - The network header structures in libnet proved useful so nemesis
	now uses them where appropriate
  - Code is re-used wherever possible resulting in a much more concise
	code base
- Full payload functionality
  - Payloads can now contain NULLs within them and full-size packets
	are available on all supported platforms except Windows
- IP and TCP options support
  - All nemesis injectors (excluding ARP and Ethernet) now support IP
	options via `-O <file>`
  - All nemesis injectors using TCP as a transport protocol now
	support TCP options via `-o <file>`
- Improved IP and TCP functionality
  - Full IP fragmentation support via new `-F` command line semantics
  - ECN support in TCP with the addition of `-fE` (ECE) and `-fC` (CWR)
- Switched to GNU ChangeLog format
- Moved printout functions into `nemesis-printout.c`
- Moved file I/O functions to `nemesis-fileio.c`
- Incorporated `strlcpy()` and `strlcat()` into source tree
- Updated `configure.in` to use `AC_REPLACE_FUNCS` for locally included
  functions: `strlcpy()`, `strlcat()`, `strspn()`, `inet_aton()`
- Removed struct `OptionsData` and `PayloadData` in favor of `FileData`
- Changed `builddatafromfile()` to accept a `FileData *`
- removed `acconfig.h` and replaced with `AH_TOP` macro in `configre.in`
- updated `aclocal.m4`, missing, `mkinstalldirs`, `configure`, `configure.in`,
  `config.guess`, `Makefile.in`, `man/Makefile.in` and `src/Makefile.in` as
  part of autotools updates

### Fixes

- Man page fixes from <email:nnposter@users.sourceforge.net>
- minor man page cleanup
- nemesis-proto_ip.c:

        -    ip_meta_packetlen = ip_packetlen - (link_offet + LIBNET_IP_H);
        +    ip_meta_packetlen = ip_packetlen - (link_offset + LIBNET_IP_H);

- added `.cvsignore` to CVS
- allow TCP packets to be sent without flags using `-f-`
- allow RIP routing domain value to be 0 with RIP2
- correct mistakes in specifying payload sizes for ICMP and RIP
- added `src/memcmp.c` to satisfy automake dependency
- debug fixes to `configure.in`


[v1.32][] - 2001-06-22
----------------------

### Changes

- changes to nemesis-arp
  - Added -h and -m switches to allow for changing the sender and target
    hardware addresses within the ARP frame independant of the Ethernet
    header.
  - Added Solaris style ARP requests (`-s` option) such that the target
    hardware address is set to ff:ff:ff:ff:ff:ff rather than
    00:00:00:00:00:00 as it is in most implementations.  This is merely
    a shortcut and users wishing to set the target address manually
    should use the `-m` switch.
  - ARP requests now default to having the target hardware address set
    to 00:00:00:00:00:00 rather than duplicating what's in `enet_dst`.
- changes to nemesis-igmp
   - pull in accidental DoS protection from 1.31

### Fixes
- Fixed if (verbose) bug that prevented `libnet_get_hwaddr()` from being
  called if `verbose == 0`
- Fixed `getopt()` parsing to no longer use `if (got_link)` as optarg
  options weren't parsed properly if `-d` appeared anywhere but the
  beginning of the command line.
- relocated some sanity checks
- man page cleanup. (`-b` option doesn't exist)


[v1.31][] - 2001-06-13
----------------------

### Fixes
- Error in printf output for arp request/reply
  Pulls Source MAC off card if undefined, prevents accidental DoS ;)


[v1.3][] - 2001-06-06
---------------------

Memesis is such a bloody mess, this will be the last version of the old
libnet-nemesis -- I SWEAR! --- (bar bugfixes)

### Changes
- RARP added (thanks to Jeff Nathan <email:jeff at wwti dot com> for
  pointing out Libnet had RARP support, while I have been busy
  unlibnetizing source code... Since some people wanted this feature...)
- RAW4ALL OpenBSD patch support added (inject nemesis packets as a
  normal user!)

[v1.2][] - 2000-12-31
---------------------

### Fixes
- ICMP checksum fix patched (did not affect ICMP injection, but not
  proper)
- Makefile fixes (roll in the changes made in OpenBSD land)


[v1.1][] - 2000-06-24
---------------------

**NOTE:** nemesis is only being maintained for bugfixes now.  A next
	generation of the tool is currently being developed that will have a
	shell based interface rather than a command line.  As future
	features are implemented, it will become readily apparent why this
	is being done.

### Fixes
- Injection fixes
  - DNS (no frame on layer 2),
  - ICMP (false reporting)
- New packet payload hex dumping algorithm created from scratch...  many
  people rip tcpdump's hex dumping algorithm, which might be more
  robust, but this is 100% my OWN algorithm -- so if it totally sucks,
  please tell me and I will rip tcpdump's algorithm.  I think it works
  nice and is considerably less code than the other flavors.
- ICMP man page update - ICMP types/codes notated, so you don't have to
  refer to the source.
- Payload fixes


[v1.0][] - 2000-04-14
---------------------

### Fixes
- Injection fix - non-payload packet wasn't injecting after changes made
  between 0.9.1 and 1.0pre1 releases


v1.0pre1 - Major bug fix release
--------------------------------

MANY bugfixes.

### Fixes
- Packet stream loop tightening, Binary payload now does what it is
  supposed too ;)
- Socket fixes -- tested with large files


v0.9.1 - Bug fix release
------------------------

### Fixes
- b0rked the ethernet checksums patch, recoded and verified


v0.9 - OSPF Completed
---------------------

### Changes
- OSPF completed (5 additional packet types)

### Fixes
- autoconf adjustments to ease into obsd ports tree patches supplied by:
  <email:brad at comstyle dot com>


v0.8 - Build system overhaul
----------------------------

### Changes
- autoconf style configuration

### Fixes
- misc cosmetic fixes


v0.7 - More protocols
---------------------

### Changes
- addition of DNS protocol
- addition of IGMP protocol
- addition of RIP protocol
- finished layer 2 support for all completed protocols


[v0.666b] - Minor fixes
-------------------------------

### Fixes
- `getopt()` fixes to OSPF and ICMP
- misc cosmetic fixes


v0.666a - initial public release
--------------------------------

### Changes
- ARP, ICMP, OSPF¹ (unfinished), TCP, UDP implemented


[v1.4]:  http://sf.net/nemesis/nemesis-1.4.tar.gz
[v1.32]: http://ftp.twaren.net/BSD/OpenBSD/distfiles/nemesis-1.32.tar.gz
[v1.31]: http://ftp.twaren.net/BSD/OpenBSD/distfiles/nemesis-1.31.tar.gz
[v1.3]:  http://ftp.twaren.net/BSD/OpenBSD/distfiles/nemesis-1.3.tar.gz
[v1.2]:  http://ftp.twaren.net/BSD/OpenBSD/distfiles/nemesis-1.2.tar.gz
[v1.1]:  http://ftp.twaren.net/BSD/OpenBSD/distfiles/nemesis-1.1.tar.gz
[v1.0]:  http://ftp.twaren.net/BSD/OpenBSD/distfiles/nemesis-1.0.tar.gz
