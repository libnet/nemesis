# Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
#
# Suggested reading:  "GNU Autoconf, Automake and Libtool" New Riders Press

AC_PREREQ(2.61)
AC_INIT(nemesis, 1.7, https://github.com/libnet/nemesis/issues,,
	http://troglobit.com/projects/nemesis/)
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([src/nemesis.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_LIBOBJ_DIR([lib])
AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])

# Determine host type before performing further tests.
AC_CANONICAL_HOST

# Program tests
AM_PROG_CC_STDC
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

case "$host" in
  *-linux*)
    ;;
  *-freebsd*)
    ;;
  *-openbsd*)
    ;;
  *-netbsd*)
    ;;
  *-solaris*)
    ;;

  *-apple*)
    LDFLAGS="${LDFLAGS}   -L/sw/lib"
    CPPFLAGS="${CPPFLAGS} -I/sw/include"
    ;;

  *)
    AC_MSG_WARN(Your OS is not officially supported yet)
    AC_MSG_WARN(Nemesis may not work properly)
    ;;
esac

# Library tests
AC_CHECK_LIB(m, fabs)
AC_CHECK_LIB(nsl, inet_ntoa)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(resolv, hstrerror)

AC_CHECK_LIB([net], [libnet_name_resolve],
      [AC_MSG_ERROR([libnet 1.0.x found. Nemesis >= 1.5 requires libnet 1.1.x])])
AC_CHECK_LIB([net], [libnet_init], ,[AC_MSG_ERROR([libnet 1.1.x not found])])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([unistd.h errno.h strings.h netdb.h limits.h libnet.h	 \
	machine/endian.h sys/time.h sys/param.h arpa/inet.h netinet/in.h \
	netinet/if_ether.h net/ethernet.h])

# Checks for library functions.
AC_CHECK_FUNCS([gethostbyname gettimeofday inet_ntoa isascii memset	\
	strchr strdup strerror strrchr strtoul])

# Check for usually missing API's, which we can replace
AC_REPLACE_FUNCS(getopt inet_aton memcmp strlcat strlcpy strsep)

AC_OUTPUT
