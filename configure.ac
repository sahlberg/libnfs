AC_PREREQ(2.50)
AC_INIT([libnfs], [1.5.0], [ronniesahlberg@gmail.com])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign])
AC_CANONICAL_HOST

# Work around stupid autoconf default cflags. pt 1
SAVE_CFLAGS="x${CFLAGS}"

AC_PROG_CC
AC_PROG_LIBTOOL

AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG

# Work around stupid autoconf default cflags. pt 2
if test "$SAVE_CFLAGS" = "x"; then
  CFLAGS=""
fi

# We always want 64 bit file offsets
CFLAGS="${CFLAGS} -D_FILE_OFFSET_BITS=64"

AC_CHECK_PROG([HAVE_RPCGEN], [rpcgen], [yes], [no])
if test x$HAVE_RPCGEN != xyes; then
  AC_MSG_ERROR([Can not find required program])
fi

#option: examples
AC_ARG_ENABLE([examples],
              [AC_HELP_STRING([--enable-examples],
                              [Build example programs])],
	      [ENABLE_EXAMPLES=$enableval],
	      [ENABLE_EXAMPLES="no"])

# We need popt to compile the examples
if test x$ENABLE_EXAMPLES = xyes; then
AC_MSG_CHECKING(whether libpopt is available)
ac_save_CFLAGS="$CFLAGS"
ac_save_LIBS="$LIBS"
CFLAGS="$CFLAGS $GLIB_CFLAGS"
LIBS="$GLIB_LIBS $LIBS -lpopt"
AC_TRY_RUN([
/*
 * Just see if we can compile/link with popt
 */
#include <popt.h>

int main(int argc, const char *argv[])
{
	struct poptOption popt_options[] = {
		POPT_TABLEEND
	};
	poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	return 0;
}
], ac_cv_have_popt=yes, ac_cv_have_popt=no,
   [echo $ac_n "compile with POPT. Assuming OK... $ac_c"
    ac_cv_have_popt=yes])
CFLAGS="$ac_save_CFLAGS"
LIBS="$ac_save_LIBS"
if test "$ac_cv_have_popt" = yes ; then
  AC_MSG_RESULT(yes)
  MAYBE_EXAMPLES="examples"
else
  AC_MSG_RESULT(no)
  AC_MSG_NOTICE(You need libpopt to compile the sample libnfs clients.)
  AC_MSG_NOTICE(Only the library will be compiled and installed.)
fi
fi

AC_SUBST(MAYBE_EXAMPLES)


AC_ARG_ENABLE(tirpc,
  	[AC_HELP_STRING([--enable-tirpc],
  			[enable use of TI-RPC @<:@default=no@:>@])],
  	enable_tirpc=$enableval,
	enable_tirpc='no')

case $host in
  *darwin*)
    RPCGENFLAGS=-DU_INT64_PLATTFORM_TYPE="u_int64_t"
    ;;
  *cygwin*)
    RPCGENFLAGS=-DU_INT64_PLATTFORM_TYPE="u_int64_t"
    ;;
  *solaris*)
    AC_CHECK_HEADERS([sys/filio.h])
    AC_CHECK_HEADERS([sys/sockio.h])
    if test x$ENABLE_EXAMPLES = xyes; then
      AC_CHECK_LIB([socket], [main], , [AC_MSG_ERROR([Can not find required library])])
      AC_CHECK_LIB([nsl],    [main], , [AC_MSG_ERROR([Can not find required library])])
    fi
    ;;
  *)
    ;;
esac

AC_SUBST(RPCGENFLAGS)

# check for SA_LEN
dnl Check if sockaddr data structure includes a "sa_len"
AC_CHECK_MEMBER([struct sockaddr.sa_len],
                [ AC_DEFINE(HAVE_SOCKADDR_LEN,1,[Whether sockaddr struct has sa_len]) ],
                [],
                [
#include <sys/types.h>
#include <sys/socket.h>
])

LIBNFS_PC_REQ_PRIVATE=

if test "$enable_tirpc" = "yes"; then
	PKG_CHECK_MODULES(TIRPC, libtirpc, [],
		AC_MSG_ERROR([unable to locate libtirpc files]))
	CFLAGS="${CFLAGS} ${TIRPC_CFLAGS}"
	LIBS="${LIBS} ${TIRPC_LIBS}"
	LIBNFS_PC_REQ_PRIVATE="${LIBNFS_PC_REQ_PRIVATE} libtirpc"
fi

AC_SUBST(LIBNFS_PC_REQ_PRIVATE)

#output
AC_CONFIG_FILES([Makefile]
                [include/Makefile]
                [lib/Makefile]
                [mount/Makefile]
                [nfs/Makefile]
                [nlm/Makefile]
                [portmap/Makefile]
                [rquota/Makefile]
                [examples/Makefile]
               )

AC_OUTPUT([libnfs.pc])
