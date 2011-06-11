AC_PREREQ(2.50)
AC_INIT(libnfs, m4_esyscmd([grep 'Version:' ./packaging/RPM/libnfs.spec.in 2>/dev/null | head -1 | sed -e 's/[ \t]*Version:[ \t]*\([^ \t]*\)[ \t]*.*/\1/' | tr -d '\n']))
AC_CONFIG_SRCDIR([lib/init.c])

if test "${libdir}" = '${exec_prefix}/lib'; then
  case `uname -m` in
    x86_64|ppc64|powerpc64)
      libdir='${exec_prefix}/lib64'
      ;;
    *)
      libdir='${exec_prefix}/lib'
      ;;
  esac
fi

is_solaris="no"
is_darwin="no"
install="/usr/bin/install"
ldconfig="ldconfig"

case `uname` in
  Linux*)
    ;;
  Darwin*)
    libdir='${exec_prefix}/lib'
    ldconfig='echo no ldconfig on darwin'
    is_darwin="yes"
    ;;
  AIX*)
    ;;
  SunOS)
    is_solaris="yes"
    install="ginstall"
    ldconfig="echo no ldconfig on solaris"
    LIBS="$LIBS -lsocket -lnsl"
    ;;
  *)
    ;;
esac

if test "$ac_cv_prog_gcc" = yes; then
   CFLAGS="$CFLAGS -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings"
fi

LOGDIR='${localstatedir}/log'
AC_ARG_WITH([logdir],
	[  --with-logdir=DIR       path to log directory [[LOCALSTATEDIR/log]]],
	LOGDIR=$withval)
if test ! -z "$LOGDIR"; then
  if test "$LOGDIR" = "yes" -o "$LOGDIR" = "no"; then
    AC_MSG_ERROR([--with-logdir must specify a path])
  fi
fi
AC_SUBST(LOGDIR)

AC_ARG_WITH([examples],
              [  --without-examples  Disable build of examples],
	      [ENABLE_EXAMPLES="no"],
	      [ENABLE_EXAMPLES="yes"]
	      )
AC_SUBST(ENABLE_EXAMPLES)

AC_ARG_WITH([ldconfig],
	    [  --without-ldconfig  Disable call of ldconfig on make install],
	    [ldconfig='echo ldconfig disabled'])

if test x"$cross_compiling" = xyes; then
  ldconfig='echo crosscompiling: ldconfig disabled'
fi

AC_CONFIG_HEADER(config.h)

EXTRA_OBJ=""

#AC_CHECK_HEADERS(sched.h)
#AC_CHECK_FUNCS(mlockall)

AC_CACHE_CHECK([for sin_len in sock],libnfs_cv_HAVE_SOCK_SIN_LEN,[
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>],
[struct sockaddr_in sock; sock.sin_len = sizeof(sock);],
libnfs_cv_HAVE_SOCK_SIN_LEN=yes,libnfs_cv_HAVE_SOCK_SIN_LEN=no)])
if test x"$libnfs_cv_HAVE_SOCK_SIN_LEN" = x"yes"; then
    AC_DEFINE(HAVE_SOCK_SIN_LEN,1,[Whether the sockaddr_in struct has a sin_len property])
fi
AC_SUBST(libdir)
AC_SUBST(install)
AC_SUBST(ldconfig)
AC_SUBST(is_darwin)
#AC_SUBST(LIBNFS_LDFLAGS)

AC_OUTPUT(Makefile)
