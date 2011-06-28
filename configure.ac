AC_PREREQ(2.50)
AC_INIT([libnfs], [0.0.0])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign])
AC_CANONICAL_HOST

case $host in
  *darwin*)
    RPCGENFLAGS=-DU_INT64_PLATTFORM_TYPE="u_int64_t"
    ;;
  *)
    ;;
esac

AC_SUBST(RPCGENFLAGS)

# Work around stupid autoconf default cflags. pt 1
SAVE_CFLAGS="x${CFLAGS}"

AC_PROG_CC
AC_PROG_LIBTOOL

AM_PROG_CC_C_O

# Work around stupid autoconf default cflags. pt 2
if test "$SAVE_CFLAGS" = "x"; then
  CFLAGS=""
fi

AC_CHECK_PROG([HAVE_RPCGEN], [rpcgen], [yes], [no])
if test x$HAVE_RPCGEN != xyes; then
  AC_MSG_ERROR([Can not find required program])
fi

# option: logdir
AC_ARG_WITH([logdir],
	    [AC_HELP_STRING([--with-logdir=DIR],
                            [path to log directory [[LOCALSTATEDIR/log]]])],
            [LOGDIR=$withval],
            [LOGDIR='${localstatedir}/log'])

#if test ! -d "$LOGDIR"; then
#  AC_MSG_ERROR([--with-logdir must specify a path])
#fi
AC_SUBST(LOGDIR)

#option: examples
AC_ARG_ENABLE([examples],
              [AC_HELP_STRING([--enable-examples],
                              [Build example programs])],
	      [ENABLE_EXAMPLES=$enableval],
	      [ENABLE_EXAMPLES="no"])

if test x$ENABLE_EXAMPLES = xyes; then
  MAYBE_EXAMPLES="examples"
fi
AC_SUBST(MAYBE_EXAMPLES)

#output
AC_CONFIG_FILES([Makefile]
                [include/Makefile]
                [lib/Makefile]
                [mount/Makefile]
                [nfs/Makefile]
                [portmap/Makefile]
                [rquota/Makefile]
                [examples/Makefile]
               )

AC_OUTPUT
