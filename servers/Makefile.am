AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/portmap \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../lib/libnfs.la -lpopt

if HAVE_TLS
COMMON_LIBS += $(TLS_LIBS)
endif

#
# Code shared by all the example servers. Built here as a convenience library
# so that it gets proper dependency tracking and works for out of tree builds,
# the subdirectories link it in as ../libnfs-server.la.
#
noinst_LTLIBRARIES = libnfs-server.la
libnfs_server_la_SOURCES = libnfs-server.c libnfs-server.h

# "." first so that libnfs-server.la is built before the servers using it
SUBDIRS = . nfsd rpcbind statd
