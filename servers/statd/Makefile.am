noinst_PROGRAMS = rpc.statd
rpc_statd_SOURCES = rpc.statd.c

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/nsm \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../../lib/libnfs.la -lpopt

if HAVE_TLS
COMMON_LIBS += -lgnutls
endif

rpc_statd_LDADD = ../libnfs-server.o $(COMMON_LIBS) -ltalloc -ltevent
