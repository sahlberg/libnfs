noinst_PROGRAMS = nfsd
nfsd_SOURCES = nfsd.c mountd.c mountd.h

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/nfs \
	-I$(abs_top_srcdir)/nlm \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../../lib/libnfs.la -lpopt

if HAVE_TLS
COMMON_LIBS += $(TLS_LIBS)
endif

nfsd_LDADD = ../libnfs-server.la $(COMMON_LIBS) -ltalloc -ltevent
