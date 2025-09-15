noinst_PROGRAMS = nfsd

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/nfs \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../../lib/libnfs.la -lpopt

if HAVE_TLS
COMMON_LIBS += -lgnutls
endif

nfsd_LDADD = ../libnfs-server.o $(COMMON_LIBS) -ltalloc -ltevent
