AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/nfsc \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../lib/libnfs.la -lpopt

if HAVE_TLS
COMMON_LIBS += -lgnutls
endif

SUBDIRS = rpcbind
