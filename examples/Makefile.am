noinst_PROGRAMS = nfsclient-async nfsclient-raw nfsclient-sync nfsclient-bcast nfsclient-listservers nfs-io portmap-client

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/nfs \
	-I$(abs_top_srcdir)/portmap \
	-I$(abs_top_srcdir)/rquota \
	"-D_U_=__attribute__((unused))"

AM_LDFLAGS = ../lib/.libs/libnfs.la -lpopt
