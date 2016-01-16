noinst_PROGRAMS = nfsclient-async nfsclient-raw nfsclient-sync nfsclient-bcast nfsclient-listservers nfs-io portmap-client

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/include/win32 \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/nfs \
	-I$(abs_top_srcdir)/portmap \
	-I$(abs_top_srcdir)/rquota \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../lib/libnfs.la -lpopt
nfsclient_async_LDADD = $(COMMON_LIBS)
nfsclient_raw_LDADD = $(COMMON_LIBS)
nfsclient_sync_LDADD = $(COMMON_LIBS)
nfsclient_bcast_LDADD = $(COMMON_LIBS)
nfsclient_listservers_LDADD = $(COMMON_LIBS)
nfs_io_LDADD = $(COMMON_LIBS)
portmap_client_LDADD = $(COMMON_LIBS)
