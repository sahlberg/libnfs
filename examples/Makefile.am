noinst_PROGRAMS = nfsclient-async nfsclient-raw nfsclient-sync nfsclient-bcast nfsclient-listservers nfs-fh nfs-io nfs-ln nfs4-cat portmap-client portmap-server

if HAVE_TALLOC_TEVENT
noinst_PROGRAMS += nfs4-cat-talloc
endif

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/include/win32 \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/nfs \
	-I$(abs_top_srcdir)/nfs4 \
	-I$(abs_top_srcdir)/portmap \
	-I$(abs_top_srcdir)/rquota \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../lib/libnfs.la -lpopt
nfsclient_async_LDADD = $(COMMON_LIBS)
nfsclient_raw_LDADD = $(COMMON_LIBS)
nfsclient_sync_LDADD = $(COMMON_LIBS)
nfsclient_bcast_LDADD = $(COMMON_LIBS)
nfsclient_listservers_LDADD = $(COMMON_LIBS)
nfs_fh_LDADD = $(COMMON_LIBS)
nfs_io_LDADD = $(COMMON_LIBS)
nfs_ln_LDADD = $(COMMON_LIBS)
nfs4_cat_LDADD = $(COMMON_LIBS) -levent
nfs4_cat_talloc_LDADD = $(COMMON_LIBS) -ltevent -ltalloc
portmap_client_LDADD = $(COMMON_LIBS)
portmap_server_LDADD = $(COMMON_LIBS) -levent
