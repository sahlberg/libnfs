noinst_PROGRAMS = nfsclient-async nfsclient-raw nfsclient-sync \
	nfsclient-bcast nfsclient-listservers nfs-fh nfs-io nfs-ln nfs4-cat \
	portmap-client rpcbind nfs-writefile nfs-stats-cb \
	nfs-nfsstat nfs-cat-preadv

if HAVE_TALLOC_TEVENT
noinst_PROGRAMS += nfs4-cat-talloc
endif

if HAVE_PTHREAD
LIBS += -lpthread
noinst_PROGRAMS += nfs-pthreads-example nfs-pthreads-fstat \
	nfs-pthreads-writefile nfs-pthreads-async-writefile
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
if HAVE_TLS
COMMON_LIBS += -lgnutls
endif
nfs_writefile_LDADD = $(COMMON_LIBS)
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
nfs_cat_preadv_LDADD = $(COMMON_LIBS)
portmap_client_LDADD = $(COMMON_LIBS)
nfs_pthreads_example_LDADD = $(COMMON_LIBS)
nfs_pthreads_fstat_LDADD = $(COMMON_LIBS)
nfs_pthreads_writefile_LDADD = $(COMMON_LIBS)
nfs_pthreads_async_writefile_LDADD = $(COMMON_LIBS)
nfs_stats_cb_LDADD = $(COMMON_LIBS)
nfs_nfsstat_LDADD = $(COMMON_LIBS)
rpcbind_LDADD = libnfs-server.o $(COMMON_LIBS) -levent
