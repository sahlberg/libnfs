noinst_PROGRAMS = nfsclient-async nfsclient-raw nfsclient-sync nfsclient-bcast nfsclient-listservers nfs-ls nfs-cp

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/nfsc \
	-I../mount \
	-I../nfs \
	-I../rquota \
	-I../portmap \
	"-D_U_=__attribute__((unused))"

AM_LDFLAGS = ../lib/.libs/libnfs.la -lpopt

nfs_ls_SOURCES = nfs-ls.c

nfs_cp_SOURCES = nfs-cp.c

nfsclient_async_SOURCES = nfsclient-async.c

nfsclient_raw_SOURCES = nfsclient-raw.c

nfsclient_sync_SOURCES = nfsclient-sync.c

nfsclient_bcast_SOURCES = nfsclient-bcast.c

nfsclient_listservers_SOURCES = nfsclient-listservers.c

