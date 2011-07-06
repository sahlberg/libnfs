noinst_PROGRAMS = nfsclient-async nfsclient-raw nfsclient-sync nfsclient-bcast nfsclient-listservers

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/nfs \
	-I$(abs_top_srcdir)/rquota \
	-I$(abs_top_srcdir)/portmap \
	"-D_U_=__attribute__((unused))"

AM_LDFLAGS = $(abs_top_srcdir)/lib/.libs/libnfs.la

nfsclient_async_SOURCES = nfsclient-async.c

nfsclient_raw_SOURCES = nfsclient-raw.c

nfsclient_sync_SOURCES = nfsclient-sync.c

nfsclient_bcast_SOURCES = nfsclient-bcast.c

nfsclient_listservers_SOURCES = nfsclient-listservers.c

