noinst_PROGRAMS = nfsclient-async nfsclient-raw nfsclient-sync nfsclient-bcast nfsclient-listservers

nfsclient_async_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/mount \
	"-D_U_=__attribute__((unused))"
nfsclient_async_SOURCES = nfsclient-async.c
nfsclient_async_LDADD = $(abs_top_srcdir)/lib/.libs/libnfs.la

nfsclient_raw_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/nfs \
	-I$(abs_top_srcdir)/rquota \
	"-D_U_=__attribute__((unused))"
nfsclient_raw_SOURCES = nfsclient-raw.c
nfsclient_raw_LDADD = $(abs_top_srcdir)/lib/.libs/libnfs.la

nfsclient_sync_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/mount \
	"-D_U_=__attribute__((unused))"
nfsclient_sync_SOURCES = nfsclient-sync.c
nfsclient_sync_LDADD = $(abs_top_srcdir)/lib/.libs/libnfs.la

nfsclient_bcast_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/portmap \
	"-D_U_=__attribute__((unused))"
nfsclient_bcast_SOURCES = nfsclient-bcast.c
nfsclient_bcast_LDADD = $(abs_top_srcdir)/lib/.libs/libnfs.la

nfsclient_listservers_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/mount \
	"-D_U_=__attribute__((unused))"
nfsclient_listservers_SOURCES = nfsclient-listservers.c
nfsclient_listservers_LDADD = $(abs_top_srcdir)/lib/.libs/libnfs.la

