bin_PROGRAMS = nfs-cat nfs-ls

if HAVE_PTHREAD
LIBS += -lpthread
endif

if !HAVE_WIN32
bin_PROGRAMS += nfs-cp nfs-stat
endif

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/win32 \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../lib/libnfs.la $(LIBSOCKET)

nfs_cat_LDADD = $(COMMON_LIBS)
nfs_ls_LDADD = $(COMMON_LIBS)
nfs_cp_LDADD = $(COMMON_LIBS)
nfs_stat_LDADD = $(COMMON_LIBS)
