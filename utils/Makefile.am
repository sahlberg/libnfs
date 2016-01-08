bin_PROGRAMS = nfs-cat nfs-ls

if !HAVE_WIN32
bin_PROGRAMS += nfs-cp
endif

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/win32 \
	"-D_U_=__attribute__((unused))"

AM_LDFLAGS = ../lib/.libs/libnfs.la $(LIBSOCKET)
