bin_PROGRAMS = nfs-cat nfs-cp nfs-ls

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/mount \
	"-D_U_=__attribute__((unused))"

AM_LDFLAGS = ../lib/.libs/libnfs.la
