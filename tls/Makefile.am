noinst_LTLIBRARIES = libtls.la

tls_SOURCES_GENERATED =
tls_HEADERS_GENERATED =
tls_GENERATED = $(tls_SOURCES_GENERATED) $(tls_HEADERS_GENERATED)

CLEANFILES = $(nfs_GENERATED) tls-stamp

libtls_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		      -I$(abs_top_srcdir)/include/nfsc \
		      -I$(abs_top_srcdir)/win32

libtls_la_SOURCES = \
	$(tls_SOURCES_GENERATED) \
	handshake.c  ktls.c tls-private.h

$(tls_GENERATED) : tls-stamp
tls-stamp : tls.x
	rm -f $(nfs_GENERATED)
	touch tls-stamp
