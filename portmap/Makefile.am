noinst_LTLIBRARIES = libportmap.la

portmap_SOURCES_GENERATED =
portmap_HEADERS_GENERATED =
portmap_GENERATED = $(portmap_SOURCES_GENERATED) $(portmap_HEADERS_GENERATED)

CLEANFILES = $(portmap_GENERATED) portmap-stamp

libportmap_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
			 -I$(abs_top_srcdir)/include/nfsc \
			 -I$(abs_top_srcdir)/win32
libportmap_la_SOURCES = \
	$(portmap_SOURCES_GENERATED) \
	portmap.c libnfs-raw-portmap.c libnfs-raw-portmap.h

$(portmap_GENERATED) : portmap-stamp
portmap-stamp : portmap.x
	rm -f $(portmap_GENERATED)
	touch portmap-stamp

compile_rpc:
	cd $(srcdir) && python3 ../tools/zdrgen.py portmap.x libnfs-raw-portmap.h libnfs-raw-portmap.c
