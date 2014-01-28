noinst_LTLIBRARIES = libportmap.la

portmap_SOURCES_GENERATED =
portmap_HEADERS_GENERATED =
portmap_GENERATED = $(portmap_SOURCES_GENERATED) $(portmap_HEADERS_GENERATED)

CLEANFILES = $(portmap_GENERATED) portmap-stamp

libportmap_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
			 -I$(abs_top_srcdir)/include/nfsc
libportmap_la_SOURCES = \
	$(portmap_SOURCES_GENERATED) \
	portmap.c libnfs-raw-portmap.c libnfs-raw-portmap.h

$(portmap_GENERATED) : portmap-stamp
portmap-stamp : portmap.x
	rm -f $(portmap_GENERATED)
	touch portmap-stamp

compile_rpc:	
	rpcgen -h portmap.x | sed -e "s/#include <rpc\/rpc.h>//" | sed -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" > libnfs-raw-portmap.h
	rpcgen -c portmap.x | sed -e "s/#include \".*portmap.h\"/#include \"libnfs-zdr.h\"\n#include \"libnfs-raw-portmap.h\"/" -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" -e "s/register int32_t \*buf;/register int32_t *buf;\n	buf = NULL;/" > libnfs-raw-portmap.c
