noinst_LTLIBRARIES = libportmap.la

portmap_SOURCES_GENERATED =
portmap_HEADERS_GENERATED =
portmap_GENERATED = $(portmap_SOURCES_GENERATED) $(portmap_HEADERS_GENERATED)

CLEANFILES = $(portmap_GENERATED) portmap-stamp

libportmap_la_CPPFLAGS = -I$(abs_top_srcdir)/include
libportmap_la_SOURCES = \
	$(portmap_SOURCES_GENERATED) \
	portmap.c libnfs-raw-portmap.c

$(portmap_GENERATED) : portmap-stamp
portmap-stamp : portmap.x
	rm -f $(portmap_GENERATED)
	touch portmap-stamp

compile_rpc:	
	rpcgen -h @RPCGENFLAGS@ portmap.x | sed -e "s/#include <rpc\/rpc.h>//" | sed -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" > libnfs-raw-portmap.h
	rpcgen -c @RPCGENFLAGS@ portmap.x | sed -e "s/#include \".*portmap.h\"/#include \"libnfs-zdr.h\"\n#include \"libnfs-raw-portmap.h\"/" -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" > libnfs-raw-portmap.c
