noinst_LTLIBRARIES = libnfs.la

nfs_SOURCES_GENERATED =
nfs_HEADERS_GENERATED =
nfs_GENERATED = $(nfs_SOURCES_GENERATED) $(nfs_HEADERS_GENERATED)

CLEANFILES = $(nfs_GENERATED) nfs-stamp

libnfs_la_CPPFLAGS = -I$(abs_top_srcdir)/include
libnfs_la_SOURCES = \
	$(nfs_SOURCES_GENERATED) \
	nfs.c nfsacl.c libnfs-raw-nfs.c

$(nfs_GENERATED) : nfs-stamp
nfs-stamp : nfs.x
	rm -f $(nfs_GENERATED)
	touch nfs-stamp

compile_rpc:	
	rpcgen -h @RPCGENFLAGS@ nfs.x | sed -e "s/#include <rpc\/rpc.h>//" | sed -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" > libnfs-raw-nfs.h
	rpcgen -c @RPCGENFLAGS@ nfs.x | sed -e "s/#include \".*nfs.h\"/#include \"libnfs-xdr.h\"\n#include \"libnfs-raw-nfs.h\"/" -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" > libnfs-raw-nfs.c
