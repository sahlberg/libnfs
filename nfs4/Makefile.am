noinst_LTLIBRARIES = libnfs4.la

nfs4_SOURCES_GENERATED =
nfs4_HEADERS_GENERATED =
nfs4_GENERATED = $(nfs4_SOURCES_GENERATED) $(nfs4_HEADERS_GENERATED)

CLEANFILES = $(nfs_GENERATED) nfs4-stamp

libnfs4_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		      -I$(abs_top_srcdir)/include/nfsc \
		      -I$(abs_top_srcdir)/win32
libnfs4_la_SOURCES = \
	$(nfs4_SOURCES_GENERATED) \
	nfs4.c libnfs-raw-nfs4.c libnfs-raw-nfs4.h

$(nfs4_GENERATED) : nfs4-stamp
nfs4-stamp : nfs4.x
	rm -f $(nfs_GENERATED)
	touch nfs4-stamp

compile_rpc:	
	cat nfs4.x | head -29 >libnfs-raw-nfs4.h
	rpcgen -h nfs4.x | sed \
-e "s/#include <rpc\/rpc.h>/#include <nfsc\/libnfs-zdr.h>/" \
-e "s/xdr/zdr/g" \
-e "s/XDR/ZDR/g" \
-e "s/#define _NFS_H_RPCGEN/#define _NFS_H_RPCGEN\n#include <nfsc\/libnfs-zdr.h>/g" \
-e "s/#define NFS3_COOKIEVERFSIZE 8/#define NFS3_COOKIEVERFSIZE 8\n\n/g" \
-e "s/ CLIENT / void /g" \
-e "s/SVCXPRT /void /g" \
-e "s/bool_t/uint32_t/g" >> libnfs-raw-nfs4.h
	cat nfs4.x | head -29 >libnfs-raw-nfs4.c
	rpcgen -c nfs4.x | sed \
-e "s/#include \".*nfs4.h\"/#include \"libnfs-xdr.h\"\n#include \"libnfs-raw-nfs4.h\"/" \
-e "s/xdr/zdr/g" \
-e "s/XDR/ZDR/g" \
-e "s/bool_t/uint32_t/g" \
-e "s/register int32_t \*buf;//" \
-e "s/int i;//" >> libnfs-raw-nfs4.c
