noinst_LTLIBRARIES = libnfs.la

nfs_SOURCES_GENERATED =
nfs_HEADERS_GENERATED =
nfs_GENERATED = $(nfs_SOURCES_GENERATED) $(nfs_HEADERS_GENERATED)

CLEANFILES = $(nfs_GENERATED) nfs-stamp

libnfs_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		     -I$(abs_top_srcdir)/include/nfsc
libnfs_la_SOURCES = \
	$(nfs_SOURCES_GENERATED) \
	nfs.c nfsacl.c libnfs-raw-nfs.c libnfs-raw-nfs.h

$(nfs_GENERATED) : nfs-stamp
nfs-stamp : nfs.x
	rm -f $(nfs_GENERATED)
	touch nfs-stamp

compile_rpc:	
	rpcgen -h nfs.x | sed -e "s/#include <rpc\/rpc.h>//" -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" -e "s/#define _NFS_H_RPCGEN/#define _NFS_H_RPCGEN\n#include <nfsc\/libnfs-zdr.h>/g" -e "s/#define NFS3_COOKIEVERFSIZE 8/#define NFS3_COOKIEVERFSIZE 8\n\n#if defined(ANDROID)\ntypedef long long int quad_t;\ntypedef long long unsigned u_quad_t;\n#endif\n#if defined(WIN32)\ntypedef long long int quad_t;\ntypedef long long unsigned u_quad_t;\n#endif/g" > libnfs-raw-nfs.h
	rpcgen -c nfs.x | sed -e "s/#include \".*nfs.h\"/#include \"libnfs-xdr.h\"\n#include \"libnfs-raw-nfs.h\"/" -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" -e "s/register int32_t \*buf;/register int32_t *buf;\n	buf = NULL;/" > libnfs-raw-nfs.c
