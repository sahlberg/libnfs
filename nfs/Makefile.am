noinst_LTLIBRARIES = libnfs.la

nfs_SOURCES_GENERATED = libnfs-raw-nfs.c
nfs_HEADERS_GENERATED = libnfs-raw-nfs.h
nfs_GENERATED = $(nfs_SOURCES_GENERATED) $(nfs_HEADERS_GENERATED)

CLEANFILES = $(nfs_GENERATED) nfs-stamp

libnfs_la_CPPFLAGS = -I$(abs_top_srcdir)/include
libnfs_la_SOURCES = \
	$(nfs_SOURCES_GENERATED) \
	nfs.c nfsacl.c

$(nfs_GENERATED) : nfs-stamp
nfs-stamp : nfs.x
	rm -f $(nfs_GENERATED)
	rpcgen -h @RPCGENFLAGS@ $< > libnfs-raw-nfs.h
	rpcgen -c @RPCGENFLAGS@ $< | sed -e "s/#include \".*nfs.h\"/#include \"libnfs-raw-nfs.h\"/" -e "s/^xdr_uint64/static xdr_uint64_broken/" > libnfs-raw-nfs.c
	echo "" >> libnfs-raw-nfs.c
	echo "xdr_uint64 (XDR *xdrs, uint64 *objp)" >> libnfs-raw-nfs.c
	echo "{" >> libnfs-raw-nfs.c
	echo "	uint32_t i;" >> libnfs-raw-nfs.c
	echo "" >> libnfs-raw-nfs.c
	echo "        switch (xdrs->x_op) {" >> libnfs-raw-nfs.c
	echo "        case XDR_DECODE:" >> libnfs-raw-nfs.c
	echo "		if (!xdr_u_int (xdrs, &i))" >> libnfs-raw-nfs.c
	echo "			return FALSE;" >> libnfs-raw-nfs.c
	echo "		*objp = i;" >> libnfs-raw-nfs.c
	echo "		*objp <<= 32;" >> libnfs-raw-nfs.c
	echo "" >> libnfs-raw-nfs.c
	echo "		if (!xdr_u_int (xdrs, &i))" >> libnfs-raw-nfs.c
	echo "			return FALSE;" >> libnfs-raw-nfs.c
	echo "		*objp |= i;" >> libnfs-raw-nfs.c
	echo "" >> libnfs-raw-nfs.c
	echo "		return TRUE;" >> libnfs-raw-nfs.c
	echo "	case XDR_ENCODE:" >> libnfs-raw-nfs.c
	echo "		i = ((*objp) >> 32) & 0xffffffff;" >> libnfs-raw-nfs.c
	echo "		if (!xdr_u_int (xdrs, &i))" >> libnfs-raw-nfs.c
	echo "			return FALSE;" >> libnfs-raw-nfs.c
	echo "" >> libnfs-raw-nfs.c
	echo "		i = ((*objp)      ) & 0xffffffff;" >> libnfs-raw-nfs.c
	echo "		if (!xdr_u_int (xdrs, &i))" >> libnfs-raw-nfs.c
	echo "			return FALSE;" >> libnfs-raw-nfs.c
	echo "		return TRUE;" >> libnfs-raw-nfs.c
	echo "	}" >> libnfs-raw-nfs.c
	echo "}" >> libnfs-raw-nfs.c
	touch nfs-stamp
	
