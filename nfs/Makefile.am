noinst_LTLIBRARIES = libnfs.la

nfs_SOURCES_GENERATED =
nfs_HEADERS_GENERATED =
nfs_GENERATED = $(nfs_SOURCES_GENERATED) $(nfs_HEADERS_GENERATED)

CLEANFILES = $(nfs_GENERATED) nfs-stamp

libnfs_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		     -I$(abs_top_srcdir)/include/nfsc \
		     -I$(abs_top_srcdir)/win32
libnfs_la_SOURCES = \
	$(nfs_SOURCES_GENERATED) \
	nfs.c nfsacl.c libnfs-raw-nfs.c libnfs-raw-nfs.h

$(nfs_GENERATED) : nfs-stamp
nfs-stamp : nfs.x
	rm -f $(nfs_GENERATED)
	touch nfs-stamp

compile_rpc:
	cd $(srcdir) && python3 ../tools/zdrgen.py --header-extra libnfs-raw-nfs.h.extra nfs.x libnfs-raw-nfs.h libnfs-raw-nfs.c
