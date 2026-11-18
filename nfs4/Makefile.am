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
	cd $(srcdir) && python3 ../tools/zdrgen.py --header-extra libnfs-raw-nfs4.h.extra --source-extra libnfs-raw-nfs4.c.fragment --skip READ4resok --skip WRITE4args nfs4.x libnfs-raw-nfs4.h libnfs-raw-nfs4.c
