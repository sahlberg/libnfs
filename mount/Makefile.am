noinst_LTLIBRARIES = libmount.la

mount_SOURCES_GENERATED =
mount_HEADERS_GENERATED =
mount_GENERATED = $(mount_SOURCES_GENERATED) $(mount_HEADERS_GENERATED)

CLEANFILES = $(mount_GENERATED) mount-stamp

libmount_la_CPPFLAGS = -I$(abs_top_srcdir)/include
libmount_la_SOURCES = \
	$(mount_SOURCES_GENERATED) \
	mount.c libnfs-raw-mount.c

$(mount_GENERATED) : mount-stamp
mount-stamp : mount.x
	rm -f $(mount_GENERATED)
	touch mount-stamp

compile_rpc:	
	rpcgen -h @RPCGENFLAGS@ mount.x | sed -e "s/#include <rpc\/rpc.h>//" | sed -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" > libnfs-raw-mount.h
	rpcgen -c @RPCGENFLAGS@ mount.x | sed -e "s/#include \".*mount.h\"/#include \"libnfs-xdr.h\"\n#include \"libnfs-raw-mount.h\"/" -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" > libnfs-raw-mount.c