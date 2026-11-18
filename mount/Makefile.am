noinst_LTLIBRARIES = libmount.la

mount_SOURCES_GENERATED =
mount_HEADERS_GENERATED =
mount_GENERATED = $(mount_SOURCES_GENERATED) $(mount_HEADERS_GENERATED)

CLEANFILES = $(mount_GENERATED) mount-stamp

libmount_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		       -I$(abs_top_srcdir)/include/nfsc \
		       -I$(abs_top_srcdir)/win32
libmount_la_SOURCES = \
	$(mount_SOURCES_GENERATED) \
	mount.c libnfs-raw-mount.c libnfs-raw-mount.h

$(mount_GENERATED) : mount-stamp
mount-stamp : mount.x
	rm -f $(mount_GENERATED)
	touch mount-stamp

compile_rpc:
	cd $(srcdir) && python3 ../tools/zdrgen.py mount.x libnfs-raw-mount.h libnfs-raw-mount.c
