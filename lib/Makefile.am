lib_LTLIBRARIES = libnfs.la

libnfs_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		     -I$(abs_top_srcdir)/mount \
		     -I$(abs_top_srcdir)/nfs \
		     -I$(abs_top_srcdir)/portmap \
		     -I$(abs_top_srcdir)/rquota \
		     "-D_U_=__attribute__((unused))"

libnfs_la_SOURCES = \
	init.c \
	libnfs.c \
	libnfs-sync.c \
	pdu.c \
	socket.c

libnfs_la_LIBADD = \
	$(abs_top_srcdir)/mount/libmount.la \
	$(abs_top_srcdir)/nfs/libnfs.la \
	$(abs_top_srcdir)/portmap/libportmap.la \
	$(abs_top_srcdir)/rquota/librquota.la 

