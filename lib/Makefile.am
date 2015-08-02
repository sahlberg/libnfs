AM_CFLAGS=$(WARN_CFLAGS)

lib_LTLIBRARIES = libnfs.la

libnfs_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		     -I$(abs_top_srcdir)/include/nfsc \
		     -I$(abs_top_srcdir)/mount \
		     -I$(abs_top_srcdir)/nfs \
		     -I$(abs_top_srcdir)/nlm \
		     -I$(abs_top_srcdir)/nsm \
		     -I$(abs_top_srcdir)/portmap \
		     -I$(abs_top_srcdir)/rquota \
		     "-D_U_=__attribute__((unused))"

libnfs_la_SOURCES = \
	init.c \
	libnfs.c \
	libnfs-sync.c \
	libnfs-zdr.c \
	pdu.c \
	socket.c

SOCURRENT=9
SOREVISION=0
SOAGE=1
libnfs_la_LDFLAGS = -version-info $(SOCURRENT):$(SOREVISION):$(SOAGE)
libnfs_la_LIBADD = \
	../mount/libmount.la \
	../nfs/libnfs.la \
	../nlm/libnlm.la \
	../nsm/libnsm.la \
	../portmap/libportmap.la \
	../rquota/librquota.la 

