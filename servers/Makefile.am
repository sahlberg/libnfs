noinst_PROGRAMS = rpcbind

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/include/win32 \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/nfs \
	-I$(abs_top_srcdir)/nfs4 \
	-I$(abs_top_srcdir)/portmap \
	-I$(abs_top_srcdir)/rquota \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../lib/libnfs.la -lpopt

if HAVE_TLS
COMMON_LIBS += -lgnutls
endif

rpcbind_LDADD = libnfs-server.o rpcbind_data.o $(COMMON_LIBS) -levent

compile_rpc:	
	cat rpcbind_data.x | head -1 >rpcbind_data.h
	rpcgen -h rpcbind_data.x | sed -e "s/#include <rpc\/rpc.h>/#include <nfsc\/libnfs-zdr.h>/" | sed -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" -e "s/ CLIENT / void /g" -e "s/SVCXPRT /void /g" -e "s/bool_t/uint32_t/g" -e "s/u_int/uint32_t/" >> rpcbind_data.h
	cat rpcbind_data.x | head -1 >rpcbind_data.c
	rpcgen -c rpcbind_data.x | sed -e "s/#include \".*portmap.h\"/#include \"libnfs-zdr.h\"\n#include \"libnfs-raw-portmap.h\"/" -e "s/xdr/zdr/g" -e "s/XDR/ZDR/g" -e "s/register int32_t \*buf;//" -e "s/bool_t/uint32_t/g" -e "s/[ \t]*buf = /		int32_t *buf;\n		buf = /" -e "s/\(u_int \*\)/uint32_t \*/" >> rpcbind_data.c
