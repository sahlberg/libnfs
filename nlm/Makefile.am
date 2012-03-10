noinst_LTLIBRARIES = libnlm.la

nlm_SOURCES_GENERATED = libnfs-raw-nlm.c
nlm_HEADERS_GENERATED = libnfs-raw-nlm.h
nlm_GENERATED = $(nlm_SOURCES_GENERATED) $(nlm_HEADERS_GENERATED)

CLEANFILES = $(nlm_GENERATED) nlm-stamp

libnlm_la_CPPFLAGS = -I$(abs_top_srcdir)/include
libnlm_la_SOURCES = \
	$(nlm_SOURCES_GENERATED) \
	nlm.c

$(nlm_GENERATED) : nlm-stamp
nlm-stamp : nlm.x
	rm -f $(nlm_GENERATED)
	rpcgen -h @RPCGENFLAGS@ $< > libnfs-raw-nlm.h
	rpcgen -c @RPCGENFLAGS@ $< | sed -e "s/#include \".*nlm.h\"/#include \"libnfs-raw-nlm.h\"/" > libnfs-raw-nlm.c
	touch nlm-stamp
	
