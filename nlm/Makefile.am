noinst_LTLIBRARIES = libnlm.la

nlm_SOURCES_GENERATED =
nlm_HEADERS_GENERATED =
nlm_GENERATED = $(nlm_SOURCES_GENERATED) $(nlm_HEADERS_GENERATED)

CLEANFILES = $(nlm_GENERATED) nlm-stamp

libnlm_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		     -I$(abs_top_srcdir)/include/nfsc \
		     -I$(abs_top_srcdir)/win32
libnlm_la_SOURCES = \
	$(nlm_SOURCES_GENERATED) \
	nlm.c libnfs-raw-nlm.c libnfs-raw-nlm.h

$(nlm_GENERATED) : nlm-stamp
nlm-stamp : nlm.x
	rm -f $(nlm_GENERATED)
	touch nlm-stamp

compile_rpc:
	cd $(srcdir) && python3 ../tools/zdrgen.py nlm.x libnfs-raw-nlm.h libnfs-raw-nlm.c
