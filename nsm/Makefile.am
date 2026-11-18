noinst_LTLIBRARIES = libnsm.la

nsm_SOURCES_GENERATED =
nsm_HEADERS_GENERATED =
nsm_GENERATED = $(nsm_SOURCES_GENERATED) $(nsm_HEADERS_GENERATED)

CLEANFILES = $(nsm_GENERATED) nsm-stamp

libnsm_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		     -I$(abs_top_srcdir)/include/nfsc \
		     -I$(abs_top_srcdir)/win32
libnsm_la_SOURCES = \
	$(nsm_SOURCES_GENERATED) \
	nsm.c libnfs-raw-nsm.c libnfs-raw-nsm.h

$(nsm_GENERATED) : nsm-stamp
nsm-stamp : nsm.x
	rm -f $(nsm_GENERATED)
	touch nsm-stamp

compile_rpc:
	cd $(srcdir) && python3 ../tools/zdrgen.py nsm.x libnfs-raw-nsm.h libnfs-raw-nsm.c
