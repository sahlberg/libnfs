noinst_LTLIBRARIES = librquota.la

rquota_SOURCES_GENERATED =
rquota_HEADERS_GENERATED =
rquota_GENERATED = $(rquota_SOURCES_GENERATED) $(rquota_HEADERS_GENERATED)

CLEANFILES = $(rquota_GENERATED) rquota-stamp

librquota_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
			-I$(abs_top_srcdir)/include/nfsc \
			-I$(abs_top_srcdir)/win32
librquota_la_SOURCES = \
	$(rquota_SOURCES_GENERATED) \
	rquota.c libnfs-raw-rquota.c libnfs-raw-rquota.h

$(rquota_GENERATED) : rquota-stamp
rquota-stamp : rquota.x
	rm -f $(rquota_GENERATED)
	touch rquota-stamp

compile_rpc:
	cd $(srcdir) && python3 ../tools/zdrgen.py rquota.x libnfs-raw-rquota.h libnfs-raw-rquota.c
