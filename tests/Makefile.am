AM_CPPFLAGS = -I${srcdir}/../include -I${srcdir}/../include/nfsc \
	"-D_U_=__attribute__((unused))" \
	"-D_R_(A,B)=__attribute__((format(printf,A,B)))"
AM_CFLAGS = $(WARN_CFLAGS)
LDADD = ../lib/libnfs.la

noinst_PROGRAMS = prog_fstat prog_rename prog_stat prog_symlink prog_timeout

EXTRA_PROGRAMS = ld_timeout
CLEANFILES = ld_timeout.o ld_timeout.so

ld_timeout_SOURCES = ld_timeout.c
ld_timeout_CFLAGS = $(AM_CFLAGS) -fPIC

bin_SCRIPTS = ld_timeout.so

ld_timeout.o: ld_timeout-ld_timeout.o
	$(LIBTOOL) --mode=link $(CC) -o $@ $^

ld_timeout.so: ld_timeout.o
	$(CC) -shared -o ld_timeout.so ld_timeout.o -ldl



T = `ls test_*.sh`

test: $(noinst_PROGRAMS)
	for TEST in $(T); do \
		echo "Running $$TEST"; \
		echo "--------------"; \
		sh $$TEST || exit 1;   \
		echo "--------------"; \
		echo; \
	done
