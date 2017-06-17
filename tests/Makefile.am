AM_CPPFLAGS = -I${srcdir}/../include -I${srcdir}/../include/nfsc \
	"-D_U_=__attribute__((unused))" \
	"-D_R_(A,B)=__attribute__((format(printf,A,B)))"
AM_CFLAGS = $(WARN_CFLAGS)
LDADD = ../lib/libnfs.la

noinst_PROGRAMS = prog_stat

T = `ls test_*.sh`

test: $(noinst_PROGRAMS)
	for TEST in $(T); do \
		echo "Running $$TEST"; \
		echo "--------------"; \
		sh $$TEST || exit 1;   \
		echo "--------------"; \
		echo; \
	done
