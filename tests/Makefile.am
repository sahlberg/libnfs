AM_CPPFLAGS = -I${srcdir}/../include -I${srcdir}/../include/nfsc \
	"-D_U_=__attribute__((unused))" \
	"-D_R_(A,B)=__attribute__((format(printf,A,B)))"
AM_CFLAGS = $(WARN_CFLAGS)
LDADD = ../lib/libnfs.la

noinst_PROGRAMS = prog_access prog_access2 prog_chmod prog_chown prog_create \
	prog_fchmod prog_fchown prog_fstat prog_ftruncate prog_lchmod \
	prog_lchown prog_link prog_lseek prog_lstat prog_mkdir \
	prog_mknod prog_mount prog_opendir prog_open_read prog_open_write \
	prog_rename prog_rmdir prog_stat prog_statvfs prog_symlink \
	prog_timeout prog_truncate prog_unlink prog_utimes

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
