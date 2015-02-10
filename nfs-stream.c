#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "nfsc/libnfs.h"

int main(int argc, char *argv[])
{
	struct nfs_context *nfs;
	struct nfs_url *url;
	struct nfsfh *nfsfh = NULL;
	struct nfs_stat_64 st;
	uint64_t offset;
	char buf[32768];
	struct timeval t1, t2;
	uint64_t delta, tpc;

	if (argc != 3) {
		fprintf(stderr, "Usage: nfs-stream <nfs-url> <bytes-per-second>\n");
		exit(1);
	}

	nfs = nfs_init_context();
	url = nfs_parse_url_full(nfs, argv[1]);
	if (!url) {
		fprintf(stderr, "Can not parse URL. %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
	if (nfs_mount(nfs, url->server, url->path) != 0) {
		fprintf(stderr, "Failed to mount nfs share : %s\n",
			       nfs_get_error(nfs));
		exit(1);
	}
	if (nfs_open(nfs, url->file, O_RDONLY, &nfsfh) != 0) {
		fprintf(stderr, "Failed to open file %s: %s\n",
			url->file,
			nfs_get_error(nfs));
		exit(1);
	}
	nfs_set_streaming_mode(nfsfh, 5 * 1024 * 1024);

	if (nfs_fstat64(nfs, nfsfh, &st)) {
		fprintf(stderr, "Failed to stat file %s: %s\n",
			url->file,
			nfs_get_error(nfs));
		exit(1);
	}
	printf("File size:%lld\n", (long long)st.nfs_size);
	tpc = 1000000 / (strtol(argv[2], NULL, 10) / 32768);
	printf("Read one 32kb chunk every %d us\n", (int)tpc);
	for (offset = 0; offset < st.nfs_size; offset += 32768) {
		gettimeofday(&t1, NULL);
		nfs_read(nfs, nfsfh, 32768, buf);
		gettimeofday(&t2, NULL);
		delta = t2.tv_sec * 1000000LL + t2.tv_usec -
		  t1.tv_sec * 1000000LL - t1.tv_usec;
		printf("Read latency:%lld us\n", (long long)delta);
		if (tpc > delta) {
			//printf("Sleep for %d us\n", (int)(tpc - delta));
			usleep(tpc - delta);
		}
	}

	nfs_close(nfs, nfsfh);
	nfs_destroy_context(nfs);	
	nfs_destroy_url(url);
	return 0;
}
