#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libnfs.h"

void usage(void)
{
    fprintf(stderr, "Usage: prog_parse_url_full <url> <server> <port> <path> <file>\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    struct nfs_context *nfs;
    struct nfs_url *nfs_url;
    int ret = 0;
    int expected_port;

    if (argc != 6)
    {
        usage();
    }

    nfs = nfs_init_context();
    if (nfs == NULL) {
        fprintf(stderr, "failed to init context\n");
        return 1;
    }

    nfs_url = nfs_parse_url_full(nfs, argv[1]);
    if (nfs_url == NULL) {
        fprintf(stderr, "Failed to parse URL: %s\n", nfs_get_error(nfs));
        nfs_destroy_context(nfs);
        return 1;
    }

    if (strcmp(nfs_url->server, argv[2]) != 0) {
        fprintf(stderr, "Unexpected server name: %s (expected: %s)\n", 
                nfs_url->server ? nfs_url->server : "(null)", argv[2]);
        ret = 1;
    }

    expected_port = atoi(argv[3]);
    if (nfs_url->port != expected_port) {
        fprintf(stderr, "Unexpected port: %d (expected: %d)\n", 
                nfs_url->port, expected_port);
        ret = 1;
    }

    if (strcmp(nfs_url->path, argv[4]) != 0) {
        fprintf(stderr, "Unexpected path: %s (expected: %s)\n", 
                nfs_url->path ? nfs_url->path : "(null)", argv[4]);
        ret = 1;
    }

    if (strcmp(nfs_url->file, argv[5]) != 0) {
        fprintf(stderr, "Unexpected file: %s (expected: %s)\n", 
                nfs_url->file ? nfs_url->file : "(null)", argv[5]);
        ret = 1;
    }

    nfs_destroy_url(nfs_url);
    nfs_destroy_context(nfs);

    return ret;
}