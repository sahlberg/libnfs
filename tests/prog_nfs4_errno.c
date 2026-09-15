#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

int main(void)
{
        assert(nfsstat4_to_errno(NFS4_OK) == 0);
        assert(nfsstat4_to_errno(NFS4ERR_STALE) == -ESTALE);
        assert(nfsstat4_to_errno(NFS4ERR_IO) == -EIO);
        assert(nfsstat4_to_errno(NFS4ERR_NOENT) == -ENOENT);
        assert(nfsstat4_to_errno(NFS4ERR_ACCESS) == -EACCES);
        puts("PASS: stale filehandle is distinguishable from I/O and pathname errors");
        return 0;
}
