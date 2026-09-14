# Fuzzing libnfs

libFuzzer target for the RPC reply decoding, i.e. everything a server
sends back to the client. Not part of the normal build, nothing else in
the tree depends on it.

The harness feeds a buffer to one of the generated ZDR reply decoders,
picked by the first input byte, the same dispatch rpc_process_pdu uses
when it hands a reply to the per procedure decoder. All 157 of them are
covered: NFS v2/v3, mount v1/v3, NLM, portmap v2/v3, rquota and the
NFSv4.x compound, so the deep structures (READDIRPLUS3, fattr3, NFSv4
operations and attributes) get reached too.

Build libnfs first, then the target:

    cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=OFF
    cmake --build build -j$(nproc)

    clang -std=c11 -g -fsanitize=fuzzer,address -fno-omit-frame-pointer \
      -I include -I include/nfsc -I nfs -I mount -I nlm -I rquota -I portmap -I nfs4 -I build \
      fuzzing/libnfs_reply_fuzzer.c build/lib/libnfs.a -lpthread \
      -o libnfs_reply_fuzzer

Run it over the seeds:

    ./libnfs_reply_fuzzer fuzzing/seeds/

seeds/ is a small corpus spread across the decoder table.

The idea is to hook this up to OSS Fuzz so it keeps running there
under sanitizers continuously.
