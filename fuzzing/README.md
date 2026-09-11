# Fuzzing libnfs

This directory contains a libFuzzer target for libnfs decoding of RPC
replies, the client side of the NFS data path: everything a malicious or
misbehaving NFS server sends back to the client.

It is intentionally standalone and decoupled from the normal build;
nothing in the main source tree references it.

## Target

`libnfs_reply_fuzzer.c` mirrors how `rpc_process_pdu` hands a decoded
reply to the per procedure decoder: the first input byte selects one of
the generated ZDR reply decoders from the `new_packets`-style dispatch
and the remaining bytes are the reply payload. The table covers 157
decoders across NFS v2/v3, mount v1/v3, NLM, portmap v2/v3, rquota and
the NFSv4.x compound, so all generated XDR reply parsing is exercised,
including deep structures such as READDIRPLUS3, fattr3 and NFSv4
operations and attributes.

`seeds/` holds a small seed corpus spanning the decoder table.

## Building and running

Build libnfs first, for example:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=OFF
cmake --build build -j$(nproc)
```

Then compile the fuzz target against it with the libFuzzer and
AddressSanitizer flags:

```
clang -std=c11 -g -fsanitize=fuzzer,address -fno-omit-frame-pointer \
  -I include/nfsc -I nfs -I mount -I nlm -I rquota -I portmap -I nfs4 -I build \
  fuzzing/libnfs_reply_fuzzer.c \
  build/lib/libnfs.a -lpthread \
  -o libnfs_reply_fuzzer
```

Run it over the seed corpus:

```
./libnfs_reply_fuzzer fuzzing/seeds/
```

## OSS-Fuzz

This target is intended to be integrated into Google's OSS-Fuzz program
for the libnfs project, running it continuously under AddressSanitizer
and UndefinedBehaviorSanitizer.
