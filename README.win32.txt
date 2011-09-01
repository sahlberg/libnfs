1. checkout oncrpc-win32 project (branch hyper!)
2. build oncrpc-win32 project (see README.win32 in the projects dir)
3. checkout libnfs (branch win32)
4. adapt oncrpc-win32 path in win32/win32build.bat
4. build libnfs with cd win32;win32build.bat
5. copy lib/libnfs.dll and <oncrpc-win32-path>/win32/bin/liboncrpc.dll to the dir where the executable is...