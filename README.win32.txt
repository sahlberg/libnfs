LibNFS requires a oncrpc library and rpcgen compiler that can handle
64 bit types. Link below for one such package, but any 64bit capable oncrpc
package should work with some effort.


1. checkout git://github.com/Memphiz/oncrpc-win32.git project (branch hyper!)
2. build oncrpc-win32 project (see README.win32 in the projects dir)
3. checkout libnfs (branch win32)
4. adapt oncrpc-win32 path in win32/win32build.bat
4. build libnfs with cd win32;win32build.bat
5. copy lib/libnfs.dll and <oncrpc-win32-path>/win32/bin/liboncrpc.dll to the dir where the executable is...
