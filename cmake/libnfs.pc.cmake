# libnfs pkg-config file

prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_PREFIX@
libdir=@INSTALL_LIB_DIR@
includedir=@INSTALL_INC_DIR@

Name: libnfs
Description: libnfs is a client library for accessing NFS shares over a network.
Version: @PROJECT_VERSION@
Requires:
Conflicts:
Libs: -L${libdir} -lnfs @PKG_LIBLIST@
Cflags: -I${includedir}
