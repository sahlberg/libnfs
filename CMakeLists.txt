cmake_minimum_required(VERSION 3.16)

# The autotools files are the single source of truth for the version and for
# the library ABI version; everything below is derived from them so that a
# release only ever has to be bumped in configure.ac and lib/Makefile.am.

# The release version, from AC_INIT() in configure.ac.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/configure.ac" LIBNFS_CONFIGURE_AC)
if(NOT LIBNFS_CONFIGURE_AC MATCHES "AC_INIT\\(\\[libnfs\\],[ \t]*\\[([0-9]+\\.[0-9]+\\.[0-9]+)\\]")
  message(FATAL_ERROR "cannot parse the libnfs version out of AC_INIT() in configure.ac")
endif()
set(LIBNFS_VERSION "${CMAKE_MATCH_1}")
unset(LIBNFS_CONFIGURE_AC)

# The libtool current:revision:age triple, from lib/Makefile.am.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/lib/Makefile.am" LIBNFS_LIB_MAKEFILE_AM)
foreach(var SOCURRENT SOREVISION SOAGE)
  if(NOT LIBNFS_LIB_MAKEFILE_AM MATCHES "(^|\n)[ \t]*${var}[ \t]*=[ \t]*([0-9]+)")
    message(FATAL_ERROR "cannot parse ${var} out of lib/Makefile.am")
  endif()
  set(${var} "${CMAKE_MATCH_2}")
endforeach()
unset(LIBNFS_LIB_MAKEFILE_AM)

# libtool installs the library as libnfs.so.(current-age).age.revision with the
# soname libnfs.so.(current-age). Mirror that here so that the cmake build and
# the autotools build produce interchangeable libraries.
math(EXPR SOMAJOR "${SOCURRENT} - ${SOAGE}")
set(SOVERSION ${SOMAJOR} CACHE STRING "" FORCE)
set(LIBNFS_SOFILE_VERSION ${SOMAJOR}.${SOAGE}.${SOREVISION})

project(libnfs
        LANGUAGES C
        VERSION ${LIBNFS_VERSION})

# Re-run cmake when the autotools files we just parsed are edited.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
             "${CMAKE_CURRENT_SOURCE_DIR}/configure.ac"
             "${CMAKE_CURRENT_SOURCE_DIR}/lib/Makefile.am")

message(STATUS "libnfs ${LIBNFS_VERSION}, library libnfs.so.${LIBNFS_SOFILE_VERSION} (soname libnfs.so.${SOVERSION})")

include(cmake/GNUInstallDirs.cmake)

set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Installation directory for binaries")
set(INSTALL_LIB_DIR "${CMAKE_INSTALL_FULL_LIBDIR}" CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
set(INSTALL_MAN_DIR "${CMAKE_INSTALL_PREFIX}/share/man" CACHE PATH "Installation directory for manual pages")
set(INSTALL_PKGCONFIG_DIR "${INSTALL_LIB_DIR}/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
set(INSTALL_CMAKE_DIR "${INSTALL_LIB_DIR}/cmake/libnfs" CACHE PATH "Installation directory for cmake (.cmake) files")

option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(ENABLE_TESTS "Build and run test programs" OFF)
option(ENABLE_DOCUMENTATION "Build Documentation" OFF)
option(ENABLE_UTILS "Build util programs" OFF)
option(ENABLE_EXAMPLES "Build example programs" OFF)
option(ENABLE_MULTITHREADING "Enable multithreading support" OFF)
set(ENABLE_TLS "AUTO" CACHE STRING "Build RPC-with-TLS support: ON, OFF or AUTO (only if gnutls and kTLS are available)")
set_property(CACHE ENABLE_TLS PROPERTY STRINGS AUTO ON OFF)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(CMAKE_INSTALL_RPATH "${INSTALL_LIB_DIR}")
  set(CMAKE_SKIP_INSTALL_RPATH FALSE)
endif()

if(ENABLE_TESTS)
  set(ENABLE_UTILS ON CACHE BOOL "Building utils required by tests" FORCE)
endif()

if(ENABLE_MULTITHREADING)
  add_definitions(-DHAVE_MULTITHREADING)
endif()

include(cmake/Macros.cmake)

if(IOS)
    find_package(GSSAPI)

    if(GSSAPI_FOUND)
        add_definitions(-DHAVE_LIBKRB5)
    endif()
endif()

include(cmake/ConfigureChecks.cmake)

include_directories(${CMAKE_CURRENT_BINARY_DIR}
                    include
                    include/nfsc)

# list of system libs (sockets/etc) to be linked on this system
set(SYSTEM_LIBRARIES "")
# list of core (static) libraries built in current configuration (used by lib/CMakeLists.txt)
set(CORE_LIBRARIES "" CACHE INTERNAL "")

# make sure related functions are exported in final dll
if(WIN32 AND BUILD_SHARED_LIBS)
  add_definitions(-Dlibnfs_EXPORTS)
endif()

if(ENABLE_MULTITHREADING AND PTHREAD_LIBRARY)
    list(APPEND SYSTEM_LIBRARIES pthread)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
  add_definitions("-D_U_=__attribute__((unused))")
  #
  # Currently RPC-with-TLS support is only available on Linux since it depends on kTLS support
  # on Linux.
  #
  # TODO: BSD also has kTLS support, but that will need separate validation.
  #
  # ENABLE_TLS=AUTO (the default) builds TLS support only if gnutls and the kernel kTLS
  # headers/definitions are all available, ENABLE_TLS=ON fails the configure step if they
  # are not and ENABLE_TLS=OFF never builds TLS support.
  #
  if(ENABLE_TLS)
    include(CheckSymbolExists)
    include(CheckCSourceCompiles)

    find_package(GnuTLS "3.4.6")
    if(NOT GNUTLS_FOUND)
      set(TLS_MISSING "gnutls >= 3.4.6 not found")
    else()
      #
      # Make sure the headers and the kernel definitions we use are all present before we
      # enable TLS support, to avoid running into issues later during build. GnuTLS package
      # found but gnutls/gnutls.h not found is a serious issue while if the kTLS bits are
      # missing it would likely mean that user is using a kernel not supporting kTLS so we
      # simply don't turn on TLS support.
      #
      set(CMAKE_REQUIRED_INCLUDES ${GNUTLS_INCLUDE_DIR})
      set(CMAKE_REQUIRED_LIBRARIES ${GNUTLS_LIBRARIES})

      check_include_file("gnutls/gnutls.h" HAVE_GNUTLS_H)
      if(NOT HAVE_GNUTLS_H EQUAL "1")
        message(FATAL_ERROR "GnuTLS found but gnutls/gnutls.h not found, GNUTLS_INCLUDE_DIR is ${GNUTLS_INCLUDE_DIR}")
      endif()

      check_include_file("linux/tls.h" HAVE_LINUX_TLS_H)
      if(NOT HAVE_LINUX_TLS_H EQUAL "1")
        set(TLS_MISSING "linux/tls.h not found, likely a kernel w/o kTLS support")
      else()
        #
        # linux/tls.h alone is not enough, we also need the socket options used to switch a
        # socket to the TLS ULP and to install the keys, and the crypto info struct.
        #
        check_c_source_compiles("
          #include <sys/socket.h>
          #include <netinet/tcp.h>
          #include <linux/tls.h>
          int main(void) {
            struct tls12_crypto_info_aes_gcm_128 info;
            info.info.version = TLS_1_2_VERSION;
            info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
            (void)setsockopt(0, SOL_TCP, TCP_ULP, \"tls\", sizeof(\"tls\"));
            (void)setsockopt(0, SOL_TLS, TLS_TX, &info, sizeof(info));
            return 0;
          }" HAVE_KTLS)
        if(NOT HAVE_KTLS)
          set(TLS_MISSING "kTLS definitions (TCP_ULP, SOL_TLS, TLS_TX) not found in the kernel headers")
        endif()
      endif()

      unset(CMAKE_REQUIRED_INCLUDES)
      unset(CMAKE_REQUIRED_LIBRARIES)
    endif()

    if(TLS_MISSING)
      if(ENABLE_TLS STREQUAL "AUTO")
        message(STATUS "Building without RPC-with-TLS support: ${TLS_MISSING}")
      else()
        message(FATAL_ERROR "ENABLE_TLS is on but ${TLS_MISSING}")
      endif()
    else()
      message(STATUS "Using ${GNUTLS_LIBRARIES}")
      add_definitions(-DHAVE_TLS)
      list(APPEND SYSTEM_LIBRARIES ${GNUTLS_LIBRARIES})
      add_subdirectory(tls)
    endif()
  endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL Windows OR CMAKE_SYSTEM_NAME STREQUAL WindowsStore)
  add_definitions("-D_U_=" -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE)
  list(APPEND SYSTEM_LIBRARIES ws2_32)
  add_subdirectory(win32)
elseif(CMAKE_SYSTEM_NAME STREQUAL Solaris)
  add_definitions("-D_U_=__attribute__((unused))")
  find_library(SOCKET_LIBRARY socket)
  find_library(NSL_LIBRARY nsl)
  list(APPEND SYSTEM_LIBRARIES ${SOCKET_LIBRARY} ${NSL_LIBRARY})
elseif(CMAKE_SYSTEM_NAME STREQUAL aros)
  add_definitions("-D_U_=__attribute__((unused))")
  add_definitions(-DAROS)
  add_subdirectory(aros)
else()
  add_definitions("-D_U_=__attribute__((unused))")
endif()

add_subdirectory(mount)
add_subdirectory(nfs)
add_subdirectory(nfs4)
add_subdirectory(nlm)
add_subdirectory(nsm)
add_subdirectory(portmap)
add_subdirectory(rquota)
add_subdirectory(lib)   # this has to be last (it links all static libs mentioned in CORE_LIBRARIES)

add_subdirectory(doc)

if(ENABLE_EXAMPLES)
  add_subdirectory(examples)
endif()

if(ENABLE_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(ENABLE_UTILS)
  add_subdirectory(utils)
endif()

# this will create build-tree-specific config file (so downstream client can use this specific build without having to install package)
export(EXPORT libnfs
       NAMESPACE libnfs::
       FILE "${CMAKE_CURRENT_BINARY_DIR}/libnfs-config.cmake")

# this will create relocatable config file in installation directory
install(EXPORT libnfs
        DESTINATION "${INSTALL_CMAKE_DIR}"
        NAMESPACE libnfs::
        FILE libnfs-config.cmake)

# handle version file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/libnfs-config-version.cmake
                                 VERSION ${PROJECT_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

install(FILES cmake/FindNFS.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/libnfs-config-version.cmake
        DESTINATION ${INSTALL_CMAKE_DIR})

# handle pc-config files
set(PKG_LIBLIST "")
foreach(LIB ${SYSTEM_LIBRARIES})
  if(IS_ABSOLUTE ${LIB} AND EXISTS ${LIB})
    list(APPEND PKG_LIBLIST "${LIB}")
  else()
    list(APPEND PKG_LIBLIST "-l${LIB}")
  endif()
endforeach()
configure_file(cmake/libnfs.pc.cmake
               ${CMAKE_CURRENT_BINARY_DIR}/libnfs.pc @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libnfs.pc
        DESTINATION ${INSTALL_PKGCONFIG_DIR})

# handle headers installation
install(DIRECTORY include/nfsc
        DESTINATION ${INSTALL_INC_DIR})

install(FILES mount/libnfs-raw-mount.h
              nfs/libnfs-raw-nfs.h
              nfs4/libnfs-raw-nfs4.h
              nlm/libnfs-raw-nlm.h
              nsm/libnfs-raw-nsm.h
              portmap/libnfs-raw-portmap.h
              rquota/libnfs-raw-rquota.h
        DESTINATION ${INSTALL_INC_DIR}/nfsc)
