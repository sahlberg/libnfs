set(SOURCES handshake.c
            ktls.c)
set(INCLUDEDIRS ${GNUTLS_INCLUDE_DIR})
core_add_library(tls)
