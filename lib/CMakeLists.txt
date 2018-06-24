set(SOURCES init.c
            libnfs.c
            libnfs-sync.c
            libnfs-zdr.c
            nfs_v3.c
            nfs_v4.c
            pdu.c
            socket.c)

add_library(nfs ${SOURCES})
target_link_libraries(nfs PUBLIC ${core_DEPENDS})
target_include_directories(nfs PUBLIC ../include)
set_target_properties(nfs PROPERTIES
                          VERSION ${PROJECT_VERSION}
                          SOVERSION ${SOVERSION})
add_dependencies(nfs ${core_DEPENDS})
add_definitions("-D_U_=__attribute__((unused))")

install(TARGETS nfs EXPORT nfs
                    RUNTIME DESTINATION bin
                    ARCHIVE DESTINATION lib
                    LIBRARY DESTINATION lib)
